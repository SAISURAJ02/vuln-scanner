import socket
import ssl
import re
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

TIMEOUT = 6
MAX_BODY_BYTES = 2_000_000

# some servers/WAFs block requests with the default python UA, so fake a browser
UA = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
}

# small demo list, would hook into an actual CVE feed for real use
VULN_LIBS = {
    "jquery": {"max_safe": (3, 5, 0), "note": "old jQuery versions have known XSS bugs (CVE-2020-11022 etc.)"},
    "angular": {"max_safe": (1, 8, 0), "note": "AngularJS 1.x is EOL, sandbox escape XSS issues"},
    "bootstrap": {"max_safe": (4, 3, 1), "note": "older Bootstrap has XSS in tooltip/popover data attrs"},
}

SECURITY_HEADERS = {
    "Content-Security-Policy": "mitigates XSS/data-injection by restricting content sources",
    "Strict-Transport-Security": "forces HTTPS, prevents downgrade/MITM",
    "X-Frame-Options": "prevents clickjacking",
    "X-Content-Type-Options": "prevents MIME-sniffing (should be 'nosniff')",
    "Referrer-Policy": "controls referrer leakage to other sites",
    "Permissions-Policy": "restricts which browser APIs the page can use",
}

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-alt", 27017: "MongoDB",
}


def is_private_target(hostname):
    try:
        if hostname in ("localhost", "127.0.0.1", "::1"):
            return True
        ip = socket.gethostbyname(hostname)
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def check_headers(url, retried=False):
    findings = []
    try:
        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True, headers=UA, stream=True)

        # cap the read instead of resp.text - don't want to buffer a huge page
        raw = b""
        for chunk in resp.iter_content(chunk_size=8192):
            raw += chunk
            if len(raw) >= MAX_BODY_BYTES:
                break
        html = raw.decode(resp.encoding or "utf-8", errors="replace")

        for header, note in SECURITY_HEADERS.items():
            if header not in resp.headers:
                findings.append({
                    "check": "security_headers", "severity": "medium",
                    "title": f"Missing {header}", "detail": note,
                })

        server = resp.headers.get("Server", "")
        if server and re.search(r"\d", server):
            findings.append({
                "check": "info_disclosure", "severity": "low",
                "title": f"Server header reveals version: {server}",
                "detail": "version disclosure helps attackers target CVEs for that exact version",
            })

        cookie = resp.headers.get("Set-Cookie", "")
        if cookie:
            if "Secure" not in cookie:
                findings.append({"check": "cookies", "severity": "medium",
                                  "title": "Cookie missing Secure flag",
                                  "detail": "cookie can be sent over plain HTTP"})
            if "HttpOnly" not in cookie:
                findings.append({"check": "cookies", "severity": "medium",
                                  "title": "Cookie missing HttpOnly flag",
                                  "detail": "cookie readable via JS, worse if XSS is present"})

        return findings, html

    except requests.exceptions.TooManyRedirects:
        return [{"check": "headers", "severity": "info", "title": "Too many redirects",
                 "detail": "possible redirect loop"}], ""
    except requests.exceptions.SSLError as e:
        return [{"check": "headers", "severity": "high", "title": "SSL error while fetching page",
                 "detail": str(e)}], ""
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        # https might just not be offered - try http once before giving up
        if url.startswith("https://") and not retried:
            http_url = "http://" + url[len("https://"):]
            fb_findings, fb_html = check_headers(http_url, retried=True)
            fb_findings.append({
                "check": "ssl_tls", "severity": "medium",
                "title": "Site not reachable over HTTPS — fell back to HTTP",
                "detail": "port 443 didn't respond, scanned over plain HTTP instead",
            })
            return fb_findings, fb_html
        return [{"check": "headers", "severity": "info", "title": "Could not connect to target",
                 "detail": str(e)}], ""
    except requests.exceptions.RequestException as e:
        return [{"check": "headers", "severity": "info", "title": "Could not fetch headers",
                 "detail": str(e)}], ""


def check_ssl(hostname, port=443, https_confirmed=False):
    if not hostname:
        return [{"check": "ssl_tls", "severity": "info", "title": "No hostname to check",
                 "detail": "couldn't parse a hostname from the target URL"}]

    findings = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()

                if version in ("TLSv1", "TLSv1.1"):
                    findings.append({"check": "ssl_tls", "severity": "high",
                                      "title": f"Weak TLS version in use: {version}",
                                      "detail": "TLS 1.0/1.1 are deprecated, known attacks exist"})

                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_left = (not_after.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
                if days_left < 14:
                    findings.append({"check": "ssl_tls", "severity": "high",
                                      "title": f"SSL certificate expires soon ({days_left} days)",
                                      "detail": "expired certs break trust and cause outages"})
    except ssl.SSLError as e:
        findings.append({"check": "ssl_tls", "severity": "high", "title": "SSL error", "detail": str(e)})
    except (socket.gaierror, socket.timeout):
        if https_confirmed:
            findings.append({
                "check": "ssl_tls", "severity": "info", "title": "Could not complete detailed TLS check",
                "detail": "page loaded fine over HTTPS but the raw handshake didn't complete - probably "
                          "local network interference, not an issue on the target's end",
            })
        else:
            findings.append({"check": "ssl_tls", "severity": "info", "title": "Could not reach target on port 443",
                             "detail": "host may not resolve, be unreachable, or not serve HTTPS at all"})
    except ConnectionRefusedError:
        findings.append({"check": "ssl_tls", "severity": "info", "title": "Connection refused on port 443",
                         "detail": "target doesn't appear to serve HTTPS on the standard port"})
    except Exception as e:
        findings.append({"check": "ssl_tls", "severity": "info", "title": "Could not verify SSL/TLS",
                         "detail": str(e)})
    return findings


def check_https_enforced(url):
    parsed = urlparse(url)
    if parsed.scheme == "https":
        return []

    findings = []
    try:
        http_url = f"http://{parsed.netloc}{parsed.path}"
        resp = requests.get(http_url, timeout=TIMEOUT, allow_redirects=False, headers=UA)
        if resp.status_code not in (301, 302, 307, 308) or "https" not in resp.headers.get("Location", ""):
            findings.append({"check": "ssl_tls", "severity": "high", "title": "HTTPS not enforced",
                             "detail": "site doesn't redirect HTTP to HTTPS"})
    except requests.exceptions.RequestException:
        pass
    return findings


def check_outdated_libs(html):
    findings = []
    for lib, info in VULN_LIBS.items():
        matches = re.findall(rf"{lib}[.\-/]?(\d+)\.(\d+)\.(\d+)", html, re.IGNORECASE)
        versions = [tuple(int(x) for x in m) for m in matches]
        old = [v for v in versions if v < info["max_safe"]]
        if not old:
            continue
        worst = min(old)
        findings.append({
            "check": "outdated_libs", "severity": "medium",
            "title": f"Outdated {lib} version {'.'.join(map(str, worst))} detected",
            "detail": info["note"],
        })
    return findings


def check_open_ports(hostname):
    # only scan private/local targets, don't want to hit random public IPs
    if not is_private_target(hostname):
        return [{"check": "port_scan", "severity": "info", "title": "Port scan skipped",
                 "detail": "target is public - port scanning is restricted to localhost/private targets"}]

    findings = []
    for port, service in COMMON_PORTS.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((hostname, port)) == 0:
                    findings.append({
                        "check": "port_scan",
                        "severity": "info" if port in (80, 443) else "medium",
                        "title": f"Open port {port} ({service})",
                        "detail": f"{service} is reachable - make sure that's intentional",
                    })
        except socket.error:
            pass
    return findings


def compute_risk_score(findings):
    weights = {"high": 10, "medium": 5, "low": 2, "info": 0}
    total = sum(weights.get(f["severity"], 0) for f in findings)

    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.get("severity", "info")] += 1

    if total >= 30:
        grade = "Critical"
    elif total >= 15:
        grade = "High Risk"
    elif total >= 5:
        grade = "Moderate Risk"
    else:
        grade = "Low Risk"

    return {"score": total, "grade": grade, "counts": counts}


def _safe_run(name, fn, *args):
    # one bad check shouldn't kill the whole scan
    try:
        return fn(*args)
    except Exception as e:
        return [{"check": name, "severity": "info", "title": f"{name} check failed to complete", "detail": str(e)}]


def run_scan(target_url):
    target_url = (target_url or "").strip()
    if not target_url:
        raise ValueError("target is empty")

    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    parsed = urlparse(target_url)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"could not parse a hostname from '{target_url}'")

    # only try the raw TLS handshake if https was actually intended - an
    # explicit http:// target might be on a port that doesn't speak TLS at all
    wants_https = parsed.scheme == "https"

    findings = []

    try:
        header_findings, html = check_headers(target_url)
    except Exception as e:
        header_findings, html = [{"check": "headers", "severity": "info",
                                   "title": "Header check failed to complete", "detail": str(e)}], ""
    findings += header_findings

    fell_back = any(f.get("title", "").startswith("Site not reachable over HTTPS") for f in header_findings)
    if fell_back and target_url.startswith("https://"):
        target_url = "http://" + target_url[len("https://"):]

    if wants_https:
        findings += _safe_run("ssl_tls", check_ssl, hostname, parsed.port or 443, not fell_back)
        if not fell_back:
            findings += _safe_run("ssl_tls", check_https_enforced, target_url)

    findings += _safe_run("outdated_libs", check_outdated_libs, html)
    findings += _safe_run("port_scan", check_open_ports, hostname)

    return {
        "target": target_url,
        "hostname": hostname,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
        "risk": compute_risk_score(findings),
    }
