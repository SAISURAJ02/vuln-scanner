import { useState, useEffect } from 'react'

const API_BASE = 'http://localhost:5000/api'

const SEVERITY_COLOR = {
  high: '#dc2626',
  medium: '#d97706',
  low: '#2563eb',
  info: '#6b7280',
}

const GRADE_COLOR = {
  Critical: '#dc2626',
  'High Risk': '#ea580c',
  'Moderate Risk': '#d97706',
  'Low Risk': '#16a34a',
}

function RiskBadge({ grade, score }) {
  return (
    <div style={{
      display: 'inline-flex', alignItems: 'center', gap: 8,
      background: GRADE_COLOR[grade] || '#6b7280',
      color: 'white', padding: '6px 14px', borderRadius: 20,
      fontWeight: 600, fontSize: 14,
    }}>
      {grade} · Score {score}
    </div>
  )
}

function FindingRow({ finding }) {
  return (
    <div style={{
      borderLeft: `4px solid ${SEVERITY_COLOR[finding.severity] || '#6b7280'}`,
      padding: '10px 14px', marginBottom: 8, background: '#f9fafb', borderRadius: 4,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <strong style={{ fontSize: 14 }}>{finding.title}</strong>
        <span style={{
          fontSize: 11, textTransform: 'uppercase', fontWeight: 700,
          color: SEVERITY_COLOR[finding.severity] || '#6b7280',
        }}>
          {finding.severity}
        </span>
      </div>
      <p style={{ margin: '4px 0 0', fontSize: 13, color: '#4b5563' }}>{finding.detail}</p>
    </div>
  )
}

function ScanResult({ result }) {
  if (!result) return null
  return (
    <div style={{ marginTop: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div>
          <h3 style={{ margin: 0 }}>{result.target}</h3>
          <span style={{ fontSize: 12, color: '#6b7280' }}>
            Scanned {new Date(result.scanned_at).toLocaleString()}
          </span>
        </div>
        <RiskBadge grade={result.risk.grade} score={result.risk.score} />
      </div>

      <div style={{ display: 'flex', gap: 12, marginBottom: 16 }}>
        {Object.entries(result.risk.counts).map(([sev, count]) => (
          <div key={sev} style={{
            flex: 1, textAlign: 'center', padding: '10px 0',
            background: '#fff', border: '1px solid #e5e7eb', borderRadius: 6,
          }}>
            <div style={{ fontSize: 22, fontWeight: 700, color: SEVERITY_COLOR[sev] }}>{count}</div>
            <div style={{ fontSize: 11, textTransform: 'uppercase', color: '#6b7280' }}>{sev}</div>
          </div>
        ))}
      </div>

      {result.findings.length === 0 ? (
        <p style={{ color: '#16a34a' }}>No issues found.</p>
      ) : (
        result.findings.map((f, i) => <FindingRow key={i} finding={f} />)
      )}
    </div>
  )
}

export default function App() {
  const [target, setTarget] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)
  const [history, setHistory] = useState([])

  const loadHistory = async () => {
    try {
      const res = await fetch(`${API_BASE}/scans`)
      const data = await res.json()
      setHistory(data)
    } catch {
      // backend not reachable yet — ignore on initial load
    }
  }

  useEffect(() => { loadHistory() }, [])

  const runScan = async (e) => {
    e.preventDefault()
    if (!target.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const res = await fetch(`${API_BASE}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target.trim() }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Scan failed')
      setResult(data)
      loadHistory()
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      fontFamily: 'system-ui, sans-serif', maxWidth: 800, margin: '0 auto',
      padding: '32px 16px', color: '#111827',
    }}>
      <h1 style={{ marginBottom: 4 }}>🔍 Vulnerability Scanner Dashboard</h1>
      <p style={{ color: '#6b7280', marginTop: 0 }}>
        Passive security scan — headers, SSL/TLS, cookies, outdated libraries, and open ports (localhost only).
      </p>

      <form onSubmit={runScan} style={{ display: 'flex', gap: 8, marginTop: 20 }}>
        <input
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="example.com or localhost:8000"
          style={{
            flex: 1, padding: '10px 14px', fontSize: 14,
            border: '1px solid #d1d5db', borderRadius: 6,
          }}
        />
        <button
          type="submit"
          disabled={loading}
          style={{
            padding: '10px 20px', fontSize: 14, fontWeight: 600,
            background: loading ? '#9ca3af' : '#111827', color: 'white',
            border: 'none', borderRadius: 6, cursor: loading ? 'default' : 'pointer',
          }}
        >
          {loading ? 'Scanning…' : 'Scan'}
        </button>
      </form>

      {error && (
        <p style={{ color: '#dc2626', marginTop: 12, fontSize: 14 }}>⚠ {error}</p>
      )}

      <ScanResult result={result} />

      {history.length > 0 && (
        <div style={{ marginTop: 40 }}>
          <h3>Scan History</h3>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ textAlign: 'left', borderBottom: '2px solid #e5e7eb' }}>
                <th style={{ padding: 8 }}>Target</th>
                <th style={{ padding: 8 }}>Scanned At</th>
                <th style={{ padding: 8 }}>Risk</th>
              </tr>
            </thead>
            <tbody>
              {history.map((h) => (
                <tr key={h.id} style={{ borderBottom: '1px solid #f3f4f6' }}>
                  <td style={{ padding: 8 }}>{h.target}</td>
                  <td style={{ padding: 8 }}>{new Date(h.scanned_at).toLocaleString()}</td>
                  <td style={{ padding: 8 }}>
                    <span style={{ color: GRADE_COLOR[h.risk_grade], fontWeight: 600 }}>
                      {h.risk_grade} ({h.risk_score})
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
