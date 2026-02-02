"""Flask API for the Vulnerability Scanner Dashboard."""

from flask import Flask, request, jsonify
from flask_cors import CORS

import db
import scanner

app = Flask(__name__)
CORS(app)  # allow the React dev server to call this API

db.init_db()


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()

    if not target:
        return jsonify({"error": "target is required"}), 400

    try:
        result = scanner.run_scan(target)
    except ValueError as e:
        return jsonify({"error": f"invalid target: {e}"}), 400
    except Exception as e:
        return jsonify({"error": f"scan failed: {e}"}), 500

    scan_id = db.save_scan(result)
    result["id"] = scan_id
    return jsonify(result), 201


@app.route("/api/scans", methods=["GET"])
def list_scans():
    scans = db.get_all_scans()
    return jsonify(scans)


@app.route("/api/scans/<int:scan_id>", methods=["GET"])
def get_scan(scan_id):
    result = db.get_scan(scan_id)
    if not result:
        return jsonify({"error": "not found"}), 404
    return jsonify(result)


@app.route("/api/scans/<int:scan_id>", methods=["DELETE"])
def delete_scan(scan_id):
    deleted = db.delete_scan(scan_id)
    if not deleted:
        return jsonify({"error": "not found"}), 404
    return jsonify({"deleted": True})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
