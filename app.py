import json
import re
import time
import secrets
import threading
from collections import defaultdict, Counter
from pathlib import Path
import tempfile
from flask import Flask, render_template, request, redirect, url_for, flash, Response
from werkzeug.utils import secure_filename
import google.generativeai as genai
from queue import Queue
from functools import lru_cache
import os
from datetime import datetime
import csv
from io import StringIO

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = tempfile.mkdtemp()

# Configuration from environment variables
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '')
USE_AI_ANALYSIS = bool(GEMINI_API_KEY)

if USE_AI_ANALYSIS:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel('gemini-1.5-flash')

# Redis would be better for production, but using a thread-safe queue for simplicity
analysis_results = {}
event_queue = Queue()

# Constants
ALLOWED_EXTENSIONS = {'json'}
BATCH_SIZE = 10  # Number of URIs to analyze in a single AI request
MAX_URI_LENGTH = 200  # Maximum URI length to send to AI

from mitre_data import (
    MITRE_ATTACK_TYPES,
    MITRE_VULNERABILITY_PATTERNS,
    MITRE_SEVERITY_LEVEL
)

class RateLimiter:
    def __init__(self, max_calls, period):
        self.max_calls = max_calls
        self.period = period
        self.calls = []
        self.lock = threading.Lock()

    def __call__(self):
        with self.lock:
            now = time.time()
            # Remove calls older than the period
            self.calls = [call for call in self.calls if now - call <= self.period]
            
            if len(self.calls) >= self.max_calls:
                sleep_time = self.period - (now - self.calls[0])
                if sleep_time > 0:
                    time.sleep(sleep_time)
                self.calls = self.calls[1:]
            
            self.calls.append(time.time())

# Global rate limiter for AI requests
ai_rate_limiter = RateLimiter(max_calls=60, period=60)  # 60 requests per minute

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_severity_style(severity):
    return {
        "CRITICAL": "danger",
        "HIGH": "warning",
        "MEDIUM": "info",
        "LOW": "success",
        "INFORMATION": "primary",
        "INFO": "primary"
    }.get(severity.upper(), "secondary")

def is_highly_suspicious(uri):
    """Heuristic to filter URIs that really need AI analysis"""
    suspicious_keywords = [
        'php', 'cmd', 'exec', 'system', 'admin', 'config', 
        'password', 'select', 'union', 'http', 'https', 'ftp',
        '../', '..\\', '%00', '%20', ';', '|', '&', '<', '>'
    ]
    
    # Skip short URIs that aren't suspicious
    if len(uri) < 10:
        return False
        
    # Skip URIs with static file extensions
    static_extensions = ['.jpg', '.png', '.css', '.js', '.ico']
    if any(uri.lower().endswith(ext) for ext in static_extensions):
        return False
        
    # Check for suspicious keywords
    return any(keyword in uri.lower() for keyword in suspicious_keywords)

def analyze_uris_with_regex(entries):
    """Perform regex-based analysis on URIs"""
    mitre_summary = defaultdict(lambda: {"count": 0, "requests": 0, "uris": []})
    uri_analysis = []
    
    for entry in entries:
        uri = entry.get("URI", "")
        request_count = entry.get("request_count", 0)
        detected_mitres = []
        
        for mitre_id, pattern_data in MITRE_VULNERABILITY_PATTERNS.items():
            if re.search(pattern_data["pattern"], uri, re.IGNORECASE):
                mitre_summary[mitre_id]["count"] += 1
                mitre_summary[mitre_id]["requests"] += request_count
                mitre_summary[mitre_id]["uris"].append(uri)
                detected_mitres.append(mitre_id)
        
        uri_analysis.append({
            "uri": uri,
            "request_count": request_count,
            "is_threat": len(detected_mitres) > 0,
            "mitre_ids": detected_mitres
        })
    
    return mitre_summary, uri_analysis

def batch_analyze_with_ai(uris):
    """Analyze a batch of URIs with AI"""
    if not USE_AI_ANALYSIS:
        return []
    
    ai_rate_limiter()  # Apply rate limiting
    
    try:
        prompt = f"""
        Analyze these URIs for security threats (respond with JSON array):
        [
            {{
                "uri": "{uris[0][:MAX_URI_LENGTH]}",
                "is_threat": boolean,
                "mitre_id": "TXXXX" or null,
                "confidence": "low/medium/high",
                "vulnerability_name": "Descriptive name"
            }},
            ... (more items)
        ]
        """
        
        response = model.generate_content(prompt)
        return json.loads(response.text)
    except Exception as e:
        print(f"AI batch analysis failed: {str(e)}")
        return []

def analyze_suspicious_uris(uri_analysis):
    """Perform AI analysis on suspicious URIs that didn't match regex patterns"""
    if not USE_AI_ANALYSIS:
        return uri_analysis, defaultdict(lambda: {"count": 0, "requests": 0, "uris": []})
    
    # Group URIs into batches for efficiency
    suspicious_uris = [uri for uri in uri_analysis if not uri["is_threat"] and is_highly_suspicious(uri["uri"])]
    batched_results = []
    
    for i in range(0, len(suspicious_uris), BATCH_SIZE):
        batch = suspicious_uris[i:i+BATCH_SIZE]
        batched_results.extend(batch_analyze_with_ai([uri["uri"] for uri in batch]))
    
    # Process AI results
    mitre_summary = defaultdict(lambda: {"count": 0, "requests": 0, "uris": []})
    
    for result, uri_data in zip(batched_results, suspicious_uris):
        if result.get("is_threat", False) and result.get("mitre_id"):
            mitre_id = result["mitre_id"]
            mitre_summary[mitre_id]["count"] += 1
            mitre_summary[mitre_id]["requests"] += uri_data["request_count"]
            mitre_summary[mitre_id]["uris"].append(uri_data["uri"])
            uri_data["is_threat"] = True
            uri_data["mitre_ids"].append(mitre_id)
            
            # Add vulnerability name if provided by AI
            if "vulnerability_name" in result:
                MITRE_ATTACK_TYPES[mitre_id] = result["vulnerability_name"]
    
    return uri_analysis, mitre_summary

def generate_summary_data(mitre_summary):
    """Generate summary statistics from analysis results"""
    total_uri = sum(item["count"] for item in mitre_summary.values())
    total_requests = sum(item["requests"] for item in mitre_summary.values())
    unique_uris = len(set(uri for item in mitre_summary.values() for uri in item["uris"]))
    total_attacks = sum(item["count"] for item in mitre_summary.values())
    total_ids = len(mitre_summary)

    severity_counter = Counter()
    for mitre_id, data in mitre_summary.items():
        severity = MITRE_SEVERITY_LEVEL.get(mitre_id, "INFO")
        severity_counter[severity.upper()] += data["count"]

    severity_summary = [
        {"level": level.title(), "count": count, "style": get_severity_style(level)}
        for level, count in severity_counter.items()
    ]

    return {
        "total_uri": total_uri,
        "total_requests": total_requests,
        "unique_uris": unique_uris,
        "total_attacks": total_attacks,
        "total_ids": total_ids,
        "severity_summary": severity_summary
    }

def generate_techniques_data(mitre_summary):
    """Generate MITRE technique data for display"""
    techniques_data = []
    for mitre_id, data in sorted(mitre_summary.items(), key=lambda item: item[1]["count"], reverse=True):
        technique = MITRE_ATTACK_TYPES.get(mitre_id, "Unknown")
        vuln_data = MITRE_VULNERABILITY_PATTERNS.get(mitre_id, {})
        vulnerability_name = vuln_data.get("vulnerability_name", technique)
        severity = MITRE_SEVERITY_LEVEL.get(mitre_id, "INFO")
        
        techniques_data.append({
            "mitre_id": mitre_id,
            "technique": technique,
            "vulnerability_name": vulnerability_name,
            "severity": severity,
            "severity_style": get_severity_style(severity),
            "count": data["count"],
            "requests": data["requests"],
            "sample_uris": data["uris"][:5]
        })
    return techniques_data

def generate_ai_recommendations(mitre_summary):
    """Generate security recommendations based on findings"""
    if not USE_AI_ANALYSIS:
        return "AI analysis was disabled (no API key provided). Recommendations based on pattern matching only."
    
    try:
        prompt = f"""
        Based on these security findings from MITRE ATT&CK framework, provide:
        1. Immediate actions to take (prioritized by severity)
        2. Long-term remediation strategies
        3. Security controls to implement
        4. Monitoring recommendations
        
        Findings:
        {json.dumps({
            mitre_id: {
                "technique": MITRE_ATTACK_TYPES.get(mitre_id, "Unknown"),
                "severity": MITRE_SEVERITY_LEVEL.get(mitre_id, "INFO"),
                "count": data["count"],
                "sample_uris": data["uris"][:3]
            }
            for mitre_id, data in mitre_summary.items()
        }, indent=2)}
        
        Format your response with clear headings for each section and prioritize by severity.
        """
        
        ai_rate_limiter()
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"AI recommendation generation failed: {str(e)}"

def generate_spreadsheet_data(mitre_summary, uri_analysis):
    """Generate data for spreadsheet export"""
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        "Timestamp", "URI", "Request Count", "Threat Detected", 
        "MITRE ID", "Technique", "Vulnerability Name", "Severity"
    ])
    
    # Write data rows
    for uri_data in uri_analysis:
        if uri_data["is_threat"]:
            for mitre_id in uri_data["mitre_ids"]:
                technique = MITRE_ATTACK_TYPES.get(mitre_id, "Unknown")
                vulnerability_name = MITRE_VULNERABILITY_PATTERNS.get(mitre_id, {}).get("vulnerability_name", technique)
                
                writer.writerow([
                    datetime.now().isoformat(),
                    uri_data["uri"],
                    uri_data["request_count"],
                    "YES",
                    mitre_id,
                    technique,
                    vulnerability_name,
                    MITRE_SEVERITY_LEVEL.get(mitre_id, "INFO")
                ])
        else:
            writer.writerow([
                datetime.now().isoformat(),
                uri_data["uri"],
                uri_data["request_count"],
                "NO",
                "",
                "",
                "",
                ""
            ])
    
    return output.getvalue()

def background_analysis(filepath, session_id):
    """Main analysis function that runs in background thread"""
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        # First pass: quick regex analysis
        mitre_summary, uri_analysis = analyze_uris_with_regex(data[:1000])  # Process first 1000 entries
        
        # Send immediate updates for UI
        for uri_data in uri_analysis:
            event_queue.put((session_id, json.dumps({
                "type": "uri_update",
                "data": {
                    "uri": uri_data["uri"][:100],
                    "is_threat": uri_data["is_threat"],
                    "mitre_ids": uri_data["mitre_ids"],
                    "request_count": uri_data["request_count"]
                }
            })))
            time.sleep(0.01)  # Small delay for UI updates
        
        # Second pass: AI analysis for suspicious URIs
        if USE_AI_ANALYSIS:
            uri_analysis, ai_summary = analyze_suspicious_uris(uri_analysis)
            
            # Merge AI findings with regex findings
            for mitre_id, data in ai_summary.items():
                if mitre_id in mitre_summary:
                    mitre_summary[mitre_id]["count"] += data["count"]
                    mitre_summary[mitre_id]["requests"] += data["requests"]
                    mitre_summary[mitre_id]["uris"].extend(data["uris"])
                else:
                    mitre_summary[mitre_id] = data
            
            # Send AI detection updates
            for uri_data in uri_analysis:
                if uri_data["is_threat"] and any(mitre_id in ai_summary for mitre_id in uri_data["mitre_ids"]):
                    event_queue.put((session_id, json.dumps({
                        "type": "ai_detection",
                        "data": {
                            "uri": uri_data["uri"][:100],
                            "mitre_id": next(mitre_id for mitre_id in uri_data["mitre_ids"] if mitre_id in ai_summary),
                            "technique": MITRE_ATTACK_TYPES.get(next(mitre_id for mitre_id in uri_data["mitre_ids"] if mitre_id in ai_summary), "Unknown")
                        }
                    })))
        
        # Generate final results
        summary = generate_summary_data(mitre_summary)
        techniques = generate_techniques_data(mitre_summary)
        recommendations = generate_ai_recommendations(mitre_summary)
        spreadsheet_data = generate_spreadsheet_data(mitre_summary, uri_analysis)
        
        # Store results for download
        analysis_results[session_id] = {
            "spreadsheet": spreadsheet_data,
            "timestamp": datetime.now().isoformat()
        }
        
        # Send completion event
        event_queue.put((session_id, json.dumps({
            "type": "complete",
            "data": {
                "summary": summary,
                "techniques": techniques,
                "recommendations": recommendations
            }
        })))
        
    except Exception as e:
        event_queue.put((session_id, json.dumps({
            "type": "error",
            "data": str(e)
        })))
    finally:
        Path(filepath).unlink(missing_ok=True)

@app.route('/stream/<session_id>')
def stream(session_id):
    def event_stream():
        while True:
            try:
                sid, event = event_queue.get(timeout=10)
                if sid == session_id:
                    yield f"data: {event}\n\n"
                    if json.loads(event).get("type") == "complete":
                        break
            except:
                break
    return Response(event_stream(), mimetype="text/event-stream")

@app.route('/download/<session_id>')
def download_results(session_id):
    if session_id not in analysis_results:
        flash('Results not found or expired')
        return redirect(url_for('upload_file'))
    
    data = analysis_results[session_id]
    filename = f"firewall_analysis_{data['timestamp']}.csv"
    
    response = Response(
        data["spreadsheet"],
        mimetype="text/csv",
        headers={"Content-disposition": f"attachment; filename={filename}"}
    )
    
    return response

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            session_id = secrets.token_hex(8)
            filename = secure_filename(file.filename)
            filepath = Path(app.config['UPLOAD_FOLDER']) / filename
            file.save(filepath)
            
            # Start background analysis
            threading.Thread(
                target=background_analysis,
                args=(filepath, session_id),
                daemon=True
            ).start()
            
            return render_template('results.html', session_id=session_id)
    
    return render_template('upload.html')

if __name__ == '__main__':
    app.run()
