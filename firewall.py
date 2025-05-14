import os
import sys
import time
import json
import threading
import requests
import re
import base64
import ipaddress
import urllib.parse
from datetime import datetime
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP, Raw
from flask import Flask, render_template, jsonify, request

# Constants
THRESHOLD = 100  # Max packets per second before rate limiting
MAX_HISTORY_SIZE = 1000  # Max events to store in memory
EMAIL_API_KEY = "EMAIL_API_KEY"  # Replace with actual one
EMAIL_API_URL = "https://api.emailprovider.com/v1/send"  # Replace with actual email API endpoint
EMAIL_FROM = "firewall@yourdomain.com"
EMAIL_TO = "admin@yourdomain.com"
DASHBOARD_HOST = "0.0.0.0"  # Listen on all interfaces
DASHBOARD_PORT = 8080
ALERT_COOLDOWN = 300  # Seconds between alerts for the same IP (5 minutes)

# Global statistics
stats = {
    "total_packets": 0,
    "blocked_ips": set(),
    "detected_attacks": defaultdict(int),  # Count by attack type
    "rate_limit_blocks": 0,
    "blacklist_blocks": 0,
    "start_time": time.time()
}

# Store recent events for dashboard display
events_history = deque(maxlen=MAX_HISTORY_SIZE)
packet_history = defaultdict(lambda: deque(maxlen=60))  # Store 60 seconds of packet counts
block_history = []  # Store blocked IP data
last_alert_time = defaultdict(float)  # Track when alerts were last sent for an IP

# OWASP Top 10 and common attack pattern definitions
ATTACK_SIGNATURES = {
    # SQL Injection patterns
    "sql_injection": [
        r"(?i)(\b(select|update|delete|insert|drop|alter|create|union)\b.+\b(from|into|table|database|values)\b)",
        r"(?i)((\%27)|('))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
        r"(?i)(\b(or|and)\b\s+\d+\s*[=<>])",
        r"(?i)((\%27)|(')|(\-\-)|(\%23)|(#))",
        r"(?i)((\%3D)|(=))[^\n]*((\%27)|(')|((\-\-)|(\%3B)|(;)))",
        r"(?i)exec(\s|\+)+(s|x)p\w+",
        r"(?i)SLEEP\(\d+\)"
    ],
    
    # Cross-Site Scripting (XSS) patterns
    "xss": [
        r"(?i)<[^\w<>]*(?:[^<>\"'\s]*:)?[^\w<>]*(?:\W*s\W*c\W*r\W*i\W*p\W*t|\W*f\W*o\W*r\W*m|\W*s\W*t\W*y\W*l\W*e|\W*b\W*a\W*s\W*e|\W*i\W*m\W*g)",
        r"(?i)(<script[^>]*>[\s\S]*?<\/script>|<[^>]+on\w+\s*=|javascript:)",
        r"(?i)(\b)(on\S+)(\s*=\s*[\"']?[^\"'>\s]*)",
        r"(?i)((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)",
        r"(?i)((\%3C)|<)[^\n]+((\%3E)|>)"
    ],
    
    # Path Traversal patterns
    "path_traversal": [
        r"(?i)(\.\./|\.\.\%2f|\.\%2e/|\.\%2e\%2f|\%2e\%2e\%2f|\%2e\%2e/)",
        r"(?i)(/etc/passwd|/etc/shadow|/etc/hosts|c:\\windows\\win.ini|boot\.ini|/proc/self/environ)",
        r"(?i)(%00|\\0|\.\.%c0%af|%c1%9c)"
    ],
    
    # Command Injection patterns
    "command_injection": [
        r"(?i)(\||;|`|\$\(|\$\{|\&\&|\|\|)",
        r"(?i)(system\(|exec\(|shell_exec\(|passthru\(|eval\(|popen\()",
        r"(?i)(/bin/sh|/bin/bash|cmd\.exe|powershell\.exe)"
    ],
    
    # Server-Side Request Forgery (SSRF) patterns
    "ssrf": [
        r"(?i)(127\.0\.0\.1|localhost|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+|192\.168\.\d+\.\d+)",
        r"(?i)(file://|dict://|gopher://|ldap://)"
    ],
    
    # XML-related attacks (XXE, XPath Injection)
    "xml_attack": [
        r"(?i)(\<!DOCTYPE|\<\!ENTITY|\<\!ELEMENT)",
        r"(?i)(\%PDF|\%JVBERY|\%TVqQAA)"
    ],
    
    # Local/Remote File Inclusion
    "file_inclusion": [
        r"(?i)((https?|ftp|php|data|file)(:\/\/|%3a%2f%2f))",
        r"(?i)((\=|%3D)https?:\/\/)"
    ],
    
    # Cross-Site Request Forgery (CSRF) patterns
    "csrf": [
        r"(?i)(authenticity_token|csrf_token|anticsrf)",
        r"(?i)(verify=|confirm=|token=)"
    ],
    
    # Web Shell detection
    "webshell": [
        r"(?i)(c99shell|r57shell|wso\.php|shell\.php|filesman\.php)",
        r"(?i)(passthru|shell_exec|system|phpinfo|base64_decode|edoced_46esab|chmod|mkdir|fopen|fclose|readfile)"
    ],
    
    # Common malware/bot user-agents
    "malicious_useragent": [
        r"(?i)(zgrab|dirbuster|nikto|nessus|sqlmap|python-requests\/|wget\/|curl\/|scanner|nmap)",
        r"(?i)(metasploit|burpsuite|zap\/|dafanbuddy|wprecon|acunetix|appscan)",
        r"(?i)(python|perl|go\-http\-client|winhttp|libwww)"
    ],
    
    # Denial of Service attack patterns
    "dos_attack": [
        r"(slowloris|torshammer|hping)",
        r"(\.(\.)+)"
    ],
    
    # Log4j/Log4Shell vulnerability exploitation
    "log4j": [
        r"(?i)(\$\{jndi:(ldap|rmi|dns|corba|iiop)://)",
        r"(?i)(\$\{(ctx|lower|upper))"
    ],
    
    # Apache Struts vulnerability exploitation
    "struts": [
        r"(?i)(%\{(\#|%23)_memberAccess)",
        r"(?i)((#|%23)_memberAccess\[)"
    ],
    
    # Ransomware/Cryptominers
    "ransomware": [
        r"(?i)(wannacry|petya|ryuk|locky|cryptolocker)",
        r"(?i)(monero|coinhive\.min\.js)"
    ]
}

# Suspicious file extensions to monitor
SUSPICIOUS_EXTENSIONS = [
    ".php", ".asp", ".aspx", ".jsp", ".exe", ".bat", ".sh", ".ps1", ".py", ".pl",
    ".cgi", ".dll", ".config", ".bak", ".old", ".sql", ".log"
]

# Read IPs from a file
def read_ip_file(filename):
    try:
        with open(filename, "r") as file:
            ips = [line.strip() for line in file]
        return set(ips)
    except FileNotFoundError:
        print(f"Warning: {filename} not found, creating empty file.")
        with open(filename, "w") as file:
            pass
        return set()

# Decode URL-encoded or base64-encoded payloads
def decode_payload(payload):
    decoded_payloads = [payload]
    
    # Try URL decoding (multiple times for nested encoding)
    try:
        url_decoded = urllib.parse.unquote(payload)
        if url_decoded != payload:
            decoded_payloads.append(url_decoded)
            # Try second level decoding
            url_decoded2 = urllib.parse.unquote(url_decoded)
            if url_decoded2 != url_decoded:
                decoded_payloads.append(url_decoded2)
    except:
        pass
    
    # Try base64 decoding
    try:
        # Try to find base64 patterns
        base64_pattern = re.compile(r'[A-Za-z0-9+/]{30,}={0,2}')
        matches = base64_pattern.findall(payload)
        for match in matches:
            try:
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                if decoded and len(decoded) > 5:  # Avoid false positives on short strings
                    decoded_payloads.append(decoded)
            except:
                pass
    except:
        pass
    
    return decoded_payloads

# Check for known attack signatures
def detect_attack_signatures(data):
    detections = []
    
    # Process potential encodings
    payload_variations = decode_payload(data)
    
    # Check each attack type
    for attack_type, patterns in ATTACK_SIGNATURES.items():
        for pattern in patterns:
            for payload in payload_variations:
                if re.search(pattern, payload):
                    detections.append(attack_type)
                    stats["detected_attacks"][attack_type] += 1
                    break
            if attack_type in detections:
                break
    
    return detections

# Check if HTTP request contains suspicious file paths
def check_suspicious_paths(data):
    try:
        # Extract URL from HTTP request
        match = re.search(r"(GET|POST|PUT|DELETE|HEAD)\s+([^\s]+)", data)
        if match:
            path = match.group(2)
            
            # Check for suspicious extensions
            for ext in SUSPICIOUS_EXTENSIONS:
                if ext in path:
                    return f"Suspicious extension: {ext}"
            
            # Check for admin/sensitive paths
            sensitive_paths = ["admin", "backup", "wp-admin", "phpmyadmin", "manager", "console"]
            for sensitive in sensitive_paths:
                if f"/{sensitive}/" in path or path.endswith(f"/{sensitive}"):
                    return f"Sensitive path access: {sensitive}"
    except:
        pass
    
    return None

# Check for Nimda worm signature and other HTTP-based exploits
def detect_http_attacks(packet):
    detections = []
    
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = bytes(packet[Raw].load).decode('latin-1', errors='ignore')
        
        # Legacy Nimda detection
        if packet[TCP].dport == 80 and b"GET /scripts/root.exe" in packet[Raw].load:
            detections.append("nimda_worm")
        
        # Detect HTTP-based attacks using signatures
        if packet[TCP].dport == 80 or packet[TCP].dport == 443:
            # Check for HTTP request
            if payload.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")):
                attack_signatures = detect_attack_signatures(payload)
                detections.extend(attack_signatures)
                
                # Check for suspicious paths
                suspicious_path = check_suspicious_paths(payload)
                if suspicious_path:
                    detections.append(f"suspicious_path:{suspicious_path}")
    
    return detections

# Log events to a file and memory
def log_event(message, event_type="info"):
    # Create log folder if it doesn't exist
    log_folder = "logs"
    os.makedirs(log_folder, exist_ok=True)
    
    # Get current timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Format the log message
    log_message = f"[{timestamp}] {message}"
    
    # Write to daily log file
    log_date = datetime.now().strftime("%Y-%m-%d")
    log_file = os.path.join(log_folder, f"firewall_{log_date}.log")
    
    with open(log_file, "a") as file:
        file.write(f"{log_message}\n")
    
    # Store in memory for dashboard
    event_object = {
        "timestamp": timestamp,
        "message": message,
        "type": event_type
    }
    events_history.append(event_object)
    
    # Print to console
    print(log_message)

# Send email alert
def send_email_alert(subject, message, ip=None):
    # Check cooldown period for this IP
    current_time = time.time()
    if ip and (current_time - last_alert_time.get(ip, 0) < ALERT_COOLDOWN):
        log_event(f"Alert for IP {ip} suppressed (cooldown period)", "info")
        return
    
    try:
        payload = {
            "api_key": EMAIL_API_KEY,
            "from": EMAIL_FROM,
            "to": EMAIL_TO,
            "subject": subject,
            "message": message
        }
        
        response = requests.post(EMAIL_API_URL, json=payload)
        
        if response.status_code == 200:
            log_event(f"Email alert sent: {subject}")
            if ip:
                last_alert_time[ip] = current_time
        else:
            log_event(f"Failed to send email alert. Status code: {response.status_code}", "error")
    except Exception as e:
        log_event(f"Error sending email alert: {str(e)}", "error")

# Block an IP using iptables or pfctl
def block_ip(ip, reason):
    try:
        # Check if this is a valid IP address (avoid command injection)
        ipaddress.ip_address(ip)
        
        # Use appropriate firewall command based on OS
        if sys.platform == "darwin":
            # For macOS - use pfctl
            block_command = f"echo 'block drop from {ip} to any' | sudo pfctl -ef -"
        else:
            # For Linux - use iptables
            block_command = f"sudo iptables -A INPUT -s {ip} -j DROP"
            
        os.system(block_command)
        
        stats["blocked_ips"].add(ip)
        
        # Record when this IP was blocked
        block_data = {
            "ip": ip,
            "reason": reason,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        block_history.append(block_data)
        
        # Send email alert
        subject = f"Firewall Alert: IP {ip} Blocked"
        message = f"""The IP address {ip} has been blocked.
Reason: {reason}
Time: {block_data['timestamp']}

This is an automated alert from your enhanced network firewall.
"""
        threading.Thread(target=send_email_alert, args=(subject, message, ip)).start()
        
        return True
    except Exception as e:
        log_event(f"Error blocking IP {ip}: {str(e)}", "error")
        return False

# Process network packets
def packet_callback(packet):
    if IP not in packet:
        return
        
    # Update total packet count
    stats["total_packets"] += 1
    
    src_ip = packet[IP].src
    
    # Check if IP is in the whitelist
    if src_ip in whitelist_ips:
        return
    
    # Check if IP is in the blacklist
    if src_ip in blacklist_ips:
        if block_ip(src_ip, "Blacklisted IP"):
            log_event(f"Blocking blacklisted IP: {src_ip}", "block")
            stats["blacklist_blocks"] += 1
        return
    
    # Check for attack signatures in HTTP traffic
    attack_detections = detect_http_attacks(packet)
    if attack_detections:
        attack_types = ", ".join(attack_detections)
        if block_ip(src_ip, f"Attack detected: {attack_types}"):
            log_event(f"Blocking IP: {src_ip}, detected attack types: {attack_types}", "attack")
        return
    
    # Track packet rate
    current_time = int(time.time())
    packet_count[src_ip] += 1
    
    # Add to packet history for visualization
    if current_time not in packet_history[src_ip]:
        packet_history[src_ip].append(current_time)
    
    # Check if we should reset counters (every second)
    if current_time > last_check[0]:
        # Calculate packet rates for all IPs
        for ip, count in packet_count.items():
            time_interval = current_time - last_check[0]
            if time_interval > 0:  # Avoid division by zero
                packet_rate = count / time_interval
                
                # Check if rate exceeds threshold
                if packet_rate > THRESHOLD and ip not in stats["blocked_ips"]:
                    if block_ip(ip, f"Rate limit exceeded ({packet_rate:.2f} packets/sec)"):
                        log_event(f"Blocking IP: {ip}, packet rate: {packet_rate:.2f} packets/sec", "ratelimit")
                        stats["rate_limit_blocks"] += 1
        
        # Reset packet counters
        packet_count.clear()
        last_check[0] = current_time

# Initialize Flask app for dashboard
app = Flask(__name__)

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/stats')
def api_stats():
    uptime = time.time() - stats["start_time"]
    return jsonify({
        "total_packets": stats["total_packets"],
        "blocked_ips": len(stats["blocked_ips"]),
        "detected_attacks": dict(stats["detected_attacks"]),
        "rate_limit_blocks": stats["rate_limit_blocks"],
        "blacklist_blocks": stats["blacklist_blocks"],
        "uptime": int(uptime)
    })

@app.route('/api/events')
def api_events():
    return jsonify(list(events_history))

@app.route('/api/blocks')
def api_blocks():
    return jsonify(block_history)

@app.route('/api/traffic')
def api_traffic():
    # Prepare traffic data for charts
    traffic_data = {}
    current_time = int(time.time())
    
    # Create traffic data for the last 60 seconds
    for ip, timestamps in packet_history.items():
        traffic_data[ip] = [0] * 60
        for t in timestamps:
            if current_time - t < 60:  # Only include data from the last minute
                idx = 59 - (current_time - t)
                traffic_data[ip][idx] += 1
    
    return jsonify(traffic_data)

@app.route('/api/attack-stats')
def api_attack_stats():
    # Return attack statistics
    if not stats["detected_attacks"]:
        return jsonify([])
    
    attack_data = [{"name": attack, "count": count} for attack, count in stats["detected_attacks"].items()]
    return jsonify(sorted(attack_data, key=lambda x: x["count"], reverse=True))

@app.route('/whitelist', methods=['GET', 'POST'])
def manage_whitelist():
    if request.method == 'POST':
        action = request.form.get('action')
        ip = request.form.get('ip')
        
        try:
            # Validate IP address
            ipaddress.ip_address(ip)
            
            if action == 'add':
                whitelist_ips.add(ip)
                with open("whitelist.txt", "w") as f:
                    for whitelist_ip in whitelist_ips:
                        f.write(f"{whitelist_ip}\n")
                log_event(f"Added {ip} to whitelist", "config")
            elif action == 'remove':
                whitelist_ips.discard(ip)
                with open("whitelist.txt", "w") as f:
                    for whitelist_ip in whitelist_ips:
                        f.write(f"{whitelist_ip}\n")
                log_event(f"Removed {ip} from whitelist", "config")
        except ValueError:
            pass
    
    return render_template('whitelist.html', ips=sorted(whitelist_ips))

@app.route('/blacklist', methods=['GET', 'POST'])
def manage_blacklist():
    if request.method == 'POST':
        action = request.form.get('action')
        ip = request.form.get('ip')
        
        try:
            # Validate IP address
            ipaddress.ip_address(ip)
            
            if action == 'add':
                blacklist_ips.add(ip)
                with open("blacklist.txt", "w") as f:
                    for blacklist_ip in blacklist_ips:
                        f.write(f"{blacklist_ip}\n")
                log_event(f"Added {ip} to blacklist", "config")
            elif action == 'remove':
                blacklist_ips.discard(ip)
                with open("blacklist.txt", "w") as f:
                    for blacklist_ip in blacklist_ips:
                        f.write(f"{blacklist_ip}\n")
                log_event(f"Removed {ip} from blacklist", "config")
        except ValueError:
            pass
    
    return render_template('blacklist.html', ips=sorted(blacklist_ips))

# Start dashboard in a separate thread
def run_dashboard():
    # Create templates directory if it doesn't exist
    os.makedirs("templates", exist_ok=True)
    
    # Create dashboard.html file
    with open("templates/dashboard.html", "w") as f:
        f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enhanced Firewall Dashboard</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <style>
        body { padding: 20px; background-color: #f8f9fa; }
        .card { margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .stats-card { text-align: center; }
        .stats-card h3 { font-size: 2rem; margin: 10px 0; }
        .event-item { padding: 8px; border-bottom: 1px solid #eee; }
        .event-item.block { background-color: #ffebee; }
        .event-item.attack { background-color: #f8bbd0; }
        .event-item.malware { background-color: #ffecb3; }
        .event-item.ratelimit { background-color: #e8f5e9; }
        .event-item.config { background-color: #e1f5fe; }
        #eventList { max-height: 400px; overflow-y: auto; }
        .navbar { margin-bottom: 20px; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">Enhanced Network Firewall</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav">
                    <li class="nav-item">
                        <a class="nav-link active" href="/">Dashboard</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/whitelist">Whitelist</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/blacklist">Blacklist</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container-fluid">
        <div class="row">
            <div class="col-md-3">
                <div class="card stats-card">
                    <div class="card-body">
                        <h5 class="card-title">Total Packets</h5>
                        <h3 id="totalPackets">0</h3>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stats-card">
                    <div class="card-body">
                        <h5 class="card-title">Blocked IPs</h5>
                        <h3 id="blockedIPs">0</h3>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stats-card">
                    <div class="card-body">
                        <h5 class="card-title">Attack Detections</h5>
                        <h3 id="attackDetections">0</h3>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stats-card">
                    <div class="card-body">
                        <h5 class="card-title">Uptime</h5>
                        <h3 id="uptime">0s</h3>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row mt-4">
            <div class="col-md-8">
                <div class="row">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">
                                <h5>Traffic Monitor</h5>
                            </div>
                            <div class="card-body">
                                <canvas id="trafficChart" height="250"></canvas>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">
                                <h5>Attack Distribution</h5>
                            </div>
                            <div class="card-body">
                                <canvas id="attackChart" height="250"></canvas>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="card mt-4">
                    <div class="card-header">
                        <h5>Blocked IPs</h5>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>IP Address</th>
                                        <th>Reason</th>
                                        <th>Time</th>
                                    </tr>
                                </thead>
                                <tbody id="blockedList">
                                    <!-- Blocked IPs will be listed here -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        <h5>Recent Events</h5>
                    </div>
                    <div class="card-body p-0">
                        <div id="eventList">
                            <!-- Events will be listed here -->
                        </div>
                    </div>
                </div>
                
                <div class="card mt-4">
                    <div class="card-header">
                        <h5>OWASP Top 10 Detections</h5>
                    </div>
                    <div class="card-body">
                        <table class="table table-sm">
                            <thead>
                                <tr>
                                    <th>Attack Type</th>
                                    <th>Count</th>
                                </tr>
                            </thead>
                            <tbody id="attackList">
                                <!-- Attack types will be listed here -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
    <script>
        // Initialize charts
        const trafficCtx = document.getElementById('trafficChart').getContext('2d');
        const trafficChart = new Chart(trafficCtx, {
            type: 'line',
            data: {
                labels: Array.from({length: 60}, (_, i) => `${59-i}s`),
                datasets: []
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Packets'
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Time (seconds ago)'
