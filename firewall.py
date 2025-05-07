import os
import sys
import time
import json
import threading
import requests
from datetime import datetime
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP
from flask import Flask, render_template, jsonify

# Constants
THRESHOLD = 100
MAX_HISTORY_SIZE = 1000  # Max events to store in memory
EMAIL_API_KEY = "YOUR_EMAIL_API_KEY"  # Replace with your email API key
EMAIL_API_URL = "https://api.emailprovider.com/v1/send"  # Replace with actual email API endpoint
EMAIL_FROM = "firewall@yourdomain.com"
EMAIL_TO = "admin@yourdomain.com"
DASHBOARD_HOST = "0.0.0.0"  # Listen on all interfaces
DASHBOARD_PORT = 8080

# Global statistics
stats = {
    "total_packets": 0,
    "blocked_ips": set(),
    "nimda_detections": 0,
    "rate_limit_blocks": 0,
    "blacklist_blocks": 0,
    "start_time": time.time()
}

# Store recent events for dashboard display
events_history = deque(maxlen=MAX_HISTORY_SIZE)
packet_history = defaultdict(lambda: deque(maxlen=60))  # Store 60 seconds of packet counts
block_history = []  # Store blocked IP data

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

# Check for Nimda worm signature
def is_nimda_worm(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        payload = bytes(packet[TCP].payload)
        return b"GET /scripts/root.exe" in payload
    return False

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
def send_email_alert(subject, message):
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
        else:
            log_event(f"Failed to send email alert. Status code: {response.status_code}", "error")
    except Exception as e:
        log_event(f"Error sending email alert: {str(e)}", "error")

# Block an IP using iptables
def block_ip(ip, reason):
    try:
        # For macOS - use pfctl
        block_command = f"echo 'block drop from {ip} to any' | sudo pfctl -ef -"
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
        message = f"The IP address {ip} has been blocked.\nReason: {reason}\nTime: {block_data['timestamp']}"
        threading.Thread(target=send_email_alert, args=(subject, message)).start()
        
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
    
    # Check for Nimda worm signature
    if is_nimda_worm(packet):
        if block_ip(src_ip, "Nimda Worm Detection"):
            log_event(f"Blocking Nimda source IP: {src_ip}", "malware")
            stats["nimda_detections"] += 1
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
        "nimda_detections": stats["nimda_detections"],
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
    <title>Firewall Dashboard</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <style>
        body { padding: 20px; background-color: #f8f9fa; }
        .card { margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .stats-card { text-align: center; }
        .stats-card h3 { font-size: 2rem; margin: 10px 0; }
        .event-item { padding: 8px; border-bottom: 1px solid #eee; }
        .event-item.block { background-color: #ffebee; }
        .event-item.malware { background-color: #ffecb3; }
        .event-item.ratelimit { background-color: #e8f5e9; }
        #eventList { max-height: 400px; overflow-y: auto; }
    </style>
</head>
<body>
    <div class="container-fluid">
        <h1 class="mb-4">Network Firewall Dashboard</h1>
        
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
                        <h5 class="card-title">Malware Detected</h5>
                        <h3 id="malwareDetected">0</h3>
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
                <div class="card">
                    <div class="card-header">
                        <h5>Traffic Monitor</h5>
                    </div>
                    <div class="card-body">
                        <canvas id="trafficChart" height="250"></canvas>
                    </div>
                </div>
                
                <div class="card mt-4">
                    <div class="card-header">
                        <h5>Blocked IPs</h5>
                    </div>
                    <div class="card-body">
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
            </div>
        </div>
    </div>
    
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
                        }
                    }
                },
                plugins: {
                    legend: {
                        position: 'top',
                    }
                },
                animation: {
                    duration: 0
                }
            }
        });
        
        // Format time duration
        function formatDuration(seconds) {
            const hrs = Math.floor(seconds / 3600);
            const mins = Math.floor((seconds % 3600) / 60);
            const secs = Math.floor(seconds % 60);
            
            let result = '';
            if (hrs > 0) result += `${hrs}h `;
            if (mins > 0) result += `${mins}m `;
            result += `${secs}s`;
            
            return result;
        }
        
        // Update dashboard with latest data
        function updateDashboard() {
            // Update statistics
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('totalPackets').textContent = data.total_packets.toLocaleString();
                    document.getElementById('blockedIPs').textContent = data.blocked_ips;
                    document.getElementById('malwareDetected').textContent = data.nimda_detections;
                    document.getElementById('uptime').textContent = formatDuration(data.uptime);
                });
            
            // Update events
            fetch('/api/events')
                .then(response => response.json())
                .then(events => {
                    const eventList = document.getElementById('eventList');
                    eventList.innerHTML = '';
                    
                    // Display most recent events first
                    events.reverse().forEach(event => {
                        const eventDiv = document.createElement('div');
                        eventDiv.className = `event-item ${event.type}`;
                        eventDiv.innerHTML = `
                            <strong>${event.timestamp}</strong>: ${event.message}
                        `;
                        eventList.appendChild(eventDiv);
                    });
                });
            
            // Update blocked IPs
            fetch('/api/blocks')
                .then(response => response.json())
                .then(blocks => {
                    const blockedList = document.getElementById('blockedList');
                    blockedList.innerHTML = '';
                    
                    blocks.reverse().forEach(block => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${block.ip}</td>
                            <td>${block.reason}</td>
                            <td>${block.timestamp}</td>
                        `;
                        blockedList.appendChild(row);
                    });
                });
            
            // Update traffic chart
            fetch('/api/traffic')
                .then(response => response.json())
                .then(trafficData => {
                    // Clear previous datasets
                    trafficChart.data.datasets = [];
                    
                    // Add new datasets (limit to top 5 IPs by traffic)
                    const topIPs = Object.keys(trafficData)
                        .map(ip => ({
                            ip,
                            total: trafficData[ip].reduce((sum, count) => sum + count, 0)
                        }))
                        .sort((a, b) => b.total - a.total)
                        .slice(0, 5)
                        .map(item => item.ip);
                    
                    // Generate random colors for IPs
                    const getColor = (index) => {
                        const colors = [
                            'rgba(255, 99, 132, 0.7)',
                            'rgba(54, 162, 235, 0.7)',
                            'rgba(255, 206, 86, 0.7)',
                            'rgba(75, 192, 192, 0.7)',
                            'rgba(153, 102, 255, 0.7)'
                        ];
                        return colors[index % colors.length];
                    };
                    
                    topIPs.forEach((ip, index) => {
                        trafficChart.data.datasets.push({
                            label: ip,
                            data: trafficData[ip],
                            backgroundColor: getColor(index),
                            borderColor: getColor(index),
                            borderWidth: 2,
                            tension: 0.4
                        });
                    });
                    
                    trafficChart.update();
                });
        }
        
        // Update dashboard every 2 seconds
        setInterval(updateDashboard, 2000);
        updateDashboard();
    </script>
</body>
</html>""")
    
    # Start Flask app
    app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT, debug=False)

if __name__ == "__main__":
    # Check for root privileges
    if os.geteuid() != 0:
        print("This script requires root privileges.")
        sys.exit(1)
    
    # Import whitelist and blacklist IPs
    whitelist_ips = read_ip_file("whitelist.txt")
    blacklist_ips = read_ip_file("blacklist.txt")
    
    # Initialize variables
    packet_count = defaultdict(int)
    last_check = [int(time.time())]
    
    # Start dashboard in a separate thread
    print(f"Starting dashboard on http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
    dashboard_thread = threading.Thread(target=run_dashboard)
    dashboard_thread.daemon = True
    dashboard_thread.start()
    
    # Start packet sniffing
    log_event("Firewall started. Monitoring network traffic...")
    print(f"THRESHOLD: {THRESHOLD} packets/second")
    
    try:
        # Start packet sniffing
        sniff(filter="ip", prn=packet_callback, store=0)
    except KeyboardInterrupt:
        log_event("Firewall stopped by user.", "info")
        print("\nFirewall stopped. Goodbye!")