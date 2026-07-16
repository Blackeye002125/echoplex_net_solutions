#!/usr/bin/env python3
"""
ECHOPLEX Backend Server - Deployed on Render.com
URL: https://echoplex-net-solutions.onrender.com
"""

import subprocess
import json
import socket
import os
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

def get_network_range():
    """Get the local network range"""
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        ip_parts = local_ip.split('.')
        return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    except:
        return "192.168.1.0/24"

def scan_network(network_range=None):
    """Scan network for active devices"""
    if not network_range:
        network_range = get_network_range()
    
    # Extract base IP
    base = network_range.replace('/24', '')
    base_parts = base.split('.')
    base_ip = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}"
    
    devices = []
    
    # Scan all IPs in range
    for i in range(1, 255):
        ip = f"{base_ip}.{i}"
        try:
            # Use ping to check if device is active
            result = subprocess.run(
                ['ping', '-n', '1', '-w', '100', ip],
                capture_output=True,
                text=True,
                timeout=2
            )
            
            if result.returncode == 0:
                # Try to get hostname
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    hostname = f"Device-{i}"
                
                # Try to get MAC address
                mac = "Unknown"
                try:
                    arp_result = subprocess.run(
                        ['arp', '-a', ip],
                        capture_output=True,
                        text=True
                    )
                    for line in arp_result.stdout.split('\n'):
                        if ip in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                mac = parts[1] if len(parts) > 1 else "Unknown"
                            break
                except:
                    pass
                
                # Detect device type from hostname
                device_type = "💻 Device"
                hostname_lower = hostname.lower()
                if 'server' in hostname_lower:
                    device_type = "🖥 Server"
                elif 'phone' in hostname_lower or 'iphone' in hostname_lower:
                    device_type = "📱 Mobile"
                elif 'laptop' in hostname_lower:
                    device_type = "💻 Laptop"
                elif 'router' in hostname_lower or 'switch' in hostname_lower:
                    device_type = "📡 Router"
                elif 'printer' in hostname_lower:
                    device_type = "🖨 Printer"
                
                devices.append({
                    'ip': ip,
                    'hostname': hostname,
                    'mac': mac,
                    'type': device_type,
                    'os': 'Unknown'
                })
                
                print(f"Found: {ip} - {hostname}")
                
        except Exception as e:
            pass
    
    return devices

@app.route('/api/scan-network', methods=['GET'])
def scan_network_endpoint():
    """API endpoint to scan network"""
    network_range = request.args.get('range')
    if not network_range:
        network_range = get_network_range()
    
    print(f"Scanning network: {network_range}")
    devices = scan_network(network_range)
    print(f"Found {len(devices)} devices")
    
    return jsonify(devices)

@app.route('/api/status', methods=['GET'])
def status():
    """API status endpoint"""
    return jsonify({
        'status': 'online',
        'version': 'ECHOPLEX v5.0',
        'server': 'Render.com - echoplex-net-solutions',
        'timestamp': str(socket.gethostname())
    })

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'})

@app.route('/', methods=['GET'])
def index():
    """Root endpoint"""
    return jsonify({
        'name': 'ECHOPLEX Backend',
        'version': 'v5.0',
        'status': 'running',
        'backend_url': 'https://echoplex-net-solutions.onrender.com',
        'endpoints': {
            '/api/status': 'Check server status',
            '/api/scan-network': 'Scan network for devices',
            '/api/health': 'Health check'
        }
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"⚡ ECHOPLEX Backend Server Starting...")
    print(f"🌐 Backend URL: https://echoplex-net-solutions.onrender.com")
    print(f"📡 Ready to scan your REAL network!")
    print(f"🔗 Server running on port: {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
