#!/usr/bin/env python3
"""
ECHOPLEX Backend Server - Any Device, Any Network
URL: https://echoplex-net-solutions.onrender.com
"""

import subprocess
import json
import socket
import os
import re
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = os.urandom(24)
CORS(app)

# ============================================================
#  QUANTUM API KEY (Optional)
# ============================================================
QUANTUM_API_KEY = os.environ.get('QUANTUM_API_KEY', '')

def scan_specific_ip(ip):
    """Scan a specific IP address - Works for ANY device"""
    if not ip:
        return {'error': 'No IP provided'}
    
    # Validate IP format
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if not ip_pattern.match(ip):
        return {'error': 'Invalid IP format'}
    
    device = {
        'ip': ip,
        'hostname': ip,
        'mac': 'Unknown',
        'type': '💻 Device',
        'os': 'Unknown',
        'online': False
    }
    
    try:
        # Ping the IP
        result = subprocess.run(
            ['ping', '-n', '1', '-w', '200', ip],
            capture_output=True,
            text=True,
            timeout=2
        )
        
        if result.returncode == 0:
            device['online'] = True
            
            # Try to get hostname
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                device['hostname'] = hostname
            except:
                pass
            
            # Try to get MAC address
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
                            device['mac'] = parts[1] if len(parts) > 1 else "Unknown"
                        break
            except:
                pass
            
            # Detect device type
            hostname_lower = device['hostname'].lower()
            if 'server' in hostname_lower:
                device['type'] = '🖥 Server'
            elif 'phone' in hostname_lower or 'iphone' in hostname_lower:
                device['type'] = '📱 Mobile'
            elif 'laptop' in hostname_lower:
                device['type'] = '💻 Laptop'
            elif 'router' in hostname_lower or 'switch' in hostname_lower:
                device['type'] = '📡 Router'
            elif 'printer' in hostname_lower:
                device['type'] = '🖨 Printer'
            elif 'camera' in hostname_lower:
                device['type'] = '📷 Camera'
            elif 'tv' in hostname_lower:
                device['type'] = '📺 Smart TV'
            
            print(f"✅ Found: {ip} - {device['hostname']}")
        else:
            print(f"❌ No response: {ip}")
            return {'error': 'Device not responding', 'ip': ip}
            
    except Exception as e:
        print(f"⚠️ Error: {str(e)}")
        return {'error': str(e), 'ip': ip}
    
    return device

# ============================================================
#  ENDPOINTS
# ============================================================

@app.route('/api/scan-ip', methods=['GET'])
def scan_ip_endpoint():
    """Scan a specific IP address"""
    target_ip = request.args.get('ip')
    if not target_ip:
        return jsonify({'error': 'No IP provided'}), 400
    
    print(f"📡 Scanning IP: {target_ip}")
    device = scan_specific_ip(target_ip)
    
    if 'error' in device:
        return jsonify(device), 404
    
    return jsonify({'device': device, 'status': 'success'})

@app.route('/api/status', methods=['GET'])
def status():
    """API status"""
    return jsonify({
        'status': 'online',
        'version': 'ECHOPLEX v5.0',
        'message': 'Ready to scan any IP'
    })

@app.route('/api/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({'status': 'healthy'})

@app.route('/', methods=['GET'])
def index():
    """Root endpoint"""
    return jsonify({
        'name': 'ECHOPLEX Backend',
        'version': 'v5.0',
        'status': 'running',
        'endpoints': {
            '/api/status': 'Check server status',
            '/api/scan-ip?ip=192.168.1.1': 'Scan an IP'
        }
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"⚡ ECHOPLEX Backend Starting...")
    print(f"📡 Ready to scan ANY IP")
    print(f"🔗 Running on port: {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
