#!/usr/bin/env python3
"""
ECHOPLEX Backend Server - REAL Network Scanner + IBM Quantum API
URL: https://echoplex-net-solutions.onrender.com
"""

import subprocess
import json
import socket
import os
import re
import platform
import ipaddress
import shutil
import time
from collections import defaultdict
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = os.urandom(24)
CORS(app)

# ============================================================
#  🔑 LOAD IBM QUANTUM API KEY FROM ENVIRONMENT
#  (NO CHANGES TO QUANTUM API - left intact)
# ============================================================
QUANTUM_API_KEY = os.environ.get('QUANTUM_API_KEY', '')
QUANTUM_API_URL = os.environ.get('QUANTUM_API_URL', 'https://quantum.ibm.com/api')

# Simple scan token to protect the scan endpoint. Set SCAN_TOKEN in env.
SCAN_TOKEN = os.environ.get('SCAN_TOKEN') or None

print(f"🔑 QUANTUM_API_KEY loaded: {'✅' if QUANTUM_API_KEY else '❌ Not set'}")
if SCAN_TOKEN:
    print("🔒 Scan token configured")
else:
    print("🔓 No SCAN_TOKEN set — /api/scan-ip will be open (recommended to set SCAN_TOKEN env var)")

# ============================================================
#  In-memory stores and rate limiting
# ============================================================
_devices_store = {}  # ip -> device dict (ephemeral)
_rate_limit = defaultdict(lambda: {'count': 0, 'start': 0})
RATE_LIMIT_MAX = int(os.environ.get('RATE_LIMIT_MAX', 30))
RATE_LIMIT_WINDOW = int(os.environ.get('RATE_LIMIT_WINDOW', 60))

def _check_rate_limit(client_ip):
    now = time.time()
    entry = _rate_limit[client_ip]
    if now - entry['start'] > RATE_LIMIT_WINDOW:
        entry['start'] = now
        entry['count'] = 0
    entry['count'] += 1
    allowed = entry['count'] <= RATE_LIMIT_MAX
    if not allowed:
        print(f"⚠️ Rate limit exceeded for {client_ip}: {entry['count']} reqs")
    return allowed

# ============================================================
#  Cross-platform, safer IP scan function
# ============================================================
MAC_RE = re.compile(r'([0-9a-f]{2}(?:[:\-][0-9a-f]{2}){5})', re.I)

def scan_specific_ip(ip):
    """Scan a specific IP address (safer / cross-platform).
    - Validates IP using ipaddress
    - Only allows private/local addresses
    - Uses platform-aware ping and best-effort neighbor lookup for MAC
    - Returns device dict or {'error': ...}
    """
    if not ip:
        return {'error': 'No IP provided'}

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {'error': 'Invalid IP format'}

    # Only allow private/local addresses to prevent scanning arbitrary hosts
    if not addr.is_private:
        return {'error': 'Only private/local IP addresses are allowed'}

    device = {
        'ip': ip,
        'hostname': ip,
        'mac': 'Unknown',
        'type': '💻 Device',
        'os': platform.system(),
        'online': False
    }

    system = platform.system().lower()

    # ensure ping exists
    if shutil.which('ping') is None:
        return {'error': 'ping command not available on server'}

    # Choose ping command per OS
    if system == 'windows':
        ping_cmd = ['ping', '-n', '1', '-w', '1000', ip]  # timeout in ms
    else:
        # -c 1 = 1 packet, -W 1 = 1 second timeout (Linux). On macOS, -W expects ms on some builds; best-effort.
        ping_cmd = ['ping', '-c', '1', '-W', '1', ip]

    try:
        result = subprocess.run(ping_cmd, capture_output=True, text=True, timeout=6)
        if result.returncode != 0:
            # not reachable
            return {'error': 'Device not responding', 'ip': ip, 'stdout': (result.stdout or '')[:200]}

        device['online'] = True

        # reverse DNS
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            device['hostname'] = hostname
        except Exception:
            pass

        # Best-effort MAC lookup
        try:
            if system == 'windows':
                arp_cmd = ['arp', '-a', ip]
            else:
                if shutil.which('ip'):
                    arp_cmd = ['ip', 'neigh', 'show', ip]
                else:
                    arp_cmd = ['arp', '-n', ip]

            arp_result = subprocess.run(arp_cmd, capture_output=True, text=True, timeout=3)
            out = arp_result.stdout or ''
            m = MAC_RE.search(out)
            if m:
                device['mac'] = m.group(1)
        except Exception:
            pass

        # Heuristics for device type
        hostname_lower = device['hostname'].lower() if device['hostname'] else ''
        if any(x in hostname_lower for x in ('iphone', 'phone', 'android')):
            device['type'] = '📱 Mobile'
            device['isPhone'] = True
        elif any(x in hostname_lower for x in ('laptop', 'notebook')):
            device['type'] = '💻 Laptop'
            device['isComputer'] = True
        elif any(x in hostname_lower for x in ('desktop', 'pc', 'server')):
            device['type'] = '💻 Computer'
            device['isComputer'] = True
        elif 'router' in hostname_lower or 'switch' in hostname_lower:
            device['type'] = '📡 Router'
        elif 'printer' in hostname_lower:
            device['type'] = '🖨 Printer'
        elif 'camera' in hostname_lower:
            device['type'] = '📷 Camera'
        elif 'tv' in hostname_lower or 'television' in hostname_lower:
            device['type'] = '📺 Smart TV'

        print(f"✅ Found REAL device: {ip} - {device.get('hostname')} ({device.get('type')})")

    except subprocess.TimeoutExpired:
        return {'error': 'ping timed out', 'ip': ip}
    except Exception as e:
        print(f"⚠️ Error scanning {ip}: {e}")
        return {'error': str(e), 'ip': ip}

    # store in devices store for frontend to query
    _devices_store[ip] = device
    return device

# ============================================================
#  QUANTUM API ENDPOINTS (UNCHANGED)
# ============================================================

@app.route('/api/quantum/status', methods=['GET'])
def quantum_status():
    """Check quantum API connection status"""
    return jsonify({
        'connected': bool(QUANTUM_API_KEY),
        'api_key_configured': bool(QUANTUM_API_KEY),
        'api_url': QUANTUM_API_URL,
        'message': 'Quantum API ready' if QUANTUM_API_KEY else 'Quantum API key not configured'
    })

@app.route('/api/quantum/analyze', methods=['POST'])
def quantum_analyze():
    """Run quantum analysis on user's device data"""
    if not QUANTUM_API_KEY:
        return jsonify({
            'error': 'Quantum API key not configured',
            'status': 'error'
        }), 400

    data = request.get_json()
    devices = data.get('devices', [])

    quantum_results = {
        'status': 'success',
        'user_ip': request.remote_addr,
        'analysis_type': 'quantum_neural_network',
        'devices_analyzed': len(devices),
        'quantum_confidence': 98.5,
        'threat_predictions': [
            {'device': d.get('ip'), 'risk_score': 10 + (hash(d.get('ip', '')) % 90)}
            for d in devices[:5]
        ],
        'quantum_entanglement': 'active',
        'qubit_coherence': '99.8%'
    }

    return jsonify(quantum_results)

# ============================================================
#  NEW: Device endpoints + protected scan endpoint
# ============================================================

def _check_token(req):
    if not SCAN_TOKEN:
        return True
    # check header X-SCAN-TOKEN or ?token=
    token = req.headers.get('X-SCAN-TOKEN') or req.args.get('token')
    return token == SCAN_TOKEN

@app.route('/api/scan-ip', methods=['GET'])
def scan_ip_endpoint():
    """Scan a specific IP address - Finds YOUR real devices"""
    target_ip = request.args.get('ip')
    if not target_ip:
        return jsonify({'error': 'No IP provided'}), 400

    # token check
    if not _check_token(request):
        return jsonify({'error': 'Invalid or missing scan token'}), 401

    # rate limit per client
    client_ip = request.remote_addr or 'unknown'
    if not _check_rate_limit(client_ip):
        return jsonify({'error': 'Rate limit exceeded'}), 429

    print(f"📡 Scanning IP: {target_ip} (from {client_ip})")
    device = scan_specific_ip(target_ip)

    if 'error' in device:
        return jsonify(device), 404

    return jsonify({'device': device, 'status': 'success'})

@app.route('/api/devices', methods=['GET'])
def devices_list():
    """Return devices discovered during this process (ephemeral)"""
    return jsonify({'devices': list(_devices_store.values()), 'count': len(_devices_store)})

@app.route('/api/block', methods=['POST'])
def block_device():
    data = request.get_json() or {}
    ip = data.get('ip')
    if not ip:
        return jsonify({'error': 'No IP provided'}), 400
    device = _devices_store.get(ip)
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    device['status'] = 'blocked'
    _devices_store[ip] = device
    print(f"🚫 Device blocked: {ip}")
    return jsonify({'status': 'blocked', 'device': device})

@app.route('/api/lock', methods=['POST'])
def lock_down():
    # simulate emergency lockdown: mark all devices as blocked
    for ip, device in _devices_store.items():
        device['status'] = 'blocked'
    print("🔒 Emergency lockdown applied to all discovered devices")
    return jsonify({'status': 'locked', 'count': len(_devices_store)})

# ============================================================
#  STATUS / HEALTH / ROOT (UNCHANGED)
# ============================================================

@app.route('/api/status', methods=['GET'])
def status():
    return jsonify({
        'status': 'online',
        'version': 'ECHOPLEX v5.0 Quantum + REAL',
        'quantum_connected': bool(QUANTUM_API_KEY),
        'message': 'Scanning YOUR actual network devices with Quantum AI'
    })

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy'})

@app.route('/', methods=['GET'])
def index():
    return jsonify({
        'name': 'ECHOPLEX Quantum + REAL Scanner',
        'version': 'v5.0',
        'status': 'running',
        'quantum_enabled': bool(QUANTUM_API_KEY),
        'message': 'Finds YOUR actual devices + IBM Quantum AI protection',
        'endpoints': {
            '/api/status': 'Check server status',
            '/api/scan-ip?ip=192.168.1.1': 'Scan a specific IP',
            '/api/quantum/status': 'Check Quantum API status',
            '/api/quantum/analyze': 'Run Quantum analysis',
            '/api/devices': 'List discovered devices',
            '/api/block': 'POST {ip} to block a device (simulation)'
        }
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"⚡ ECHOPLEX Quantum + REAL Scanner Starting...")
    print(f"🔑 Quantum API: {'✅ Configured' if QUANTUM_API_KEY else '❌ Not configured'}")
    print(f"🔒 Scan token: {'✅ Configured' if SCAN_TOKEN else '❌ Not configured'}")
    print(f"📡 Scanning YOUR actual network - NO GHOST DEVICES")
    print(f"📱 Will find YOUR phone, computer, and all devices")
    print(f"🔗 Running on port: {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
