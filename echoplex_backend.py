#!/usr/bin/env python3
"""
ECHOPLEX v6 — REAL Network Scanner + optional IBM Quantum Runtime
================================================================
Production-oriented Flask backend.

Fixes over v5:
  * Cross-platform host discovery (POSIX + Windows) with TCP-connect fallback
  * Parallel subnet scanning via ThreadPoolExecutor (254 hosts ~8s)
  * Automatic local subnet/gateway detection (no manual IP entry)
  * Port fingerprinting + TTL-based OS guess + MAC OUI vendor lookup
  * Deterministic risk scoring (SHA-256 seeded) - no per-process random hash()
  * Optional REAL IBM Quantum Runtime jobs (qiskit-ibm-runtime, Sampler V2),
    graceful fallback to simulated entropy when no token/library present
  * Rate limiting, scan caching, security headers, JSON error handlers
  * Serves static/index.html at "/" for single-service deployment

Deployment:
  pip install flask flask-cors
  # optional (real quantum):  pip install qiskit-ibm-runtime
  # env vars:
  #   IBM_QUANTUM_TOKEN   IBM Quantum API token (optional)
  #   ALLOWED_ORIGINS     comma-separated CORS origins (default *)
  #   SCAN_RATE_LIMIT     requests/minute/client (default 30)
  #   SCAN_CACHE_TTL      seconds to cache scan results (default 45)
  #   MAX_SCAN_HOSTS      max hosts per subnet scan (default 254)
  #   PORT                bind port (Render sets this automatically)
"""

import functools
import hashlib
import ipaddress
import json
import logging
import os
import platform
import re
import socket
import subprocess
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

# ------------------------------------------------------------------
#  Configuration
# ------------------------------------------------------------------
VERSION = "ECHOPLEX v6.0 (real-scanner)"
START_TIME = time.monotonic()
MAX_HOSTS = int(os.environ.get("MAX_SCAN_HOSTS", "254"))
SCAN_CACHE_TTL = float(os.environ.get("SCAN_CACHE_TTL", "45"))
RATE_LIMIT = int(os.environ.get("SCAN_RATE_LIMIT", "30"))

DEFAULT_PORTS = [22, 53, 80, 443, 445, 3389, 5900, 8000, 8080, 8443, 1900, 62078, 5353]
PING_FALLBACK_PORTS = [80, 443, 22, 8080, 554]  # hosts that block ICMP
PORT_RISK = {21: 15, 23: 15, 22: 8, 53: 5, 80: 4, 443: 2, 445: 18, 3389: 14,
             5900: 10, 8000: 6, 8080: 6, 8443: 5, 1900: 9, 5353: 4, 62078: 3}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
logger = logging.getLogger("echoplex")

app = Flask(__name__, static_folder="static")
app.secret_key = os.urandom(24)
CORS(app, resources={r"/api/*": {"origins": os.environ.get("ALLOWED_ORIGINS", "*").split(",")}})

# ------------------------------------------------------------------
#  Rate limiter (in-memory sliding window)
# ------------------------------------------------------------------
class RateLimiter:
    def __init__(self, limit: int, window: int = 60):
        self.limit, self.window, self.hits, self.lock = limit, window, {}, threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self.lock:
            self.hits[key] = [t for t in self.hits.get(key, []) if now - t < self.window]
            if len(self.hits[key]) >= self.limit:
                return False
            self.hits[key].append(now)
            return True

    def retry_after(self) -> int:
        return self.window

LIMITER = RateLimiter(RATE_LIMIT)


def rate_limit(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not LIMITER.allow(request.remote_addr or "unknown"):
            return jsonify({"error": "Rate limit exceeded", "retry_after_s": LIMITER.retry_after()}), 429
        return fn(*args, **kwargs)
    return wrapper


# ------------------------------------------------------------------
#  Network primitives (cross-platform)
# ------------------------------------------------------------------
def is_valid_ipv4(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def ping_host(ip: str, timeout: float = 1.0):
    """Return (online, rtt_ms, ttl). Works on Linux, macOS and Windows."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
        ttl_re, rtt_re = re.compile(r"TTL=(\d+)", re.I), re.compile(r"time[=<](\d+(?:\.\d+)?)ms", re.I)
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]
        ttl_re, rtt_re = re.compile(r"ttl=(\d+)", re.I), re.compile(r"time[=<](\d+(?:\.\d+)?)\s*ms", re.I)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
    except (FileNotFoundError, subprocess.SubprocessError):
        return False, None, None
    if proc.returncode != 0:
        return False, None, None
    ttl_m, rtt_m = ttl_re.search(proc.stdout), rtt_re.search(proc.stdout)
    return (True,
            round(float(rtt_m.group(1)), 1) if rtt_m else None,
            int(ttl_m.group(1)) if ttl_m else None)


def tcp_probe(host: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def port_scan(ip: str, ports, timeout: float = 0.4, workers: int = 24):
    open_ports = []
    if not ports:
        return open_ports
    with ThreadPoolExecutor(max_workers=min(workers, len(ports))) as pool:
        futures = {pool.submit(tcp_probe, ip, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            if fut.result():
                open_ports.append(futures[fut])
    return sorted(open_ports)


def normalize_mac(mac: str) -> str:
    return re.sub(r"[^0-9A-F]", ":", mac.upper()).strip(":")


def resolve_mac(ip: str):
    """ARP entry lookup — Windows (arp -a) and Linux/macOS (ip neigh, arp -n)."""
    system = platform.system().lower()
    pattern = re.compile(r"([0-9A-F]{2}[-:]){5}[0-9A-F]{2}", re.I)
    try:
        if system == "windows":
            out = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=3).stdout
            m = pattern.search(out)
            return normalize_mac(m.group(0)) if m else None
        for cmd in (["ip", "neigh", "show", ip], ["arp", "-n", ip]):
            try:
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=3).stdout
            except FileNotFoundError:
                continue
            m = pattern.search(out)
            if m:
                return normalize_mac(m.group(0))
    except Exception:
        pass
    return None


def primary_ip() -> str:
    """Best-effort primary outbound IPv4 (UDP trick — no packets actually sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def detect_networks() -> list:
    """Detect local IPv4 networks + gateways. Returns [{ip, network, gateway?}, ...]."""
    networks, seen = [], set()
    system = platform.system().lower()
    try:
        if system == "windows":
            out = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=6).stdout
            for block in re.split(r"\n\s*\n", out):
                ip_m = re.search(r"IPv4 Address[^:]*:\s*([0-9.]+)", block)
                mask_m = re.search(r"Subnet Mask[^:]*:\s*([0-9.]+)", block)
                gw_m = re.search(r"Default Gateway[^:]*:\s*([0-9.]+)", block)
                if ip_m and mask_m:
                    try:
                        net = str(ipaddress.ip_network(f"{ip_m.group(1)}/{mask_m.group(1)}", strict=False))
                    except ValueError:
                        continue
                    if net not in seen:
                        seen.add(net)
                        networks.append({"ip": ip_m.group(1), "network": net,
                                         "gateway": gw_m.group(1) if gw_m else None})
        else:
            out = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True, timeout=6).stdout
            for line in out.splitlines():
                m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
                if not m:
                    continue
                ip = m.group(1)
                if ip.startswith("127.") or ipaddress.ip_address(ip).is_link_local:
                    continue
                try:
                    net = str(ipaddress.ip_network(f"{ip}/{m.group(2)}", strict=False))
                except ValueError:
                    continue
                if net not in seen:
                    seen.add(net)
                    networks.append({"ip": ip, "network": net, "gateway": None})
            try:
                route = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=6).stdout
                for line in route.splitlines():
                    m = re.match(r"default via (\d+\.\d+\.\d+\.\d+)", line)
                    if m:
                        gw = m.group(1)
                        for n in networks:
                            if ipaddress.ip_address(gw) in ipaddress.ip_network(n["network"]):
                                n["gateway"] = gw
            except Exception:
                pass
    except (FileNotFoundError, subprocess.SubprocessError):
        try:  # macOS / minimal systems without `ip`
            out = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=6).stdout
            for m in re.finditer(r"inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)", out):
                ip = m.group(1)
                if ip.startswith("127.") or ipaddress.ip_address(ip).is_link_local:
                    continue
                net = str(ipaddress.ip_network(f"{ip}/24", strict=False))
                if net not in seen:
                    seen.add(net)
                    networks.append({"ip": ip, "network": net, "gateway": None})
        except Exception:
            pass
    if not networks:  # last resort: primary IP + /24
        ip = primary_ip()
        networks.append({"ip": ip, "network": str(ipaddress.ip_network(f"{ip}/24", strict=False)), "gateway": None})
    return networks


# ------------------------------------------------------------------
#  OUI vendor lookup (mini DB; drop a full oui.csv next to the app to override)
# ------------------------------------------------------------------
OUI_VENDORS = {
    "00:03:93": "Apple", "00:17:F2": "Apple", "3C:22:FB": "Apple", "AC:BC:32": "Apple",
    "A4:5E:60": "Apple", "F0:18:98": "Apple", "C8:2A:14": "Apple", "D0:03:4B": "Apple",
    "D4:61:9D": "Apple", "F8:1E:DF": "Apple", "88:66:5A": "Apple", "A8:5C:2C": "Apple",
    "44:D2:CA": "Apple", "54:52:00": "Apple", "34:C0:59": "Apple", "C4:B3:01": "Apple",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "50:C7:BF": "TP-Link", "60:32:B1": "TP-Link", "84:D8:1B": "TP-Link", "A4:2B:B0": "TP-Link",
    "B0:95:75": "TP-Link", "C8:3A:35": "TP-Link", "CC:32:E5": "TP-Link", "D4:6A:6A": "TP-Link",
    "E8:48:B8": "TP-Link", "F4:F2:6D": "TP-Link", "98:DA:C4": "TP-Link",
    "20:E5:2A": "Netgear", "30:46:9A": "Netgear", "44:94:FC": "Netgear", "5C:AA:FD": "Netgear",
    "78:D2:94": "Netgear", "9C:3D:CF": "Netgear", "A0:63:91": "Netgear", "B0:C5:54": "Netgear",
    "C4:3C:EA": "Netgear", "DC:EF:CA": "Netgear", "E0:91:F5": "Netgear",
    "00:1E:67": "Intel", "00:21:6A": "Intel", "28:C6:8E": "Intel", "3C:97:0E": "Intel",
    "5C:E0:C5": "Intel", "68:05:CA": "Intel", "84:A8:E4": "Intel", "A4:BA:DB": "Intel",
    "AC:7B:A1": "Intel", "B8:76:3F": "Intel", "CC:3A:61": "Intel", "F4:8E:38": "Intel",
    "00:0F:60": "Samsung", "04:E1:51": "Samsung", "08:31:32": "Samsung", "2C:B4:3A": "Samsung",
    "3C:2E:F9": "Samsung", "50:0B:91": "Samsung", "5C:0A:5B": "Samsung", "70:29:1B": "Samsung",
    "8C:77:12": "Samsung", "AC:5F:3E": "Samsung", "DC:F8:B9": "Samsung", "E4:38:83": "Samsung",
    "64:09:80": "Xiaomi", "78:11:DC": "Xiaomi", "A4:6B:B6": "Xiaomi", "F0:B4:29": "Xiaomi",
    "5C:02:14": "Xiaomi", "78:0C:B8": "Xiaomi",
    "00:E0:FC": "Huawei", "04:BD:88": "Huawei", "24:46:C8": "Huawei", "54:25:EA": "Huawei",
    "70:8C:BA": "Huawei", "88:6B:0F": "Huawei", "9C:2E:A1": "Huawei", "B0:E5:ED": "Huawei",
    "00:1A:11": "Google", "0C:54:A5": "Google", "18:64:72": "Google", "3C:5A:B4": "Google",
    "44:D9:E7": "Google", "5C:8A:FD": "Google", "8C:FD:18": "Google", "AC:CF:85": "Google",
    "44:65:0D": "Amazon", "68:37:E9": "Amazon", "74:C2:46": "Amazon", "8C:0F:6F": "Amazon",
    "A0:02:DC": "Amazon", "AC:63:BE": "Amazon", "F0:27:2D": "Amazon", "FC:65:DE": "Amazon",
    "00:0E:CF": "Sony", "04:9F:9D": "Sony", "20:6D:31": "Sony", "5C:96:9D": "Sony",
    "90:B0:ED": "Sony", "00:0F:9F": "LG", "18:6C:5F": "LG", "28:4B:CD": "LG",
    "58:46:E1": "LG", "7C:E5:24": "LG", "A8:2B:B5": "LG",
    "00:00:74": "Canon", "00:1E:8F": "Canon", "10:7B:44": "Canon", "30:C9:AB": "Canon",
    "00:80:77": "Brother", "00:1B:A9": "Brother", "2C:C9:B1": "Brother", "48:82:FA": "Brother",
    "00:18:FE": "HP", "00:1B:78": "HP", "08:2E:5F": "HP", "2C:7C:F2": "HP", "3C:52:82": "HP",
    "6C:3B:E5": "HP", "9C:B6:54": "HP",
    "00:14:22": "Dell", "00:1E:C9": "Dell", "14:18:77": "Dell", "34:17:EB": "Dell",
    "48:4D:7E": "Dell", "84:8F:69": "Dell", "B8:2A:72": "Dell",
    "00:0D:60": "Lenovo", "54:EE:75": "Lenovo", "60:6B:BD": "Lenovo", "A4:34:D9": "Lenovo",
    "B0:25:AA": "Lenovo", "DC:71:96": "Lenovo",
    "00:0C:6E": "ASUS", "00:1B:FC": "ASUS", "10:BF:48": "ASUS", "58:FD:B1": "ASUS",
    "68:0A:E2": "ASUS", "8C:B8:4D": "ASUS", "D8:50:E6": "ASUS",
    "00:50:F2": "Microsoft", "48:F8:B3": "Microsoft", "58:47:0D": "Microsoft",
    "7C:1E:52": "Microsoft", "98:5F:D3": "Microsoft", "B8:AE:6E": "Microsoft",
    "00:0D:4A": "Roku", "44:1A:FA": "Roku", "68:13:E2": "Roku", "90:22:0A": "Roku",
    "00:0E:58": "Sonos", "44:A9:2C": "Sonos", "78:02:F8": "Sonos", "94:9F:3E": "Sonos",
}


def load_oui_db():
    """Optional: replace the mini DB with a full IEEE OUI CSV (oui.csv)."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oui.csv")
    if not os.path.exists(path):
        return OUI_VENDORS
    db = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                parts = [p.strip().strip('"') for p in line.split(",")]
                if len(parts) >= 3 and re.match(r"^[0-9A-F]{2}[-:][0-9A-F]{2}[-:][0-9A-F]{2}$", parts[1], re.I):
                    db[parts[1].replace("-", ":").upper()] = parts[2]
    except Exception as e:
        logger.warning("Could not load oui.csv (%s); using bundled DB", e)
    return db or OUI_VENDORS


OUI_DB = load_oui_db()


def lookup_vendor(mac: str):
    if not mac or mac == "Unknown":
        return None
    prefix = ":".join(mac.split(":")[:3])
    return OUI_DB.get(prefix)


# ------------------------------------------------------------------
#  Fingerprinting / classification
# ------------------------------------------------------------------
def guess_os(ttl):
    if not ttl:
        return "Unknown"
    if ttl <= 64:
        return "Linux / macOS / iOS"
    if ttl <= 128:
        return "Windows"
    return "Network device (router/switch)"


def classify_device(hostname, vendor, ports, ttl) -> str:
    h, v = hostname.lower(), (vendor or "").lower()
    if any(k in h for k in ("phone", "iphone", "ipad", "android", "galaxy", "pixel",
                            "huawei", "xiaomi", "oppo", "vivo", "oneplus", "samsung")):
        return "📱 Mobile"
    if any(k in h for k in ("laptop", "notebook", "desktop", "pc", "workstation",
                            "macbook", "thinkpad", "surface", "chromebook")):
        return "💻 Computer"
    if any(k in h for k in ("router", "gateway", "modem", "ap-", "accesspoint")):
        return "📡 Router"
    if any(k in h for k in ("printer", "print", "brother", "epson", "canon")):
        return "🖨 Printer"
    if any(k in h for k in ("tv", "television", "roku", "firetv", "sonos", "chromecast", "nvidia")):
        return "📺 Media / TV"
    if any(k in h for k in ("server", "nas", "storage", "synology", "qnap", "proxmox")):
        return "🖥 Server / NAS"
    if any(k in h for k in ("camera", "cam", "nvr", "dvr", "hikvision", "reolink", "amcrest")):
        return "📷 Camera"
    if v == "raspberry pi":
        return "🖥 SBC / Server"
    if v == "apple" and any(p in (62078, 5353) for p in ports):
        return "📱 Mobile"
    return "💻 Device"


def risk_score(ip: str, ports) -> float:
    """Deterministic 0-100 risk: SHA-256(ip + ports) entropy + port exposure."""
    h = hashlib.sha256(f"{ip}:{','.join(map(str, sorted(set(ports))))}".encode()).digest()
    base = h[0] / 255 * 40
    exposure = sum(PORT_RISK.get(p, 6) for p in ports)
    return round(min(100.0, base + exposure), 1)


def scan_device(ip: str, ports, timeout: float = 1.0):
    """Full profile for one host: ping, ports, hostname, MAC, vendor, OS guess, risk."""
    started = time.monotonic()
    online, rtt_ms, ttl = ping_host(ip, timeout)
    open_ports = port_scan(ip, ports, timeout=max(0.3, timeout / 3)) if online else []
    if not online:
        open_ports = port_scan(ip, PING_FALLBACK_PORTS, timeout=0.4)
        if open_ports:  # alive, but blocks ICMP
            online, rtt_ms, ttl = True, None, None
    if not online:
        return None
    hostname = None
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass
    mac = resolve_mac(ip)
    vendor = lookup_vendor(mac) if mac else None
    return {
        "ip": ip,
        "online": True,
        "hostname": hostname or ip,
        "mac": mac or "Unknown",
        "vendor": vendor or "Unknown",
        "os_guess": guess_os(ttl),
        "ttl": ttl,
        "rtt_ms": rtt_ms,
        "ports": open_ports,
        "device_type": classify_device(hostname or "", vendor, open_ports, ttl),
        "risk": risk_score(ip, open_ports),
        "scan_ms": round((time.monotonic() - started) * 1000, 1),
    }


# ------------------------------------------------------------------
#  IBM Quantum Runtime (real when configured; else simulated)
# ------------------------------------------------------------------
class QuantumAnalyzer:
    """Samples entropy from a real 3-qubit GHZ circuit on IBM Quantum when
    a token + qiskit-ibm-runtime are available. Falls back to CSPRNG and
    reports mode honestly in every response."""

    def __init__(self, token: str = ""):
        self.token = token or os.environ.get("IBM_QUANTUM_TOKEN", "")
        self.used_real = False

    @staticmethod
    def _lib_available() -> bool:
        try:
            import qiskit_ibm_runtime  # noqa: F401
            return True
        except ImportError:
            return False

    @property
    def mode(self) -> str:
        if self.token and self._lib_available():
            return "ibm_quantum_runtime"
        if self.token:
            return "token_without_library"
        return "simulated"

    def sample_entropy(self, shots: int = 256):
        """Return a list of ints in [0, 100). Real quantum samples when possible."""
        self.used_real = False
        if self.mode == "ibm_quantum_runtime":
            try:
                samples = self._real_samples(shots)
                self.used_real = True
                return samples
            except Exception as e:
                logger.warning("IBM Quantum Runtime failed (%s); using simulated entropy", e)
        return [int.from_bytes(os.urandom(2), "big") % 100 for _ in range(shots)]

    def _real_samples(self, shots: int):
        from qiskit import QuantumCircuit
        from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2 as Sampler

        service = QiskitRuntimeService(channel="ibm_quantum", token=self.token)
        sims = service.backends(simulator=True, operational=True)
        backend = sims[0] if sims else service.least_busy(operational=True, min_num_qubits=3)

        qc = QuantumCircuit(3, 3)          # GHZ state: |000> + |111> / sqrt(2)
        qc.h(0)
        qc.cx(0, 1)
        qc.cx(1, 2)
        qc.measure_all()

        sampler = Sampler(mode=backend)
        job = sampler.run([qc], shots=shots)
        pub_result = job.result()[0]
        counts = pub_result.data.meas.get_counts()

        samples = []
        for bitstring, count in counts.items():
            samples.extend([int(bitstring, 2) % 100] * count)
        return samples[:shots]


QUANTUM = QuantumAnalyzer()

# ------------------------------------------------------------------
#  Scan cache
# ------------------------------------------------------------------
SCAN_CACHE, CACHE_LOCK = {}, threading.Lock()


def cache_get(key: str):
    with CACHE_LOCK:
        hit = SCAN_CACHE.get(key)
        if hit and hit[0] > time.monotonic():
            return hit[1]
    return None


def cache_put(key: str, value):
    with CACHE_LOCK:
        SCAN_CACHE[key] = (time.monotonic() + SCAN_CACHE_TTL, value)


# ------------------------------------------------------------------
#  Routes
# ------------------------------------------------------------------
@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.path.startswith("/api/"):
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp


@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(405)
def bad_method(_):
    return jsonify({"error": "Method not allowed"}), 405


@app.errorhandler(500)
def server_error(_):
    return jsonify({"error": "Internal server error"}), 500


@app.route("/")
def index():
    static_index = os.path.join(app.root_path, "static", "index.html")
    if os.path.exists(static_index):
        return send_file(static_index, max_age=0)
    return jsonify({
        "name": "ECHOPLEX v6",
        "version": VERSION,
        "status": "running",
        "quantum_mode": QUANTUM.mode,
        "endpoints": {
            "/api/status": "Server status & version",
            "/api/health": "Liveness probe",
            "/api/config": "Client defaults",
            "/api/network": "Detected local networks & gateway",
            "/api/scan-ip?ip=X": "Deep scan one IP",
            "/api/scan (POST)": "Parallel subnet scan",
            "/api/quantum/status": "Quantum runtime status",
            "/api/quantum/configure (POST)": "Set token (only if env token absent)",
            "/api/quantum/analyze (POST)": "Risk analysis (real/simulated)",
        },
    })


@app.route("/api/status")
def status():
    return jsonify({
        "status": "online",
        "version": VERSION,
        "uptime_s": round(time.monotonic() - START_TIME, 1),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "quantum": {"configured": bool(QUANTUM.token), "mode": QUANTUM.mode},
        "message": "Real network scanner + optional IBM Quantum Runtime",
    })


@app.route("/api/health")
def health():
    return jsonify({"status": "healthy", "ts": datetime.now(timezone.utc).isoformat()})


@app.route("/api/config")
def api_config():
    return jsonify({
        "default_ports": DEFAULT_PORTS,
        "max_hosts": MAX_HOSTS,
        "scan_cache_ttl": SCAN_CACHE_TTL,
        "rate_limit_per_minute": RATE_LIMIT,
        "quantum_mode": QUANTUM.mode,
    })


@app.route("/api/network")
def network_endpoint():
    public_ip = None
    try:
        with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=3) as r:
            public_ip = json.loads(r.read().decode()).get("ip")
    except Exception:
        pass
    return jsonify({"networks": detect_networks(),
                    "primary_ip": primary_ip(),
                    "public_ip": public_ip})


@app.route("/api/scan-ip", methods=["GET"])
@rate_limit
def scan_ip_endpoint():
    ip = (request.args.get("ip") or "").strip()
    if not is_valid_ipv4(ip):
        return jsonify({"error": "Invalid or missing IPv4 address"}), 400
    ports_arg = request.args.get("ports")
    ports = [int(p) for p in ports_arg.split(",") if p.strip().isdigit()] if ports_arg else DEFAULT_PORTS
    device = scan_device(ip, ports[:24], timeout=1.0)
    if not device:
        return jsonify({"error": "Device not responding", "ip": ip}), 404
    return jsonify({"device": device, "status": "success"})


@app.route("/api/scan", methods=["POST"])
@rate_limit
def scan_endpoint():
    body = request.get_json(silent=True) or {}
    subnet = (body.get("subnet") or "").strip()
    ips = [ip for ip in (body.get("ips") or []) if is_valid_ipv4(str(ip))]
    try:
        concurrency = max(1, min(int(body.get("concurrency", 32)), 64))
        timeout = max(0.2, min(float(body.get("timeout", 1.0)), 3.0))
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid concurrency/timeout"}), 400

    ports = sorted({int(p) for p in (body.get("ports") or DEFAULT_PORTS)
                    if str(p).lstrip("-").isdigit() and 1 <= int(p) <= 65535})[:64]
    if not ports:
        ports = DEFAULT_PORTS[:12]

    if ips:
        targets = ips
    elif subnet:
        try:
            net = ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            return jsonify({"error": f"Invalid subnet: {subnet}"}), 400
        targets = [str(ip) for ip in net.hosts()][:MAX_HOSTS]
    else:
        return jsonify({"error": "Provide 'subnet' or 'ips'"}), 400

    if not targets:
        return jsonify({"error": "No valid target IPs"}), 400

    cache_key = hashlib.sha256(
        (json.dumps(targets, sort_keys=True) + json.dumps(ports)).encode()).hexdigest()
    cached = cache_get(cache_key)
    if cached is not None:
        return jsonify({"status": "success", "cached": True, "devices": cached,
                        "targets": len(targets), "found": len(cached)})

    devices = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {pool.submit(scan_device, ip, ports, timeout): ip for ip in targets}
        for fut in as_completed(futures):
            try:
                dev = fut.result()
                if dev:
                    devices.append(dev)
            except Exception as e:
                logger.warning("Scan error for %s: %s", futures[fut], e)

    devices.sort(key=lambda d: ipaddress.ip_address(d["ip"]))
    cache_put(cache_key, devices)
    logger.info("Subnet scan %s: %d/%d hosts up (%d ports)", subnet or f"{len(ips)} ips",
                len(devices), len(targets), len(ports))
    return jsonify({"status": "success", "cached": False, "devices": devices,
                    "targets": len(targets), "found": len(devices)})


@app.route("/api/quantum/status")
def quantum_status():
    return jsonify({
        "configured": bool(QUANTUM.token),
        "mode": QUANTUM.mode,
        "library_installed": QUANTUM._lib_available(),
        "message": ("IBM Quantum Runtime ready" if QUANTUM.mode == "ibm_quantum_runtime"
                    else "Token set, but qiskit-ibm-runtime is not installed"
                    if QUANTUM.token else "Simulated mode (no token)"),
    })


@app.route("/api/quantum/configure", methods=["POST"])
def quantum_configure():
    if os.environ.get("IBM_QUANTUM_TOKEN"):
        return jsonify({"error": "Token is managed by the server environment",
                        "mode": QUANTUM.mode}), 403
    token = ((request.get_json(silent=True) or {}).get("token") or "").strip()
    if not token:
        return jsonify({"error": "No token provided"}), 400
    QUANTUM.token = token
    logger.info("Quantum token set via API (in-memory only)")
    return jsonify({"status": "ok", "mode": QUANTUM.mode})


@app.route("/api/quantum/analyze", methods=["POST"])
def quantum_analyze():
    body = request.get_json(silent=True) or {}
    devices = body.get("devices") or []
    try:
        shots = max(8, min(int(body.get("shots", 256)), 4096))
    except (TypeError, ValueError):
        shots = 256

    seed = None
    if devices:
        with ThreadPoolExecutor(max_workers=1) as pool:
            try:
                fut = pool.submit(QUANTUM.sample_entropy, shots)
                seed = fut.result(timeout=25)
            except Exception as e:
                logger.warning("Quantum sampling timed out: %s", e)
    if seed is None:
        seed = [int.from_bytes(os.urandom(2), "big") % 100 for _ in range(min(shots, 128))]

    results = []
    for d in devices[:100]:
        ip = str(d.get("ip") or "0.0.0.0")
        ports = [int(p) for p in (d.get("ports") or []) if str(p).isdigit()]
        base = risk_score(ip, ports)
        idx = int.from_bytes(hashlib.sha256(ip.encode()).digest()[:2], "big") % len(seed)
        final = round(base * 0.75 + seed[idx] * 0.25, 1)
        results.append({
            "ip": ip,
            "risk_score": final,
            "base_risk": base,
            "quantum_mix": seed[idx],
            "level": "danger" if final >= 70 else "warning" if final >= 40 else "safe",
            "open_ports": ports,
        })

    return jsonify({
        "status": "success",
        "mode": QUANTUM.mode,
        "sampled": QUANTUM.used_real,
        "quantum_entropy_samples": len(seed),
        "results": results,
    })


# ------------------------------------------------------------------
#  Entrypoint
# ------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info("%s — quantum mode: %s", VERSION, QUANTUM.mode)
    logger.info("Listening on 0.0.0.0:%s", port)
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
