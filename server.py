"""
=============================================================================
UNFURL SECURITY MICROSERVICE - Python Advanced Threat Intelligence Engine
=============================================================================
Provides passive DNS resolution, SSL/TLS certificate inspection, 
HTTP security header auditing, and Shannon entropy calculation via a REST API.
"""

import os
import re
import ssl
import math
import time
import random
import socket
import json
import ipaddress
import urllib.request
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from concurrent.futures import ThreadPoolExecutor

PORT = int(os.environ.get("PORT", 8000))
EXECUTOR = ThreadPoolExecutor(max_workers=10)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# High-risk TLD list often abused in phishing campaigns
SUSPICIOUS_TLDS = {
    'xyz', 'top', 'work', 'click', 'gq', 'tk', 'ml', 'cf', 'ga', 
    'buzz', 'rest', 'fit', 'surf', 'icu', 'cam', 'country', 'kim'
}

# Common targeted high-profile brands for keyword matching
HIGH_PROFILE_BRANDS = [
    'paypal', 'google', 'microsoft', 'apple', 'netflix', 'amazon', 
    'facebook', 'instagram', 'binance', 'coinbase', 'metamask', 'wellsfargo'
]

def calculate_entropy(text: str) -> float:
    """Calculates the Shannon Entropy of a string to detect randomized DGA domains."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    entropy = - sum([p * math.log(p, 2) for p in prob])
    return round(entropy, 3)

def is_private_ip(ip: str) -> bool:
    """Checks if an IP address belongs to private / local loopback / link-local / multicast ranges (SSRF risk)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved
    except ValueError:
        # If it is not a valid IP address, return False
        return False

def resolve_dns_intel(hostname: str) -> dict:
    """Performs passive DNS resolution and reverse PTR lookups."""
    result = {
        'resolved_ips': [],
        'is_private_ip': False,
        'dns_success': False,
        'reverse_ptr': None,
        'error': None
    }
    try:
        # Extract clean hostname without port
        clean_host = hostname.split(':')[0]
        _, _, ip_list = socket.gethostbyname_ex(clean_host)
        result['resolved_ips'] = ip_list
        result['dns_success'] = True
        
        # Check for SSRF / Internal IP exposure
        for ip in ip_list:
            if is_private_ip(ip):
                result['is_private_ip'] = True
                break
                
        # Attempt Reverse DNS (PTR) lookup on primary IP
        if ip_list:
            try:
                ptr, _, _ = socket.gethostbyaddr(ip_list[0])
                result['reverse_ptr'] = ptr
            except Exception:
                result['reverse_ptr'] = "No PTR record found"

    except socket.gaierror as e:
        result['error'] = f"DNS Resolution Failed: {str(e)}"
    except Exception as e:
        result['error'] = str(e)
        
    return result

def inspect_ssl_certificate(hostname: str, port: int = 443) -> dict:
    """Establishes a TLS connection to inspect SSL/TLS certificates."""
    result = {
        'has_ssl': False,
        'issuer': None,
        'subject': None,
        'version': None,
        'san_domains': [],
        'error': None
    }
    
    clean_host = hostname.split(':')[0]
    # Skip raw IP addresses or non-standard hosts for SSL check
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', clean_host):
        result['error'] = "Skipped SSL check for raw IP address"
        return result

    context = ssl.create_default_context()
    try:
        with socket.create_connection((clean_host, port), timeout=3.5) as sock:
            with context.wrap_socket(sock, server_hostname=clean_host) as ssock:
                cert = ssock.getpeercert()
                result['has_ssl'] = True
                result['version'] = ssock.version()
                
                # Parse Issuer & Subject
                issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                subject_dict = dict(x[0] for x in cert.get('subject', []))
                result['issuer'] = issuer_dict.get('organizationName') or issuer_dict.get('commonName', 'Unknown')
                result['subject'] = subject_dict.get('commonName', 'Unknown')
                
                # Subject Alternative Names (SANs)
                sans = cert.get('subjectAltName', [])
                result['san_domains'] = [item[1] for item in sans if item[0] == 'DNS'][:10] # Limit to top 10

    except Exception as e:
        result['error'] = f"TLS handshake failed or port 443 closed ({str(e)})"
        
    return result

def audit_http_headers(target_url: str) -> dict:
    """Queries HTTP headers to evaluate security hardening (HSTS, CSP, etc.)."""
    result = {
        'status_code': None,
        'server_header': None,
        'security_headers': {
            'strict_transport_security': False,
            'content_security_policy': False,
            'x_frame_options': False,
            'x_content_type_options': False
        },
        'error': None
    }
    
    try:
        req = urllib.request.Request(
            target_url, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) UnfurlSecurityScanner/2.0'},
            method='HEAD'
        )
        with urllib.request.urlopen(req, timeout=4.0) as response:
            result['status_code'] = response.status
            headers = response.headers
            
            result['server_header'] = headers.get('Server', 'Hidden / Protected')
            result['security_headers']['strict_transport_security'] = 'Strict-Transport-Security' in headers
            result['security_headers']['content_security_policy'] = 'Content-Security-Policy' in headers
            result['security_headers']['x_frame_options'] = 'X-Frame-Options' in headers
            result['security_headers']['x_content_type_options'] = 'X-Content-Type-Options' in headers

    except urllib.error.HTTPError as e:
        result['status_code'] = e.code
        result['error'] = f"HTTP Error {e.code}"
    except Exception as e:
        result['error'] = f"Connection failed ({str(e)})"
        
    return result

class SecurityAPIHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler providing REST API endpoints for frontend telemetry."""

    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        # Enable CORS for frontend interaction
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers(200)

    def do_GET(self):
        if self.path == '/api/health':
            self._set_headers(200)
            self.wfile.write(json.dumps({'status': 'online', 'service': 'Unfurl Python Telemetry Engine'}).encode())
        elif self.path == '/api/sniffer/stream':
            self._handle_telemetry_stream()
        elif self.path.startswith('/api/'):
            self._set_headers(404)
            self.wfile.write(json.dumps({'error': 'Endpoint not found'}).encode())
        else:
            self._serve_static_file()

    def _handle_telemetry_stream(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Connection', 'keep-alive')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

        sample_ips = ["192.168.1.15", "10.0.4.88", "172.16.0.4", "8.8.8.8", "1.1.1.1", "45.33.32.156"]
        threat_ports = {
            22: "SSH (Brute Force Risk)",
            23: "Telnet (Cleartext Risk)",
            445: "SMB (EternalBlue / Ransomware Risk)",
            3389: "RDP (Remote Access Risk)"
        }

        try:
            while True:
                time.sleep(random.uniform(0.4, 0.9))
                src = random.choice(sample_ips)
                dst = random.choice(sample_ips)
                while dst == src:
                    dst = random.choice(sample_ips)
                    
                protocol = random.choice(["TCP", "TCP", "TCP", "UDP", "UDP", "ICMP"])
                src_port = random.randint(1024, 65535) if protocol != "ICMP" else None
                
                if random.random() < 0.18:
                    dst_port = random.choice([22, 23, 445, 3389])
                    is_suspicious = True
                    alert_reason = f"Targeted Port {dst_port}: {threat_ports[dst_port]}"
                else:
                    dst_port = random.choice([80, 443, 53, 8080]) if protocol != "ICMP" else None
                    is_suspicious = False
                    alert_reason = "Normal"

                size = random.randint(64, 1500)
                if size > 1400 and not is_suspicious:
                    is_suspicious = True
                    alert_reason = f"Large Payload Anomaly ({size} bytes)"

                packet_data = {
                    "timestamp": time.strftime("%H:%M:%S"),
                    "src": f"{src}:{src_port}" if src_port else src,
                    "dst": f"{dst}:{dst_port}" if dst_port else dst,
                    "protocol": protocol,
                    "size": size,
                    "is_suspicious": is_suspicious,
                    "alert": alert_reason
                }

                message = f"data: {json.dumps(packet_data)}\n\n"
                self.wfile.write(message.encode('utf-8'))
                self.wfile.flush()
        except Exception:
            pass

    def _serve_static_file(self):
        req_path = urllib.parse.urlparse(self.path).path
        if req_path == '/' or not req_path:
            req_path = '/index.html'
        
        # Prevent directory traversal attacks
        filepath = os.path.abspath(os.path.join(BASE_DIR, req_path.lstrip('/')))
        if not filepath.startswith(BASE_DIR):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'403 Forbidden')
            return

        if os.path.exists(filepath) and os.path.isfile(filepath):
            ext = os.path.splitext(filepath)[1].lower()
            mime_types = {
                '.html': 'text/html; charset=utf-8',
                '.css': 'text/css; charset=utf-8',
                '.js': 'application/javascript; charset=utf-8',
                '.json': 'application/json; charset=utf-8',
                '.svg': 'image/svg+xml',
                '.ico': 'image/x-icon',
                '.png': 'image/png',
                '.jpg': 'image/jpeg'
            }
            content_type = mime_types.get(ext, 'application/octet-stream')
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            with open(filepath, 'rb') as f:
                self.wfile.write(f.read())
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'404 File Not Found')

    def do_POST(self):
        if self.path == '/api/analyze':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            try:
                payload = json.loads(post_data.decode('utf-8'))
                target_url = payload.get('url', '').strip()
                
                if not target_url:
                    self._set_headers(400)
                    self.wfile.write(json.dumps({'error': 'No URL provided'}).encode())
                    return

                # Parse URL
                if not re.match(r'^https?://', target_url, re.I):
                    target_url = 'http://' + target_url

                parsed = urllib.parse.urlparse(target_url)
                hostname = parsed.hostname or ''
                
                # Perform asynchronous threat telemetry checks
                dns_future = EXECUTOR.submit(resolve_dns_intel, hostname)
                ssl_future = EXECUTOR.submit(inspect_ssl_certificate, hostname)
                http_future = EXECUTOR.submit(audit_http_headers, target_url)

                dns_data = dns_future.result()
                ssl_data = ssl_future.result()
                http_data = http_future.result()
                
                # Entropy Analysis
                domain_entropy = calculate_entropy(hostname)
                tld = hostname.split('.')[-1].lower() if '.' in hostname else ''
                is_suspicious_tld = tld in SUSPICIOUS_TLDS

                response_data = {
                    'target_url': target_url,
                    'hostname': hostname,
                    'entropy': {
                        'score': domain_entropy,
                        'is_high_entropy': domain_entropy > 3.8
                    },
                    'suspicious_tld': is_suspicious_tld,
                    'dns_telemetry': dns_data,
                    'ssl_telemetry': ssl_data,
                    'http_telemetry': http_data
                }

                self._set_headers(200)
                self.wfile.write(json.dumps(response_data).encode())

            except Exception as e:
                self._set_headers(500)
                self.wfile.write(json.dumps({'error': f"Internal Server Error: {str(e)}"}).encode())
        else:
            self._set_headers(404)

def run_server():
    server_address = ('', PORT)
    httpd = HTTPServer(server_address, SecurityAPIHandler)
    print("=========================================================")
    print(f"[+] UNFURL Python Security Telemetry Microservice active!")
    print(f"[+] Listening on REST Endpoint: http://localhost:{PORT}/api/analyze")
    print("=========================================================")
    httpd.serve_forever()

if __name__ == '__main__':
    run_server()
