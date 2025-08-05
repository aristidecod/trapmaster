#!/usr/bin/env python3

"""
HTTP Honeypot - Simule un panneau d'administration web
"""

from flask import Flask, request, render_template_string, redirect, jsonify
import logging
import datetime
import json
import os
import requests
from threading import Thread

class HTTPHoneypot:
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port
        self.app = Flask(__name__)
        self.setup_logging()
        self.setup_routes()
        
    def setup_logging(self):
        """Configure logging system"""
        os.makedirs('logs', exist_ok=True)
        
        # Désactiver les logs Flask
        flask_logger = logging.getLogger('werkzeug')
        flask_logger.setLevel(logging.ERROR)
        
        self.logger = logging.getLogger('http_honeypot')
        self.logger.setLevel(logging.INFO)
        
        file_handler = logging.FileHandler('logs/http_honeypot.log')
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        # Éviter la duplication
        self.logger.propagate = False

    def get_geolocation(self, ip):
        """Get geolocation info for an IP address"""
        if ip in ['127.0.0.1', 'localhost', '::1'] or ip.startswith('192.168.') or ip.startswith('10.'):
            return {'country': 'Local Network', 'city': 'LAN', 'region': 'Private'}
        
        try:
            response = requests.get(
                f'http://ip-api.com/json/{ip}?fields=status,country,city,regionName,isp,lat,lon,proxy',
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'region': data.get('regionName', 'Unknown'),
                        'isp': data.get('isp', 'Unknown'),
                        'lat': data.get('lat', 0),
                        'lon': data.get('lon', 0),
                        'proxy': data.get('proxy', False)
                    }
        except Exception as e:
            self.logger.error(f"Geolocation error for {ip}: {e}")
        
        return {'country': 'Unknown', 'city': 'Unknown', 'region': 'Unknown'}

    def log_access(self, request_type, path, credentials=None, additional_data=None):
        """Log HTTP access attempts"""
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        user_agent = request.headers.get('User-Agent', 'Unknown')
        timestamp = datetime.datetime.now().isoformat()
        
        # Get geolocation
        geo_info = self.get_geolocation(client_ip)
        location = f"{geo_info['city']}, {geo_info['country']}"
        
        # Console output
        print(f"🌐 HTTP {request_type} | {client_ip} ({location}) | {path}")
        if credentials:
            print(f"   └─ Credentials: {credentials['username']}:{credentials['password']}")
        
        # Enhanced logging
        log_data = {
            'timestamp': timestamp,
            'type': 'http_access',
            'ip': client_ip,
            'geolocation': geo_info,
            'request_type': request_type,
            'path': path,
            'user_agent': user_agent,
            'credentials': credentials,
            'additional_data': additional_data
        }
        
        # Text log
        log_msg = f"HTTP_ACCESS | IP: {client_ip} | Location: {location} | Method: {request_type} | Path: {path} | UA: {user_agent}"
        if credentials:
            log_msg += f" | User: {credentials['username']} | Pass: {credentials['password']}"
        
        self.logger.info(log_msg)
        
        # JSON log
        with open('logs/http_honeypot_json.log', 'a') as f:
            f.write(json.dumps(log_data) + '\n')

    def setup_routes(self):
        """Setup HTTP routes and handlers"""
        
        # Page d'accueil - redirige vers login
        @self.app.route('/')
        def index():
            self.log_access('GET', '/')
            return redirect('/admin')
        
        # Panel d'administration fake
        @self.app.route('/admin')
        @self.app.route('/login')
        @self.app.route('/administrator')
        def admin_panel():
            self.log_access('GET', request.path)
            return render_template_string(ADMIN_LOGIN_TEMPLATE)
        
        # Traitement des tentatives de login
        @self.app.route('/admin', methods=['POST'])
        @self.app.route('/login', methods=['POST'])
        @self.app.route('/administrator', methods=['POST'])
        def admin_login():
            username = request.form.get('username', '')
            password = request.form.get('password', '')
            
            credentials = {'username': username, 'password': password}
            self.log_access('POST', request.path, credentials)
            
            # Toujours rejeter et afficher un message d'erreur
            return render_template_string(ADMIN_LOGIN_TEMPLATE, 
                                        error="Invalid username or password")
        
        # Pages communes scannées par les bots
        common_paths = [
            '/wp-admin', '/wp-login.php', '/wordpress', '/wp',
            '/phpmyadmin', '/pma', '/mysql',
            '/admin.php', '/admin.html', '/administrator.php',
            '/panel', '/control', '/dashboard',
            '/api', '/api/v1', '/rest',
            '/backup', '/backups', '/dump',
            '/.env', '/config', '/settings'
        ]
        
        for path in common_paths:
            self.app.add_url_rule(path, f'route_{path.replace("/", "_")}', 
                                lambda p=path: self.handle_scan_attempt(p), 
                                methods=['GET', 'POST'])
        
        # Catch-all pour les autres tentatives
        @self.app.route('/<path:path>')
        def catch_all(path):
            self.log_access('GET', f'/{path}')
            return "404 Not Found", 404

    def handle_scan_attempt(self, path):
        """Handle scanning attempts on common paths"""
        self.log_access('GET', path, additional_data={'scan_attempt': True})
        
        # Simuler différentes réponses selon le path
        if 'wp' in path or 'wordpress' in path:
            return "WordPress not found", 404
        elif 'phpmyadmin' in path or 'pma' in path:
            return "phpMyAdmin access denied", 403
        elif 'api' in path:
            return jsonify({"error": "Unauthorized", "code": 401}), 401
        else:
            return "Access Denied", 403

    def start(self):
        """Start the HTTP honeypot server"""
        print("🌐 HTTP Honeypot Starting...")
        print(f"📡 Listening on http://{self.host}:{self.port}")
        print("🎯 Ready to catch web attacks!")
        print("-" * 50)
        
        self.logger.info(f"HTTP Honeypot started on {self.host}:{self.port}")
        
        try:
            self.app.run(host=self.host, port=self.port, debug=False)
        except KeyboardInterrupt:
            print("\n🛑 Shutting down HTTP Honeypot...")
            self.logger.info("HTTP Honeypot stopped by user")

# Template HTML pour le panneau d'admin fake
ADMIN_LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel - Login</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; background: #f0f0f0; margin: 0; padding: 50px; }
        .login-box { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h2 { text-align: center; color: #333; margin-bottom: 30px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 3px; box-sizing: border-box; }
        input[type="submit"] { width: 100%; background: #007cba; color: white; padding: 12px; border: none; border-radius: 3px; cursor: pointer; font-size: 16px; }
        input[type="submit"]:hover { background: #005a87; }
        .error { color: red; text-align: center; margin: 10px 0; padding: 10px; background: #ffebee; border-radius: 3px; }
        .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>🔐 Administration Panel</h2>
        {% if error %}
            <div class="error">{{ error }}</div>
        {% endif %}
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <input type="submit" value="Sign In">
        </form>
        <div class="footer">
            Server Management System v2.1<br>
            Authorized personnel only
        </div>
    </div>
</body>
</html>
"""

if __name__ == "__main__":
    honeypot = HTTPHoneypot(host='0.0.0.0', port=8080)
    honeypot.start()