#! /usr/bin/env python3

"""
TrapMaster - SSH Honeypot
"""

import socket
import socket
import threading
import paramiko
import logging
import datetime
import time
import os
from colorama import Fore, Style, init

# Initialize colorama for colored output
init(autoreset=True)

class SSHHoneypot:
    def __init__(self, host='0.0.0.0', port=2222):
        self.host = host
        self.port = port
        self.setup_logging()
        self.setup_ssh_server()
        
    def setup_logging(self):
        """Configure logging system"""
        # Create logs directory if it doesn't exist
        os.makedirs('logs', exist_ok=True)
        
        # Setup logger
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/honeypot.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def setup_ssh_server(self):
        """Setup SSH server configuration"""
        # Generate or load SSH host key
        self.host_key = paramiko.RSAKey.generate(2048)
        
    def log_attempt(self, client_ip, username, password, success=False):
        """Log authentication attempt"""
        timestamp = datetime.datetime.now().isoformat()
        
        if success:
            print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {client_ip} - {username}:{password}")
        else:
            print(f"{Fore.RED}[FAILED]{Style.RESET_ALL} {client_ip} - {username}:{password}")
            
        # File logging
        self.logger.info(f"AUTH_ATTEMPT | IP: {client_ip} | Username: {username} | Password: {password} | Success: {success}")
        
    def handle_client(self, client_socket, client_addr):
        """Handle incoming SSH connection"""
        client_ip = client_addr[0]
        transport = None
        
        try:
            print(f"{Fore.CYAN}🔗 New connection from {client_ip}{Style.RESET_ALL}")
            
            # Create SSH transport
            transport = paramiko.Transport(client_socket)
            transport.add_server_key(self.host_key)
            
            # Create server interface
            server = SSHServerInterface(self, client_ip)
            
            # Start SSH server
            transport.start_server(server=server)
            
            # Wait for authentication
            event = threading.Event()
            transport.auth_handler.auth_event = event
            
            # Wait a bit for authentication attempts
            time.sleep(2)
            
            try:
                channel = transport.accept(40)
                if channel:
                    channel.send(b"Welcome to the server!\r\n")
                    time.sleep(1)
                    channel.close()
            except NameError:
                pass
                
        except paramiko.SSHException as e:
            self.logger.info(f"SSH Exception from {client_ip}: {str(e)}")
        except Exception as e:
            self.logger.error(f"Error handling client {client_ip}: {str(e)}")
        finally:
            try:
                if transport:
                    transport.close()
            except:
                pass
            try:
                client_socket.close()
            except:
                pass
                
    def start(self):
        """Start the honeypot server"""
        print(f"{Fore.CYAN} TrapMaster SSH Honeypot Starting...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW} Listening on {self.host}:{self.port}{Style.RESET_ALL}")
        print(f"{Fore.GREEN} Ready to catch threats!{Style.RESET_ALL}")
        print("-" * 50)
        
        try:
            # Create socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(100)
            
            self.logger.info(f"Honeypot started on {self.host}:{self.port}")
            
            while True:
                client_socket, client_addr = server_socket.accept()
                
                # Handle each client in a separate thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_addr)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}🛑 Shutting down TrapMaster...{Style.RESET_ALL}")
            self.logger.info("Honeypot stopped by user")
        except Exception as e:
            print(f"{Fore.RED}❌ Error: {str(e)}{Style.RESET_ALL}")
            self.logger.error(f"Server error: {str(e)}")
        finally:
            server_socket.close()

class SSHServerInterface(paramiko.ServerInterface):
    """Custom SSH server interface for the honeypot"""
    
    def __init__(self, honeypot, client_ip):
        self.honeypot = honeypot
        self.client_ip = client_ip
        
    def check_auth_password(self, username, password):
        """Handle password authentication attempts"""
        #print(f"🔧 DEBUG: check_auth_password called! {username}:{password}")
        self.honeypot.log_attempt(self.client_ip, username, password, success=False)
        
        # Always reject but log everything
        return paramiko.AUTH_FAILED
        
    def check_auth_publickey(self, username, key):
        """Handle public key authentication attempts"""
        #print(f"🔧 DEBUG: check_auth_publickey called! {username}")
        # Log public key attempts
        key_type = key.get_name()
        self.honeypot.logger.info(f"PUBKEY_ATTEMPT | IP: {self.client_ip} | Username: {username} | Key_type: {key_type}")
        return paramiko.AUTH_FAILED

    def check_auth_none(self, username):
        """Handle 'none' authentication attempts"""
        #print(f"🔧 DEBUG: check_auth_none called! {username}")
        return paramiko.AUTH_PARTIALLY_SUCCESSFUL
        
    def get_allowed_auths(self, username):
        """Return allowed authentication methods"""
        #print(f"🔧 DEBUG: get_allowed_auths called! Returning: password,publickey")
        return "password,publickey"
    
    def check_channel_request(self, kind, chanid):
        """Handle channel requests"""
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


if __name__ == "__main__":
    honeypot = SSHHoneypot(host='0.0.0.0', port=2222)
    honeypot.start()

    