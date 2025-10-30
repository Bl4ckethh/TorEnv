#!/usr/bin/env python3
"""
Tor Connection Script for OSINT Research
Configures Python requests to route through Tor network
Auto-installs and configures Tor on Linux systems

Usage:
    ./torenv.py --start    Start Tor service
    ./torenv.py --stop     Stop Tor service
    ./torenv.py --status   Check Tor status
    ./torenv.py --instances 3 --rotate   Rotate IP every request
    ./torenv.py            Interactive setup and test
"""

import requests
import socket
import socks
from stem import Signal
from stem.control import Controller
import time
import sys
import subprocess
import os
import shutil
import argparse
import tempfile
from pathlib import Path
import atexit
import threading

# Colors for better visibility
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_success(msg):
    print(f"{Colors.GREEN}[Success]{Colors.END} {msg}")

def print_error(msg):
    print(f"{Colors.RED}[Error]{Colors.END} {msg}")

def print_info(msg):
    print(f"{Colors.BLUE}[*]{Colors.END} {msg}")

def print_warning(msg):
    print(f"{Colors.YELLOW}[Warning]{Colors.END} {msg}")

def print_tor_active():
    print(f"\n{Colors.BOLD}{Colors.GREEN}╔══════════════════════════════════════╗{Colors.END}")
    print(f"{Colors.BOLD}{Colors.GREEN}║   ONION TOR IS ACTIVE AND ROUTING ONION   ║{Colors.END}")
    print(f"{Colors.BOLD}{Colors.GREEN}╚══════════════════════════════════════╝{Colors.END}\n")


# <<< MULTI-INSTANCE ROTATION >>> 
class TorInstance:
    def __init__(self, idx, base_dir="/tmp/tor-instances"):
        self.idx = idx
        self.base_dir = base_dir
        self.dir = f"{base_dir}/instance_{idx}"
        self.socks_port = 9050 + idx
        self.control_port = 9051 + idx
        self.pid_file = f"{self.dir}/tor.pid"
        self.torrc_file = f"{self.dir}/torrc"
        self.process = None
        os.makedirs(self.dir, exist_ok=True)

    def generate_torrc(self):
        config = f"""
SocksPort {self.socks_port}
ControlPort {self.control_port}
DataDirectory {self.dir}
PidFile {self.pid_file}
CookieAuthentication 0
HashedControlPassword {self.hashed_password}
"""
        with open(self.torrc_file, 'w') as f:
            f.write(config.strip() + "\n")

    def start(self):
        self.generate_torrc()
        cmd = ['tor', '-f', self.torrc_file]
        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print_info(f"Started Tor instance {self.idx} → SOCKS {self.socks_port} | Control {self.control_port}")

    def stop(self):
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(5)
            except:
                self.process.kill()
        if os.path.exists(self.dir):
            shutil.rmtree(self.dir, ignore_errors=True)
        print_info(f"Stopped Tor instance {self.idx}")

    def get_session(self):
        session = requests.Session()
        proxy_url = f'socks5h://127.0.0.1:{self.socks_port}'
        session.proxies = {'http': proxy_url, 'https': proxy_url}
        return session
# <<< END MULTI-INSTANCE >>>



class TorSession:
    def __init__(self, tor_port=9050, control_port=9051, verbose=False):
        self.tor_port = tor_port
        self.control_port = control_port
        self.password = "TorEnvSecure2025!"  # Change this!
        self.session = None
        self.verbose = verbose
        self.last_newnym = 0
        
        # <<< MULTI-INSTANCE >>>
        self.instances = None
        self.current_idx = 0
        self.rotate_every = 0  # 0 = disabled, 1 = every request
        # <<< END >>>

        # Generate hashed password
        try:
            result = subprocess.run(['tor', '--hash-password', self.password], capture_output=True, text=True, timeout=10)
            self.hashed_password = result.stdout.strip().split('\n')[-1].strip()
        except:
            self.hashed_password = "16:YOUR_HASH_HERE"  # Fallback

    def log_verbose(self, msg):
        if self.verbose:
            print(f"{Colors.CYAN}[DEBUG] {msg}{Colors.END}")
    
    def detect_package_manager(self):
        package_managers = ['apt', 'apt-get', 'dnf', 'yum', 'pacman', 'zypper']
        for pm in package_managers:
            if shutil.which(pm):
                print_success(f"Detected package manager: {pm}")
                return pm
        return None
    
    def check_tor_version(self):
        try:
            result = subprocess.run(['tor', '--version'], capture_output=True, text=True, timeout=5)
            version_line = result.stdout.split('\n')[0]
            self.log_verbose(f"Tor version: {version_line}")
            import re
            match = re.search(r'(\d+)\.(\d+)\.(\d+)', version_line)
            if match:
                major, minor, patch = map(int, match.groups())
                if (major, minor) < (0, 4):
                    print_warning(f"Tor version {major}.{minor}.{patch} is outdated")
                    print_info("Consider upgrading: sudo apt update && sudo apt upgrade tor")
                else:
                    self.log_verbose(f"Tor version {major}.{minor}.{patch} is acceptable")
            return True
        except Exception as e:
            self.log_verbose(f"Could not check Tor version: {e}")
            return False
    
    def install_tor(self):
        if not sys.platform.startswith('linux'):
            print_error("Auto-install only supported on Linux")
            return False
        print_info("Tor not found. Attempting to install...")
        pm = self.detect_package_manager()
        if not pm:
            print_error("Could not detect package manager")
            return False
        if pm in ['apt', 'apt-get']:
            try:
                print_info("Updating package lists...")
                subprocess.run(['sudo', pm, 'update'], check=True, capture_output=not self.verbose)
                print_info("Installing Tor...")
                subprocess.run(['sudo', pm, 'install', '-y', 'tor'], check=True, capture_output=not self.verbose)
                print_success("Tor installed successfully")
                self.check_tor_version()
                return True
            except subprocess.CalledProcessError as e:
                print_error(f"Installation failed: {e}")
                return False
        elif pm == 'pacman':
            try:
                print_info("Installing Tor with pacman...")
                subprocess.run(['sudo', 'pacman', '-S', '--noconfirm', 'tor'], check=True, capture_output=not self.verbose)
                print_success("Tor installed successfully")
                self.check_tor_version()
                return True
            except subprocess.CalledProcessError as e:
                print_error(f"Installation failed: {e}")
                return False
        elif pm in ['dnf', 'yum']:
            try:
                print_info(f"Installing Tor with {pm}...")
                subprocess.run(['sudo', pm, 'install', '-y', 'tor'], check=True, capture_output=not self.verbose)
                print_success("Tor installed successfully")
                self.check_tor_version()
                return True
            except subprocess.CalledProcessError as e:
                print_error(f"Installation failed: {e}")
                return False
        return False
    
    def detect_existing_tor_config(self):
        torrc_paths = ['/etc/tor/torrc', '/usr/local/etc/tor/torrc']
        for torrc_path in torrc_paths:
            if os.path.exists(torrc_path):
                try:
                    with open(torrc_path, 'r') as f:
                        content = f.read()
                    import re
                    socks_match = re.search(r'^\s*SocksPort\s+(\d+)', content, re.MULTILINE)
                    control_match = re.search(r'^\s*ControlPort\s+(\d+)', content, re.MULTILINE)
                    if socks_match:
                        detected_socks = int(socks_match.group(1))
                        if detected_socks != self.tor_port:
                            print_warning(f"Detected SocksPort {detected_socks} (expected {self.tor_port})")
                            self.tor_port = detected_socks
                    if control_match:
                        detected_control = int(control_match.group(1))
                        if detected_control != self.control_port:
                            print_warning(f"Detected ControlPort {detected_control} (expected {self.control_port})")
                            self.control_port = detected_control
                    return True
                except:
                    pass
        return False
    
    def verify_torrc_syntax(self, torrc_path):
        try:
            result = subprocess.run(['tor', '--verify-config', '-f', torrc_path], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.log_verbose("torrc syntax is valid")
                return True
            else:
                print_error(f"Invalid torrc syntax: {result.stderr}")
                return False
        except Exception as e:
            print_warning(f"Could not verify torrc: {e}")
            return True
    
    def configure_tor(self):
        torrc_paths = ['/etc/tor/torrc', '/usr/local/etc/tor/torrc', os.path.expanduser('~/.torrc')]
        torrc_path = None
        for path in torrc_paths:
            if os.path.exists(path):
                torrc_path = path
                break
        if not torrc_path:
            print_error("Could not find torrc configuration file")
            return False
        print_info(f"Configuring Tor at {torrc_path}...")
        try:
            with open(torrc_path, 'r') as f:
                content = f.read()
                if 'HashedControlPassword' in content and '9051' in content:
                    print_success("Tor already configured with password auth")
                    return True
        except PermissionError:
            pass

        config_lines = [
            '\n# Added by TorEnv - PASSWORD AUTH (No Group/Login Needed)',
            f'SocksPort {self.tor_port}',
            f'ControlPort 127.0.0.1:{self.control_port}',
            f'HashedControlPassword {self.hashed_password}',
            'CookieAuthentication 0',
        ]
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
                tmp_path = tmp.name
                tmp.write('\n'.join(config_lines) + '\n')
            result = subprocess.run(
                ['sudo', 'bash', '-c', f'cat {tmp_path} >> {torrc_path}'],
                capture_output=True, text=True
            )
            os.unlink(tmp_path)
            if result.returncode != 0:
                print_error("Failed to update Tor configuration")
                print_error(result.stderr)
                return False
            print_success("Tor configured with password auth")
            if not self.verify_torrc_syntax(torrc_path):
                print_error("Configuration syntax is invalid")
                print_warning("You may need to manually fix /etc/tor/torrc")
                return False
            return True
        except Exception as e:
            print_error(f"Error configuring Tor: {e}")
            return False
    
    def check_bootstrap_status(self):
        if not self.check_control_port():
            return False, "Control port not open"
        try:
            with Controller.from_port(port=self.control_port) as controller:
                controller.authenticate(password=self.password)
                bootstrap_status = controller.get_info("status/bootstrap-phase")
                self.log_verbose(f"Bootstrap status: {bootstrap_status}")
                import re
                match = re.search(r'PROGRESS=(\d+)', bootstrap_status)
                if match:
                    progress = match.group(1)
                    if progress == '100':
                        return True, "Complete"
                    else:
                        return False, f"{progress}%"
                return False, "Unknown"
        except Exception as e:
            self.log_verbose(f"Bootstrap check failed: {e}")
            return False, "Authenticating..."
    
    def start_tor_service(self):
        if not sys.platform.startswith('linux'):
            return False
        print_info("Starting Tor service...")
        try:
            subprocess.run(['sudo', 'systemctl', 'start', 'tor'], check=True, capture_output=not self.verbose)
            print_info("Waiting for Tor to initialize...")
            time.sleep(5)
            if self.check_tor_running():
                print_success("Tor is running (SOCKS port active)")
                return True
            return False
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        try:
            subprocess.run(['sudo', 'service', 'tor', 'start'], check=True, capture_output=not self.verbose)
            time.sleep(5)
            if self.check_tor_running():
                print_success("Tor service started")
                return True
            return False
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        print_error("Could not start Tor service automatically")
        print_warning("Try manually: sudo systemctl start tor")
        return False
    
    def stop_tor_service(self):
        if not sys.platform.startswith('linux'):
            return False
        print_info("Stopping Tor service...")
        try:
            subprocess.run(['sudo', 'systemctl', 'stop', 'tor'], check=True, capture_output=True)
            print_success("Tor service stopped")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        try:
            subprocess.run(['sudo', 'service', 'tor', 'stop'], check=True, capture_output=True)
            print_success("Tor service stopped")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        print_error("Could not stop Tor service")
        return False
    
    def get_tor_status(self):
        if not sys.platform.startswith('linux'):
            return None
        try:
            result = subprocess.run(['systemctl', 'status', 'tor'], capture_output=True, text=True, timeout=5)
            return result.stdout
        except:
            try:
                result = subprocess.run(['service', 'tor', 'status'], capture_output=True, text=True, timeout=5)
                return result.stdout
            except:
                return None
    
    def parse_tor_status(self):
        status = self.get_tor_status()
        if not status:
            return "unknown"
        if "Active: active" in status:
            return "active"
        elif "Active: inactive" in status:
            return "inactive"
        elif "Active: failed" in status:
            return "failed"
        else:
            return "unknown"
    
    def check_tor_installed(self):
        return shutil.which('tor') is not None
    
    def check_tor_running(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            result = sock.connect_ex(('127.0.0.1', self.tor_port))
            sock.close()
            return result == 0
        except:
            return False
    
    def check_control_port(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            result = sock.connect_ex(('127.0.0.1', self.control_port))
            sock.close()
            return result == 0
        except:
            return False
    
    def auto_setup_tor(self):
        print(f"\n{Colors.BOLD}{'='*50}")
        print("Auto-Setup: Checking Tor Installation")
        print(f"{'='*50}{Colors.END}\n")
        self.detect_existing_tor_config()
        print_info("Step 1/3: Checking Tor installation...")
        if not self.check_tor_installed():
            print_error("Tor is not installed on your system")
            print(f"\n{Colors.CYAN}Would you like to install Tor now?{Colors.END}")
            response = input(f"\n{Colors.BOLD}Install Tor? [Y/n]: {Colors.END}").lower()
            if response in ['y', 'yes', '']:
                print()
                if not self.install_tor():
                    print_error("Installation failed")
                    print_info("Try manually: sudo apt install tor")
                    return False
            else:
                print_warning("\nCannot proceed without Tor")
                print_info("Install manually: sudo apt install tor")
                return False
        else:
            print_success("Tor is already installed Success")
            self.check_tor_version()
        print(f"\n{Colors.BOLD}---{Colors.END}")
        print_info("Step 2/3: Checking Tor service status...")
        if not self.check_tor_running():
            print_warning("Tor service is not running")
            print(f"\n{Colors.CYAN}Would you like to start Tor now?{Colors.END}")
            response = input(f"\n{Colors.BOLD}Start Tor service? [Y/n]: {Colors.END}").lower()
            if response in ['y', 'yes', '']:
                print()
                if not self.start_tor_service():
                    print_error("Failed to start Tor")
                    print_info("Try manually: ./torenv.py --start")
                    return False
                if not self.check_tor_running():
                    print_error("Tor failed to start properly")
                    return False
                print_tor_active()
            else:
                print_warning("\nCannot proceed without running Tor")
                print_info("Start Tor later with: ./torenv.py --start")
                return False
        else:
            print_success("Tor service is running Success")
            is_ready, status = self.check_bootstrap_status()
            if is_ready:
                print_success(f"Tor is fully bootstrapped Success")
            else:
                print_info(f"Bootstrap status: {status}")
            print_tor_active()
        print(f"\n{Colors.BOLD}---{Colors.END}")
        print_info("Step 3/3: Configuring control port with password auth...")
        if self.configure_tor():
            print_info("Restarting Tor to apply password auth...")
            subprocess.run(['sudo', 'systemctl', 'restart', 'tor'], capture_output=True)
            time.sleep(5)
            if self.check_control_port():
                print_success("Password auth configured - no re-login needed!")
            else:
                print_warning("Control port not ready after restart")
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*50}")
        print("Success Setup Complete!")
        print(f"{'='*50}{Colors.END}\n")
        return True
        
    def setup_session(self):
        self.session = requests.Session()
        self.session.proxies = {
            'http': f'socks5h://127.0.0.1:{self.tor_port}',
            'https': f'socks5h://127.0.0.1:{self.tor_port}'
        }
        socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", self.tor_port)
        socket.socket = socks.socksocket
        print_success(f"Tor session configured on port {self.tor_port}")
        return self.session
    
    def get_ip(self):
        try:
            session = self.get_current_session()
            response = session.get('https://check.torproject.org/api/ip', timeout=30)
            data = response.json()
            ip = data.get('IP', 'Unknown')
            print(f"{Colors.CYAN}Current Tor IP: {Colors.BOLD}{ip}{Colors.END}")
            if data.get('IsTor'):
                print_success("Success Verified by Tor Project: IP is routing through Tor")
            else:
                print_warning("Warning Tor Project says: NOT using Tor!")
            return ip
        except requests.exceptions.ConnectionError:
            print_error("Connection refused. Tor might not be running.")
            return None
        except Exception as e:
            print_error(f"Error getting IP: {e}")
            return None

    def get_current_session(self):
        if self.instances:
            inst = self.instances[self.current_idx]
            return inst.get_session()
        else:
            if not self.session:
                self.setup_session()
            return self.session

    def renew_circuit(self):
        current_time = time.time()
        if current_time - self.last_newnym < 10:
            wait_time = 10 - (current_time - self.last_newnym)
            print_warning(f"Rate limited. Wait {wait_time:.1f}s before requesting new circuit")
            return False
        try:
            with Controller.from_port(port=self.control_port) as controller:
                controller.authenticate(password=self.password)
                controller.signal(Signal.NEWNYM)
                self.last_newnym = current_time
                print_success("New Tor circuit requested - Getting new identity...")
                time.sleep(5)
                return True
        except Exception as e:
            print_error(f"Error renewing circuit: {e}")
            return False
    
    def test_connection(self):
        print(f"\n{Colors.BOLD}{'='*50}")
        print("Testing Tor Connection")
        print(f"{'='*50}{Colors.END}\n")
        try:
            print_info("Getting your regular IP (not through Tor)...")
            regular_response = requests.get('https://api.ipify.org?format=json', timeout=10)
            regular_ip = regular_response.json()['ip']
            print(f"{Colors.YELLOW}Your Regular IP: {Colors.BOLD}{regular_ip}{Colors.END}")
            print_info("Getting your Tor IP (through Tor network)...")
            tor_ip = self.get_ip()
            if tor_ip is None:
                print_error("Failed to connect through Tor")
                return False
            if regular_ip != tor_ip:
                print(f"\n{Colors.BOLD}{Colors.GREEN}╔══════════════════════════════════════╗")
                print(f"║          Success TOR IS WORKING!           ║")
                print(f"╚══════════════════════════════════════╝{Colors.END}")
                print(f"\n{Colors.GREEN}Regular IP: {regular_ip}")
                print(f"Tor IP:     {tor_ip}")
                print(f"Status:     {Colors.BOLD}ANONYMOUS{Colors.END}\n")
                return True
            else:
                print_warning("IPs are the same - Tor might not be working correctly")
                return False
        except requests.exceptions.RequestException as e:
            print_error(f"Connection test failed: {e}")
            return False
    
    def make_request(self, url, method='GET', **kwargs):
        session = self.get_current_session()
        try:
            if 'timeout' not in kwargs:
                kwargs['timeout'] = 30
            if method.upper() == 'GET':
                response = session.get(url, **kwargs)
            elif method.upper() == 'POST':
                response = session.post(url, **kwargs)
            else:
                raise ValueError(f"Unsupported method: {method}")
            if response.status_code in [403, 429] or any(kw in response.text.lower() for kw in ['captcha', 'blocked', 'rate limit']):
                print_warning(f"Block detected (status {response.status_code}) — rotating instance...")
                if self.instances:
                    self.current_idx = (self.current_idx + 1) % len(self.instances)
            if self.instances and self.rotate_every > 0:
                self.current_idx = (self.current_idx + 1) % len(self.instances)
            return response
        except requests.exceptions.ConnectionError:
            print_error("Connection refused. Check if Tor is still running.")
            if self.instances:
                self.current_idx = (self.current_idx + 1) % len(self.instances)
            return None
        except Exception as e:
            print_error(f"Request failed: {e}")
            return None


def main():
    parser = argparse.ArgumentParser(
        description='ONION Tor OSINT Research Tool - Automated Tor Management',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./torenv.py --start     Start Tor service
  ./torenv.py --stop      Stop Tor service  
  ./torenv.py --status    Check Tor status
  ./torenv.py --instances 3 --rotate   Rotate IP every request
  ./torenv.py --verbose   Run with verbose output
  ./torenv.py             Interactive setup and test
        """,
        add_help=True
    )
    parser.add_argument('--start', action='store_true', help='Start Tor service')
    parser.add_argument('--stop', action='store_true', help='Stop Tor service')
    parser.add_argument('--status', action='store_true', help='Check Tor status and display current IP')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose debug output')
    parser.add_argument('--instances', type=int, default=1, help='Number of Tor instances (default: 1)')
    parser.add_argument('--rotate', action='store_true', help='Rotate instance on every request')

    args = parser.parse_args()
    tor = TorSession(verbose=args.verbose)

    if args.instances > 1:
        for inst in range(args.instances):
            instance = TorInstance(inst)
            instance.hashed_password = tor.hashed_password  # Share password
            tor.instances = tor.instances or []
            tor.instances.append(instance)
            instance.start()
        def cleanup():
            for inst in tor.instances:
                inst.stop()
        atexit.register(cleanup)
        if args.rotate:
            tor.rotate_every = 1

    if args.start:
        print(f"\n{Colors.BOLD}{'='*50}")
        print("Starting Tor Service")
        print(f"{'='*50}{Colors.END}\n")
        if not tor.check_tor_installed():
            print_error("Tor is not installed")
            print_info("Run without arguments for auto-install: ./torenv.py")
            sys.exit(1)
        if tor.check_tor_running():
            print_success("Tor is already running")
            print_tor_active()
        else:
            if tor.start_tor_service():
                time.sleep(2)
                if tor.check_tor_running():
                    print_tor_active()
                    tor.setup_session()
                    tor.get_ip()
                else:
                    print_error("Failed to start Tor")
                    sys.exit(1)
        sys.exit(0)
    
    elif args.stop:
        print(f"\n{Colors.BOLD}{'='*50}")
        print("Stopping Tor Service")
        print(f"{'='*50}{Colors.END}\n")
        if not tor.check_tor_running():
            print_info("Tor is not running")
        else:
            tor.stop_tor_service()
        sys.exit(0)
    
    elif args.status:
        if sys.platform.startswith('linux') or sys.platform == 'darwin':
            os.system('clear')
        elif os.name == 'nt':
            os.system('cls')
        print("="*50)
        print("Tor Status Check")
        print("="*50)
        if tor.check_tor_installed():
            print_success("Tor is installed")
        else:
            print_error("Tor is not installed")
        if tor.instances:
            for i, inst in enumerate(tor.instances):
                try:
                    ip = requests.get('https://api.ipify.org', proxies=inst.get_session().proxies, timeout=10).text
                    print_success(f"Instance {i}: SOCKS {inst.socks_port} → IP: {ip}")
                except:
                    print_error(f"Instance {i}: Failed to get IP")
        elif tor.check_tor_running():
            print_success(f"Tor is running on port {tor.tor_port}")
            print_tor_active()
            tor.setup_session()
            tor.get_ip()
        else:
            print_error("Tor is not running")
            print_info("Start with: ./torenv.py --start")
        if tor.check_control_port():
            print_success(f"Control port {tor.control_port} is accessible")
        else:
            print_warning("Control port is not accessible")
        status = tor.get_tor_status()
        if status:
            print(f"Detailed Status:")
            print(status)
        sys.exit(0)
    
    if sys.platform.startswith('linux') or sys.platform == 'darwin':
        os.system('clear')
    elif os.name == 'nt':
        os.system('cls')
    
    print(f"{Colors.BOLD}{Colors.MAGENTA}")
    print("="*50)
    print("    ONION TOR OSINT RESEARCH TOOL ONION")
    print("    Automated Tor Setup & Management")
    print("="*50)
    print(Colors.END)
    print(f"\n{Colors.CYAN}Welcome! This wizard will help you set up Tor for")
    print(f"anonymous OSINT research and web browsing.{Colors.END}\n")
    input(f"{Colors.BOLD}Press Enter to begin setup...{Colors.END}")
    if not tor.auto_setup_tor():
        print(f"\n{Colors.RED}{'='*50}")
        print("Setup Incomplete")
        print(f"{'='*50}{Colors.END}")
        print_error("Setup was not completed")
        print_info("Fix the issues above and run: ./torenv.py")
        sys.exit(1)
    print(f"\n{Colors.BOLD}{'='*50}")
    print("Running Connection Test")
    print(f"{'='*50}{Colors.END}\n")
    print_info("This will verify that your traffic is being routed through Tor...")
    time.sleep(1)
    if not tor.test_connection():
        print_error("\nConnection test failed")
        print_info("Try restarting Tor: ./torenv.py --stop && ./torenv.py --start")
        sys.exit(1)
    print(f"\n{Colors.BOLD}{'='*50}")
    print("Verifying with Tor Project")
    print(f"{'='*50}{Colors.END}\n")
    print_info("Checking with torproject.org...")
    response = tor.make_request('https://check.torproject.org/api/ip')
    if response:
        data = response.json()
        if data.get('IsTor'):
            print_success("Success Tor Project confirms: You are using Tor!")
            print(f"{Colors.CYAN}   Response: {data}{Colors.END}")
    if tor.check_control_port():
        print(f"\n{Colors.BOLD}{'='*50}")
        print("Testing Identity Change")
        print(f"{'='*50}{Colors.END}\n")
        print_info("Testing circuit renewal (changing your IP)...")
        old_ip = tor.get_ip()
        if tor.renew_circuit():
            new_ip = tor.get_ip()
            if old_ip and new_ip and old_ip != new_ip:
                print(f"\n{Colors.GREEN}{Colors.BOLD}Success Identity Change Successful!{Colors.END}")
                print(f"{Colors.CYAN}  Previous IP: {old_ip}")
                print(f"  New IP:      {new_ip}{Colors.END}")
            else:
                print_warning("IP didn't change (Tor may reuse circuits, try again later)")
    else:
        print(f"\n{Colors.YELLOW}Note: Control port uses password auth - no group required{Colors.END}")
    print(f"\n{Colors.BOLD}{Colors.GREEN}")
    print("="*50)
    print("    Success SETUP COMPLETE - TOR IS READY!")
    print("="*50)
    print(Colors.END)
    print(f"\n{Colors.BOLD}Quick Commands:{Colors.END}")
    print(f"  {Colors.CYAN}./torenv.py --start{Colors.END}   → Start Tor service")
    print(f"  {Colors.CYAN}./torenv.py --stop{Colors.END}    → Stop Tor service")
    print(f"  {Colors.CYAN}./torenv.py --status{Colors.END}  → Check Tor status")
    print(f"  {Colors.CYAN}./torenv.py --instances 3 --rotate{Colors.END} → New IP every request")
    print(f"  {Colors.CYAN}./torenv.py --help{Colors.END}    → Show help menu")
    print(f"\n{Colors.BOLD}Python Usage:{Colors.END}")
    print(f"{Colors.YELLOW}from torenv import TorSession\n")
    print(f"tor = TorSession()")
    print(f"tor.setup_session()")
    print(f"response = tor.make_request('https://example.com')")
    print(f"tor.renew_circuit()  # Get new IP{Colors.END}")
    print(f"\n{Colors.BOLD}{Colors.GREEN}You're now ready for anonymous OSINT research!{Colors.END}")
    print(f"{Colors.YELLOW}Warning  Remember: Use Tor responsibly and ethically{Colors.END}\n")


if __name__ == "__main__":
    main()
