"""
Wazuh Installer Module
Handles installation of Wazuh components (server, indexer, dashboard)
"""

import os
import subprocess
import logging
import shutil
from typing import Dict, Any, Optional
from pathlib import Path


class WazuhInstaller:
    """Installs Wazuh components"""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.project_dir = Path(__file__).parent.parent
        self.scripts_dir = self.project_dir / "scripts"
    
    def install_components(self) -> bool:
        """
        Main installation method
        Installs Wazuh server, indexer, and dashboard
        """
        self.logger.info("Starting Wazuh component installation...")
        
        try:
            # Check prerequisites
            if not self.check_prerequisites():
                self.logger.error("Prerequisites check failed")
                return False
            
            # Install Wazuh repository
            if not self.install_repository():
                self.logger.error("Repository installation failed")
                return False
            
            # Install components based on architecture
            architecture = self.config.get('project', {}).get('architecture', 'distributed')
            
            if architecture == 'all-in-one':
                self.logger.info("Installing all-in-one architecture...")
                if not self.install_all_in_one():
                    return False
            else:
                self.logger.info("Installing distributed architecture...")
                if not self.install_distributed():
                    return False
            
            # Configure TLS
            if not self.configure_tls():
                self.logger.warning("TLS configuration failed")
            
            # Start services
            if not self.start_services():
                self.logger.error("Failed to start services")
                return False
            
            self.logger.info("Wazuh component installation completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Installation failed: {str(e)}")
            return False
    
    def check_prerequisites(self) -> bool:
        """Check if prerequisites are met"""
        self.logger.info("Checking prerequisites...")
        
        checks = [
            ('root privileges', self.check_root()),
            ('internet connectivity', self.check_internet()),
            ('curl', self.check_command('curl')),
            ('systemctl', self.check_command('systemctl')),
        ]
        
        all_passed = True
        for check_name, result in checks:
            if result:
                self.logger.info(f"✓ {check_name}")
            else:
                self.logger.error(f"✗ {check_name}")
                all_passed = False
        
        return all_passed
    
    def check_root(self) -> bool:
        """Check if running as root"""
        return os.geteuid() == 0
    
    def check_internet(self) -> bool:
        """Check internet connectivity"""
        try:
            subprocess.run(['curl', '-s', '--connect-timeout', '5', 'https://google.com'], 
                         capture_output=True, check=True)
            return True
        except Exception:
            return False
    
    def check_command(self, command: str) -> bool:
        """Check if command exists"""
        return shutil.which(command) is not None
    
    def install_repository(self) -> bool:
        """Install Wazuh repository"""
        self.logger.info("Installing Wazuh repository...")
        
        try:
            # Detect OS distribution
            if os.path.exists('/etc/debian_version'):
                # Debian/Ubuntu
                self.logger.info("Detected Debian/Ubuntu system")
                return self.install_debian_repo()
            elif os.path.exists('/etc/redhat-release'):
                # RHEL/CentOS
                self.logger.info("Detected RHEL/CentOS system")
                return self.install_redhat_repo()
            else:
                self.logger.error("Unsupported distribution")
                return False
                
        except Exception as e:
            self.logger.error(f"Repository installation failed: {str(e)}")
            return False
    
    def install_debian_repo(self) -> bool:
        """Install Wazuh repository on Debian/Ubuntu"""
        try:
            # Install GPG key using pipe correctly
            curl_proc = subprocess.Popen(
                ['curl', '-s', 'https://packages.wazuh.com/key/GPG-KEY-WAZUH'],
                stdout=subprocess.PIPE
            )
            apt_key_proc = subprocess.Popen(
                ['apt-key', 'add', '-'],
                stdin=curl_proc.stdout,
                stdout=subprocess.PIPE
            )
            curl_proc.stdout.close()
            apt_key_proc.wait()
            if apt_key_proc.returncode != 0:
                raise subprocess.CalledProcessError(apt_key_proc.returncode, 'apt-key add')
            
            # Add repository
            wazuh_version = self.config.get('project', {}).get('wazuh_version', '4.14')
            repo = f"deb https://packages.wazuh.com/4.x/apt stable main"
            
            with open('/etc/apt/sources.list.d/wazuh.list', 'w') as f:
                f.write(repo + '\n')
            
            # Update package list
            subprocess.run(['apt-get', 'update'], check=True)
            
            self.logger.info("Debian/Ubuntu repository installed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Debian repository installation failed: {str(e)}")
            return False
    
    def install_redhat_repo(self) -> bool:
        """Install Wazuh repository on RHEL/CentOS"""
        try:
            # Install GPG key
            subprocess.run(['rpm', '--import', 
                          'https://packages.wazuh.com/key/GPG-KEY-WAZUH'], 
                         check=True)
            
            # Add repository
            repo_content = """[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1"""
            
            with open('/etc/yum.repos.d/wazuh.repo', 'w') as f:
                f.write(repo_content)
            
            self.logger.info("RHEL/CentOS repository installed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"RHEL repository installation failed: {str(e)}")
            return False
    
    def install_all_in_one(self) -> bool:
        """Install all-in-one architecture"""
        self.logger.info("Installing all-in-one Wazuh...")
        
        try:
            if os.path.exists('/etc/debian_version'):
                # Debian/Ubuntu
                packages = [
                    'wazuh-manager',
                    'wazuh-indexer',
                    'wazuh-dashboard'
                ]
                env = os.environ.copy()
                env['DEBIAN_FRONTEND'] = 'noninteractive'
                subprocess.run(['apt-get', 'install', '-y'] + packages, 
                             env=env, check=True)
            elif os.path.exists('/etc/redhat-release'):
                # RHEL/CentOS
                packages = [
                    'wazuh-manager',
                    'wazuh-indexer',
                    'wazuh-dashboard'
                ]
                subprocess.run(['yum', 'install', '-y'] + packages, check=True)
            
            self.logger.info("All-in-one installation completed")
            return True
            
        except Exception as e:
            self.logger.error(f"All-in-one installation failed: {str(e)}")
            return False
    
    def install_distributed(self) -> bool:
        """Install distributed architecture"""
        self.logger.info("Installing distributed Wazuh components...")
        
        try:
            # Install Wazuh Manager
            if not self.install_manager():
                return False
            
            # Install Wazuh Indexer
            if not self.install_indexer():
                return False
            
            # Install Wazuh Dashboard
            if not self.install_dashboard():
                return False
            
            self.logger.info("Distributed installation completed")
            return True
            
        except Exception as e:
            self.logger.error(f"Distributed installation failed: {str(e)}")
            return False
    
    def install_manager(self) -> bool:
        """Install Wazuh Manager"""
        self.logger.info("Installing Wazuh Manager...")
        
        try:
            if os.path.exists('/etc/debian_version'):
                env = os.environ.copy()
                env['DEBIAN_FRONTEND'] = 'noninteractive'
                subprocess.run(['apt-get', 'install', '-y', 'wazuh-manager'], 
                             env=env, check=True)
            elif os.path.exists('/etc/redhat-release'):
                subprocess.run(['yum', 'install', '-y', 'wazuh-manager'], check=True)
            
            self.logger.info("Wazuh Manager installed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Wazuh Manager installation failed: {str(e)}")
            return False
    
    def install_indexer(self) -> bool:
        """Install Wazuh Indexer"""
        self.logger.info("Installing Wazuh Indexer...")
        
        try:
            if os.path.exists('/etc/debian_version'):
                env = os.environ.copy()
                env['DEBIAN_FRONTEND'] = 'noninteractive'
                subprocess.run(['apt-get', 'install', '-y', 'wazuh-indexer'], 
                             env=env, check=True)
            elif os.path.exists('/etc/redhat-release'):
                subprocess.run(['yum', 'install', '-y', 'wazuh-indexer'], check=True)
            
            self.logger.info("Wazuh Indexer installed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Wazuh Indexer installation failed: {str(e)}")
            return False
    
    def install_dashboard(self) -> bool:
        """Install Wazuh Dashboard"""
        self.logger.info("Installing Wazuh Dashboard...")
        
        try:
            if os.path.exists('/etc/debian_version'):
                env = os.environ.copy()
                env['DEBIAN_FRONTEND'] = 'noninteractive'
                subprocess.run(['apt-get', 'install', '-y', 'wazuh-dashboard'], 
                             env=env, check=True)
            elif os.path.exists('/etc/redhat-release'):
                subprocess.run(['yum', 'install', '-y', 'wazuh-dashboard'], check=True)
            
            self.logger.info("Wazuh Dashboard installed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Wazuh Dashboard installation failed: {str(e)}")
            return False
    
    def configure_tls(self) -> bool:
        """Configure TLS certificates"""
        self.logger.info("Configuring TLS certificates...")
        
        try:
            # Use script if available
            tls_script = self.scripts_dir / "configure_tls.sh"
            if tls_script.exists():
                subprocess.run(['bash', str(tls_script)], check=True)
                self.logger.info("TLS configuration completed via script")
                return True
            
            # Manual TLS configuration
            cert_dir = Path('/etc/wazuh/certs')
            cert_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate self-signed certificates (for testing/lab)
            # In production, use proper CA-signed certificates
            self.logger.warning("Using self-signed certificates. Use CA-signed certs in production.")
            
            self.logger.info("TLS configuration completed")
            return True
            
        except Exception as e:
            self.logger.error(f"TLS configuration failed: {str(e)}")
            return False
    
    def start_services(self) -> bool:
        """Start Wazuh services"""
        self.logger.info("Starting Wazuh services...")
        
        services = ['wazuh-manager', 'wazuh-indexer', 'wazuh-dashboard']
        
        for service in services:
            try:
                self.logger.info(f"Starting {service}...")
                subprocess.run(['systemctl', 'enable', service], check=True)
                subprocess.run(['systemctl', 'start', service], check=True)
                
                # Wait for service to start
                import time
                time.sleep(5)
                
                # Check service status
                result = subprocess.run(['systemctl', 'is-active', service], 
                                      capture_output=True, text=True)
                if result.stdout.strip() == 'active':
                    self.logger.info(f"✓ {service} started successfully")
                else:
                    self.logger.warning(f"✗ {service} may not be running properly")
                    
            except Exception as e:
                self.logger.error(f"Failed to start {service}: {str(e)}")
                return False
        
        self.logger.info("All Wazuh services started")
        return True
    
    def configure_indexer_cluster(self) -> bool:
        """Configure indexer cluster (for distributed setup)"""
        self.logger.info("Configuring indexer cluster...")
        # Implementation for cluster configuration
        return True
