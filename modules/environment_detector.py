"""
Environment Detector Module
Detects and validates the system environment for Wazuh deployment
"""

import os
import platform
import subprocess
import logging
import psutil
import distro
from typing import Dict, Any, Optional


class EnvironmentDetector:
    """Detects and validates the deployment environment"""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.environment_info = {}
    
    def detect_environment(self) -> Dict[str, Any]:
        """
        Main detection method
        Returns comprehensive environment information
        """
        self.logger.info("Starting environment detection...")
        
        try:
            # Detect OS
            self.environment_info['os'] = self.detect_os()
            
            # Detect hardware resources
            self.environment_info['hardware'] = self.detect_hardware()
            
            # Detect network
            self.environment_info['network'] = self.detect_network()
            
            # Detect installed dependencies
            self.environment_info['dependencies'] = self.detect_dependencies()
            
            # Detect Wazuh components if already installed
            self.environment_info['wazuh_components'] = self.detect_wazuh_components()
            
            # Detect available ports
            self.environment_info['ports'] = self.detect_available_ports()
            
            # Validate environment
            self.environment_info['validation'] = self.validate_environment()
            
            self.print_environment_summary()
            return self.environment_info
            
        except Exception as e:
            self.logger.error(f"Environment detection failed: {str(e)}")
            return {}
    
    def detect_os(self) -> Dict[str, str]:
        """Detect operating system information"""
        self.logger.info("Detecting operating system...")
        
        os_info = {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'hostname': platform.node(),
        }
        
        # Linux distribution specific
        if platform.system() == 'Linux':
            try:
                os_info['distribution'] = distro.name()
                os_info['distribution_version'] = distro.version()
                os_info['distribution_id'] = distro.id()
            except Exception as e:
                self.logger.warning(f"Could not detect Linux distribution: {str(e)}")
        
        self.logger.info(f"OS detected: {os_info.get('distribution', os_info['system'])}")
        return os_info
    
    def detect_hardware(self) -> Dict[str, Any]:
        """Detect hardware resources"""
        self.logger.info("Detecting hardware resources...")
        
        hardware_info = {
            'cpu_count': psutil.cpu_count(logical=True),
            'cpu_physical': psutil.cpu_count(logical=False),
            'memory_total': psutil.virtual_memory().total,
            'memory_available': psutil.virtual_memory().available,
            'memory_used': psutil.virtual_memory().used,
            'memory_percent': psutil.virtual_memory().percent,
            'disk_total': psutil.disk_usage('/').total,
            'disk_used': psutil.disk_usage('/').used,
            'disk_free': psutil.disk_usage('/').free,
            'disk_percent': psutil.disk_usage('/').percent,
        }
        
        # Convert to human readable
        hardware_info['memory_total_gb'] = round(hardware_info['memory_total'] / (1024**3), 2)
        hardware_info['memory_available_gb'] = round(hardware_info['memory_available'] / (1024**3), 2)
        hardware_info['disk_total_gb'] = round(hardware_info['disk_total'] / (1024**3), 2)
        hardware_info['disk_free_gb'] = round(hardware_info['disk_free'] / (1024**3), 2)
        
        self.logger.info(f"Hardware: CPU={hardware_info['cpu_count']}, "
                        f"RAM={hardware_info['memory_total_gb']}GB, "
                        f"Disk={hardware_info['disk_total_gb']}GB")
        
        return hardware_info
    
    def detect_network(self) -> Dict[str, Any]:
        """Detect network configuration"""
        self.logger.info("Detecting network configuration...")
        
        network_info = {}
        
        try:
            # Get network interfaces
            network_info['interfaces'] = []
            for interface, addrs in psutil.net_if_addrs().items():
                interface_info = {'name': interface, 'addresses': []}
                for addr in addrs:
                    interface_info['addresses'].append({
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                    })
                network_info['interfaces'].append(interface_info)
            
            # Get default gateway
            try:
                result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'default' in line:
                            network_info['default_gateway'] = line.split()[2]
                            break
            except Exception as e:
                self.logger.warning(f"Could not detect default gateway: {str(e)}")
            
            # DNS servers
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    dns_servers = [line.split()[1] for line in f if line.startswith('nameserver')]
                    network_info['dns_servers'] = dns_servers
            except Exception as e:
                self.logger.warning(f"Could not read DNS configuration: {str(e)}")
            
            self.logger.info(f"Network: {len(network_info['interfaces'])} interfaces detected")
            
        except Exception as e:
            self.logger.error(f"Network detection failed: {str(e)}")
        
        return network_info
    
    def detect_dependencies(self) -> Dict[str, bool]:
        """Detect installed dependencies"""
        self.logger.info("Detecting dependencies...")
        
        dependencies = {
            'python3': self.check_command('python3'),
            'python': self.check_command('python'),
            'pip3': self.check_command('pip3'),
            'curl': self.check_command('curl'),
            'wget': self.check_command('wget'),
            'openssl': self.check_command('openssl'),
            'systemctl': self.check_command('systemctl'),
            'docker': self.check_command('docker'),
        }
        
        self.logger.info(f"Dependencies: {sum(dependencies.values())}/{len(dependencies)} available")
        return dependencies
    
    def detect_wazuh_components(self) -> Dict[str, Any]:
        """Detect if Wazuh components are already installed"""
        self.logger.info("Detecting Wazuh components...")
        
        components = {
            'wazuh_manager': self.check_wazuh_service('wazuh-manager'),
            'wazuh_indexer': self.check_wazuh_service('wazuh-indexer'),
            'wazuh_dashboard': self.check_wazuh_service('wazuh-dashboard'),
            'wazuh_agent': self.check_wazuh_service('wazuh-agent'),
        }
        
        # Check installation paths
        components['paths'] = {
            'manager': os.path.exists('/var/ossec'),
            'indexer': os.path.exists('/etc/wazuh-indexer'),
            'dashboard': os.path.exists('/usr/share/wazuh-dashboard'),
        }
        
        installed = sum([v for k, v in components.items() if isinstance(v, bool)])
        self.logger.info(f"Wazuh components: {installed} installed")
        
        return components
    
    def detect_available_ports(self) -> Dict[str, bool]:
        """Detect if required ports are available"""
        self.logger.info("Detecting available ports...")
        
        ports = {
            15150: self.check_port(15150),  # Wazuh Manager API
            1514: self.check_port(1514),     # Wazuh Manager
            9200: self.check_port(9200),     # Wazuh Indexer
            443: self.check_port(443),       # Wazuh Dashboard
        }
        
        self.logger.info(f"Port availability: {sum(ports.values())}/{len(ports)} available")
        return ports
    
    def check_command(self, command: str) -> bool:
        """Check if a command is available"""
        try:
            result = subprocess.run(['which', command], capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def check_wazuh_service(self, service_name: str) -> bool:
        """Check if a Wazuh service is installed"""
        try:
            result = subprocess.run(['systemctl', 'status', service_name], 
                                  capture_output=True, text=True)
            # Service exists if returncode is 0 (running/stopped) or 3 (stopped)
            # returncode 4 means service not found
            return result.returncode in [0, 3] or 'could not be found' not in result.stderr
        except Exception:
            return False
    
    def check_port(self, port: int) -> bool:
        """Check if a port is available"""
        try:
            for conn in psutil.net_connections():
                if conn.laddr.port == port:
                    return False
            return True
        except Exception:
            return True
    
    def validate_environment(self) -> Dict[str, Any]:
        """Validate environment against requirements"""
        self.logger.info("Validating environment...")
        
        validation = {
            'os_compatible': False,
            'memory_sufficient': False,
            'disk_sufficient': False,
            'ports_available': False,
            'dependencies_ok': False,
            'overall': False,
        }
        
        # OS compatibility
        os_info = self.environment_info.get('os', {})
        if os_info.get('system') == 'Linux':
            validation['os_compatible'] = True
        
        # Memory check (minimum 4GB for all-in-one)
        hardware = self.environment_info.get('hardware', {})
        if hardware.get('memory_total_gb', 0) >= 4:
            validation['memory_sufficient'] = True
        
        # Disk check (minimum 20GB free)
        if hardware.get('disk_free_gb', 0) >= 20:
            validation['disk_sufficient'] = True
        
        # Ports check
        ports = self.environment_info.get('ports', {})
        if all(ports.values()):
            validation['ports_available'] = True
        
        # Dependencies check
        deps = self.environment_info.get('dependencies', {})
        if deps.get('curl') and deps.get('openssl') and deps.get('systemctl'):
            validation['dependencies_ok'] = True
        
        # Overall validation
        validation['overall'] = all([
            validation['os_compatible'],
            validation['memory_sufficient'],
            validation['disk_sufficient'],
            validation['dependencies_ok']
        ])
        
        self.logger.info(f"Validation result: {'PASS' if validation['overall'] else 'FAIL'}")
        return validation
    
    def print_environment_summary(self):
        """Print environment summary to console"""
        print("\n" + "="*70)
        print("ENVIRONMENT DETECTION SUMMARY")
        print("="*70 + "\n")
        
        # OS
        os_info = self.environment_info.get('os', {})
        print(f"Operating System:")
        print(f"  - System: {os_info.get('system', 'Unknown')}")
        print(f"  - Distribution: {os_info.get('distribution', 'Unknown')}")
        print(f"  - Version: {os_info.get('distribution_version', 'Unknown')}")
        print(f"  - Hostname: {os_info.get('hostname', 'Unknown')}\n")
        
        # Hardware
        hardware = self.environment_info.get('hardware', {})
        print(f"Hardware Resources:")
        print(f"  - CPU: {hardware.get('cpu_physical', 'Unknown')} cores "
              f"({hardware.get('cpu_count', 'Unknown')} threads)")
        print(f"  - RAM: {hardware.get('memory_total_gb', 0)} GB total, "
              f"{hardware.get('memory_available_gb', 0)} GB available")
        print(f"  - Disk: {hardware.get('disk_total_gb', 0)} GB total, "
              f"{hardware.get('disk_free_gb', 0)} GB free\n")
        
        # Dependencies
        deps = self.environment_info.get('dependencies', {})
        print(f"Dependencies:")
        for dep, status in deps.items():
            status_str = "✓" if status else "✗"
            print(f"  - {dep}: {status_str}")
        print()
        
        # Wazuh Components
        wazuh = self.environment_info.get('wazuh_components', {})
        print(f"Wazuh Components:")
        for comp, status in wazuh.items():
            if isinstance(status, bool):
                status_str = "✓ Installed" if status else "✗ Not installed"
                print(f"  - {comp}: {status_str}")
        print()
        
        # Validation
        validation = self.environment_info.get('validation', {})
        print(f"Validation:")
        overall = validation.get('overall', False)
        print(f"  - Overall: {'✓ PASS' if overall else '✗ FAIL'}")
        for check, status in validation.items():
            if check != 'overall':
                status_str = "✓" if status else "✗"
                print(f"  - {check}: {status_str}")
        print()
