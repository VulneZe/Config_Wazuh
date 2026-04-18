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
        """Print environment summary to console with recommendations"""
        print("\n" + "="*70)
        print("ENVIRONMENT DETECTION SUMMARY")
        print("="*70 + "\n")
        
        # OS
        os_info = self.environment_info.get('os', {})
        print(f"{Fore.CYAN}Operating System:{Style.RESET_ALL}")
        print(f"  - System: {os_info.get('system', 'Unknown')}")
        print(f"  - Distribution: {os_info.get('distribution', 'Unknown')}")
        print(f"  - Version: {os_info.get('distribution_version', 'Unknown')}")
        print(f"  - Hostname: {os_info.get('hostname', 'Unknown')}")
        print(f"  - Architecture: {os_info.get('machine', 'Unknown')}")
        print()
        
        # Hardware
        hardware = self.environment_info.get('hardware', {})
        print(f"{Fore.CYAN}Hardware Resources:{Style.RESET_ALL}")
        print(f"  - CPU: {hardware.get('cpu_physical', 'Unknown')} cores "
              f"({hardware.get('cpu_count', 'Unknown')} threads)")
        print(f"  - RAM: {hardware.get('memory_total_gb', 0)} GB total, "
              f"{hardware.get('memory_available_gb', 0)} GB available ({hardware.get('memory_percent', 0)}% used)")
        print(f"  - Disk: {hardware.get('disk_total_gb', 0)} GB total, "
              f"{hardware.get('disk_free_gb', 0)} GB free ({hardware.get('disk_percent', 0)}% used)")
        print()
        
        # Hardware recommendations
        self.print_hardware_recommendations(hardware)
        
        # Network
        network = self.environment_info.get('network', {})
        print(f"{Fore.CYAN}Network Configuration:{Style.RESET_ALL}")
        interfaces = network.get('interfaces', [])
        print(f"  - Interfaces: {len(interfaces)} detected")
        for interface in interfaces[:3]:  # Show first 3 interfaces
            print(f"    - {interface['name']}")
            for addr in interface['addresses'][:2]:  # Show first 2 addresses
                print(f"      {addr['family']}: {addr['address']}")
        if len(interfaces) > 3:
            print(f"    ... and {len(interfaces) - 3} more")
        
        if 'default_gateway' in network:
            print(f"  - Default Gateway: {network['default_gateway']}")
        
        if 'dns_servers' in network:
            print(f"  - DNS Servers: {', '.join(network['dns_servers'][:3])}")
        print()
        
        # Dependencies
        deps = self.environment_info.get('dependencies', {})
        print(f"{Fore.CYAN}Dependencies:{Style.RESET_ALL}")
        for dep, status in deps.items():
            status_str = f"{Fore.GREEN}✓{Style.RESET_ALL}" if status else f"{Fore.RED}✗{Style.RESET_ALL}"
            print(f"  - {dep}: {status_str}")
        print()
        
        # Wazuh Components
        wazuh = self.environment_info.get('wazuh_components', {})
        print(f"{Fore.CYAN}Wazuh Components:{Style.RESET_ALL}")
        for comp, status in wazuh.items():
            if isinstance(status, bool):
                status_str = f"{Fore.GREEN}✓ Installed{Style.RESET_ALL}" if status else f"{Fore.RED}✗ Not installed{Style.RESET_ALL}"
                print(f"  - {comp}: {status_str}")
        
        paths = wazuh.get('paths', {})
        if paths:
            print(f"\n  Installation Paths:")
            for comp, exists in paths.items():
                status_str = f"{Fore.GREEN}✓{Style.RESET_ALL}" if exists else f"{Fore.RED}✗{Style.RESET_ALL}"
                print(f"    - {comp}: {status_str}")
        print()
        
        # Wazuh recommendations
        self.print_wazuh_recommendations(wazuh)
        
        # Ports
        ports = self.environment_info.get('ports', {})
        print(f"{Fore.CYAN}Port Availability:{Style.RESET_ALL}")
        port_names = {
            15150: "Wazuh Manager API",
            1514: "Wazuh Manager",
            9200: "Wazuh Indexer",
            443: "Wazuh Dashboard"
        }
        for port, available in ports.items():
            status_str = f"{Fore.GREEN}Available{Style.RESET_ALL}" if available else f"{Fore.RED}In use{Style.RESET_ALL}"
            print(f"  - {port_names.get(port, f'Port {port}')}: {status_str}")
        print()
        
        # Validation
        validation = self.environment_info.get('validation', {})
        print(f"{Fore.CYAN}Validation:{Style.RESET_ALL}")
        overall = validation.get('overall', False)
        overall_str = f"{Fore.GREEN}✓ PASS{Style.RESET_ALL}" if overall else f"{Fore.RED}✗ FAIL{Style.RESET_ALL}"
        print(f"  - Overall: {overall_str}")
        for check, status in validation.items():
            if check != 'overall':
                status_str = f"{Fore.GREEN}✓{Style.RESET_ALL}" if status else f"{Fore.RED}✗{Style.RESET_ALL}"
                print(f"  - {check}: {status_str}")
        print()
        
        # Overall recommendations
        self.print_overall_recommendations(validation)
    
    def print_hardware_recommendations(self, hardware: Dict[str, Any]):
        """Print hardware-specific recommendations"""
        print(f"{Fore.YELLOW}Hardware Recommendations:{Style.RESET_ALL}")
        
        # CPU recommendations
        cpu_cores = hardware.get('cpu_physical', 0)
        if cpu_cores < 2:
            print(f"  {Fore.RED}⚠{Style.RESET_ALL} CPU: Minimum 2 cores required for all-in-one, 8+ recommended for production")
        elif cpu_cores < 8:
            print(f"  {Fore.YELLOW}⚠{Style.RESET_ALL} CPU: 8+ cores recommended for production deployment")
        else:
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} CPU: Sufficient for production")
        
        # RAM recommendations
        ram_gb = hardware.get('memory_total_gb', 0)
        if ram_gb < 4:
            print(f"  {Fore.RED}⚠{Style.RESET_ALL} RAM: Minimum 4GB required for all-in-one")
        elif ram_gb < 8:
            print(f"  {Fore.YELLOW}⚠{Style.RESET_ALL} RAM: 8-16GB recommended for all-in-one, 32GB+ for distributed")
        elif ram_gb < 32:
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} RAM: Sufficient for all-in-one, consider 32GB+ for distributed")
        else:
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} RAM: Excellent for production")
        
        # Disk recommendations
        disk_free_gb = hardware.get('disk_free_gb', 0)
        if disk_free_gb < 20:
            print(f"  {Fore.RED}⚠{Style.RESET_ALL} Disk: Minimum 20GB free space required")
        elif disk_free_gb < 50:
            print(f"  {Fore.YELLOW}⚠{Style.RESET_ALL} Disk: 50GB+ recommended for production logs")
        else:
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} Disk: Sufficient space available")
        print()
    
    def print_wazuh_recommendations(self, wazuh: Dict[str, Any]):
        """Print Wazuh-specific recommendations"""
        print(f"{Fore.YELLOW}Wazuh Deployment Recommendations:{Style.RESET_ALL}")
        
        installed_count = sum([v for k, v in wazuh.items() if isinstance(v, bool)])
        
        if installed_count == 0:
            print(f"  {Fore.YELLOW}ℹ{Style.RESET_ALL} No Wazuh components detected")
            print(f"  {Fore.CYAN}→{Style.RESET_ALL} Recommend: Full deployment (all-in-one architecture)")
        elif installed_count == 3:
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} All Wazuh components installed")
            print(f"  {Fore.CYAN}→{Style.RESET_ALL} Recommend: Configuration update only")
        else:
            print(f"  {Fore.YELLOW}⚠{Style.RESET_ALL} Partial Wazuh installation detected ({installed_count}/3 components)")
            print(f"  {Fore.CYAN}→{Style.RESET_ALL} Recommend: Complete installation or reconfigure existing")
        
        print()
    
    def print_overall_recommendations(self, validation: Dict[str, Any]):
        """Print overall deployment recommendations"""
        print(f"{Fore.YELLOW}Overall Deployment Recommendations:{Style.RESET_ALL}")
        
        if validation.get('overall'):
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} Environment is suitable for Wazuh deployment")
            print(f"  {Fore.CYAN}→{Style.RESET_ALL} You can proceed with full deployment")
        else:
            print(f"  {Fore.RED}⚠{Style.RESET_ALL} Environment has issues that need attention")
            
            if not validation.get('os_compatible'):
                print(f"  {Fore.RED}✗{Style.RESET_ALL} OS not compatible - Linux required")
            
            if not validation.get('memory_sufficient'):
                print(f"  {Fore.RED}✗{Style.RESET_ALL} Insufficient memory - minimum 4GB required")
            
            if not validation.get('disk_sufficient'):
                print(f"  {Fore.RED}✗{Style.RESET_ALL} Insufficient disk space - minimum 20GB required")
            
            if not validation.get('dependencies_ok'):
                print(f"  {Fore.RED}✗{Style.RESET_ALL} Missing dependencies - install curl, openssl, systemctl")
            
            print(f"  {Fore.CYAN}→{Style.RESET_ALL} Address the issues above before proceeding")
        
        print()
