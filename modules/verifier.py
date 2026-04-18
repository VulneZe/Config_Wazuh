"""
Verifier Module
Performs verification and audit of Wazuh deployment
"""

import os
import logging
import subprocess
from typing import Dict, Any, List
from pathlib import Path


class Verifier:
    """Verifies Wazuh deployment"""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        # Use configurable paths from config
        paths = config.get('paths', {})
        self.wazuh_config_path = Path(paths.get('wazuh_config', '/var/ossec/etc'))
        self.verification_results = {}
    
    def run_verification(self) -> bool:
        """
        Main verification method
        Runs all verification checks
        """
        self.logger.info("Starting verification and audit...")
        
        try:
            # Verify services
            self.verify_services()
            
            # Verify configuration files
            self.verify_configuration_files()
            
            # Verify TLS configuration
            self.verify_tls()
            
            # Verify agent groups
            self.verify_agent_groups()
            
            # Verify connectivity
            self.verify_connectivity()
            
            # Verify indexer health
            self.verify_indexer_health()
            
            # Verify dashboard access
            self.verify_dashboard()
            
            # Print summary
            self.print_verification_summary()
            
            # Return overall result
            return self.get_overall_result()
            
        except Exception as e:
            self.logger.error(f"Verification failed: {str(e)}")
            return False
    
    def verify_services(self) -> bool:
        """Verify Wazuh services are running"""
        self.logger.info("Verifying services...")
        
        services = ['wazuh-manager', 'wazuh-indexer', 'wazuh-dashboard']
        results = {}
        
        for service in services:
            try:
                result = subprocess.run(
                    ['systemctl', 'is-active', service],
                    capture_output=True,
                    text=True
                )
                
                is_active = result.stdout.strip() == 'active'
                results[service] = {
                    'status': 'active' if is_active else 'inactive',
                    'enabled': is_active
                }
                
                if is_active:
                    self.logger.info(f"✓ {service} is running")
                else:
                    self.logger.warning(f"✗ {service} is not running")
                    
            except Exception as e:
                results[service] = {
                    'status': 'error',
                    'error': str(e)
                }
                self.logger.error(f"Error checking {service}: {str(e)}")
        
        self.verification_results['services'] = results
        return all(r.get('status') == 'active' for r in results.values())
    
    def verify_configuration_files(self) -> bool:
        """Verify configuration files exist and are valid"""
        self.logger.info("Verifying configuration files...")
        
        config_files = {
            'ossec.conf': self.wazuh_config_path / 'ossec.conf',
            'local_rules.xml': self.wazuh_config_path / 'rules' / 'local_rules.xml',
            'local_decoder.xml': self.wazuh_config_path / 'decoders' / 'local_decoder.xml',
        }
        
        results = {}
        all_valid = True
        
        for file_name, file_path in config_files.items():
            exists = file_path.exists()
            readable = False
            
            if exists:
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                    readable = len(content) > 0
                except Exception:
                    readable = False
            
            results[file_name] = {
                'exists': exists,
                'readable': readable,
                'path': str(file_path)
            }
            
            if exists and readable:
                self.logger.info(f"✓ {file_name} exists and is readable")
            else:
                self.logger.warning(f"✗ {file_name} issue (exists: {exists}, readable: {readable})")
                all_valid = False
        
        self.verification_results['configuration_files'] = results
        return all_valid
    
    def verify_tls(self) -> bool:
        """Verify TLS configuration"""
        self.logger.info("Verifying TLS configuration...")
        
        cert_dir = Path('/etc/wazuh/certs')
        
        results = {
            'cert_dir_exists': cert_dir.exists(),
            'cert_files': []
        }
        
        if cert_dir.exists():
            cert_files = ['root-ca.pem', 'manager.pem', 'manager.key', 'indexer.pem', 'indexer.key', 'dashboard.pem', 'dashboard.key']
            
            for cert_file in cert_files:
                file_path = cert_dir / cert_file
                exists = file_path.exists()
                results['cert_files'].append({
                    'name': cert_file,
                    'exists': exists
                })
                
                if exists:
                    self.logger.info(f"✓ TLS certificate: {cert_file}")
                else:
                    self.logger.warning(f"✗ TLS certificate missing: {cert_file}")
        else:
            self.logger.warning("✗ TLS certificate directory does not exist")
        
        self.verification_results['tls'] = results
        return results['cert_dir_exists'] and all(f['exists'] for f in results['cert_files'])
    
    def verify_agent_groups(self) -> bool:
        """Verify agent groups are configured"""
        self.logger.info("Verifying agent groups...")
        
        shared_path = self.wazuh_config_path / 'shared'
        agent_groups = self.config.get('agent_groups', {}).get('groups', {})
        
        results = {}
        configured_count = 0
        
        for group_name in agent_groups.keys():
            group_path = shared_path / group_name
            agent_conf = group_path / 'agent.conf'
            
            exists = group_path.exists()
            has_config = agent_conf.exists()
            
            results[group_name] = {
                'group_exists': exists,
                'config_exists': has_config
            }
            
            if exists and has_config:
                configured_count += 1
                self.logger.info(f"✓ Agent group configured: {group_name}")
            else:
                self.logger.warning(f"✗ Agent group issue: {group_name}")
        
        self.verification_results['agent_groups'] = results
        return configured_count == len(agent_groups)
    
    def verify_connectivity(self) -> bool:
        """Verify network connectivity"""
        self.logger.info("Verifying connectivity...")
        
        results = {}
        
        # Check manager API
        manager_port = self.config.get('WAZUH_MANAGER_PORT', 15150)
        manager_host = self.config.get('WAZUH_MANAGER_HOST', 'localhost')
        results['manager_api'] = self.check_port(manager_host, manager_port)
        
        # Check indexer
        indexer_port = self.config.get('WAZUH_INDEXER_PORT', 9200)
        indexer_host = self.config.get('WAZUH_INDEXER_HOST', 'localhost')
        results['indexer'] = self.check_port(indexer_host, indexer_port)
        
        # Check dashboard
        dashboard_port = self.config.get('WAZUH_DASHBOARD_PORT', 443)
        dashboard_host = self.config.get('WAZUH_DASHBOARD_HOST', 'localhost')
        results['dashboard'] = self.check_port(dashboard_host, dashboard_port)
        
        for service, accessible in results.items():
            if accessible:
                self.logger.info(f"✓ {service} is accessible")
            else:
                self.logger.warning(f"✗ {service} is not accessible")
        
        self.verification_results['connectivity'] = results
        return all(results.values())
    
    def check_port(self, host: str, port: int) -> bool:
        """Check if a port is accessible"""
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def verify_indexer_health(self) -> bool:
        """Verify Wazuh Indexer health"""
        self.logger.info("Verifying indexer health...")
        
        try:
            import requests
            import urllib3
            
            # Disable SSL warnings for self-signed certs
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            indexer_host = self.config.get('WAZUH_INDEXER_HOST', 'localhost')
            indexer_port = self.config.get('WAZUH_INDEXER_PORT', 9200)
            indexer_user = self.config.get('INDEXER_USER', 'admin')
            indexer_password = self.config.get('INDEXER_PASSWORD', 'admin')
            
            url = f"https://{indexer_host}:{indexer_port}/_cluster/health"
            
            response = requests.get(
                url,
                auth=(indexer_user, indexer_password),
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                health = response.json()
                status = health.get('status', 'unknown')
                
                results = {
                    'status': status,
                    'number_of_nodes': health.get('number_of_nodes', 0),
                    'active_shards': health.get('active_shards', 0),
                }
                
                self.verification_results['indexer_health'] = results
                
                if status in ['green', 'yellow']:
                    self.logger.info(f"✓ Indexer health: {status}")
                    return True
                else:
                    self.logger.warning(f"✗ Indexer health: {status}")
                    return False
            else:
                self.logger.error(f"✗ Indexer health check failed: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Indexer health check error: {str(e)}")
            self.verification_results['indexer_health'] = {'error': str(e)}
            return False
    
    def verify_dashboard(self) -> bool:
        """Verify Wazuh Dashboard access"""
        self.logger.info("Verifying dashboard access...")
        
        try:
            import requests
            import urllib3
            
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            dashboard_host = self.config.get('WAZUH_DASHBOARD_HOST', 'localhost')
            dashboard_port = self.config.get('WAZUH_DASHBOARD_PORT', 443)
            dashboard_user = self.config.get('WAZUH_API_USER', 'admin')
            dashboard_password = self.config.get('WAZUH_API_PASSWORD', 'admin')
            
            url = f"https://{dashboard_host}:{dashboard_port}/api/status"
            
            response = requests.get(
                url,
                auth=(dashboard_user, dashboard_password),
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.info("✓ Dashboard is accessible")
                self.verification_results['dashboard'] = {'accessible': True}
                return True
            else:
                self.logger.warning(f"✗ Dashboard returned status: {response.status_code}")
                self.verification_results['dashboard'] = {'accessible': False, 'status': response.status_code}
                return False
                
        except Exception as e:
            self.logger.error(f"Dashboard verification error: {str(e)}")
            self.verification_results['dashboard'] = {'accessible': False, 'error': str(e)}
            return False
    
    def print_verification_summary(self):
        """Print verification summary"""
        print("\n" + "="*70)
        print("VERIFICATION SUMMARY")
        print("="*70 + "\n")
        
        # Services
        if 'services' in self.verification_results:
            print("Services:")
            for service, result in self.verification_results['services'].items():
                status = result.get('status', 'unknown')
                symbol = "✓" if status == 'active' else "✗"
                print(f"  {symbol} {service}: {status}")
            print()
        
        # Configuration files
        if 'configuration_files' in self.verification_results:
            print("Configuration Files:")
            for file_name, result in self.verification_results['configuration_files'].items():
                exists = result.get('exists', False)
                symbol = "✓" if exists else "✗"
                print(f"  {symbol} {file_name}")
            print()
        
        # TLS
        if 'tls' in self.verification_results:
            tls = self.verification_results['tls']
            print("TLS Configuration:")
            print(f"  {'✓' if tls.get('cert_dir_exists') else '✗'} Certificate directory exists")
            for cert in tls.get('cert_files', []):
                symbol = "✓" if cert.get('exists') else "✗"
                print(f"  {symbol} {cert.get('name')}")
            print()
        
        # Agent groups
        if 'agent_groups' in self.verification_results:
            print("Agent Groups:")
            for group, result in self.verification_results['agent_groups'].items():
                configured = result.get('group_exists') and result.get('config_exists')
                symbol = "✓" if configured else "✗"
                print(f"  {symbol} {group}")
            print()
        
        # Connectivity
        if 'connectivity' in self.verification_results:
            print("Connectivity:")
            for service, accessible in self.verification_results['connectivity'].items():
                symbol = "✓" if accessible else "✗"
                print(f"  {symbol} {service}")
            print()
        
        # Indexer health
        if 'indexer_health' in self.verification_results:
            health = self.verification_results['indexer_health']
            if 'status' in health:
                print(f"Indexer Health: {health['status']}")
                print(f"  Nodes: {health.get('number_of_nodes', 0)}")
                print(f"  Active Shards: {health.get('active_shards', 0)}")
            print()
    
    def get_overall_result(self) -> bool:
        """Get overall verification result"""
        # Check critical components
        critical_checks = [
            self.verification_results.get('services', {}),
            self.verification_results.get('configuration_files', {}),
        ]
        
        # All services should be active
        services_ok = all(
            r.get('status') == 'active' 
            for r in self.verification_results.get('services', {}).values()
        )
        
        # All critical config files should exist
        config_ok = all(
            r.get('exists') 
            for r in self.verification_results.get('configuration_files', {}).values()
        )
        
        return services_ok and config_ok
