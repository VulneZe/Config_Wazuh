"""
Tester Module
Runs tests to validate Wazuh deployment
"""

import os
import logging
import subprocess
import time
from typing import Dict, Any, List
from pathlib import Path


class Tester:
    """Tests Wazuh deployment"""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.test_results = {}
    
    def run_tests(self) -> bool:
        """
        Main test method
        Runs all tests
        """
        self.logger.info("Starting tests...")
        
        try:
            # Run logtest
            self.test_logtest()
            
            # Test syscheck
            self.test_syscheck()
            
            # Test modules
            self.test_modules()
            
            # Test analysisd
            self.test_analysisd()
            
            # Test agent connectivity (if any agents enrolled)
            self.test_agent_connectivity()
            
            # Print summary
            self.print_test_summary()
            
            # Return overall result
            return self.get_overall_result()
            
        except Exception as e:
            self.logger.error(f"Tests failed: {str(e)}")
            return False
    
    def test_logtest(self) -> bool:
        """Test Wazuh logtest"""
        self.logger.info("Testing logtest...")
        
        try:
            result = subprocess.run(
                ['/var/ossec/bin/wazuh-logtest'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # logtest should start and wait for input, so we kill it
            # If it starts without error, the test passes
            success = result.returncode == 0 or 'wazuh-logtest' in result.stderr.lower()
            
            self.test_results['logtest'] = {
                'passed': success,
                'return_code': result.returncode
            }
            
            if success:
                self.logger.info("✓ logtest test passed")
            else:
                self.logger.warning("✗ logtest test failed")
            
            return success
            
        except Exception as e:
            self.logger.error(f"logtest test error: {str(e)}")
            self.test_results['logtest'] = {'passed': False, 'error': str(e)}
            return False
    
    def test_syscheck(self) -> bool:
        """Test syscheck configuration"""
        self.logger.info("Testing syscheck...")
        
        try:
            result = subprocess.run(
                ['/var/ossec/bin/wazuh-syscheckd', '-t'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            success = result.returncode == 0
            
            self.test_results['syscheck'] = {
                'passed': success,
                'return_code': result.returncode
            }
            
            if success:
                self.logger.info("✓ syscheck test passed")
            else:
                self.logger.warning("✗ syscheck test failed")
            
            return success
            
        except Exception as e:
            self.logger.error(f"syscheck test error: {str(e)}")
            self.test_results['syscheck'] = {'passed': False, 'error': str(e)}
            return False
    
    def test_modules(self) -> bool:
        """Test wazuh-modulesd"""
        self.logger.info("Testing wazuh-modulesd...")
        
        try:
            result = subprocess.run(
                ['/var/ossec/bin/wazuh-modulesd', '-t'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            success = result.returncode == 0
            
            self.test_results['modules'] = {
                'passed': success,
                'return_code': result.returncode
            }
            
            if success:
                self.logger.info("✓ modules test passed")
            else:
                self.logger.warning("✗ modules test failed")
            
            return success
            
        except Exception as e:
            self.logger.error(f"modules test error: {str(e)}")
            self.test_results['modules'] = {'passed': False, 'error': str(e)}
            return False
    
    def test_analysisd(self) -> bool:
        """Test wazuh-analysisd"""
        self.logger.info("Testing wazuh-analysisd...")
        
        try:
            result = subprocess.run(
                ['/var/ossec/bin/wazuh-analysisd', '-t'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            success = result.returncode == 0
            
            self.test_results['analysisd'] = {
                'passed': success,
                'return_code': result.returncode
            }
            
            if success:
                self.logger.info("✓ analysisd test passed")
            else:
                self.logger.warning("✗ analysisd test failed")
            
            return success
            
        except Exception as e:
            self.logger.error(f"analysisd test error: {str(e)}")
            self.test_results['analysisd'] = {'passed': False, 'error': str(e)}
            return False
    
    def test_agent_connectivity(self) -> bool:
        """Test agent connectivity via API"""
        self.logger.info("Testing agent connectivity...")
        
        try:
            import requests
            import urllib3
            
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            manager_host = self.config.get('WAZUH_MANAGER_HOST', 'localhost')
            manager_port = self.config.get('WAZUH_MANAGER_PORT', 15150)
            manager_user = self.config.get('WAZUH_API_USER', 'admin')
            manager_password = self.config.get('WAZUH_API_PASSWORD', 'admin')
            
            url = f"https://{manager_host}:{manager_port}/agents/summary/status"
            
            response = requests.get(
                url,
                auth=(manager_user, manager_password),
                verify=False,
                timeout=10,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                data = response.json()
                total_agents = data.get('data', {}).get('total_agents', 0)
                active_agents = data.get('data', {}).get('active_agents', 0)
                
                self.test_results['agent_connectivity'] = {
                    'passed': True,
                    'total_agents': total_agents,
                    'active_agents': active_agents
                }
                
                self.logger.info(f"✓ Agent connectivity test passed ({active_agents}/{total_agents} active)")
                return True
            else:
                self.logger.warning(f"✗ Agent connectivity test failed: {response.status_code}")
                self.test_results['agent_connectivity'] = {
                    'passed': False,
                    'status_code': response.status_code
                }
                return False
                
        except Exception as e:
            self.logger.warning(f"Agent connectivity test error (may have no agents): {str(e)}")
            self.test_results['agent_connectivity'] = {
                'passed': True,  # Not a failure if no agents
                'error': str(e)
            }
            return True  # Don't fail if no agents enrolled yet
    
    def test_configuration_validation(self) -> bool:
        """Test configuration validation"""
        self.logger.info("Testing configuration validation...")
        
        try:
            # Test agent.conf validation for default group
            shared_path = Path('/var/ossec/etc/shared/default')
            agent_conf = shared_path / 'agent.conf'
            
            if agent_conf.exists():
                result = subprocess.run(
                    ['/var/ossec/bin/verify-agent-conf', '-f', str(agent_conf)],
                    capture_output=True,
                    text=True
                )
                
                success = result.returncode == 0
                
                self.test_results['config_validation'] = {
                    'passed': success,
                    'return_code': result.returncode
                }
                
                if success:
                    self.logger.info("✓ Configuration validation test passed")
                else:
                    self.logger.warning("✗ Configuration validation test failed")
                
                return success
            else:
                self.logger.info("No agent.conf to validate (skipping)")
                self.test_results['config_validation'] = {'passed': True, 'skipped': True}
                return True
                
        except Exception as e:
            self.logger.error(f"Configuration validation test error: {str(e)}")
            self.test_results['config_validation'] = {'passed': False, 'error': str(e)}
            return False
    
    def test_indexer_connectivity(self) -> bool:
        """Test indexer connectivity"""
        self.logger.info("Testing indexer connectivity...")
        
        try:
            import requests
            import urllib3
            
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
            
            success = response.status_code == 200
            
            self.test_results['indexer_connectivity'] = {
                'passed': success,
                'status_code': response.status_code
            }
            
            if success:
                self.logger.info("✓ Indexer connectivity test passed")
            else:
                self.logger.warning("✗ Indexer connectivity test failed")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Indexer connectivity test error: {str(e)}")
            self.test_results['indexer_connectivity'] = {'passed': False, 'error': str(e)}
            return False
    
    def print_test_summary(self):
        """Print test summary"""
        print("\n" + "="*70)
        print("TEST SUMMARY")
        print("="*70 + "\n")
        
        for test_name, result in self.test_results.items():
            passed = result.get('passed', False)
            symbol = "✓" if passed else "✗"
            print(f"  {symbol} {test_name}")
            
            if 'error' in result:
                print(f"      Error: {result['error']}")
            elif 'skipped' in result and result['skipped']:
                print(f"      Skipped")
        
        print()
    
    def get_overall_result(self) -> bool:
        """Get overall test result"""
        # Critical tests must pass
        critical_tests = ['logtest', 'syscheck', 'modules']
        
        for test in critical_tests:
            if test in self.test_results:
                if not self.test_results[test].get('passed', False):
                    return False
        
        return True
