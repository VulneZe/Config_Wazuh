"""
Test Suite for Wazuh Deployer
Runs basic validation tests
"""

import sys
import os
import unittest
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestConfigurationFiles(unittest.TestCase):
    """Test configuration files"""
    
    def setUp(self):
        self.config_dir = Path(__file__).parent.parent / 'config'
    
    def test_config_yaml_exists(self):
        """Test that config.yaml exists"""
        config_file = self.config_dir / 'config.yaml'
        self.assertTrue(config_file.exists(), "config.yaml should exist")
    
    def test_agent_groups_yaml_exists(self):
        """Test that agent_groups.yaml exists"""
        agent_groups_file = self.config_dir / 'agent_groups.yaml'
        self.assertTrue(agent_groups_file.exists(), "agent_groups.yaml should exist")


class TestModules(unittest.TestCase):
    """Test Python modules"""
    
    def test_environment_detector_import(self):
        """Test that environment_detector can be imported"""
        try:
            from modules.environment_detector import EnvironmentDetector
            self.assertIsNotNone(EnvironmentDetector)
        except ImportError as e:
            self.fail(f"Failed to import environment_detector: {e}")
    
    def test_installer_import(self):
        """Test that installer can be imported"""
        try:
            from modules.installer import WazuhInstaller
            self.assertIsNotNone(WazuhInstaller)
        except ImportError as e:
            self.fail(f"Failed to import installer: {e}")
    
    def test_config_manager_import(self):
        """Test that config_manager can be imported"""
        try:
            from modules.config_manager import ConfigManager
            self.assertIsNotNone(ConfigManager)
        except ImportError as e:
            self.fail(f"Failed to import config_manager: {e}")
    
    def test_verifier_import(self):
        """Test that verifier can be imported"""
        try:
            from modules.verifier import Verifier
            self.assertIsNotNone(Verifier)
        except ImportError as e:
            self.fail(f"Failed to import verifier: {e}")


class TestTemplates(unittest.TestCase):
    """Test template files"""
    
    def setUp(self):
        self.templates_dir = Path(__file__).parent.parent / 'templates'
    
    def test_agent_default_conf_exists(self):
        """Test that agent_default.conf exists"""
        template_file = self.templates_dir / 'agent_default.conf'
        self.assertTrue(template_file.exists(), "agent_default.conf should exist")
    
    def test_agent_linux_servers_conf_exists(self):
        """Test that agent_linux_servers.conf exists"""
        template_file = self.templates_dir / 'agent_linux_servers.conf'
        self.assertTrue(template_file.exists(), "agent_linux_servers.conf should exist")
    
    def test_local_rules_xml_exists(self):
        """Test that local_rules.xml exists"""
        template_file = self.templates_dir / 'local_rules.xml'
        self.assertTrue(template_file.exists(), "local_rules.xml should exist")


class TestScripts(unittest.TestCase):
    """Test Bash scripts"""
    
    def setUp(self):
        self.scripts_dir = Path(__file__).parent.parent / 'scripts'
    
    def test_install_wazuh_sh_exists(self):
        """Test that install_wazuh.sh exists"""
        script_file = self.scripts_dir / 'install_wazuh.sh'
        self.assertTrue(script_file.exists(), "install_wazuh.sh should exist")
    
    def test_configure_tls_sh_exists(self):
        """Test that configure_tls.sh exists"""
        script_file = self.scripts_dir / 'configure_tls.sh'
        self.assertTrue(script_file.exists(), "configure_tls.sh should exist")
    
    def test_verify_services_sh_exists(self):
        """Test that verify_services.sh exists"""
        script_file = self.scripts_dir / 'verify_services.sh'
        self.assertTrue(script_file.exists(), "verify_services.sh should exist")


class TestMainScript(unittest.TestCase):
    """Test main script"""
    
    def test_wazuh_deployer_py_exists(self):
        """Test that wazuh_deployer.py exists"""
        main_script = Path(__file__).parent.parent / 'wazuh_deployer.py'
        self.assertTrue(main_script.exists(), "wazuh_deployer.py should exist")


def run_tests():
    """Run all tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test cases
    suite.addTests(loader.loadTestsFromTestCase(TestConfigurationFiles))
    suite.addTests(loader.loadTestsFromTestCase(TestModules))
    suite.addTests(loader.loadTestsFromTestCase(TestTemplates))
    suite.addTests(loader.loadTestsFromTestCase(TestScripts))
    suite.addTests(loader.loadTestsFromTestCase(TestMainScript))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Return exit code
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
