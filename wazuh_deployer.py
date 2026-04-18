#!/usr/bin/env python3
"""
Wazuh Deployer - Main Entry Point
Interactive assistant for complete Wazuh configuration and deployment
"""

import os
import sys
import yaml
import logging
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
import colorama
from colorama import Fore, Style, Back
import jsonschema

# Initialize colorama for cross-platform colored output
colorama.init()

# Add modules to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import modules
from modules.environment_detector import EnvironmentDetector
from modules.installer import WazuhInstaller
from modules.config_manager import ConfigManager
from modules.technical_base import TechnicalBaseConfig
from modules.dashboard_config import DashboardConfig
from modules.integrations import IntegrationsConfig
from modules.verifier import Verifier
from modules.tester import Tester
from modules.auto_corrector import AutoCorrector
from modules.production import ProductionManager


class WazuhDeployer:
    """Main Wazuh Deployer class - Interactive assistant"""
    
    def __init__(self):
        self.project_dir = Path(__file__).parent
        self.config_dir = self.project_dir / "config"
        self.logs_dir = self.project_dir / "logs"
        self.reports_dir = self.project_dir / "reports"
        
        # Check Python version
        self.check_python_version()
        
        # Check and install dependencies
        self.check_dependencies()
        
        # Create necessary directories
        self.logs_dir.mkdir(exist_ok=True)
        self.reports_dir.mkdir(exist_ok=True)
        
        # Setup logging
        self.setup_logging()
        
        # Load configuration
        self.config = self.load_config()
        
        # Initialize modules
        self.env_detector = EnvironmentDetector(self.config, self.logger)
        self.installer = WazuhInstaller(self.config, self.logger)
        self.config_manager = ConfigManager(self.config, self.logger)
        self.technical_base = TechnicalBaseConfig(self.config, self.logger)
        self.dashboard_config = DashboardConfig(self.config, self.logger)
        self.integrations = IntegrationsConfig(self.config, self.logger)
        self.verifier = Verifier(self.config, self.logger)
        self.tester = Tester(self.config, self.logger)
        self.auto_corrector = AutoCorrector(self.config, self.logger)
        self.production = ProductionManager(self.config, self.logger)
        
        # Deployment state
        self.deployment_state = {
            'phase': 'init',
            'environment_detected': False,
            'components_installed': False,
            'agents_configured': False,
            'technical_base_configured': False,
            'dashboard_configured': False,
            'integrations_configured': False,
            'verified': False,
            'tested': False,
            'production_ready': False
        }
    
    def setup_logging(self):
        """Setup logging configuration"""
        log_file = self.logs_dir / f"wazuh_deployer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        self.logger = logging.getLogger('WazuhDeployer')
        self.logger.info(f"Wazuh Deployer initialized. Log file: {log_file}")
    
    def validate_yaml_file(self, yaml_file: Path, schema: Optional[Dict] = None) -> bool:
        """Validate a YAML file against a schema"""
        try:
            if not yaml_file.exists():
                self.logger.error(f"YAML file not found: {yaml_file}")
                return False
            
            with open(yaml_file, 'r') as f:
                data = yaml.safe_load(f)
            
            if schema:
                jsonschema.validate(instance=data, schema=schema)
                self.logger.info(f"YAML file validated against schema: {yaml_file}")
            else:
                self.logger.info(f"YAML file loaded successfully: {yaml_file}")
            
            return True
        except yaml.YAMLError as e:
            self.logger.error(f"YAML parsing error in {yaml_file}: {str(e)}")
            return False
        except jsonschema.ValidationError as e:
            self.logger.error(f"YAML validation error in {yaml_file}: {str(e)}")
            return False
        except Exception as e:
            self.logger.error(f"Error validating {yaml_file}: {str(e)}")
            return False
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML files"""
        config = {}
        
        # Load main config
        config_file = self.config_dir / "config.yaml"
        if config_file.exists():
            if self.validate_yaml_file(config_file):
                with open(config_file, 'r') as f:
                    config.update(yaml.safe_load(f))
                self.logger.info(f"Loaded configuration from {config_file}")
            else:
                self.logger.error(f"Failed to validate configuration file: {config_file}")
        else:
            self.logger.warning(f"Configuration file not found: {config_file}")
        
        # Load agent groups config
        agent_groups_file = self.config_dir / "agent_groups.yaml"
        if agent_groups_file.exists():
            if self.validate_yaml_file(agent_groups_file):
                with open(agent_groups_file, 'r') as f:
                    config['agent_groups'] = yaml.safe_load(f)
                self.logger.info(f"Loaded agent groups from {agent_groups_file}")
            else:
                self.logger.error(f"Failed to validate agent groups file: {agent_groups_file}")
        
        return config
    
    def check_python_version(self):
        """Check if Python version is compatible (3.7+)"""
        min_version = (3, 7)
        current_version = sys.version_info[:2]
        
        if current_version < min_version:
            print(f"{Fore.RED}Error: Python {min_version[0]}.{min_version[1]}+ is required. Current version: {current_version[0]}.{current_version[1]}{Style.RESET_ALL}")
            sys.exit(1)
    
    def check_dependencies(self):
        """Check if required Python packages are installed, offer to install if missing"""
        required_packages = [
            'yaml',  # PyYAML
            'dotenv',  # python-dotenv
            'requests',
            'paramiko',
            'colorama',
            'psutil',
            'distro',
            'jsonschema',
        ]
        
        missing_packages = []
        
        for package in required_packages:
            try:
                __import__(package)
            except ImportError:
                missing_packages.append(package)
        
        if missing_packages:
            print(f"{Fore.YELLOW}Warning: Missing Python packages: {', '.join(missing_packages)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Attempting to install missing packages...{Style.RESET_ALL}")
            
            try:
                # Map package names to pip install names
                pip_names = {
                    'yaml': 'PyYAML',
                    'dotenv': 'python-dotenv',
                }
                
                packages_to_install = [pip_names.get(pkg, pkg) for pkg in missing_packages]
                subprocess.run([sys.executable, '-m', 'pip', 'install'] + packages_to_install, check=True)
                print(f"{Fore.GREEN}Successfully installed missing packages.{Style.RESET_ALL}")
            except subprocess.CalledProcessError as e:
                print(f"{Fore.RED}Error installing packages: {e}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Please run: pip install -r requirements.txt{Style.RESET_ALL}")
                sys.exit(1)

    
    def print_header(self):
        """Print welcome header"""
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{' '*20}WAZUH DEPLOYER v1.0{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{' '*15}Configuration & Deployment Assistant{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    
    def print_menu(self):
        """Print main menu"""
        print(f"{Fore.YELLOW}Main Menu - Select an option:{Style.RESET_ALL}\n")
        print(f"  {Fore.GREEN}1{Style.RESET_ALL}. Full Deployment (Complete installation and configuration)")
        print(f"  {Fore.GREEN}2{Style.RESET_ALL}. Partial Configuration (Configure specific components)")
        print(f"  {Fore.GREEN}3{Style.RESET_ALL}. Environment Detection Only")
        print(f"  {Fore.GREEN}4{Style.RESET_ALL}. Verification & Audit")
        print(f"  {Fore.GREEN}5{Style.RESET_ALL}. Run Tests")
        print(f"  {Fore.GREEN}6{Style.RESET_ALL}. Production Checklist")
        print(f"  {Fore.GREEN}7{Style.RESET_ALL}. View Current Status")
        print(f"  {Fore.GREEN}8{Style.RESET_ALL}. Auto-Correction")
        print(f"  {Fore.GREEN}9{Style.RESET_ALL}. Generate Report")
        print(f"  {Fore.RED}0{Style.RESET_ALL}. Exit\n")
    
    def get_user_choice(self, min_choice: int = 0, max_choice: int = 9) -> int:
        """Get user choice with validation"""
        while True:
            try:
                choice = input(f"{Fore.CYAN}Enter your choice [{min_choice}-{max_choice}]: {Style.RESET_ALL}")
                choice = int(choice)
                if min_choice <= choice <= max_choice:
                    return choice
                else:
                    print(f"{Fore.RED}Invalid choice. Please enter a number between {min_choice} and {max_choice}.{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}Invalid input. Please enter a number.{Style.RESET_ALL}")
    
    def confirm_action(self, message: str) -> bool:
        """Ask user for confirmation"""
        while True:
            response = input(f"{Fore.YELLOW}{message} (y/n): {Style.RESET_ALL}").lower()
            if response in ['y', 'yes']:
                return True
            elif response in ['n', 'no']:
                return False
            else:
                print(f"{Fore.RED}Please enter 'y' or 'n'.{Style.RESET_ALL}")
    
    def get_free_input(self, prompt: str, default: str = "") -> str:
        """Get free text input from user"""
        if default:
            prompt = f"{prompt} [{default}]: "
        else:
            prompt = f"{prompt}: "
        
        response = input(f"{Fore.CYAN}{prompt}{Style.RESET_ALL}").strip()
        return response if response else default
    
    def print_status(self):
        """Print current deployment status"""
        print(f"\n{Fore.CYAN}Current Deployment Status:{Style.RESET_ALL}\n")
        
        status_items = [
            ("Environment Detected", self.deployment_state['environment_detected']),
            ("Components Installed", self.deployment_state['components_installed']),
            ("Agents Configured", self.deployment_state['agents_configured']),
            ("Technical Base Configured", self.deployment_state['technical_base_configured']),
            ("Dashboard Configured", self.deployment_state['dashboard_configured']),
            ("Integrations Configured", self.deployment_state['integrations_configured']),
            ("Verified", self.deployment_state['verified']),
            ("Tested", self.deployment_state['tested']),
            ("Production Ready", self.deployment_state['production_ready'])
        ]
        
        for item, status in status_items:
            status_symbol = f"{Fore.GREEN}✓{Style.RESET_ALL}" if status else f"{Fore.RED}✗{Style.RESET_ALL}"
            print(f"  {status_symbol} {item}")
        
        print()
    
    def run_full_deployment(self):
        """Run complete deployment process"""
        print(f"\n{Fore.YELLOW}Starting Full Deployment Process...{Style.RESET_ALL}\n")
        
        if not self.confirm_action("This will perform a complete Wazuh deployment. Continue?"):
            print(f"{Fore.RED}Deployment cancelled.{Style.RESET_ALL}")
            return
        
        # Phase 0: Environment Detection
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Phase 0: Environment Detection{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        env_info = self.env_detector.detect_environment()
        if env_info:
            self.deployment_state['environment_detected'] = True
            print(f"{Fore.GREEN}Environment detection completed successfully.{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.RED}Environment detection failed. Aborting deployment.{Style.RESET_ALL}")
            return
        
        if not self.confirm_action("Continue with Phase 1 (Platform Installation)?"):
            return
        
        # Phase 1: Platform Installation
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Phase 1: Platform Installation{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        if self.installer.install_components():
            self.deployment_state['components_installed'] = True
            print(f"{Fore.GREEN}Platform installation completed successfully.{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.RED}Platform installation failed.{Style.RESET_ALL}")
            if not self.confirm_action("Continue with remaining phases?"):
                return
        
        if not self.confirm_action("Continue with Phase 2 (Agent Configuration)?"):
            return
        
        # Phase 2: Agent Configuration
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Phase 2: Agent Configuration{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        if self.config_manager.configure_agents():
            self.deployment_state['agents_configured'] = True
            print(f"{Fore.GREEN}Agent configuration completed successfully.{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.RED}Agent configuration failed.{Style.RESET_ALL}")
        
        if not self.confirm_action("Continue with Phase 3 (Technical Base)?"):
            return
        
        # Phase 3: Technical Base Configuration
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Phase 3: Technical Base Configuration{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        if self.technical_base.configure_technical_base():
            self.deployment_state['technical_base_configured'] = True
            print(f"{Fore.GREEN}Technical base configuration completed successfully.{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.RED}Technical base configuration failed.{Style.RESET_ALL}")
        
        if not self.confirm_action("Continue with Phase 4 (Dashboard Configuration)?"):
            return
        
        # Phase 4: Dashboard Configuration
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Phase 4: Dashboard Configuration{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        if self.dashboard_config.configure_dashboard():
            self.deployment_state['dashboard_configured'] = True
            print(f"{Fore.GREEN}Dashboard configuration completed successfully.{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.RED}Dashboard configuration failed.{Style.RESET_ALL}")
        
        if not self.confirm_action("Continue with Phase 5 (Integrations)?"):
            return
        
        # Phase 5: Integrations Configuration
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Phase 5: Cloud/SaaS Integrations{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        if self.integrations.configure_integrations():
            self.deployment_state['integrations_configured'] = True
            print(f"{Fore.GREEN}Integrations configuration completed successfully.{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.RED}Integrations configuration failed or skipped.{Style.RESET_ALL}")
        
        # Verification
        if not self.confirm_action("Run verification and audit?"):
            return
        
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Verification & Audit{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        if self.verifier.run_verification():
            self.deployment_state['verified'] = True
            print(f"{Fore.GREEN}Verification completed successfully.{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.RED}Verification found issues.{Style.RESET_ALL}")
        
        # Tests
        if not self.confirm_action("Run tests?"):
            return
        
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Running Tests{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        if self.tester.run_tests():
            self.deployment_state['tested'] = True
            print(f"{Fore.GREEN}Tests completed successfully.{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.RED}Some tests failed.{Style.RESET_ALL}")
        
        # Production Checklist
        if not self.confirm_action("Run production checklist?"):
            return
        
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Production Checklist{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        if self.production.run_production_checklist():
            self.deployment_state['production_ready'] = True
            print(f"{Fore.GREEN}Production checklist completed successfully.{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.RED}Production checklist found issues.{Style.RESET_ALL}")
        
        # Final summary
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Deployment Summary{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        self.print_status()
    
    def run_partial_configuration(self):
        """Run partial configuration process"""
        print(f"\n{Fore.YELLOW}Partial Configuration Mode{Style.RESET_ALL}\n")
        
        print("Select components to configure:\n")
        print("  1. Agent Groups & Configuration")
        print("  2. Technical Base (SCA, FIM, Logs)")
        print("  3. Dashboard (Data Views, Dashboards)")
        print("  4. Cloud/SaaS Integrations")
        print("  5. Custom Rules & Decoders")
        print("  6. All of the above")
        print("  0. Back to main menu\n")
        
        choice = self.get_user_choice(0, 6)
        
        if choice == 0:
            return
        elif choice == 1:
            if self.config_manager.configure_agents():
                self.deployment_state['agents_configured'] = True
        elif choice == 2:
            if self.technical_base.configure_technical_base():
                self.deployment_state['technical_base_configured'] = True
        elif choice == 3:
            if self.dashboard_config.configure_dashboard():
                self.deployment_state['dashboard_configured'] = True
        elif choice == 4:
            if self.integrations.configure_integrations():
                self.deployment_state['integrations_configured'] = True
        elif choice == 5:
            print(f"{Fore.YELLOW}Custom rules configuration - Feature coming soon{Style.RESET_ALL}")
        elif choice == 6:
            self.config_manager.configure_agents()
            self.technical_base.configure_technical_base()
            self.dashboard_config.configure_dashboard()
            self.integrations.configure_integrations()
    
    def run_environment_detection(self):
        """Run environment detection only"""
        print(f"\n{Fore.YELLOW}Environment Detection{Style.RESET_ALL}\n")
        
        env_info = self.env_detector.detect_environment()
        if env_info:
            self.deployment_state['environment_detected'] = True
            print(f"\n{Fore.GREEN}Environment detection completed successfully.{Style.RESET_ALL}\n")
        else:
            print(f"\n{Fore.RED}Environment detection failed.{Style.RESET_ALL}\n")
    
    def run_verification(self):
        """Run verification and audit"""
        print(f"\n{Fore.YELLOW}Verification & Audit{Style.RESET_ALL}\n")
        
        if self.verifier.run_verification():
            self.deployment_state['verified'] = True
            print(f"\n{Fore.GREEN}Verification completed successfully.{Style.RESET_ALL}\n")
        else:
            print(f"\n{Fore.RED}Verification found issues.{Style.RESET_ALL}\n")
    
    def run_tests(self):
        """Run tests"""
        print(f"\n{Fore.YELLOW}Running Tests{Style.RESET_ALL}\n")
        
        if self.tester.run_tests():
            self.deployment_state['tested'] = True
            print(f"\n{Fore.GREEN}Tests completed successfully.{Style.RESET_ALL}\n")
        else:
            print(f"\n{Fore.RED}Some tests failed.{Style.RESET_ALL}\n")
    
    def run_production_checklist(self):
        """Run production checklist"""
        print(f"\n{Fore.YELLOW}Production Checklist{Style.RESET_ALL}\n")
        
        if self.production.run_production_checklist():
            self.deployment_state['production_ready'] = True
            print(f"\n{Fore.GREEN}Production checklist completed successfully.{Style.RESET_ALL}\n")
        else:
            print(f"\n{Fore.RED}Production checklist found issues.{Style.RESET_ALL}\n")
    
    def run_auto_correction(self):
        """Run auto-correction"""
        print(f"\n{Fore.YELLOW}Auto-Correction{Style.RESET_ALL}\n")
        
        if not self.confirm_action("This will attempt to automatically fix detected issues. Continue?"):
            return
        
        if self.auto_corrector.run_auto_correction():
            print(f"\n{Fore.GREEN}Auto-correction completed successfully.{Style.RESET_ALL}\n")
        else:
            print(f"\n{Fore.RED}Auto-correction encountered issues.{Style.RESET_ALL}\n")
    
    def generate_report(self):
        """Generate deployment report"""
        print(f"\n{Fore.YELLOW}Generating Report{Style.RESET_ALL}\n")
        
        report_file = self.reports_dir / f"deployment_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(report_file, 'w') as f:
            f.write("Wazuh Deployment Report\n")
            f.write("=" * 70 + "\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("Deployment Status:\n")
            f.write("-" * 70 + "\n")
            for key, value in self.deployment_state.items():
                status = "✓" if value else "✗"
                f.write(f"  {status} {key}: {value}\n")
            
            f.write("\nConfiguration Summary:\n")
            f.write("-" * 70 + "\n")
            f.write(yaml.dump(self.config, default_flow_style=False))
        
        print(f"{Fore.GREEN}Report generated: {report_file}{Style.RESET_ALL}\n")
    
    def run(self):
        """Main run loop"""
        self.print_header()
        
        while True:
            self.print_menu()
            choice = self.get_user_choice()
            
            if choice == 0:
                print(f"\n{Fore.YELLOW}Thank you for using Wazuh Deployer. Goodbye!{Style.RESET_ALL}\n")
                break
            elif choice == 1:
                self.run_full_deployment()
            elif choice == 2:
                self.run_partial_configuration()
            elif choice == 3:
                self.run_environment_detection()
            elif choice == 4:
                self.run_verification()
            elif choice == 5:
                self.run_tests()
            elif choice == 6:
                self.run_production_checklist()
            elif choice == 7:
                self.print_status()
            elif choice == 8:
                self.run_auto_correction()
            elif choice == 9:
                self.generate_report()
            
            input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")


def main():
    """Main entry point"""
    try:
        deployer = WazuhDeployer()
        deployer.run()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Deployment interrupted by user.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == "__main__":
    main()
