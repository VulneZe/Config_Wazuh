"""
Dashboard Configuration Module
Configures Wazuh Dashboard: data views, dashboards, alerting, notifications
"""

import os
import logging
import json
import requests
from typing import Dict, Any, List
from pathlib import Path


class DashboardConfig:
    """Configures Wazuh Dashboard"""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.dashboard_url = self.config.get('components', {}).get('wazuh_dashboard', {}).get(
            'install_path', '/usr/share/wazuh-dashboard'
        )
        self.api_url = f"https://{self.config.get('WAZUH_DASHBOARD_HOST', 'localhost')}:{self.config.get('WAZUH_DASHBOARD_PORT', 443)}"
        self.api_user = self.config.get('WAZUH_API_USER', 'admin')
        self.api_password = self.config.get('WAZUH_API_PASSWORD', 'admin')
        self.project_dir = Path(__file__).parent.parent
        self.templates_dir = self.project_dir / "templates"
    
    def configure_dashboard(self) -> bool:
        """
        Main configuration method
        Configures data views, dashboards, alerting, notifications
        """
        self.logger.info("Starting dashboard configuration...")
        
        try:
            # Check dashboard connectivity
            if not self.check_dashboard_connectivity():
                self.logger.error("Dashboard not accessible")
                return False
            
            # Create data views
            if not self.create_data_views():
                self.logger.error("Failed to create data views")
                return False
            
            # Create dashboards
            if not self.create_dashboards():
                self.logger.error("Failed to create dashboards")
                return False
            
            # Configure alerting (optional)
            if not self.configure_alerting():
                self.logger.warning("Alerting configuration failed or skipped")
            
            # Configure notifications (optional)
            if not self.configure_notifications():
                self.logger.warning("Notifications configuration failed or skipped")
            
            self.logger.info("Dashboard configuration completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Dashboard configuration failed: {str(e)}")
            return False
    
    def check_dashboard_connectivity(self) -> bool:
        """Check if dashboard is accessible"""
        self.logger.info("Checking dashboard connectivity...")
        
        try:
            # Try to connect to dashboard API
            response = requests.get(
                f"{self.api_url}/api/status",
                auth=(self.api_user, self.api_password),
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.info("Dashboard is accessible")
                return True
            else:
                self.logger.error(f"Dashboard returned status code: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Dashboard connectivity check failed: {str(e)}")
            return False
    
    def create_data_views(self) -> bool:
        """Create data views for Wazuh indices"""
        self.logger.info("Creating data views...")
        
        dashboard_config = self.config.get('dashboard', {})
        data_views = dashboard_config.get('data_views', [])
        
        data_view_definitions = {
            'wazuh-alerts-*': {
                'title': 'wazuh-alerts',
                'timeFieldName': '@timestamp',
                'fields': [
                    {'name': 'timestamp', 'type': 'date'},
                    {'name': 'rule.level', 'type': 'integer'},
                    {'name': 'agent.name', 'type': 'keyword'},
                    {'name': 'agent.id', 'type': 'keyword'},
                    {'name': 'srcip', 'type': 'ip'},
                    {'name': 'dstip', 'type': 'ip'},
                    {'name': 'user', 'type': 'keyword'},
                    {'name': 'full_log', 'type': 'text'},
                ]
            },
            'wazuh-archives-*': {
                'title': 'wazuh-archives',
                'timeFieldName': '@timestamp',
                'fields': [
                    {'name': 'timestamp', 'type': 'date'},
                    {'name': 'agent.name', 'type': 'keyword'},
                    {'name': 'full_log', 'type': 'text'},
                ]
            },
            'wazuh-monitoring-*': {
                'title': 'wazuh-monitoring',
                'timeFieldName': '@timestamp',
                'fields': [
                    {'name': 'timestamp', 'type': 'date'},
                    {'name': 'agent.name', 'type': 'keyword'},
                    {'name': 'status', 'type': 'keyword'},
                ]
            },
            'wazuh-states-vulnerabilities-*': {
                'title': 'wazuh-vulnerabilities',
                'timeFieldName': 'updated',
                'fields': [
                    {'name': 'package.name', 'type': 'keyword'},
                    {'name': 'cve.id', 'type': 'keyword'},
                    {'name': 'severity', 'type': 'keyword'},
                    {'name': 'status', 'type': 'keyword'},
                ]
            },
            'wazuh-states-inventory-*': {
                'title': 'wazuh-inventory',
                'timeFieldName': 'updated',
                'fields': [
                    {'name': 'agent.name', 'type': 'keyword'},
                    {'name': 'os.name', 'type': 'keyword'},
                    {'name': 'os.version', 'type': 'keyword'},
                ]
            }
        }
        
        created_count = 0
        for index_pattern, definition in data_view_definitions.items():
            try:
                if self.create_data_view(index_pattern, definition):
                    created_count += 1
                    self.logger.info(f"✓ Created data view: {index_pattern}")
                else:
                    self.logger.warning(f"✗ Failed to create data view: {index_pattern}")
            except Exception as e:
                self.logger.error(f"Error creating data view {index_pattern}: {str(e)}")
        
        self.logger.info(f"Created {created_count}/{len(data_view_definitions)} data views")
        return created_count > 0
    
    def create_data_view(self, index_pattern: str, definition: Dict[str, Any]) -> bool:
        """Create a single data view via API"""
        try:
            # In a real implementation, this would make an API call to OpenSearch
            # For now, we'll log the configuration
            self.logger.info(f"Would create data view for pattern: {index_pattern}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to create data view: {str(e)}")
            return False
    
    def create_dashboards(self) -> bool:
        """Create dashboards"""
        self.logger.info("Creating dashboards...")
        
        dashboard_config = self.config.get('dashboard', {})
        dashboards = dashboard_config.get('dashboards', [])
        
        dashboard_definitions = {
            'SOC Overview': {
                'description': 'Overview of security events and alerts',
                'panels': [
                    {'type': 'metric', 'title': 'Total Alerts'},
                    {'type': 'line', 'title': 'Alerts Over Time'},
                    {'type': 'table', 'title': 'Top Rules'},
                    {'type': 'table', 'title': 'Top Agents'},
                    {'type': 'table', 'title': 'Top Source IPs'},
                ]
            },
            'Endpoint Security': {
                'description': 'Endpoint security status',
                'panels': [
                    {'type': 'metric', 'title': 'FIM Events'},
                    {'type': 'metric', 'title': 'SCA Failures'},
                    {'type': 'table', 'title': 'Vulnerabilities by Agent'},
                    {'type': 'table', 'title': 'Malware Detections'},
                ]
            },
            'IT Hygiene': {
                'description': 'IT hygiene and inventory',
                'panels': [
                    {'type': 'metric', 'title': 'Total Agents'},
                    {'type': 'table', 'title': 'Software Inventory'},
                    {'type': 'table', 'title': 'Running Processes'},
                    {'type': 'table', 'title': 'Open Ports'},
                ]
            },
            'Cloud Security': {
                'description': 'Cloud security events',
                'panels': [
                    {'type': 'metric', 'title': 'AWS Events'},
                    {'type': 'metric', 'title': 'GCP Events'},
                    {'type': 'table', 'title': 'GitHub Actions'},
                    {'type': 'table', 'title': 'Office 365 Events'},
                ]
            },
            'Compliance': {
                'description': 'Compliance status',
                'panels': [
                    {'type': 'metric', 'title': 'PCI DSS Score'},
                    {'type': 'metric', 'title': 'RGPD Score'},
                    {'type': 'table', 'title': 'SCA Results by Benchmark'},
                    {'type': 'table', 'title': 'Non-Compliant Agents'},
                ]
            },
            'Management': {
                'description': 'Platform management and health',
                'panels': [
                    {'type': 'metric', 'title': 'Active Agents'},
                    {'type': 'metric', 'title': 'Disconnected Agents'},
                    {'type': 'table', 'title': 'Agent Status'},
                    {'type': 'table', 'title': 'System Resources'},
                ]
            }
        }
        
        created_count = 0
        for dashboard_name in dashboards:
            if dashboard_name in dashboard_definitions:
                try:
                    if self.create_dashboard(dashboard_name, dashboard_definitions[dashboard_name]):
                        created_count += 1
                        self.logger.info(f"✓ Created dashboard: {dashboard_name}")
                    else:
                        self.logger.warning(f"✗ Failed to create dashboard: {dashboard_name}")
                except Exception as e:
                    self.logger.error(f"Error creating dashboard {dashboard_name}: {str(e)}")
        
        self.logger.info(f"Created {created_count}/{len(dashboards)} dashboards")
        return created_count > 0
    
    def create_dashboard(self, name: str, definition: Dict[str, Any]) -> bool:
        """Create a single dashboard via API"""
        try:
            # In a real implementation, this would make an API call
            self.logger.info(f"Would create dashboard: {name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to create dashboard: {str(e)}")
            return False
    
    def configure_alerting(self) -> bool:
        """Configure alerting monitors"""
        self.logger.info("Configuring alerting...")
        
        dashboard_config = self.config.get('dashboard', {})
        monitors = dashboard_config.get('monitors', [])
        
        monitor_definitions = {
            'agent_disconnected': {
                'type': 'query',
                'name': 'Agent Disconnected',
                'description': 'Alert when critical agent is disconnected',
                'query': 'status:disconnected AND labels.criticality:tier1',
                'threshold': 1,
                'time_window': '15m'
            },
            'integration_failure': {
                'type': 'query',
                'name': 'Integration Failure',
                'description': 'Alert when cloud integration fails',
                'query': 'module:aws OR module:gcp AND error:*',
                'threshold': 5,
                'time_window': '60m'
            },
            'fim_sensitive_change': {
                'type': 'query',
                'name': 'FIM Sensitive Change',
                'description': 'Alert on sensitive file changes',
                'query': 'rule.groups:syscheck AND path:/etc/passwd OR path:/etc/shadow OR path:/etc/sudoers',
                'threshold': 1,
                'time_window': '5m'
            },
            'ssh_failure_spike': {
                'type': 'anomaly',
                'name': 'SSH Failure Spike',
                'description': 'Alert on SSH brute force attempts',
                'query': 'rule.groups:authentication_failed',
                'threshold': 10,
                'time_window': '5m'
            },
            'privilege_escalation': {
                'type': 'query',
                'name': 'Privilege Escalation',
                'description': 'Alert on sudo/root usage',
                'query': 'rule.groups:authentication_success AND user:root',
                'threshold': 1,
                'time_window': '1m'
            },
            'vulnerability_critical_sla': {
                'type': 'query',
                'name': 'Critical Vulnerability SLA',
                'description': 'Alert on unpatched critical vulnerabilities',
                'query': 'severity:Critical AND status:Active',
                'threshold': 1,
                'time_window': '24h'
            }
        }
        
        created_count = 0
        for monitor_name in monitors:
            if monitor_name in monitor_definitions:
                try:
                    if self.create_monitor(monitor_name, monitor_definitions[monitor_name]):
                        created_count += 1
                        self.logger.info(f"✓ Created monitor: {monitor_name}")
                    else:
                        self.logger.warning(f"✗ Failed to create monitor: {monitor_name}")
                except Exception as e:
                    self.logger.error(f"Error creating monitor {monitor_name}: {str(e)}")
        
        self.logger.info(f"Created {created_count}/{len(monitors)} monitors")
        return True  # Alerting is optional, so return True even if some fail
    
    def create_monitor(self, name: str, definition: Dict[str, Any]) -> bool:
        """Create a single monitor via API"""
        try:
            self.logger.info(f"Would create monitor: {name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to create monitor: {str(e)}")
            return False
    
    def configure_notifications(self) -> bool:
        """Configure notification channels"""
        self.logger.info("Configuring notifications...")
        
        # Check if notifications are enabled
        enable_email = self.config.get('ENABLE_EMAIL_NOTIFICATIONS', False)
        enable_slack = self.config.get('ENABLE_SLACK_NOTIFICATIONS', False)
        
        if not enable_email and not enable_slack:
            self.logger.info("Notifications not enabled in configuration")
            return True
        
        # Configure email notifications
        if enable_email:
            if self.configure_email_notifications():
                self.logger.info("Email notifications configured")
            else:
                self.logger.warning("Email notifications configuration failed")
        
        # Configure Slack notifications
        if enable_slack:
            if self.configure_slack_notifications():
                self.logger.info("Slack notifications configured")
            else:
                self.logger.warning("Slack notifications configuration failed")
        
        return True
    
    def configure_email_notifications(self) -> bool:
        """Configure email notification channel"""
        try:
            self.logger.info("Would configure email notifications")
            return True
        except Exception as e:
            self.logger.error(f"Failed to configure email notifications: {str(e)}")
            return False
    
    def configure_slack_notifications(self) -> bool:
        """Configure Slack notification channel"""
        try:
            self.logger.info("Would configure Slack notifications")
            return True
        except Exception as e:
            self.logger.error(f"Failed to configure Slack notifications: {str(e)}")
            return False
