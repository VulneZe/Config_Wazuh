"""
Integrations Configuration Module
Configures cloud/SaaS integrations: Docker, AWS, GCP, GitHub, Office 365, Microsoft Graph
"""

import os
import logging
import yaml
from typing import Dict, Any
from pathlib import Path


class IntegrationsConfig:
    """Configures cloud/SaaS integrations"""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        # Use configurable paths from config
        paths = config.get('paths', {})
        self.wazuh_config_path = Path(paths.get('wazuh_config', '/var/ossec/etc'))
        self.wodles_path = Path(paths.get('wodles_dir', '/var/ossec/etc/wodles'))
        self.project_dir = Path(__file__).parent.parent
        self.templates_dir = self.project_dir / "templates"
    
    def configure_integrations(self) -> bool:
        """
        Main configuration method
        Configures enabled cloud/SaaS integrations
        """
        self.logger.info("Starting cloud/SaaS integrations configuration...")
        
        try:
            # Create wodles directory if it doesn't exist
            self.wodles_path.mkdir(parents=True, exist_ok=True)
            
            configured_count = 0
            total_count = 0
            
            # Docker integration
            total_count += 1
            if self.config.get('ENABLE_DOCKER_INTEGRATION', False):
                if self.configure_docker():
                    configured_count += 1
                    self.logger.info("✓ Docker integration configured")
                else:
                    self.logger.error("✗ Docker integration failed")
            else:
                self.logger.info("Docker integration not enabled")
            
            # AWS integration
            total_count += 1
            if self.config.get('ENABLE_AWS_INTEGRATION', False):
                if self.configure_aws():
                    configured_count += 1
                    self.logger.info("✓ AWS integration configured")
                else:
                    self.logger.error("✗ AWS integration failed")
            else:
                self.logger.info("AWS integration not enabled")
            
            # GCP integration
            total_count += 1
            if self.config.get('ENABLE_GCP_INTEGRATION', False):
                if self.configure_gcp():
                    configured_count += 1
                    self.logger.info("✓ GCP integration configured")
                else:
                    self.logger.error("✗ GCP integration failed")
            else:
                self.logger.info("GCP integration not enabled")
            
            # GitHub integration
            total_count += 1
            if self.config.get('ENABLE_GITHUB_INTEGRATION', False):
                if self.configure_github():
                    configured_count += 1
                    self.logger.info("✓ GitHub integration configured")
                else:
                    self.logger.error("✗ GitHub integration failed")
            else:
                self.logger.info("GitHub integration not enabled")
            
            # Office 365 integration
            total_count += 1
            if self.config.get('ENABLE_OFFICE365_INTEGRATION', False):
                if self.configure_office365():
                    configured_count += 1
                    self.logger.info("✓ Office 365 integration configured")
                else:
                    self.logger.error("✗ Office 365 integration failed")
            else:
                self.logger.info("Office 365 integration not enabled")
            
            # Microsoft Graph integration
            total_count += 1
            if self.config.get('ENABLE_MS_GRAPH_INTEGRATION', False):
                if self.configure_ms_graph():
                    configured_count += 1
                    self.logger.info("✓ Microsoft Graph integration configured")
                else:
                    self.logger.error("✗ Microsoft Graph integration failed")
            else:
                self.logger.info("Microsoft Graph integration not enabled")
            
            self.logger.info(f"Configured {configured_count}/{total_count} integrations")
            
            if configured_count == 0:
                self.logger.info("No integrations were enabled")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Integrations configuration failed: {str(e)}")
            return False
    
    def configure_docker(self) -> bool:
        """Configure Docker integration"""
        self.logger.info("Configuring Docker integration...")
        
        try:
            # Docker listener is configured in agent.conf via config_manager
            # This method validates Docker is available
            import subprocess
            
            result = subprocess.run(['docker', '--version'], capture_output=True, text=True)
            if result.returncode == 0:
                self.logger.info(f"Docker detected: {result.stdout.strip()}")
                return True
            else:
                self.logger.error("Docker not found or not accessible")
                return False
                
        except Exception as e:
            self.logger.error(f"Docker configuration failed: {str(e)}")
            return False
    
    def configure_aws(self) -> bool:
        """Configure AWS S3 integration"""
        self.logger.info("Configuring AWS integration...")
        
        try:
            # Check for required credentials
            aws_bucket = self.config.get('AWS_S3_BUCKET', '')
            aws_region = self.config.get('AWS_REGION', '')
            
            if not aws_bucket:
                self.logger.error("AWS_S3_BUCKET not configured")
                return False
            
            # Create AWS wodle configuration
            aws_config = self.generate_aws_config(aws_bucket, aws_region)
            
            # Write to ossec.conf
            ossec_conf = self.wazuh_config_path / 'ossec.conf'
            
            with open(ossec_conf, 'a') as f:
                f.write(aws_config)
            
            self.logger.info("AWS integration configured successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"AWS configuration failed: {str(e)}")
            return False
    
    def generate_aws_config(self, bucket: str, region: str) -> str:
        """Generate AWS S3 wodle configuration"""
        config = f"""<!-- AWS S3 integration -->
<wodle name="aws-s3">
  <disabled>no</disabled>
  <interval>10m</interval>
  <run_on_start>yes</run_on_start>
  <skip_on_error>yes</skip_on_error>
  <bucket type="cloudtrail">
    <name>{bucket}</name>
"""
        if region:
            config += f'    <aws_region>{region}</aws_region>\n'
        
        config += """    <aws_profile>default</aws_profile>
  </bucket>
</wodle>

"""
        return config
    
    def configure_gcp(self) -> bool:
        """Configure GCP Pub/Sub integration"""
        self.logger.info("Configuring GCP integration...")
        
        try:
            # Check for required credentials
            project_id = self.config.get('GCP_PROJECT_ID', '')
            subscription_name = self.config.get('GCP_SUBSCRIPTION_NAME', '')
            credentials_file = self.config.get('GCP_CREDENTIALS_FILE', '')
            
            if not project_id or not subscription_name:
                self.logger.error("GCP_PROJECT_ID or GCP_SUBSCRIPTION_NAME not configured")
                return False
            
            # Create credentials directory
            gcloud_path = self.wodles_path / 'gcloud'
            gcloud_path.mkdir(exist_ok=True)
            
            # Copy credentials file if provided
            if credentials_file and os.path.exists(credentials_file):
                import shutil
                dest_file = gcloud_path / os.path.basename(credentials_file)
                shutil.copy(credentials_file, dest_file)
                credentials_file = dest_file
            
            # Create GCP wodle configuration
            gcp_config = self.generate_gcp_config(project_id, subscription_name, credentials_file)
            
            # Write to ossec.conf
            ossec_conf = self.wazuh_config_path / 'ossec.conf'
            
            with open(ossec_conf, 'a') as f:
                f.write(gcp_config)
            
            self.logger.info("GCP integration configured successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"GCP configuration failed: {str(e)}")
            return False
    
    def generate_gcp_config(self, project_id: str, subscription_name: str, credentials_file: str) -> str:
        """Generate GCP Pub/Sub wodle configuration"""
        config = f"""<!-- GCP Pub/Sub integration -->
<gcp-pubsub>
  <pull_on_start>yes</pull_on_start>
  <interval>1m</interval>
  <project_id>{project_id}</project_id>
  <subscription_name>{subscription_name}</subscription_name>
"""
        if credentials_file:
            config += f'  <credentials_file>/var/ossec/wodles/gcloud/{os.path.basename(credentials_file)}</credentials_file>\n'
        
        config += "</gcp-pubsub>\n\n"
        return config
    
    def configure_github(self) -> bool:
        """Configure GitHub integration"""
        self.logger.info("Configuring GitHub integration...")
        
        try:
            # Check for required credentials
            org_name = self.config.get('GITHUB_ORG_NAME', '')
            api_token = self.config.get('GITHUB_API_TOKEN', '')
            
            if not org_name or not api_token:
                self.logger.error("GITHUB_ORG_NAME or GITHUB_API_TOKEN not configured")
                return False
            
            # Create GitHub wodle configuration
            github_config = self.generate_github_config(org_name, api_token)
            
            # Write to ossec.conf
            ossec_conf = self.wazuh_config_path / 'ossec.conf'
            
            with open(ossec_conf, 'a') as f:
                f.write(github_config)
            
            self.logger.info("GitHub integration configured successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"GitHub configuration failed: {str(e)}")
            return False
    
    def generate_github_config(self, org_name: str, api_token: str) -> str:
        """Generate GitHub wodle configuration"""
        config = f"""<!-- GitHub integration -->
<github>
  <enabled>yes</enabled>
  <interval>1m</interval>
  <time_delay>1m</time_delay>
  <curl_max_size>1M</curl_max_size>
  <only_future_events>yes</only_future_events>
  <api_auth>
    <org_name>{org_name}</org_name>
    <api_token>{api_token}</api_token>
  </api_auth>
  <api_parameters>
    <event_type>all</event_type>
  </api_parameters>
</github>

"""
        return config
    
    def configure_office365(self) -> bool:
        """Configure Office 365 integration"""
        self.logger.info("Configuring Office 365 integration...")
        
        try:
            # Check for required credentials
            tenant_id = self.config.get('O365_TENANT_ID', '')
            client_id = self.config.get('O365_CLIENT_ID', '')
            client_secret = self.config.get('O365_CLIENT_SECRET', '')
            
            if not tenant_id or not client_id or not client_secret:
                self.logger.error("Office 365 credentials not configured")
                return False
            
            # Create Office 365 wodle configuration
            o365_config = self.generate_office365_config(tenant_id, client_id, client_secret)
            
            # Write to ossec.conf
            ossec_conf = self.wazuh_config_path / 'ossec.conf'
            
            with open(ossec_conf, 'a') as f:
                f.write(o365_config)
            
            self.logger.info("Office 365 integration configured successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Office 365 configuration failed: {str(e)}")
            return False
    
    def generate_office365_config(self, tenant_id: str, client_id: str, client_secret: str) -> str:
        """Generate Office 365 wodle configuration"""
        config = f"""<!-- Office 365 integration -->
<office365>
  <enabled>yes</enabled>
  <interval>1m</interval>
  <curl_max_size>1M</curl_max_size>
  <only_future_events>yes</only_future_events>
  <api_auth>
    <tenant_id>{tenant_id}</tenant_id>
    <client_id>{client_id}</client_id>
    <client_secret>{client_secret}</client_secret>
    <api_type>commercial</api_type>
  </api_auth>
  <subscriptions>
    <subscription>Audit.AzureActiveDirectory</subscription>
    <subscription>Audit.General</subscription>
  </subscriptions>
</office365>

"""
        return config
    
    def configure_ms_graph(self) -> bool:
        """Configure Microsoft Graph integration"""
        self.logger.info("Configuring Microsoft Graph integration...")
        
        try:
            # Check for required credentials
            tenant_id = self.config.get('MS_GRAPH_TENANT_ID', '')
            client_id = self.config.get('MS_GRAPH_CLIENT_ID', '')
            secret_value = self.config.get('MS_GRAPH_SECRET_VALUE', '')
            
            if not tenant_id or not client_id or not secret_value:
                self.logger.error("Microsoft Graph credentials not configured")
                return False
            
            # Create Microsoft Graph wodle configuration
            graph_config = self.generate_ms_graph_config(tenant_id, client_id, secret_value)
            
            # Write to ossec.conf
            ossec_conf = self.wazuh_config_path / 'ossec.conf'
            
            with open(ossec_conf, 'a') as f:
                f.write(graph_config)
            
            self.logger.info("Microsoft Graph integration configured successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Microsoft Graph configuration failed: {str(e)}")
            return False
    
    def generate_ms_graph_config(self, tenant_id: str, client_id: str, secret_value: str) -> str:
        """Generate Microsoft Graph wodle configuration"""
        config = f"""<!-- Microsoft Graph integration -->
<ms-graph>
  <enabled>yes</enabled>
  <only_future_events>yes</only_future_events>
  <curl_max_size>10M</curl_max_size>
  <run_on_start>yes</run_on_start>
  <interval>5m</interval>
  <version>v1.0</version>
  <api_auth>
    <client_id>{client_id}</client_id>
    <tenant_id>{tenant_id}</tenant_id>
    <secret_value>{secret_value}</secret_value>
    <api_type>global</api_type>
  </api_auth>
  <resource>
    <name>security</name>
    <relationship>alerts_v2</relationship>
    <relationship>incidents</relationship>
  </resource>
  <resource>
    <name>auditLogs</name>
    <relationship>signIns</relationship>
  </resource>
  <resource>
    <name>deviceManagement</name>
    <relationship>auditEvents</relationship>
  </resource>
  <resource>
    <name>identityProtection</name>
    <relationship>riskDetections</relationship>
  </resource>
</ms-graph>

"""
        return config
