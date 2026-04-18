"""
Technical Base Configuration Module
Configures the technical base: SCA, FIM, logs, active response
"""

import os
import logging
import yaml
from typing import Dict, Any
from pathlib import Path


class TechnicalBaseConfig:
    """Configures technical base components"""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        # Use configurable paths from config
        paths = config.get('paths', {})
        self.wazuh_config_path = Path(paths.get('wazuh_config', '/var/ossec/etc'))
        self.project_dir = Path(__file__).parent.parent
        self.templates_dir = self.project_dir / "templates"
    
    def configure_technical_base(self) -> bool:
        """
        Main configuration method
        Configures syscollector, vulnerability detection, SCA, FIM, logs, active response
        """
        self.logger.info("Starting technical base configuration...")
        
        try:
            # Configure syscollector
            if not self.configure_syscollector():
                self.logger.error("Syscollector configuration failed")
                return False
            
            # Configure vulnerability detection
            if not self.configure_vulnerability_detection():
                self.logger.error("Vulnerability detection configuration failed")
                return False
            
            # Configure SCA
            if not self.configure_sca():
                self.logger.error("SCA configuration failed")
                return False
            
            # Configure FIM
            if not self.configure_fim():
                self.logger.error("FIM configuration failed")
                return False
            
            # Configure log collection
            if not self.configure_log_collection():
                self.logger.error("Log collection configuration failed")
                return False
            
            # Configure active response
            if not self.configure_active_response():
                self.logger.error("Active response configuration failed")
                return False
            
            self.logger.info("Technical base configuration completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Technical base configuration failed: {str(e)}")
            return False
    
    def configure_syscollector(self) -> bool:
        """Configure syscollector in ossec.conf"""
        self.logger.info("Configuring syscollector...")
        
        try:
            ossec_conf = self.wazuh_config_path / 'ossec.conf'
            
            # Check if file exists
            if not ossec_conf.exists():
                self.logger.error("ossec.conf not found")
                return False
            
            # Read current configuration
            with open(ossec_conf, 'r') as f:
                current_config = f.read()
            
            # Check if syscollector is already configured
            if '<wodle name="syscollector">' in current_config:
                self.logger.info("Syscollector already configured")
                return True
            
            # Generate syscollector configuration
            syscollector_config = self.generate_syscollector_config()
            
            # Append to ossec.conf
            with open(ossec_conf, 'a') as f:
                f.write(syscollector_config)
            
            self.logger.info("Syscollector configured successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Syscollector configuration failed: {str(e)}")
            return False
    
    def generate_syscollector_config(self) -> str:
        """Generate syscollector configuration"""
        tech_base = self.config.get('technical_base', {})
        syscollector = tech_base.get('syscollector', {})
        
        config = """<!-- Syscollector configuration -->
<wodle name="syscollector">
  <disabled>no</disabled>
"""
        if syscollector.get('interval'):
            config += f'  <interval>{syscollector["interval"]}</interval>\n'
        else:
            config += '  <interval>1h</interval>\n'
        
        if syscollector.get('scan_on_start'):
            config += '  <scan_on_start>yes</scan_on_start>\n'
        
        if syscollector.get('hardware'):
            config += '  <hardware>yes</hardware>\n'
        
        if syscollector.get('os'):
            config += '  <os>yes</os>\n'
        
        if syscollector.get('network'):
            config += '  <network>yes</network>\n'
        
        if syscollector.get('packages'):
            config += '  <packages>yes</packages>\n'
        
        ports_all = syscollector.get('ports_all', False)
        config += f'  <ports all="{"yes" if ports_all else "no"}">yes</ports>\n'
        
        if syscollector.get('processes'):
            config += '  <processes>yes</processes>\n'
        
        if syscollector.get('users'):
            config += '  <users>yes</users>\n'
        
        if syscollector.get('groups'):
            config += '  <groups>yes</groups>\n'
        
        if syscollector.get('services'):
            config += '  <services>yes</services>\n'
        
        if syscollector.get('browser_extensions'):
            config += '  <browser_extensions>yes</browser_extensions>\n'
        
        config += """  <synchronization>
    <max_eps>10</max_eps>
  </synchronization>
</wodle>

"""
        return config
    
    def configure_vulnerability_detection(self) -> bool:
        """Configure vulnerability detection"""
        self.logger.info("Configuring vulnerability detection...")
        
        try:
            ossec_conf = self.wazuh_config_path / 'ossec.conf'
            
            with open(ossec_conf, 'r') as f:
                current_config = f.read()
            
            if '<vulnerability-detection>' in current_config:
                self.logger.info("Vulnerability detection already configured")
                return True
            
            vuln_config = self.generate_vulnerability_config()
            
            with open(ossec_conf, 'a') as f:
                f.write(vuln_config)
            
            self.logger.info("Vulnerability detection configured successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Vulnerability detection configuration failed: {str(e)}")
            return False
    
    def generate_vulnerability_config(self) -> str:
        """Generate vulnerability detection configuration"""
        tech_base = self.config.get('technical_base', {})
        vuln = tech_base.get('vulnerability_detection', {})
        
        config = """<!-- Vulnerability detection configuration -->
<vulnerability-detection>
  <enabled>yes</enabled>
"""
        if vuln.get('index_status'):
            config += '  <index-status>yes</index-status>\n'
        
        if vuln.get('feed_update_interval'):
            config += f'  <feed-update-interval>{vuln["feed_update_interval"]}</feed-update-interval>\n'
        else:
            config += '  <feed-update-interval>60m</feed-update-interval>\n'
        
        config += "</vulnerability-detection>\n\n"
        return config
    
    def configure_sca(self) -> bool:
        """Configure Security Configuration Assessment"""
        self.logger.info("Configuring SCA...")
        
        try:
            ossec_conf = self.wazuh_config_path / 'ossec.conf'
            
            with open(ossec_conf, 'r') as f:
                current_config = f.read()
            
            if '<sca>' in current_config:
                self.logger.info("SCA already configured")
                return True
            
            sca_config = self.generate_sca_config()
            
            with open(ossec_conf, 'a') as f:
                f.write(sca_config)
            
            self.logger.info("SCA configured successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"SCA configuration failed: {str(e)}")
            return False
    
    def generate_sca_config(self) -> str:
        """Generate SCA configuration"""
        tech_base = self.config.get('technical_base', {})
        sca = tech_base.get('sca', {})
        
        config = """<!-- SCA configuration -->
<sca>
  <enabled>yes</enabled>
"""
        if sca.get('scan_on_start'):
            config += '  <scan_on_start>yes</scan_on_start>\n'
        
        if sca.get('interval'):
            config += f'  <interval>{sca["interval"]}</interval>\n'
        else:
            config += '  <interval>12h</interval>\n'
        
        if sca.get('skip_nfs'):
            config += '  <skip_nfs>yes</skip_nfs>\n'
        
        config += "</sca>\n\n"
        return config
    
    def configure_fim(self) -> bool:
        """Configure File Integrity Monitoring"""
        self.logger.info("Configuring FIM...")
        
        try:
            ossec_conf = self.wazuh_config_path / 'ossec.conf'
            
            with open(ossec_conf, 'r') as f:
                current_config = f.read()
            
            if '<syscheck>' in current_config:
                self.logger.info("FIM already configured")
                return True
            
            fim_config = self.generate_fim_config()
            
            with open(ossec_conf, 'a') as f:
                f.write(fim_config)
            
            self.logger.info("FIM configured successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"FIM configuration failed: {str(e)}")
            return False
    
    def generate_fim_config(self) -> str:
        """Generate FIM configuration"""
        tech_base = self.config.get('technical_base', {})
        fim = tech_base.get('fim', {})
        
        config = """<!-- FIM configuration -->
<syscheck>
  <disabled>no</disabled>
"""
        if fim.get('frequency'):
            config += f'  <frequency>{fim["frequency"]}</frequency>\n'
        else:
            config += '  <frequency>43200</frequency>\n'
        
        directories = fim.get('default_directories', [])
        for directory in directories:
            whodata = fim.get('whodata_enabled', True)
            config += f'  <directories check_all="yes" whodata="{"yes" if whodata else "no"}">{directory}</directories>\n'
        
        nodiff_files = fim.get('nodiff_files', [])
        for nodiff_file in nodiff_files:
            config += f'  <nodiff>{nodiff_file}</nodiff>\n'
        
        if fim.get('skip_nfs'):
            config += '  <skip_nfs>yes</skip_nfs>\n'
        
        if fim.get('skip_dev'):
            config += '  <skip_dev>yes</skip_dev>\n'
        
        if fim.get('skip_proc'):
            config += '  <skip_proc>yes</skip_proc>\n'
        
        if fim.get('skip_sys'):
            config += '  <skip_sys>yes</skip_sys>\n'
        
        config += """  <process_priority>10</process_priority>
  <max_eps>50</max_eps>
  <synchronization>
    <enabled>yes</enabled>
    <interval>5m</interval>
    <max_eps>10</max_eps>
  </synchronization>
</syscheck>

"""
        return config
    
    def configure_log_collection(self) -> bool:
        """Configure log collection"""
        self.logger.info("Configuring log collection...")
        
        try:
            ossec_conf = self.wazuh_config_path / 'ossec.conf'
            
            with open(ossec_conf, 'r') as f:
                current_config = f.read()
            
            log_collection = self.config.get('log_collection', {})
            
            # Check if logs are already configured
            if '<localfile>' in current_config:
                self.logger.info("Log collection already configured")
                return True
            
            log_config = self.generate_log_config(log_collection)
            
            with open(ossec_conf, 'a') as f:
                f.write(log_config)
            
            self.logger.info("Log collection configured successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Log collection configuration failed: {str(e)}")
            return False
    
    def generate_log_config(self, log_collection: Dict[str, Any]) -> str:
        """Generate log collection configuration"""
        config = """<!-- Log collection configuration -->
"""
        
        # Linux auth logs
        linux_auth = log_collection.get('linux_auth', {})
        if linux_auth:
            paths = linux_auth.get('paths', [])
            format_type = linux_auth.get('format', 'syslog')
            for path in paths:
                config += f'<localfile>\n'
                config += f'  <location>{path}</location>\n'
                config += f'  <log_format>{format_type}</log_format>\n'
                config += '</localfile>\n'
        
        # Linux system logs
        linux_system = log_collection.get('linux_system', {})
        if linux_system:
            paths = linux_system.get('paths', [])
            format_type = linux_system.get('format', 'syslog')
            for path in paths:
                config += f'<localfile>\n'
                config += f'  <location>{path}</location>\n'
                config += f'  <log_format>{format_type}</log_format>\n'
                config += '</localfile>\n'
        
        # Linux cron logs
        linux_cron = log_collection.get('linux_cron', {})
        if linux_cron:
            paths = linux_cron.get('paths', [])
            format_type = linux_cron.get('format', 'syslog')
            for path in paths:
                config += f'<localfile>\n'
                config += f'  <location>{path}</location>\n'
                config += f'  <log_format>{format_type}</log_format>\n'
                config += '</localfile>\n'
        
        config += "\n"
        return config
    
    def configure_active_response(self) -> bool:
        """Configure active response"""
        self.logger.info("Configuring active response...")
        
        try:
            ossec_conf = self.wazuh_config_path / 'ossec.conf'
            
            with open(ossec_conf, 'r') as f:
                current_config = f.read()
            
            if '<active-response>' in current_config:
                self.logger.info("Active response already configured")
                return True
            
            active_response = self.config.get('technical_base', {}).get('active_response', {})
            ar_config = self.generate_active_response_config(active_response)
            
            with open(ossec_conf, 'a') as f:
                f.write(ar_config)
            
            self.logger.info("Active response configured successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Active response configuration failed: {str(e)}")
            return False
    
    def generate_active_response_config(self, active_response: Dict[str, Any]) -> str:
        """Generate active response configuration"""
        config = """<!-- Active response configuration -->
<active-response>
  <disabled>no</disabled>
  <command>host-deny</command>
  <location>defined-agent</location>
"""
        if active_response.get('timeout'):
            config += f'  <timeout>{active_response["timeout"]}</timeout>\n'
        else:
            config += '  <timeout>60</timeout>\n'
        
        if active_response.get('repeated_offenders'):
            config += f'  <repeated_offenders>{active_response["repeated_offenders"]}</repeated_offenders>\n'
        else:
            config += '  <repeated_offenders>1,5,10</repeated_offenders>\n'
        
        config += """</active-response>

"""
        return config
