"""
Auto Corrector Module
Automatically corrects common issues in Wazuh deployment
"""

import os
import logging
import subprocess
from typing import Dict, Any, List
from pathlib import Path


class AutoCorrector:
    """Automatically corrects deployment issues"""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.corrections_applied = []
    
    def run_auto_correction(self) -> bool:
        """
        Main auto-correction method
        Detects and fixes common issues
        """
        self.logger.info("Starting auto-correction...")
        
        try:
            # Fix service issues
            self.fix_service_issues()
            
            # Fix permission issues
            self.fix_permission_issues()
            
            # Fix configuration issues
            self.fix_configuration_issues()
            
            # Restart services if needed
            self.restart_services()
            
            # Print summary
            self.print_correction_summary()
            
            return len(self.corrections_applied) > 0
            
        except Exception as e:
            self.logger.error(f"Auto-correction failed: {str(e)}")
            return False
    
    def fix_service_issues(self) -> bool:
        """Fix service-related issues"""
        self.logger.info("Checking for service issues...")
        
        services = ['wazuh-manager', 'wazuh-indexer', 'wazuh-dashboard']
        
        for service in services:
            try:
                # Check if service is not running
                result = subprocess.run(
                    ['systemctl', 'is-active', service],
                    capture_output=True,
                    text=True
                )
                
                if result.stdout.strip() != 'active':
                    self.logger.info(f"Attempting to fix {service}...")
                    
                    # Try to start the service
                    subprocess.run(['systemctl', 'start', service], check=True)
                    time.sleep(3)
                    
                    # Check again
                    result = subprocess.run(
                        ['systemctl', 'is-active', service],
                        capture_output=True,
                        text=True
                    )
                    
                    if result.stdout.strip() == 'active':
                        self.corrections_applied.append(f"Started service: {service}")
                        self.logger.info(f"✓ Fixed {service}")
                    else:
                        self.logger.warning(f"✗ Could not fix {service}")
                        
            except Exception as e:
                self.logger.error(f"Error fixing {service}: {str(e)}")
        
        return True
    
    def fix_permission_issues(self) -> bool:
        """Fix permission issues"""
        self.logger.info("Checking for permission issues...")
        
        wazuh_path = Path('/var/ossec')
        
        try:
            # Fix wazuh user/group ownership
            if wazuh_path.exists():
                # Check ownership
                stat = wazuh_path.stat()
                import pwd
                import grp
                
                try:
                    wazuh_user = pwd.getpwnam('wazuh')
                    wazuh_group = grp.getgrnam('wazuh')
                    
                    # Fix ownership if needed
                    if stat.st_uid != wazuh_user.pw_uid or stat.st_gid != wazuh_group.gr_gid:
                        subprocess.run(
                            ['chown', '-R', 'wazuh:wazuh', str(wazuh_path)],
                            check=True
                        )
                        self.corrections_applied.append("Fixed ownership of /var/ossec")
                        self.logger.info("✓ Fixed ownership")
                        
                except KeyError:
                    self.logger.warning("wazuh user/group not found")
            
            # Fix shared directory permissions
            shared_path = wazuh_path / 'etc' / 'shared'
            if shared_path.exists():
                subprocess.run(
                    ['chmod', '-R', '770', str(shared_path)],
                    check=True
                )
                self.corrections_applied.append("Fixed permissions of shared directory")
                self.logger.info("✓ Fixed shared directory permissions")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error fixing permissions: {str(e)}")
            return False
    
    def fix_configuration_issues(self) -> bool:
        """Fix configuration issues"""
        self.logger.info("Checking for configuration issues...")
        
        wazuh_config = Path('/var/ossec/etc')
        
        try:
            # Check if ossec.conf exists
            ossec_conf = wazuh_config / 'ossec.conf'
            if not ossec_conf.exists():
                self.logger.warning("ossec.conf does not exist")
                return False
            
            # Read configuration
            with open(ossec_conf, 'r') as f:
                content = f.read()
            
            # Check for common issues
            
            # Issue 1: Missing syscollector
            if '<wodle name="syscollector">' not in content:
                self.logger.info("Adding syscollector configuration...")
                syscollector_config = """<!-- Syscollector configuration -->
<wodle name="syscollector">
  <disabled>no</disabled>
  <interval>1h</interval>
  <scan_on_start>yes</scan_on_start>
  <hardware>yes</hardware>
  <os>yes</os>
  <network>yes</network>
  <packages>yes</packages>
  <ports all="no">yes</ports>
  <processes>yes</processes>
  <users>yes</users>
  <groups>yes</groups>
  <services>yes</services>
  <browser_extensions>yes</browser_extensions>
  <synchronization>
    <max_eps>10</max_eps>
  </synchronization>
</wodle>

"""
                with open(ossec_conf, 'a') as f:
                    f.write(syscollector_config)
                self.corrections_applied.append("Added syscollector configuration")
                self.logger.info("✓ Added syscollector configuration")
            
            # Issue 2: Missing vulnerability detection
            if '<vulnerability-detection>' not in content:
                self.logger.info("Adding vulnerability detection configuration...")
                vuln_config = """<!-- Vulnerability detection configuration -->
<vulnerability-detection>
  <enabled>yes</enabled>
  <index-status>yes</index-status>
  <feed-update-interval>60m</feed-update-interval>
</vulnerability-detection>

"""
                with open(ossec_conf, 'a') as f:
                    f.write(vuln_config)
                self.corrections_applied.append("Added vulnerability detection configuration")
                self.logger.info("✓ Added vulnerability detection configuration")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error fixing configuration: {str(e)}")
            return False
    
    def restart_services(self) -> bool:
        """Restart Wazuh services if corrections were applied"""
        if not self.corrections_applied:
            self.logger.info("No corrections applied, skipping service restart")
            return True
        
        self.logger.info("Restarting services...")
        
        services = ['wazuh-manager']
        
        for service in services:
            try:
                self.logger.info(f"Restarting {service}...")
                subprocess.run(['systemctl', 'restart', service], check=True)
                
                # Wait for service to start
                import time
                time.sleep(5)
                
                self.corrections_applied.append(f"Restarted service: {service}")
                self.logger.info(f"✓ Restarted {service}")
                
            except Exception as e:
                self.logger.error(f"Error restarting {service}: {str(e)}")
        
        return True
    
    def fix_disk_space(self) -> bool:
        """Fix disk space issues by cleaning old logs"""
        self.logger.info("Checking disk space...")
        
        try:
            import shutil
            
            # Check disk space
            disk_usage = shutil.disk_usage('/')
            free_percent = (disk_usage.free / disk_usage.total) * 100
            
            if free_percent < 10:  # Less than 10% free
                self.logger.warning(f"Low disk space: {free_percent:.1f}% free")
                
                # Clean old logs
                log_path = Path('/var/ossec/logs')
                if log_path.exists():
                    # Remove logs older than 30 days
                    import time
                    cutoff_time = time.time() - (30 * 24 * 60 * 60)
                    
                    removed_count = 0
                    for log_file in log_path.rglob('*.log'):
                        if log_file.stat().st_mtime < cutoff_time:
                            log_file.unlink()
                            removed_count += 1
                    
                    if removed_count > 0:
                        self.corrections_applied.append(f"Removed {removed_count} old log files")
                        self.logger.info(f"✓ Removed {removed_count} old log files")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error fixing disk space: {str(e)}")
            return False
    
    def fix_indexer_heap(self) -> bool:
        """Fix indexer heap size configuration"""
        self.logger.info("Checking indexer heap configuration...")
        
        try:
            jvm_options_path = Path('/etc/wazuh-indexer/jvm.options')
            
            if jvm_options_path.exists():
                with open(jvm_options_path, 'r') as f:
                    content = f.read()
                
                # Check if heap size is configured
                if '-Xms' not in content or '-Xmx' not in content:
                    self.logger.info("Configuring JVM heap size...")
                    
                    # Add heap size configuration (4GB)
                    heap_config = """
# JVM heap size configuration
-Xms4g
-Xmx4g
"""
                    with open(jvm_options_path, 'a') as f:
                        f.write(heap_config)
                    
                    self.corrections_applied.append("Configured JVM heap size")
                    self.logger.info("✓ Configured JVM heap size")
                    
                    # Restart indexer
                    subprocess.run(['systemctl', 'restart', 'wazuh-indexer'], check=True)
                    self.corrections_applied.append("Restarted wazuh-indexer")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error fixing indexer heap: {str(e)}")
            return False
    
    def print_correction_summary(self):
        """Print correction summary"""
        print("\n" + "="*70)
        print("AUTO-CORRECTION SUMMARY")
        print("="*70 + "\n")
        
        if self.corrections_applied:
            print("Corrections Applied:")
            for i, correction in enumerate(self.corrections_applied, 1):
                print(f"  {i}. {correction}")
            print()
        else:
            print("No corrections were needed or applied.\n")
