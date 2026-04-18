#!/bin/bash
# Configuration Backup Script
# Backs up Wazuh configuration files

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

# Create backup directory
create_backup_dir() {
    BACKUP_DIR="/var/backups/wazuh"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    BACKUP_PATH="${BACKUP_DIR}/backup_${TIMESTAMP}"
    
    mkdir -p "$BACKUP_PATH"
    
    echo "$BACKUP_PATH"
}

# Backup Wazuh configuration
backup_wazuh_config() {
    local backup_path=$1
    
    print_info "Backing up Wazuh configuration..."
    
    if [ -d "/var/ossec/etc" ]; then
        cp -r /var/ossec/etc "$backup_path/"
        print_info "Wazuh configuration backed up"
    else
        print_error "Wazuh configuration directory not found"
    fi
}

# Backup certificates
backup_certificates() {
    local backup_path=$1
    
    print_info "Backing up certificates..."
    
    if [ -d "/etc/wazuh/certs" ]; then
        cp -r /etc/wazuh/certs "$backup_path/"
        print_info "Certificates backed up"
    else
        print_warning "Certificate directory not found"
    fi
}

# Backup Indexer configuration
backup_indexer_config() {
    local backup_path=$1
    
    print_info "Backing up Indexer configuration..."
    
    if [ -d "/etc/wazuh-indexer" ]; then
        cp -r /etc/wazuh-indexer "$backup_path/"
        print_info "Indexer configuration backed up"
    else
        print_warning "Indexer configuration directory not found"
    fi
}

# Backup Dashboard configuration
backup_dashboard_config() {
    local backup_path=$1
    
    print_info "Backing up Dashboard configuration..."
    
    if [ -d "/usr/share/wazuh-dashboard/config" ]; then
        cp -r /usr/share/wazuh-dashboard/config "$backup_path/"
        print_info "Dashboard configuration backed up"
    else
        print_warning "Dashboard configuration directory not found"
    fi
}

# Create backup info file
create_backup_info() {
    local backup_path=$1
    
    print_info "Creating backup information file..."
    
    cat > "$backup_path/backup_info.txt" <<EOF
Wazuh Configuration Backup
===========================
Backup Date: $(date)
Backup Host: $(hostname)
Backup User: $(whoami)

Contents:
- Wazuh configuration (/var/ossec/etc)
- Certificates (/etc/wazuh/certs)
- Indexer configuration (/etc/wazuh-indexer)
- Dashboard configuration (/usr/share/wazuh-dashboard/config)

To restore:
1. Stop Wazuh services
2. Copy files back to original locations
3. Restore permissions
4. Start Wazuh services
EOF
}

# Compress backup
compress_backup() {
    local backup_path=$1
    
    print_info "Compressing backup..."
    
    local backup_dir=$(dirname "$backup_path")
    local backup_name=$(basename "$backup_path")
    local compressed_backup="${backup_dir}/${backup_name}.tar.gz"
    
    tar -czf "$compressed_backup" -C "$backup_dir" "$backup_name"
    
    # Remove uncompressed backup
    rm -rf "$backup_path"
    
    echo "$compressed_backup"
}

# Clean old backups
clean_old_backups() {
    local backup_dir=$1
    local retention_days=${2:-30}
    
    print_info "Cleaning backups older than $retention_days days..."
    
    find "$backup_dir" -name "backup_*.tar.gz" -mtime +$retention_days -delete
    
    print_info "Old backups cleaned"
}

# Main backup function
main() {
    print_info "Starting Wazuh configuration backup..."
    
    check_root
    
    # Create backup directory
    backup_path=$(create_backup_dir)
    
    # Perform backups
    backup_wazuh_config "$backup_path"
    backup_certificates "$backup_path"
    backup_indexer_config "$backup_path"
    backup_dashboard_config "$backup_path"
    
    # Create backup info
    create_backup_info "$backup_path"
    
    # Compress backup
    compressed_backup=$(compress_backup "$backup_path")
    
    # Clean old backups (keep last 30 days)
    clean_old_backups "/var/backups/wazuh" 30
    
    print_info "Backup completed successfully: $compressed_backup"
    
    # Display backup size
    backup_size=$(du -h "$compressed_backup" | cut -f1)
    print_info "Backup size: $backup_size"
}

# Run main function
main
