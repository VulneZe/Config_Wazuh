#!/bin/bash
# Wazuh Installation Script
# Installs Wazuh components (manager, indexer, dashboard)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

# Detect OS distribution
detect_os() {
    print_info "Detecting OS distribution..."
    
    if [ -f /etc/debian_version ]; then
        OS="debian"
        print_info "Detected Debian/Ubuntu"
    elif [ -f /etc/redhat-release ]; then
        OS="redhat"
        print_info "Detected RHEL/CentOS"
    else
        print_error "Unsupported OS distribution"
        exit 1
    fi
}

# Install Wazuh repository
install_repository() {
    print_info "Installing Wazuh repository..."
    
    if [ "$OS" = "debian" ]; then
        # Install GPG key
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
        
        # Add repository
        echo "deb https://packages.wazuh.com/4.x/apt stable main" > /etc/apt/sources.list.d/wazuh.list
        
        # Update package list
        apt-get update
        
    elif [ "$OS" = "redhat" ]; then
        # Install GPG key
        rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
        
        # Add repository
        cat > /etc/yum.repos.d/wazuh.repo <<EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
    fi
    
    print_info "Wazuh repository installed successfully"
}

# Install Wazuh components
install_components() {
    print_info "Installing Wazuh components..."
    
    if [ "$OS" = "debian" ]; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y \
            wazuh-manager \
            wazuh-indexer \
            wazuh-dashboard
            
    elif [ "$OS" = "redhat" ]; then
        yum install -y \
            wazuh-manager \
            wazuh-indexer \
            wazuh-dashboard
    fi
    
    print_info "Wazuh components installed successfully"
}

# Configure indexer JVM heap
configure_indexer_heap() {
    print_info "Configuring indexer JVM heap..."
    
    # Get system memory
    TOTAL_MEM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    TOTAL_MEM_GB=$((TOTAL_MEM_KB / 1024 / 1024))
    
    # Use half of total memory for heap, max 16GB
    HEAP_SIZE=$((TOTAL_MEM_GB / 2))
    if [ $HEAP_SIZE -gt 16 ]; then
        HEAP_SIZE=16
    fi
    
    # Configure JVM options
    JVM_OPTIONS_FILE="/etc/wazuh-indexer/jvm.options"
    
    if [ -f "$JVM_OPTIONS_FILE" ]; then
        # Remove existing heap settings
        sed -i '/^-Xms/d' "$JVM_OPTIONS_FILE"
        sed -i '/^-Xmx/d' "$JVM_OPTIONS_FILE"
        
        # Add new heap settings
        echo "-Xms${HEAP_SIZE}g" >> "$JVM_OPTIONS_FILE"
        echo "-Xmx${HEAP_SIZE}g" >> "$JVM_OPTIONS_FILE"
        
        print_info "Configured JVM heap to ${HEAP_SIZE}GB"
    fi
}

# Enable and start services
start_services() {
    print_info "Starting Wazuh services..."
    
    # Enable services
    systemctl enable wazuh-manager
    systemctl enable wazuh-indexer
    systemctl enable wazuh-dashboard
    
    # Start services
    systemctl start wazuh-manager
    systemctl start wazuh-indexer
    systemctl start wazuh-dashboard
    
    # Wait for services to start
    sleep 10
    
    # Check service status
    print_info "Checking service status..."
    
    for service in wazuh-manager wazuh-indexer wazuh-dashboard; do
        if systemctl is-active --quiet "$service"; then
            print_info "$service is running"
        else
            print_error "$service failed to start"
        fi
    done
}

# Main installation function
main() {
    print_info "Starting Wazuh installation..."
    
    check_root
    detect_os
    install_repository
    install_components
    configure_indexer_heap
    start_services
    
    print_info "Wazuh installation completed successfully"
}

# Run main function
main
