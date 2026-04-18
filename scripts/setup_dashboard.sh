#!/bin/bash
# Dashboard Setup Script
# Configures Wazuh Dashboard with data views and dashboards

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

# Wait for dashboard to be ready
wait_for_dashboard() {
    print_info "Waiting for dashboard to be ready..."
    
    local max_attempts=30
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if curl -k -s https://localhost:443/api/status > /dev/null 2>&1; then
            print_info "Dashboard is ready"
            return 0
        fi
        
        attempt=$((attempt + 1))
        echo "Waiting... ($attempt/$max_attempts)"
        sleep 5
    done
    
    print_error "Dashboard did not become ready in time"
    return 1
}

# Configure default password
configure_password() {
    print_info "Configuring default dashboard password..."
    
    # The default password should be changed via the dashboard UI
    print_warning "Please change the default password via the dashboard UI"
    print_info "Default credentials: admin / admin"
}

# Create data views
create_data_views() {
    print_info "Creating data views..."
    
    # Data views would be created via API calls
    # This is a placeholder for the actual implementation
    
    print_info "Data views configuration placeholder"
}

# Import dashboards
import_dashboards() {
    print_info "Importing dashboards..."
    
    # Dashboards would be imported via API calls
    # This is a placeholder for the actual implementation
    
    print_info "Dashboards import placeholder"
}

# Configure alerting
configure_alerting() {
    print_info "Configuring alerting..."
    
    # Alerting would be configured via API calls
    # This is a placeholder for the actual implementation
    
    print_info "Alerting configuration placeholder"
}

# Main function
main() {
    print_info "Starting dashboard setup..."
    
    check_root
    wait_for_dashboard
    configure_password
    create_data_views
    import_dashboards
    configure_alerting
    
    print_info "Dashboard setup completed"
    print_info "Access the dashboard at: https://<dashboard-host>:443"
}

# Run main function
main
