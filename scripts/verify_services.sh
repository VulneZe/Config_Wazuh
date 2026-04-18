#!/bin/bash
# Service Verification Script
# Checks the status of Wazuh services

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

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check service status
check_service() {
    local service=$1
    
    if systemctl is-active --quiet "$service"; then
        print_info "$service is running"
        return 0
    else
        print_error "$service is not running"
        return 1
    fi
}

# Check service enabled status
check_service_enabled() {
    local service=$1
    
    if systemctl is-enabled --quiet "$service"; then
        print_info "$service is enabled"
        return 0
    else
        print_warning "$service is not enabled"
        return 1
    fi
}

# Check port availability
check_port() {
    local port=$1
    local service=$2
    
    if ss -tuln | grep -q ":$port "; then
        print_info "Port $port is listening ($service)"
        return 0
    else
        print_error "Port $port is not listening ($service)"
        return 1
    fi
}

# Check disk space
check_disk_space() {
    print_info "Checking disk space..."
    
    df -h / | tail -1 | awk '{print "Disk usage: "$3" used, "$4" available ("$5")"}'
}

# Check memory usage
check_memory() {
    print_info "Checking memory usage..."
    
    free -h | grep Mem | awk '{print "Memory: "$3" used, "$4" available"}'
}

# Check Wazuh Manager API
check_manager_api() {
    print_info "Checking Wazuh Manager API..."
    
    local manager_port=15150
    local manager_host=localhost
    
    if curl -k -s "https://${manager_host}:${manager_port}/" > /dev/null 2>&1; then
        print_info "Wazuh Manager API is accessible"
        return 0
    else
        print_error "Wazuh Manager API is not accessible"
        return 1
    fi
}

# Check Indexer API
check_indexer_api() {
    print_info "Checking Wazuh Indexer API..."
    
    local indexer_port=9200
    local indexer_host=localhost
    
    if curl -k -s "https://${indexer_host}:${indexer_port}/_cluster/health" > /dev/null 2>&1; then
        print_info "Wazuh Indexer API is accessible"
        return 0
    else
        print_error "Wazuh Indexer API is not accessible"
        return 1
    fi
}

# Check Dashboard
check_dashboard() {
    print_info "Checking Wazuh Dashboard..."
    
    local dashboard_port=443
    local dashboard_host=localhost
    
    if curl -k -s "https://${dashboard_host}:${dashboard_port}/" > /dev/null 2>&1; then
        print_info "Wazuh Dashboard is accessible"
        return 0
    else
        print_error "Wazuh Dashboard is not accessible"
        return 1
    fi
}

# Main verification function
main() {
    echo "=========================================="
    echo "Wazuh Service Verification"
    echo "=========================================="
    echo ""
    
    # Check services
    echo "--- Service Status ---"
    check_service wazuh-manager
    check_service wazuh-indexer
    check_service wazuh-dashboard
    echo ""
    
    # Check if services are enabled
    echo "--- Service Enabled Status ---"
    check_service_enabled wazuh-manager
    check_service_enabled wazuh-indexer
    check_service_enabled wazuh-dashboard
    echo ""
    
    # Check ports
    echo "--- Port Status ---"
    check_port 15150 "Wazuh Manager API"
    check_port 1514 "Wazuh Manager"
    check_port 9200 "Wazuh Indexer"
    check_port 443 "Wazuh Dashboard"
    echo ""
    
    # Check APIs
    echo "--- API Accessibility ---"
    check_manager_api
    check_indexer_api
    check_dashboard
    echo ""
    
    # Check system resources
    echo "--- System Resources ---"
    check_disk_space
    check_memory
    echo ""
    
    echo "=========================================="
    echo "Verification Complete"
    echo "=========================================="
}

# Run main function
main
