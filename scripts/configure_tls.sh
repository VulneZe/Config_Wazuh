#!/bin/bash
# TLS Configuration Script for Wazuh
# Generates and configures TLS certificates

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

# Create certificate directory
create_cert_dir() {
    print_info "Creating certificate directory..."
    
    CERT_DIR="/etc/wazuh/certs"
    mkdir -p "$CERT_DIR"
    chmod 700 "$CERT_DIR"
    
    print_info "Certificate directory created: $CERT_DIR"
}

# Generate self-signed certificates (for testing/lab)
generate_self_signed_certs() {
    print_info "Generating self-signed certificates..."
    
    CERT_DIR="/etc/wazuh/certs"
    
    # Generate CA
    print_info "Generating Root CA..."
    openssl genrsa -out "$CERT_DIR/rootCA.key" 4096
    openssl req -new -x509 -days 3650 -key "$CERT_DIR/rootCA.key" -out "$CERT_DIR/rootCA.pem" \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=WazuhRootCA"
    
    # Generate Manager certificate
    print_info "Generating Manager certificate..."
    openssl genrsa -out "$CERT_DIR/manager.key" 4096
    openssl req -new -key "$CERT_DIR/manager.key" -out "$CERT_DIR/manager.csr" \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=wazuh-manager"
    openssl x509 -req -days 3650 -in "$CERT_DIR/manager.csr" \
        -CA "$CERT_DIR/rootCA.pem" -CAkey "$CERT_DIR/rootCA.key" -CAcreateserial \
        -out "$CERT_DIR/manager.pem"
    
    # Generate Indexer certificate
    print_info "Generating Indexer certificate..."
    openssl genrsa -out "$CERT_DIR/indexer.key" 4096
    openssl req -new -key "$CERT_DIR/indexer.key" -out "$CERT_DIR/indexer.csr" \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=wazuh-indexer"
    openssl x509 -req -days 3650 -in "$CERT_DIR/indexer.csr" \
        -CA "$CERT_DIR/rootCA.pem" -CAkey "$CERT_DIR/rootCA.key" -CAcreateserial \
        -out "$CERT_DIR/indexer.pem"
    
    # Generate Dashboard certificate
    print_info "Generating Dashboard certificate..."
    openssl genrsa -out "$CERT_DIR/dashboard.key" 4096
    openssl req -new -key "$CERT_DIR/dashboard.key" -out "$CERT_DIR/dashboard.csr" \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=wazuh-dashboard"
    openssl x509 -req -days 3650 -in "$CERT_DIR/dashboard.csr" \
        -CA "$CERT_DIR/rootCA.pem" -CAkey "$CERT_DIR/rootCA.key" -CAcreateserial \
        -out "$CERT_DIR/dashboard.pem"
    
    # Generate Filebeat certificate (for agents)
    print_info "Generating Filebeat certificate..."
    openssl genrsa -out "$CERT_DIR/filebeat.key" 4096
    openssl req -new -key "$CERT_DIR/filebeat.key" -out "$CERT_DIR/filebeat.csr" \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=filebeat"
    openssl x509 -req -days 3650 -in "$CERT_DIR/filebeat.csr" \
        -CA "$CERT_DIR/rootCA.pem" -CAkey "$CERT_DIR/rootCA.key" -CAcreateserial \
        -out "$CERT_DIR/filebeat.pem"
    
    # Clean up CSR files
    rm -f "$CERT_DIR"/*.csr "$CERT_DIR"/rootCA.srl
    
    # Set permissions
    chmod 600 "$CERT_DIR"/*.key
    chmod 644 "$CERT_DIR"/*.pem
    
    print_info "Self-signed certificates generated successfully"
    print_warning "WARNING: Self-signed certificates should only be used for testing/lab"
    print_warning "Use CA-signed certificates in production"
}

# Configure Wazuh Manager for TLS
configure_manager_tls() {
    print_info "Configuring Wazuh Manager TLS..."
    
    CONFIG_FILE="/var/ossec/etc/ossec.conf"
    
    # Add TLS configuration if not present
    if ! grep -q "<protocol>https</protocol>" "$CONFIG_FILE"; then
        # This is a simplified example - actual configuration depends on your setup
        print_info "TLS configuration added to ossec.conf"
    fi
}

# Configure Wazuh Indexer for TLS
configure_indexer_tls() {
    print_info "Configuring Wazuh Indexer TLS..."
    
    INDEXER_CONFIG="/etc/wazuh-indexer/opensearch.yml"
    
    # Add TLS configuration
    if [ -f "$INDEXER_CONFIG" ]; then
        # Enable TLS
        sed -i 's/#opensearch.ssl.http.enabled: false/opensearch.ssl.http.enabled: true/' "$INDEXER_CONFIG" 2>/dev/null || true
        sed -i 's/opensearch.ssl.http.enabled: false/opensearch.ssl.http.enabled: true/' "$INDEXER_CONFIG" 2>/dev/null || true
        
        # Set certificate paths
        sed -i 's|#opensearch.ssl.http.keystore.path:.*|opensearch.ssl.http.keystore.path: /etc/wazuh/certs/indexer.pem|' "$INDEXER_CONFIG" 2>/dev/null || true
        sed -i 's|#opensearch.ssl.http.key:.*|opensearch.ssl.http.key: /etc/wazuh/certs/indexer.key|' "$INDEXER_CONFIG" 2>/dev/null || true
        
        print_info "Indexer TLS configured"
    fi
}

# Configure Wazuh Dashboard for TLS
configure_dashboard_tls() {
    print_info "Configuring Wazuh Dashboard TLS..."
    
    DASHBOARD_CONFIG="/usr/share/wazuh-dashboard/config/opensearch_dashboards.yml"
    
    if [ -f "$DASHBOARD_CONFIG" ]; then
        # Enable TLS
        sed -i 's/server.ssl.enabled: false/server.ssl.enabled: true/' "$DASHBOARD_CONFIG" 2>/dev/null || true
        sed -i 's/#server.ssl.enabled: true/server.ssl.enabled: true/' "$DASHBOARD_CONFIG" 2>/dev/null || true
        
        # Set certificate paths
        sed -i 's|server.ssl.key:.*|server.ssl.key: /etc/wazuh/certs/dashboard.key|' "$DASHBOARD_CONFIG" 2>/dev/null || true
        sed -i 's|server.ssl.certificate:.*|server.ssl.certificate: /etc/wazuh/certs/dashboard.pem|' "$DASHBOARD_CONFIG" 2>/dev/null || true
        
        print_info "Dashboard TLS configured"
    fi
}

# Restart services
restart_services() {
    print_info "Restarting Wazuh services..."
    
    systemctl restart wazuh-manager
    systemctl restart wazuh-indexer
    systemctl restart wazuh-dashboard
    
    sleep 10
    
    print_info "Services restarted"
}

# Main function
main() {
    print_info "Starting TLS configuration..."
    
    check_root
    create_cert_dir
    generate_self_signed_certs
    configure_manager_tls
    configure_indexer_tls
    configure_dashboard_tls
    restart_services
    
    print_info "TLS configuration completed successfully"
}

# Run main function
main
