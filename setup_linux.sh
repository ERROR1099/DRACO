#!/bin/bash

# Security Toolkit Linux Setup Script

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running with sudo
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run with sudo${NC}" 
   echo "Try: sudo bash setup_linux.sh"
   exit 1
fi

# Detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
    elif type lsb_release >/dev/null 2>&1; then
        DISTRO=$(lsb_release -i | cut -d: -f2 | sed s/'^\t'//)
    else
        DISTRO=$(uname -s)
    fi
    echo $DISTRO
}

# Install system dependencies
install_dependencies() {
    local DISTRO=$1
    
    echo -e "${YELLOW}Installing system dependencies...${NC}"
    
    case $DISTRO in
        ubuntu|debian)
            apt-get update
            apt-get install -y \
                python3 \
                python3-pip \
                python3-venv \
                git \
                build-essential \
                libssl-dev \
                libffi-dev \
                python3-dev \
                nmap \
                net-tools
            ;;
        centos|rhel|fedora)
            yum update -y
            yum install -y \
                python3 \
                python3-pip \
                python3-virtualenv \
                git \
                gcc \
                openssl-devel \
                libffi-devel \
                python3-devel \
                nmap \
                net-tools
            ;;
        *)
            echo -e "${RED}Unsupported distribution: $DISTRO${NC}"
            exit 1
            ;;
    esac
}

# Create virtual environment
setup_venv() {
    echo -e "${YELLOW}Setting up virtual environment...${NC}"
    python3 -m venv venv
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install dependencies
    pip install -r requirements.txt
    
    echo -e "${GREEN}Virtual environment created successfully!${NC}"
}

# Main script
main() {
    echo -e "${GREEN}🛡️ Security Toolkit Linux Setup Script${NC}"
    
    # Detect Linux distribution
    DISTRO=$(detect_distro)
    echo -e "${YELLOW}Detected Distribution: $DISTRO${NC}"
    
    # Install dependencies
    install_dependencies $DISTRO
    
    # Setup virtual environment
    setup_venv
    
    # Set permissions
    chmod 755 ultimate_security_toolkit.py
    chmod 755 network_scanner.py
    
    echo -e "${GREEN}✅ Setup Complete!${NC}"
    echo "To activate the virtual environment: source venv/bin/activate"
    echo "To run the toolkit: python3 ultimate_security_toolkit.py"
}

# Run main function
main
