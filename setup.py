#!/usr/bin/env python3
"""
DRACO: Dynamic Reconnaissance and Cybersecurity Orchestrator
Setup and Installation Script
"""

import os
import sys
import platform
import subprocess
import json
from setuptools import setup, find_packages, Command
from setuptools.command.install import install
from distutils.util import convert_path

# DRACO ASCII Logo
DRACO_LOGO = '''
      /\    ___
     //\\  /\--\\
    (    \\/  /  \\
     \\      /   /
      \\____/---/
       \\   \\  /
        \\___\\/

🐉 DRACO: Dynamic Reconnaissance 
and Cybersecurity Orchestrator
'''

def print_banner():
    """
    Print the DRACO ASCII art banner during setup
    """
    print(DRACO_LOGO)

def post_install_setup():
    """Run initial toolkit setup after installation"""
    try:
        # Attempt to run the setup_toolkit.py script
        setup_script = os.path.join(os.path.dirname(__file__), 'setup_toolkit.py')
        subprocess.run([sys.executable, setup_script], check=True)
    except Exception as e:
        print(f"Initial setup failed: {e}")
        print("Please run 'python setup_toolkit.py' manually")

def read_requirements(filename):
    """
    Read requirements from a file and return a list of dependencies.
    
    Args:
        filename (str): Path to requirements file
    
    Returns:
        list: List of dependencies
    """
    with open(filename, 'r') as f:
        return [line.strip() for line in f 
                if line.strip() and not line.startswith('#')]

def check_system_dependencies():
    """
    Check and install system-level dependencies based on OS
    
    Returns:
        dict: System dependency installation status
    """
    system_deps = {
        'linux': {
            'packages': [
                'nmap', 
                'net-tools', 
                'build-essential', 
                'libssl-dev', 
                'libffi-dev'
            ],
            'package_manager': {
                'debian': 'apt-get install -y',
                'ubuntu': 'apt-get install -y',
                'centos': 'yum install -y',
                'fedora': 'dnf install -y',
                'rhel': 'yum install -y'
            }
        },
        'darwin': {
            'packages': [
                'nmap', 
                'openssl', 
                'libffi'
            ],
            'package_manager': {
                'darwin': 'brew install'
            }
        },
        'windows': {
            'packages': [
                'nmap', 
                'openssl'
            ],
            'package_manager': {
                'windows': 'choco install'
            }
        }
    }
    
    def install_system_deps(os_type):
        """
        Install system dependencies for a given OS
        
        Args:
            os_type (str): Operating system type
        
        Returns:
            dict: Installation status
        """
        status = {
            'success': False,
            'installed_packages': [],
            'failed_packages': []
        }
        
        if os_type not in system_deps:
            print(f"No system dependencies defined for {os_type}")
            return status
        
        os_config = system_deps[os_type]
        
        # Detect specific Linux distribution
        if os_type == 'linux':
            try:
                with open('/etc/os-release', 'r') as f:
                    os_info = dict(line.strip().split('=') for line in f if '=' in line)
                    distro = os_info.get('ID', '').strip('"').lower()
            except FileNotFoundError:
                distro = 'ubuntu'  # Default to Ubuntu
        else:
            distro = os_type
        
        package_manager = os_config['package_manager'].get(distro)
        
        if not package_manager:
            print(f"No package manager found for {distro}")
            return status
        
        for package in os_config['packages']:
            try:
                cmd = f"sudo {package_manager} {package}"
                result = subprocess.run(cmd, shell=True, check=True)
                status['installed_packages'].append(package)
            except subprocess.CalledProcessError:
                status['failed_packages'].append(package)
        
        status['success'] = len(status['failed_packages']) == 0
        return status
    
    return install_system_deps(platform.system().lower())

class SecurityToolkitInstall(install):
    """
    Custom installation command with additional setup steps
    """
    def run(self):
        # Run standard installation
        install.run(self)
        
        # Check and install system dependencies
        print("🔍 Checking system dependencies...")
        sys_dep_status = check_system_dependencies()
        
        if sys_dep_status['success']:
            print("✅ System dependencies installed successfully")
        else:
            print("⚠️ Some system dependencies could not be installed")
            print("Failed packages:", sys_dep_status['failed_packages'])
        
        # Optional: Create configuration directory
        config_dir = os.path.expanduser('~/.security_toolkit')
        os.makedirs(config_dir, exist_ok=True)
        
        # Create a basic configuration file
        config_file = os.path.join(config_dir, 'config.json')
        config_data = {
            'version': '0.1.0',
            'os': platform.system().lower(),
            'arch': platform.machine().lower(),
            'python_version': platform.python_version(),
            'installed_dependencies': sys_dep_status['installed_packages']
        }
        
        with open(config_file, 'w') as f:
            json.dump(config_data, f, indent=4)
        
        print(f"📋 Configuration saved to {config_file}")

class SecurityToolkitTest(Command):
    """
    Custom command to run toolkit tests
    """
    description = 'Run security toolkit tests'
    user_options = []
    
    def initialize_options(self):
        pass
    
    def finalize_options(self):
        pass
    
    def run(self):
        print("🧪 Running Security Toolkit Tests...")
        try:
            import pytest
            errno = pytest.main(['tests'])
            sys.exit(errno)
        except ImportError:
            print("pytest not installed. Please install pytest to run tests.")
            sys.exit(1)

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

if __name__ == '__main__':
    # Print banner when script is run directly
    print_banner()
    
    # If configuration is requested
    if len(sys.argv) > 1 and sys.argv[1] == 'configure':
        print("🛠️ Running DRACO Configuration...")
        # Add configuration logic here
        sys.exit(0)
    
    setup(
        name='DRACO',
        version='0.1.0',
        author='@ERROR1088',
        author_email='draco@error1088.com',
        description='Dynamic Reconnaissance and Cybersecurity Orchestrator',
        long_description=long_description,
        long_description_content_type='text/markdown',
        url='https://github.com/ERROR1088/DRACO',
        packages=find_packages(),
        install_requires=read_requirements('requirements.txt'),
        extras_require={
            'advanced': read_requirements('requirements-advanced.txt'),
            'dev': [
                'pytest',
                'flake8',
                'mypy'
            ]
        },
        cmdclass={
            'install': SecurityToolkitInstall,
            'test': SecurityToolkitTest
        },
        entry_points={
            'console_scripts': [
                'DRACO=DRACO:main',
                'DRACO-test=setup:SecurityToolkitTest'
            ]
        },
        classifiers=[
            'Development Status :: 3 - Alpha',
            'Intended Audience :: Information Technology',
            'License :: OSI Approved :: MIT License',
            'Operating System :: OS Independent',
            'Programming Language :: Python :: 3.7',
            'Programming Language :: Python :: 3.8',
            'Programming Language :: Python :: 3.9',
            'Topic :: Security',
            'Topic :: System :: Networking'
        ],
        python_requires='>=3.7',
        keywords='DRACO cybersecurity network-scanning ethical-hacking'
    )
