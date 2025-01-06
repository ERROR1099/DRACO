import os
import sys
import json
import platform
from typing import Dict, Any

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.prompt import Prompt, Confirm
    from rich.markdown import Markdown
except ImportError:
    print("Please install rich library: pip install rich")
    sys.exit(1)

class SecurityToolkitSetup:
    def __init__(self):
        self.console = Console()
        self.config_dir = os.path.join(os.path.dirname(__file__), 'config')
        self.config_file = os.path.join(self.config_dir, 'toolkit_config.json')
        
        # Ensure config directory exists
        os.makedirs(self.config_dir, exist_ok=True)
    
    def display_welcome_banner(self):
        """Display an attractive welcome banner"""
        banner = r"""
        ╔═══════════════════════════════════════════╗
        ║   🛡️  Advanced Security Toolkit Setup   🛡️  ║
        ╚═══════════════════════════════════════════╝
        """
        self.console.print(Panel(
            Text(banner, style="bold green"),
            border_style="green",
            title="Security Toolkit Initialization"
        ))
    
    def collect_api_keys(self) -> Dict[str, str]:
        """
        Collect API keys from user with interactive prompts
        
        Returns:
            Dict[str, str]: Collected API keys
        """
        api_keys = {}
        
        # Define API services to configure
        services = [
            {
                'name': 'Shodan',
                'key_name': 'SHODAN_API_KEY',
                'description': 'Shodan provides internet-wide scanning capabilities.',
                'url': 'https://account.shodan.io/'
            },
            {
                'name': 'Censys',
                'key_name': 'CENSYS_API_ID',
                'description': 'Censys offers comprehensive internet infrastructure scanning.',
                'url': 'https://censys.io/register'
            },
            {
                'name': 'VirusTotal',
                'key_name': 'VIRUSTOTAL_API_KEY',
                'description': 'VirusTotal provides file and URL scanning capabilities.',
                'url': 'https://www.virustotal.com/gui/join-us'
            }
        ]
        
        self.console.print("\n[bold green]🔑 API Key Configuration[/bold green]")
        
        for service in services:
            self.console.print(f"\n[bold cyan]{service['name']} API Configuration[/bold cyan]")
            self.console.print(f"Description: {service['description']}")
            self.console.print(f"Get API Key: {service['url']}")
            
            # Ask if user wants to configure this service
            if Confirm.ask(f"Do you want to configure {service['name']} API?", default=False):
                api_key = Prompt.ask(f"Enter {service['name']} API Key", password=True)
                api_keys[service['key_name']] = api_key
        
        return api_keys
    
    def generate_env_file(self, api_keys: Dict[str, str]):
        """
        Generate .env file with API keys
        
        Args:
            api_keys (Dict[str, str]): Collected API keys
        """
        env_path = os.path.join(os.path.dirname(__file__), '.env')
        
        with open(env_path, 'w') as env_file:
            for key, value in api_keys.items():
                env_file.write(f"{key}={value}\n")
        
        self.console.print("\n[bold green]✅ .env file created successfully![/bold green]")
    
    def display_setup_guide(self):
        """Display comprehensive setup and usage guide"""
        guide = """
        # 🚀 Security Toolkit Setup and Usage Guide

        ## Prerequisites
        - Python 3.8+
        - pip package manager

        ## Installation Steps
        1. Create virtual environment
        ```bash
        python -m venv venv
        source venv/bin/activate  # On Windows: venv\\Scripts\\activate
        ```

        2. Install dependencies
        ```bash
        pip install -r requirements.txt
        pip install -e .
        ```

        ## Running the Toolkit
        ```bash
        python -m src.main
        ```

        ## Features
        - Dynamic tool discovery
        - Interactive security tools
        - Comprehensive scanning capabilities

        ## Ethical Usage
        🛡️ This toolkit is for educational and authorized security research only.
        Always obtain proper permissions before scanning systems.
        """
        
        markdown = Markdown(guide)
        self.console.print(Panel(
            markdown, 
            title="🔒 Security Toolkit Guide", 
            border_style="green"
        ))
    
    def run_setup(self):
        """Execute complete toolkit setup"""
        # Clear screen
        os.system('cls' if os.name == 'nt' else 'clear')
        
        # Display welcome
        self.display_welcome_banner()
        
        # Collect API keys
        api_keys = self.collect_api_keys()
        
        # Generate environment file
        self.generate_env_file(api_keys)
        
        # Display setup guide
        self.display_setup_guide()
        
        # Final confirmation
        self.console.print("\n[bold green]🎉 Security Toolkit Setup Complete![/bold green]")
        self.console.print("[yellow]Tip: Run 'python -m src.main' to start the toolkit[/yellow]")

def main():
    setup = SecurityToolkitSetup()
    setup.run_setup()

if __name__ == "__main__":
    main()
