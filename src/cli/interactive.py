"""
Interactive CLI for cyba-Inspector
Module Developer Agent Implementation
"""

import cmd2
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Optional

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm
from rich import print as rprint

from src.enumeration.controller import EnumerationController
from src.enumeration.profiles import EnumerationProfiles
from src.utils.session import SessionManager
from src.utils.validators import InputValidator
from src.utils.colors import Colors
from src.reporting.generator import ReportGenerator


class CybaHTBShell(cmd2.Cmd):
    """Enhanced interactive shell for cyba-Inspector"""
    
    intro = f"""
{Colors.CYAN}╔════════════════════════════════════════════╗
║       cyba-Inspector Interactive Mode v2.0       ║
║                                            ║
║  Type 'help' for available commands        ║
║  Tab completion and history available      ║
╚════════════════════════════════════════════╝{Colors.RESET}
    """
    
    prompt = f"{Colors.GREEN}cyba-inspector>{Colors.RESET} "
    
    def __init__(self):
        # Initialize cmd2 with history file
        super().__init__(
            persistent_history_file=os.path.expanduser("~/.cyba_inspector_history"),
            startup_script=os.path.expanduser("~/.cyba_inspectorrc")
        )
        
        # Initialize components
        self.console = Console()
        self.validator = InputValidator()
        self.session_manager = SessionManager()
        self.enum_controller = EnumerationController()
        self.profiles = EnumerationProfiles()
        
        # State management
        self.current_target = None
        self.current_session = None
        self.active_sessions = {}
        
        # CLI settings
        self.auto_save = True
        self.color_output = True
        self.verbose = False
        
    def do_target(self, args):
        """Set or display current target
        Usage: target [IP/hostname]
        """
        if not args:
            if self.current_target:
                self.poutput(f"Current target: {Colors.YELLOW}{self.current_target}{Colors.RESET}")
            else:
                self.poutput("No target set. Use 'target <IP>' to set one.")
            return
            
        # Validate target
        if self.validator.validate_ip(args) or self.validator.validate_hostname(args):
            self.current_target = args
            self.poutput(f"Target set to: {Colors.GREEN}{args}{Colors.RESET}")
        else:
            self.perror(f"Invalid target: {args}")
    
    def do_scan(self, args):
        """Quick scan of current target
        Usage: scan [options]
        Options:
          -p, --ports PORTS    Specific ports to scan
          -sV                  Version detection
          -sC                  Script scan
        """
        if not self.current_target:
            self.perror("No target set. Use 'target <IP>' first.")
            return
            
        # Parse arguments
        parser = self.create_scan_parser()
        try:
            opts = parser.parse_args(args.split() if args else [])
        except SystemExit:
            return
            
        # Show progress
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task(f"Scanning {self.current_target}...", total=None)
            
            # Run nmap scan
            from src.enumeration.modules.nmap import NmapModule
            nmap = NmapModule()
            
            # Build nmap options
            nmap_opts = {}
            if opts.ports:
                nmap_opts['ports'] = opts.ports
            if opts.version:
                nmap_opts['version_detection'] = True
            if opts.scripts:
                nmap_opts['script_scan'] = True
                
            # Execute scan
            result = nmap.run(
                self.current_target,
                self.current_session or "temp",
                "/tmp/cyba-inspector",
                quick=True,  # Use quick scan for interactive mode
                **nmap_opts
            )
            
            progress.remove_task(task)
            
        # Display results
        if result and result.get('quick_scan', {}).get('stdout'):
            self._display_nmap_output(result['quick_scan']['stdout'])
        else:
            self.poutput("No scan results or scan failed.")
    
    def do_enum(self, args):
        """Run enumeration with interactive wizard
        Usage: enum [profile]
        """
        if not self.current_target:
            self.perror("No target set. Use 'target <IP>' first.")
            return
            
        # Show available profiles if none specified
        if not args:
            self._show_enumeration_wizard()
        else:
            self._run_enumeration(args)
    
    def do_session(self, args):
        """Manage enumeration sessions
        Usage: session [list|load|save|new]
        """
        if not args or args == "list":
            self._list_sessions()
        elif args.startswith("load "):
            session_id = args.split()[1]
            self._load_session(session_id)
        elif args == "save":
            self._save_current_session()
        elif args == "new":
            self._new_session()
        else:
            self.perror(f"Unknown session command: {args}")
    
    def do_report(self, args):
        """Generate report from current session
        Usage: report [format] [output_file]
        Formats: markdown, html, json, pdf
        """
        if not self.current_session:
            self.perror("No active session. Create or load a session first.")
            return
            
        # Parse arguments
        parts = args.split() if args else []
        format_type = parts[0] if parts else "markdown"
        output_file = parts[1] if len(parts) > 1 else None
        
        # Generate report
        with self.console.status(f"Generating {format_type} report..."):
            generator = ReportGenerator()
            report_path = generator.generate(
                self.current_session,
                format_type,
                output_file
            )
            
        self.poutput(f"Report generated: {Colors.GREEN}{report_path}{Colors.RESET}")
    
    def do_exploit(self, args):
        """Interactive exploitation helper
        Usage: exploit
        """
        self.poutput(f"{Colors.YELLOW}Exploitation Assistant{Colors.RESET}")
        self.poutput("This feature will guide you through exploitation based on findings.")
        self.poutput("Coming soon in v2.1!")
    
    # Helper methods
    def _display_scan_results(self, result):
        """Display scan results in a nice table"""
        table = Table(title=f"Scan Results for {self.current_target}")
        table.add_column("Port", style="cyan")
        table.add_column("State", style="green")
        table.add_column("Service", style="yellow")
        table.add_column("Version", style="magenta")
        
        for port_info in result.get('open_ports', []):
            table.add_row(
                str(port_info.get('port', 'N/A')),
                port_info.get('state', 'N/A'),
                port_info.get('service', 'N/A'),
                port_info.get('version', 'N/A')
            )
            
        self.console.print(table)
    
    def _display_nmap_output(self, output):
        """Display raw nmap output with basic parsing"""
        # Extract key information
        lines = output.split('\n')
        ports_section = False
        
        self.poutput(f"\n{Colors.CYAN}Scan Results for {self.current_target}{Colors.RESET}")
        self.poutput("-" * 50)
        
        for line in lines:
            if "PORT" in line and "STATE" in line:
                ports_section = True
                self.poutput(f"{Colors.YELLOW}{line}{Colors.RESET}")
            elif ports_section and line.strip() and not line.startswith("Service Info"):
                if "/tcp" in line or "/udp" in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port = parts[0]
                        state = parts[1]
                        service = ' '.join(parts[2:])
                        if "open" in state:
                            self.poutput(f"{Colors.GREEN}{port:10} {state:10} {service}{Colors.RESET}")
                        else:
                            self.poutput(f"{Colors.RED}{port:10} {state:10} {service}{Colors.RESET}")
            elif "Service Info" in line:
                self.poutput(f"\n{Colors.BLUE}{line}{Colors.RESET}")
                ports_section = False
    
    def _show_enumeration_wizard(self):
        """Interactive enumeration wizard"""
        self.poutput(f"\n{Colors.CYAN}Enumeration Wizard{Colors.RESET}")
        
        # Show available profiles
        profiles = self.profiles.list_profiles()
        
        table = Table(title="Available Profiles")
        table.add_column("Profile", style="cyan")
        table.add_column("Description", style="yellow")
        
        for profile in profiles:
            table.add_row(profile['name'], profile['description'])
            
        self.console.print(table)
        
        # Let user choose
        profile_name = Prompt.ask(
            "Select profile",
            choices=[p['name'] for p in profiles],
            default="basic"
        )
        
        self._run_enumeration(profile_name)
    
    def _run_enumeration(self, profile_name):
        """Run enumeration with specified profile"""
        # Create session if needed
        if not self.current_session:
            self.current_session = self.session_manager.create_session(
                self.current_target,
                f"interactive_{profile_name}"
            )
            
        # Run enumeration
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task(f"Running {profile_name} enumeration...", total=None)
            
            # Get machine name from session or use default
            machine_name = f"machine_{self.current_target.replace('.', '_')}"
            
            self.enum_controller.start_enumeration(
                session_id=self.current_session,
                target=self.current_target,
                name=machine_name,
                profile=profile_name
            )
            
            progress.remove_task(task)
            
        self.poutput(f"{Colors.GREEN}Enumeration complete!{Colors.RESET}")
        self.poutput(f"Session: {self.current_session}")
    
    def _list_sessions(self):
        """List all available sessions"""
        # Get all session files
        session_files = list(self.session_manager.sessions_dir.glob("*.json"))
        
        if not session_files:
            self.poutput("No sessions found.")
            return
            
        table = Table(title="Available Sessions")
        table.add_column("Session ID", style="cyan")
        table.add_column("Target", style="yellow")
        table.add_column("Name", style="blue")
        table.add_column("Created", style="green")
        table.add_column("Status", style="magenta")
        
        for session_file in session_files:
            session_id = session_file.stem
            data = self.session_manager.get_session(session_id)
            if data:
                table.add_row(
                    session_id,
                    data.get('target', 'N/A'),
                    data.get('name', 'N/A'),
                    data.get('created', 'N/A')[:19],  # Just date and time
                    data.get('status', 'N/A')
                )
                
        self.console.print(table)
    
    def _load_session(self, session_id):
        """Load a specific session"""
        data = self.session_manager.get_session(session_id)
        if data:
            self.current_session = session_id
            self.current_target = data.get('target')
            self.poutput(f"Session loaded: {Colors.GREEN}{session_id}{Colors.RESET}")
            self.poutput(f"Target: {self.current_target}")
        else:
            self.perror(f"Session not found: {session_id}")
    
    def _save_current_session(self):
        """Save current session"""
        if self.current_session:
            self.poutput(f"Session saved: {self.current_session}")
        else:
            self.perror("No active session to save.")
    
    def _new_session(self):
        """Create new session"""
        if not self.current_target:
            self.perror("Set a target first with 'target <IP>'")
            return
            
        name = Prompt.ask("Session name", default=f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.current_session = self.session_manager.create_session(self.current_target, name)
        self.poutput(f"New session created: {Colors.GREEN}{self.current_session}{Colors.RESET}")
    
    def create_scan_parser(self):
        """Create argument parser for scan command"""
        parser = cmd2.Cmd2ArgumentParser()
        parser.add_argument('-p', '--ports', help='Ports to scan')
        parser.add_argument('-sV', '--version', action='store_true', help='Version detection')
        parser.add_argument('-sC', '--scripts', action='store_true', help='Script scan')
        return parser


def main():
    """Entry point for interactive CLI"""
    shell = CybaHTBShell()
    shell.cmdloop()


if __name__ == "__main__":
    main()