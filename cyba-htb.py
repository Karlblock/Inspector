#!/usr/bin/env python3
"""
cyba-HTB - CLI Tool for HTB Enumeration & Analysis
Author: Karl Block
Version: 1.0.0
Developed for educational purposes and CPTS preparation
"""

import argparse
import sys
import os
from datetime import datetime
import json
from pathlib import Path

# Add src to path - handle both direct execution and symlink
script_path = os.path.abspath(__file__)
if os.path.islink(script_path):
    script_path = os.readlink(script_path)
script_dir = os.path.dirname(script_path)
src_path = os.path.join(script_dir, 'src')
sys.path.insert(0, src_path)

from utils.banner import display_banner
from utils.colors import Colors
from utils.validators import InputValidator
from enumeration.controller import EnumerationController
from reporting.generator import ReportGenerator
from utils.session import SessionManager
from htb_questions import HTBQuestions

class CybaHTB:
    def __init__(self):
        self.session_manager = SessionManager()
        self.enum_controller = EnumerationController()
        self.report_generator = ReportGenerator()
        self.htb_questions = HTBQuestions()
        
    def main(self):
        # Check if interactive mode requested
        if len(sys.argv) > 1 and sys.argv[1] == 'interactive':
            try:
                from src.cli.interactive import main as interactive_main
                interactive_main()
                return
            except ImportError:
                # Try alternate import path
                from cli.interactive import main as interactive_main
                interactive_main()
                return
            
        display_banner()
        parser = self.create_parser()
        args = parser.parse_args()
        
        if hasattr(args, 'func'):
            args.func(args)
        else:
            parser.print_help()
    
    def create_parser(self):
        parser = argparse.ArgumentParser(
            description='cyba-HTB - Specialized enumeration tool for Hack The Box',
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Enumeration command
        enum_parser = subparsers.add_parser('enum', help='Start enumeration')
        enum_parser.add_argument('-t', '--target', required=True, help='Target IP address')
        enum_parser.add_argument('-n', '--name', help='Machine name (auto-detected from current dir if not provided)')
        enum_parser.add_argument('-p', '--profile', default='auto', 
                                help='Enumeration profile (default: auto)')
        enum_parser.add_argument('--ports', help='Specific ports to scan (comma-separated)')
        enum_parser.add_argument('--auto-detect', action='store_true', 
                                help='Auto-detect services and adjust enumeration')
        enum_parser.add_argument('-o', '--output', help='Output directory')
        enum_parser.add_argument('--no-report', action='store_true', help='Skip automatic report generation')
        enum_parser.set_defaults(func=self.enum_handler)
        
        # Quick scan command
        quick_parser = subparsers.add_parser('quick', help='Quick enumeration for CTF')
        quick_parser.add_argument('-t', '--target', required=True, help='Target IP address')
        quick_parser.add_argument('--top-ports', type=int, default=1000, 
                                 help='Number of top ports to scan (default: 1000)')
        quick_parser.set_defaults(func=self.quick_handler)
        
        # Resume command
        resume_parser = subparsers.add_parser('resume', help='Resume previous session')
        resume_parser.add_argument('session_id', help='Session ID to resume')
        resume_parser.set_defaults(func=self.resume_handler)
        
        # Report command
        report_parser = subparsers.add_parser('report', help='Generate report')
        report_parser.add_argument('session_id', help='Session ID for report')
        report_parser.add_argument('-f', '--format', choices=['markdown', 'html', 'json', 'pdf'], 
                                  default='markdown', help='Report format')
        report_parser.add_argument('-o', '--output', help='Output file path')
        report_parser.set_defaults(func=self.report_handler)
        
        # Profiles command
        profiles_parser = subparsers.add_parser('profiles', help='Manage enumeration profiles')
        profiles_subparsers = profiles_parser.add_subparsers(dest='profiles_command')
        
        profiles_list = profiles_subparsers.add_parser('list', help='List available profiles')
        profiles_list.set_defaults(func=self.profiles_list_handler)
        
        profiles_show = profiles_subparsers.add_parser('show', help='Show profile details')
        profiles_show.add_argument('profile_name', help='Profile name to show')
        profiles_show.set_defaults(func=self.profiles_show_handler)
        
        # Sessions command
        sessions_parser = subparsers.add_parser('sessions', help='Manage sessions')
        sessions_subparsers = sessions_parser.add_subparsers(dest='sessions_command')
        
        sessions_list = sessions_subparsers.add_parser('list', help='List all sessions')
        sessions_list.set_defaults(func=self.sessions_list_handler)
        
        sessions_info = sessions_subparsers.add_parser('info', help='Show session details')
        sessions_info.add_argument('session_id', help='Session ID')
        sessions_info.set_defaults(func=self.sessions_info_handler)
        
        # Question command for HTB questions
        question_parser = subparsers.add_parser('question', help='Get help with HTB questions')
        question_parser.add_argument('query', nargs='?', help='Question or keyword to search')
        question_parser.add_argument('--list', action='store_true', help='List all available questions')
        question_parser.set_defaults(func=self.question_handler)
        
        # Tor OSINT command
        tor_parser = subparsers.add_parser('tor-osint', help='Tor/Dark Web OSINT for defensive security')
        tor_parser.add_argument('-t', '--target', required=True, help='Target domain to research')
        tor_parser.add_argument('-k', '--keywords', nargs='+', 
                               default=['password', 'leak', 'breach', 'database'],
                               help='Keywords to search for (default: password leak breach database)')
        tor_parser.add_argument('--use-tor', action='store_true', 
                               help='Enable Tor for anonymous research')
        tor_parser.add_argument('--check-hibp', action='store_true',
                               help='Check Have I Been Pwned for breaches')
        tor_parser.add_argument('--check-shodan', action='store_true',
                               help='Check Shodan for exposed services')
        tor_parser.add_argument('--report-format', choices=['markdown', 'html', 'json', 'executive'],
                               default='markdown', help='Report format (default: markdown)')
        tor_parser.add_argument('--executive-report', action='store_true',
                               help='Also generate executive summary')
        tor_parser.add_argument('--include-opsec', action='store_true',
                               help='Include OPSEC guidelines in output')
        tor_parser.add_argument('--slack-alerts', action='store_true',
                               help='Send Slack alerts for high-risk findings')
        tor_parser.add_argument('--create-tickets', action='store_true',
                               help='Create Jira tickets for critical findings')
        tor_parser.add_argument('--export-stix', action='store_true',
                               help='Export findings in STIX format')
        tor_parser.add_argument('-o', '--output', help='Output directory (default: current)')
        tor_parser.set_defaults(func=self.tor_osint_handler)
        
        return parser
    
    def enum_handler(self, args):
        """Handle enumeration command"""
        # Validate IP address
        if not InputValidator.validate_ip(args.target):
            print(f"{Colors.RED}[-] Invalid IP address: {args.target}{Colors.END}")
            sys.exit(1)
        
        # Validate ports if provided
        if args.ports and not InputValidator.validate_port(args.ports):
            print(f"{Colors.RED}[-] Invalid port specification: {args.ports}{Colors.END}")
            sys.exit(1)
        
        # Auto-detect machine name from current directory if not provided
        if not args.name:
            current_dir = os.path.basename(os.getcwd())
            # Check if we're in a machine directory
            parent_dir = os.path.basename(os.path.dirname(os.getcwd()))
            if parent_dir in ['Machines', 'StartingPoint', 'Easy', 'Medium', 'Hard', 'Insane']:
                args.name = current_dir
                print(f"{Colors.GREEN}[+] Auto-detected machine name: {args.name}{Colors.END}")
            else:
                print(f"{Colors.RED}[-] Could not auto-detect machine name. Please provide -n NAME{Colors.END}")
                sys.exit(1)
        
        # Validate machine name
        if not InputValidator.validate_machine_name(args.name):
            print(f"{Colors.RED}[-] Invalid machine name. Use only alphanumeric, dash, and underscore{Colors.END}")
            sys.exit(1)
        
        print(f"{Colors.BLUE}[*] Starting enumeration for {args.name} ({args.target}){Colors.END}")
        
        # Set output directory to current directory if not specified
        if not args.output:
            args.output = os.getcwd()
        
        # Create session
        session_id = self.session_manager.create_session(
            target=args.target,
            name=args.name,
            profile=args.profile
        )
        
        print(f"{Colors.GREEN}[+] Session created: {session_id}{Colors.END}")
        
        # Save session ID for quick access
        with open('.last_session', 'w') as f:
            f.write(session_id)
        
        # Start enumeration
        self.enum_controller.start_enumeration(
            session_id=session_id,
            target=args.target,
            name=args.name,
            profile=args.profile,
            ports=args.ports,
            auto_detect=args.auto_detect,
            output_dir=args.output
        )
        
        # Generate report automatically unless --no-report is specified
        if not args.no_report:
            print(f"\n{Colors.BLUE}[*] Generating enumeration report...{Colors.END}")
            report_file = os.path.join(args.output, f"{args.name}_enum.md")
            
            success = self.report_generator.generate_report(
                session_id=session_id,
                format='markdown',
                output_file=report_file
            )
            
            if success:
                print(f"{Colors.GREEN}[+] Report saved to: {report_file}{Colors.END}")
                
                # Also save a commands log
                commands_file = os.path.join(args.output, f"{args.name}_commands.txt")
                self._save_commands_log(session_id, commands_file)
                print(f"{Colors.GREEN}[+] Commands log saved to: {commands_file}{Colors.END}")
    
    def quick_handler(self, args):
        """Handle quick scan command"""
        # Validate IP address
        if not InputValidator.validate_ip(args.target):
            print(f"{Colors.RED}[-] Invalid IP address: {args.target}{Colors.END}")
            sys.exit(1)
        
        print(f"{Colors.BLUE}[*] Starting quick scan for {args.target}{Colors.END}")
        
        # Create quick session
        session_id = self.session_manager.create_session(
            target=args.target,
            name=f"quick_{args.target}",
            profile="quick"
        )
        
        # Run quick enumeration
        self.enum_controller.quick_enumeration(
            session_id=session_id,
            target=args.target,
            top_ports=args.top_ports
        )
    
    def resume_handler(self, args):
        """Handle resume command"""
        print(f"{Colors.BLUE}[*] Resuming session: {args.session_id}{Colors.END}")
        
        session = self.session_manager.get_session(args.session_id)
        if not session:
            print(f"{Colors.RED}[-] Session not found: {args.session_id}{Colors.END}")
            return
        
        self.enum_controller.resume_enumeration(args.session_id)
    
    def report_handler(self, args):
        """Handle report generation command"""
        print(f"{Colors.BLUE}[*] Generating {args.format} report for session: {args.session_id}{Colors.END}")
        
        output_file = args.output or f"report_{args.session_id}.{args.format}"
        
        success = self.report_generator.generate_report(
            session_id=args.session_id,
            format=args.format,
            output_file=output_file
        )
        
        if success:
            print(f"{Colors.GREEN}[+] Report generated: {output_file}{Colors.END}")
        else:
            print(f"{Colors.RED}[-] Failed to generate report{Colors.END}")
            sys.exit(1)
    
    def profiles_list_handler(self, args):
        """Handle profiles list command"""
        profiles = self.enum_controller.get_available_profiles()
        
        print(f"\n{Colors.BOLD}Available Enumeration Profiles:{Colors.END}\n")
        for profile in profiles:
            print(f"  {Colors.CYAN}{profile['name']:<15}{Colors.END} - {profile['description']}")
    
    def profiles_show_handler(self, args):
        """Handle profiles show command"""
        profile = self.enum_controller.get_profile_details(args.profile_name)
        
        if not profile:
            print(f"{Colors.RED}[-] Profile not found: {args.profile_name}{Colors.END}")
            sys.exit(1)
        
        print(f"\n{Colors.BOLD}Profile: {profile['name']}{Colors.END}")
        print(f"Description: {profile['description']}")
        print(f"\nModules:")
        for module in profile['modules']:
            print(f"  - {module}")
    
    def sessions_list_handler(self, args):
        """Handle sessions list command"""
        sessions = self.session_manager.list_sessions()
        
        if not sessions:
            print(f"{Colors.YELLOW}[!] No sessions found{Colors.END}")
            return
        
        print(f"\n{Colors.BOLD}Active Sessions:{Colors.END}\n")
        print(f"{'ID':<15} {'Target':<15} {'Name':<20} {'Profile':<15} {'Status':<10} {'Created'}")
        print("-" * 90)
        
        for session in sessions:
            print(f"{session['id']:<15} {session['target']:<15} {session['name']:<20} "
                  f"{session['profile']:<15} {session['status']:<10} {session['created']}")
    
    def sessions_info_handler(self, args):
        """Handle sessions info command"""
        session = self.session_manager.get_session(args.session_id)
        
        if not session:
            print(f"{Colors.RED}[-] Session not found: {args.session_id}{Colors.END}")
            return
        
        print(f"\n{Colors.BOLD}Session Details:{Colors.END}")
        print(json.dumps(session, indent=2))
    
    def _save_commands_log(self, session_id, output_file):
        """Save all executed commands to a file"""
        session = self.session_manager.get_session(session_id)
        if not session:
            return
        
        with open(output_file, 'w') as f:
            f.write(f"# Commands executed for {session['name']} ({session['target']})\n")
            f.write(f"# Session: {session_id}\n")
            f.write(f"# Date: {session['created']}\n\n")
            
            for module, findings in session.get('findings', {}).items():
                f.write(f"\n## {module.upper()}\n\n")
                for finding in findings:
                    data = finding['data']
                    if isinstance(data, dict) and 'command' in data:
                        f.write(f"{data['command']}\n")
    
    def question_handler(self, args):
        """Handle HTB questions"""
        if args.list:
            self.htb_questions.list_questions()
            return
        
        if not args.query:
            print(f"{Colors.YELLOW}Usage:{Colors.END}")
            print("  cyba-htb question 'admin id'")
            print("  cyba-htb question --list")
            print("\nTry searching for a keyword from the HTB question.")
            return
        
        # Search for matching questions
        matches = self.htb_questions.search_question(args.query)
        
        if not matches:
            print(f"{Colors.RED}No questions found matching '{args.query}'{Colors.END}")
            print(f"\n{Colors.YELLOW}Tip:{Colors.END} Use 'cyba-htb question --list' to see all available questions")
            return
            
        if len(matches) == 1:
            # Show the single match
            self.htb_questions.display_help(matches[0][0])
        else:
            # Multiple matches, let user choose
            print(f"\n{Colors.CYAN}Multiple questions found:{Colors.END}")
            for i, (key, data) in enumerate(matches, 1):
                print(f"  {i}. {data['question']}")
            
            print(f"\n{Colors.YELLOW}Showing first match:{Colors.END}")
            self.htb_questions.display_help(matches[0][0])
            
    def tor_osint_handler(self, args):
        """Handle Tor OSINT command"""
        from enumeration.modules.tor_osint import TorOSINTModule
        
        # Validate domain
        if not InputValidator.validate_domain(args.target):
            print(f"{Colors.RED}[-] Invalid domain: {args.target}{Colors.END}")
            sys.exit(1)
            
        print(f"{Colors.BLUE}[*] Starting Tor OSINT research for {args.target}{Colors.END}")
        print(f"{Colors.YELLOW}[!] This is for defensive security research only{Colors.END}")
        print(f"{Colors.YELLOW}[!] Ensure you have authorization for the target domain{Colors.END}")
        
        # Set output directory
        output_dir = args.output or os.getcwd()
        os.makedirs(output_dir, exist_ok=True)
        
        # Create a session for tracking
        session_id = self.session_manager.create_session(
            target=args.target,
            name=f"tor_osint_{args.target.replace('.', '_')}",
            profile='tor_osint'
        )
        
        # Initialize module
        tor_module = TorOSINTModule()
        
        # Prepare kwargs
        kwargs = {
            'keywords': args.keywords,
            'use_tor': args.use_tor,
            'check_hibp': args.check_hibp,
            'check_shodan': args.check_shodan,
            'report_format': args.report_format,
            'generate_executive_report': args.executive_report,
            'include_opsec': args.include_opsec,
            'include_recommendations': True,
            'slack_alerts': args.slack_alerts,
            'create_tickets': args.create_tickets,
            'export_stix': args.export_stix,
            'send_to_siem': False  # Can be enabled via config
        }
        
        # Run the module
        try:
            results = tor_module.run(args.target, session_id, output_dir, **kwargs)
            
            # Display results summary
            if 'error' in results:
                print(f"{Colors.RED}[-] Error: {results['error']}{Colors.END}")
            else:
                findings = results.get('findings', {})
                summary = findings.get('summary', {})
                
                print(f"\n{Colors.GREEN}[+] Tor OSINT scan completed{Colors.END}")
                print(f"{Colors.BLUE}[*] Risk Level: {summary.get('risk_level', 'Unknown')}{Colors.END}")
                print(f"{Colors.BLUE}[*] Data Leaks Found: {summary.get('data_leaks_found', 0)}{Colors.END}")
                print(f"{Colors.BLUE}[*] Threats Detected: {summary.get('threats_detected', 0)}{Colors.END}")
                
                if results.get('tor_enabled'):
                    print(f"{Colors.GREEN}[+] Tor was used (Exit IP: {results.get('tor_exit_ip', 'Unknown')}){Colors.END}")
                else:
                    print(f"{Colors.YELLOW}[!] Tor was not used (clearnet only){Colors.END}")
                    
                # Display report locations
                if results.get('report_path'):
                    print(f"\n{Colors.GREEN}[+] Main report: {results['report_path']}{Colors.END}")
                if results.get('executive_report_path'):
                    print(f"{Colors.GREEN}[+] Executive report: {results['executive_report_path']}{Colors.END}")
                if results.get('safety_report_path'):
                    print(f"{Colors.GREEN}[+] Safety report: {results['safety_report_path']}{Colors.END}")
                if results.get('opsec_guide_path'):
                    print(f"{Colors.GREEN}[+] OPSEC guide: {results['opsec_guide_path']}{Colors.END}")
                if results.get('stix_export_path'):
                    print(f"{Colors.GREEN}[+] STIX export: {results['stix_export_path']}{Colors.END}")
                    
                # Display integration results
                integrations = results.get('integrations', {})
                if integrations:
                    print(f"\n{Colors.BLUE}[*] Integration Results:{Colors.END}")
                    if 'slack' in integrations and integrations['slack'].get('alert_sent'):
                        print(f"{Colors.GREEN}[+] Slack alert sent{Colors.END}")
                    if 'jira' in integrations and integrations['jira'].get('ticket_created'):
                        print(f"{Colors.GREEN}[+] Jira ticket created: {integrations['jira']['ticket_key']}{Colors.END}")
                    if 'siem' in integrations and integrations['siem'].get('sent'):
                        print(f"{Colors.GREEN}[+] SIEM events sent: {integrations['siem']['events_count']}{Colors.END}")
                
                # Update session with results
                self.session_manager.update_session(session_id, 'tor_osint', results)
                
        except Exception as e:
            print(f"{Colors.RED}[-] Error during Tor OSINT research: {e}{Colors.END}")
            sys.exit(1)
        finally:
            # Cleanup
            tor_module.cleanup()

if __name__ == '__main__':
    app = CybaHTB()
    try:
        app.main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[-] Error: {str(e)}{Colors.END}")
        sys.exit(1)