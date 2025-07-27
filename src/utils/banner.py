"""
Banner display for cyba-Inspector
"""

from utils.colors import Colors

def display_banner():
    banner = f"""
{Colors.CYAN}
   ______     __          __  __________  ____ 
  / ____/  __/ /_  ____ _/ / / /_  __/ / / __ )
 / /   / / / / __ \/ __ `/ /_/ / / / / / / __ |
/ /___/ /_/ / /_/ / /_/ / __  / / / / / / /_/ /
\____/\__, /_.___/\__,_/_/ /_/ /_/ /_/ /_____/ 
     /____/                                     
{Colors.END}
{Colors.BOLD}Specialized HTB Enumeration & Analysis Tool{Colors.END}
{Colors.DIM}Version 1.0.0 | Created for CPTS preparation{Colors.END}
"""
    print(banner)