"""
Color codes for terminal output
"""

class Colors:
    # Colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Bright colors
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    
    # Formatting
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    HIDDEN = '\033[8m'
    STRIKETHROUGH = '\033[9m'
    
    # Reset
    END = '\033[0m'
    RESET = '\033[0m'
    
    @staticmethod
    def success(text):
        return f"{Colors.GREEN}{text}{Colors.END}"
    
    @staticmethod
    def error(text):
        return f"{Colors.RED}{text}{Colors.END}"
    
    @staticmethod
    def warning(text):
        return f"{Colors.YELLOW}{text}{Colors.END}"
    
    @staticmethod
    def info(text):
        return f"{Colors.BLUE}{text}{Colors.END}"
    
    @staticmethod
    def bold(text):
        return f"{Colors.BOLD}{text}{Colors.END}"