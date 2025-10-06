import tkinter as tk
from tkinter import messagebox
import ctypes
import os
import sys
from gui.main_window import CyberSecurityTool

def is_admin():
    """Checks for administrator privileges required for packet sniffing."""
    try:
        # For Windows
        return ctypes.windll.shell32.IsUserAnAdmin()
    except AttributeError:
        # For Linux/macOS
        return os.getuid() == 0

def main():
    """Initializes and runs the application after checking permissions."""
    if not is_admin():
        root = tk.Tk()
        root.withdraw()  # Hide the main Tkinter window
        messagebox.showerror("Permission Error", "This application needs administrator/root privileges to capture network packets.")
        root.destroy()
        sys.exit("Permission denied. Please run as administrator.")

    root = tk.Tk()
    app = CyberSecurityTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()