import tkinter as tk
from gui.main_window import CyberSecurityTool

def main():
    """Initializes and runs the application."""
    root = tk.Tk()
    app = CyberSecurityTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()