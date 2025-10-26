import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import socket
import threading
import datetime

from monitoring.monitor import NetworkMonitor
from utils.constants import VERSION, THEME_COLORS
from scapy.all import sniff, IP, TCP, UDP, ICMP

class CyberSecurityTool:
    def __init__(self, root):
        self.root = root
        self.root.title(f"Realtime Network Threat Detection v{VERSION}")
        self.root.geometry("1200x800")
        self.current_theme = "purple"
        self.monitor = NetworkMonitor()
        self.capture_running = False
        self.capture_thread = None

        self._setup_menu()
        self._setup_theme()
        self._setup_main_frame()
        self._setup_dashboard()
        self._setup_status_bar()
        self._update_stats_loop()

    def _setup_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File Menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Export Data", command=self._export_data)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        # Tools Menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Port Scanner", command=self._show_port_scanner)
        tools_menu.add_command(label="Packet Analyzer", command=self._show_packet_analyzer)
        tools_menu.add_separator()
        tools_menu.add_command(label="Bandwidth Monitor", command=self._show_bandwidth_monitor)
        menubar.add_cascade(label="Tools", menu=tools_menu)

        # Advanced Menu
        advanced_menu = tk.Menu(menubar, tearoff=0)
        advanced_menu.add_command(label="Threat Intelligence", command=self._show_threat_intel)
        advanced_menu.add_command(label="Firewall Manager", command=self._show_firewall)
        advanced_menu
