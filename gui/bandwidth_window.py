"""
Bandwidth Monitor Window
Real-time bandwidth usage visualization
"""

import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import deque
import datetime
from utils.constants import THEME_COLORS


class BandwidthWindow:
    """Window for bandwidth monitoring"""
    
    def __init__(self, parent, monitor):
        self.monitor = monitor
        self.window = tk.Toplevel(parent)
        self.window.title("Bandwidth Monitor")
        self.window.geometry("900x600")
        
        self.current_theme = "purple"
        
        # Data storage
        self.timestamps = deque(maxlen=60)
        self.bandwidth_data = deque(maxlen=60)
        self.packet_rates = deque(maxlen=60)
        
        self._setup_ui()
        self._update_loop()
    
    def _setup_ui(self):
        """Setup the UI components"""
        colors = THEME_COLORS[self.current_theme]
        self.window.config(bg=colors["bg"])
        
        # Title
        title_frame = ttk.Frame(self.window)
        title_frame.pack(fill=tk.X, padx=10, pady=10)
        
        title_label = ttk.Label(
            title_frame,
            text="📊 Bandwidth Monitor",
            font=("Consolas", 16, "bold")
        )
        title_label.pack(side=tk.LEFT)
        
        # Statistics Frame
        stats_frame = ttk.LabelFrame(self.window, text="Current Statistics")
        stats_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.stats_text = tk.Text(
            stats_frame,
            height=5,
            font=("Consolas", 10),
            bg=colors["text_bg"],
            fg=colors["text_fg"]
        )
        self.stats_text.pack(fill=tk.X, padx=5, pady=5)
        
        # Charts Container
        charts_frame = ttk.Frame(self.window)
        charts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Bandwidth Chart
        bandwidth_frame = ttk.LabelFrame(charts_frame, text="Bandwidth Usage (KB/s)")
        bandwidth_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        self.bandwidth_fig, self.bandwidth_ax = plt.subplots(figsize=(8, 3), dpi=100)
        self.bandwidth_fig.patch.set_facecolor(colors["bg"])
        self.bandwidth_ax.set_facecolor(colors["text_bg"])
        self.bandwidth_canvas = FigureCanvasTkAgg(self.bandwidth_fig, master=bandwidth_frame)
        self.bandwidth_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Packet Rate Chart
        packet_frame = ttk.LabelFrame(charts_frame, text="Packet Rate (packets/s)")
        packet_frame.pack(fill=tk.BOTH, expand=True)
        
        self.packet_fig, self.packet_ax = plt.subplots(figsize=(8, 3), dpi=100)
        self.packet_fig.patch.set_facecolor(colors["bg"])
        self.packet_ax.set_facecolor(colors["text_bg"])
        self.packet_canvas = FigureCanvasTkAgg(self.packet_fig, master=packet_frame)
        self.packet_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def _update
