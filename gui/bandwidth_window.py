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
        
        # Data storage for graphs
        self.timestamps = deque(maxlen=60)
        self.bandwidth_data = deque(maxlen=60)
        self.packet_rates = deque(maxlen=60)
        
        # Previous values for rate calculation
        self.prev_packet_count = 0
        self.prev_byte_count = 0
        self.prev_time = datetime.datetime.now()
        
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
        bandwidth_frame = ttk.LabelFrame(charts_frame, text="Bandwidth Usage Over Time")
        bandwidth_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        self.bandwidth_fig, self.bandwidth_ax = plt.subplots(figsize=(8, 3), dpi=100)
        self.bandwidth_fig.patch.set_facecolor(colors["bg"])
        self.bandwidth_ax.set_facecolor(colors["text_bg"])
        self.bandwidth_canvas = FigureCanvasTkAgg(self.bandwidth_fig, master=bandwidth_frame)
        self.bandwidth_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Packet Rate Chart
        packet_frame = ttk.LabelFrame(charts_frame, text="Packet Rate Over Time")
        packet_frame.pack(fill=tk.BOTH, expand=True)
        
        self.packet_fig, self.packet_ax = plt.subplots(figsize=(8, 3), dpi=100)
        self.packet_fig.patch.set_facecolor(colors["bg"])
        self.packet_ax.set_facecolor(colors["text_bg"])
        self.packet_canvas = FigureCanvasTkAgg(self.packet_fig, master=packet_frame)
        self.packet_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def _update_data(self):
        """Update bandwidth and packet rate data"""
        if not self.monitor.monitoring:
            return
        
        current_time = datetime.datetime.now()
        time_diff = (current_time - self.prev_time).total_seconds()
        
        if time_diff < 0.1:  # Avoid division by zero
            return
        
        stats = self.monitor.get_stats()
        current_packet_count = stats.get('packet_count', 0)
        current_byte_count = stats.get('total_bytes', 0)

        # Calculate packet rate
        packet_diff = current_packet_count - self.prev_packet_count
        packet_rate = packet_diff / time_diff if time_diff > 0 else 0
        
        # Calculate actual bandwidth
        byte_diff = current_byte_count - self.prev_byte_count
        bandwidth_kbs = (byte_diff / 1024) / time_diff if time_diff > 0 else 0

        # Store data
        self.timestamps.append(current_time.strftime("%H:%M:%S"))
        self.bandwidth_data.append(bandwidth_kbs)
        self.packet_rates.append(packet_rate)
        
        # Update previous values
        self.prev_packet_count = current_packet_count
        self.prev_byte_count = current_byte_count
        self.prev_time = current_time
        
        # Update statistics display
        self._update_stats(packet_rate, bandwidth_kbs)
        
        # Update charts
        self._update_charts()
    
    def _update_stats(self, packet_rate, bandwidth):
        """Update statistics text"""
        stats = self.monitor.get_stats()
        
        avg_bandwidth = sum(self.bandwidth_data) / len(self.bandwidth_data) if self.bandwidth_data else 0
        avg_packet_rate = sum(self.packet_rates) / len(self.packet_rates) if self.packet_rates else 0
        max_bandwidth = max(self.bandwidth_data) if self.bandwidth_data else 0
        
        stats_display = f"""Current Packet Rate: {packet_rate:.2f} packets/s
Current Bandwidth: {bandwidth:.2f} KB/s
Average Bandwidth: {avg_bandwidth:.2f} KB/s
Peak Bandwidth: {max_bandwidth:.2f} KB/s
Total Data: {stats.get('total_bytes', 0) / (1024*1024):.2f} MB"""
        
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, stats_display)
    
    def _update_charts(self):
        """Update bandwidth and packet rate charts"""
        colors = THEME_COLORS[self.current_theme]
        text_color = colors['fg']
        
        # Update Bandwidth Chart
        self.bandwidth_ax.clear()
        if len(self.bandwidth_data) > 1:
            self.bandwidth_ax.plot(
                list(self.bandwidth_data),
                color=colors['highlight'],
                linewidth=2
            )
            self.bandwidth_ax.set_ylabel('KB/s', color=text_color)
            self.bandwidth_ax.set_xlabel('Time (last 60 seconds)', color=text_color)
            self.bandwidth_ax.tick_params(colors=text_color)
            self.bandwidth_ax.grid(True, alpha=0.3)
            self.bandwidth_ax.set_facecolor(colors['text_bg'])
        
        self.bandwidth_canvas.draw()
        
        # Update Packet Rate Chart
        self.packet_ax.clear()
        if len(self.packet_rates) > 1:
            self.packet_ax.plot(
                list(self.packet_rates),
                color='#00ff00',
                linewidth=2
            )
            self.packet_ax.set_ylabel('Packets/s', color=text_color)
            self.packet_ax.set_xlabel('Time (last 60 seconds)', color=text_color)
            self.packet_ax.tick_params(colors=text_color)
            self.packet_ax.grid(True, alpha=0.3)
            self.packet_ax.set_facecolor(colors['text_bg'])
        
        self.packet_canvas.draw()
    
    def _update_loop(self):
        """Periodic update loop"""
        if self.window.winfo_exists():
            self._update_data()
            self.window.after(1000, self._update_loop)  # Update every second