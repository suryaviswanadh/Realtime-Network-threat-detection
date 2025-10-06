import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import socket
import threading
import platform
import subprocess
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
        self._setup_terminal()
        self._setup_status_bar()
        self._update_stats_loop()

    def _setup_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Export Data", command=self._export_data)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Port Scanner", command=self._show_port_scanner)
        tools_menu.add_command(label="Packet Analyzer", command=self._show_packet_analyzer)
        menubar.add_cascade(label="Tools", menu=tools_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

    def _setup_theme(self):
        colors = THEME_COLORS[self.current_theme]
        style = ttk.Style()
        self.root.config(bg=colors["bg"])
        style.theme_create("cyber_theme", parent="alt", settings={
            "TFrame": {"configure": {"background": colors["bg"]}},
            "TLabel": {"configure": {"background": colors["bg"], "foreground": colors["fg"], "font": ("Consolas", 10)}},
            "TButton": {"configure": {"background": colors["button_bg"], "foreground": colors["button_fg"], "font": ("Consolas", 10), "padding": 5},
                        "map": {"background": [("active", colors["highlight"])]}},
            "TEntry": {"configure": {"fieldbackground": colors["text_bg"], "foreground": colors["text_fg"], "insertcolor": colors["fg"], "font": ("Consolas", 10)}},
        })
        style.theme_use("cyber_theme")

    def _setup_main_frame(self):
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.rowconfigure(1, weight=1)

    def _setup_dashboard(self):
        frame = self.main_frame
        
        # Controls Frame
        controls_frame = ttk.Frame(frame)
        controls_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        ttk.Label(controls_frame, text="Target IP:").pack(side=tk.LEFT, padx=(0, 5))
        self.ip_entry = ttk.Entry(controls_frame, width=20)
        self.ip_entry.pack(side=tk.LEFT, padx=5)
        self.start_btn = ttk.Button(controls_frame, text="Start Monitoring", command=self._start_monitoring)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = ttk.Button(controls_frame, text="Stop Monitoring", command=self._stop_monitoring, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Main Content PanedWindow
        paned_window = ttk.PanedWindow(frame, orient=tk.HORIZONTAL)
        paned_window.grid(row=1, column=0, sticky="nsew")

        # Left Panel (Stats and Logs)
        left_panel = ttk.Frame(paned_window)
        left_panel.rowconfigure(1, weight=1)
        left_panel.columnconfigure(0, weight=1)
        paned_window.add(left_panel, weight=1)

        stats_lf = ttk.LabelFrame(left_panel, text="Live Statistics")
        stats_lf.grid(row=0, column=0, sticky="nsew", pady=(0, 5))
        stats_lf.columnconfigure(0, weight=1)
        self.stats_text = tk.Text(stats_lf, font=("Consolas", 10), wrap=tk.WORD, height=10, bg=THEME_COLORS[self.current_theme]["text_bg"], fg=THEME_COLORS[self.current_theme]["text_fg"])
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        log_lf = ttk.LabelFrame(left_panel, text="Security Alerts")
        log_lf.grid(row=1, column=0, sticky="nsew")
        log_lf.columnconfigure(0, weight=1)
        log_lf.rowconfigure(0, weight=1)
        self.log_text = scrolledtext.ScrolledText(log_lf, font=("Consolas", 9), wrap=tk.WORD, bg=THEME_COLORS[self.current_theme]["text_bg"], fg=THEME_COLORS[self.current_theme]["text_fg"])
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Right Panel (Charts)
        right_panel = ttk.Frame(paned_window)
        paned_window.add(right_panel, weight=1)
        right_panel.rowconfigure(0, weight=1)
        right_panel.rowconfigure(1, weight=1)
        right_panel.columnconfigure(0, weight=1)

        self.threat_chart_frame = ttk.LabelFrame(right_panel, text="Threat Distribution")
        self.threat_chart_frame.grid(row=0, column=0, sticky="nsew", pady=(0, 5))
        self.protocol_chart_frame = ttk.LabelFrame(right_panel, text="Protocol Distribution")
        self.protocol_chart_frame.grid(row=1, column=0, sticky="nsew")

    def _setup_terminal(self):
        # Terminal will be a tool window now
        pass

    def _setup_status_bar(self):
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def _start_monitoring(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Error", "Please provide a target IP address.")
            return
        try:
            socket.inet_aton(ip)
            self.monitor.start_monitoring(ip)
            self.start_btn.config(state=tk.DISABLED); self.stop_btn.config(state=tk.NORMAL)
            self.status_var.set(f"Monitoring {ip}")
        except socket.error:
            messagebox.showerror("Error", "Invalid IP address format.")
        
    def _stop_monitoring(self):
        self.monitor.stop_monitoring()
        self.start_btn.config(state=tk.NORMAL); self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("Monitoring stopped.")
        
    def _update_stats_loop(self):
        if self.monitor.monitoring:
            stats = self.monitor.get_stats()
            self.stats_text.delete(1.0, tk.END)
            stats_display = (f"Uptime: {stats['uptime']}\n"
                             f"Packets Captured: {stats['packet_count']}\n"
                             f"Threats Detected: {stats['threats_detected']}\n"
                             f"  - DoS Attacks: {stats['dos_count']}\n"
                             f"  - Port Scans: {stats['port_scan_count']}\n\n"
                             "Top Source IPs:\n" + "\n".join([f"  - {ip}: {count} pkts" for ip, count in stats['top_ips'].items()]))
            self.stats_text.insert(tk.END, stats_display)
            self._update_charts(stats); self._update_alerts()
        self.root.after(2000, self._update_stats_loop)
            
    def _update_charts(self, stats):
        bg_color = THEME_COLORS[self.current_theme]['bg']
        text_color = THEME_COLORS[self.current_theme]['fg']
        
        # Threat Chart
        for widget in self.threat_chart_frame.winfo_children(): widget.destroy()
        if stats['threats_detected'] > 0:
            labels = ['DoS', 'Port Scans']
            sizes = [stats['dos_count'], stats['port_scan_count']]
            fig1, ax1 = plt.subplots(figsize=(5, 3), dpi=100, facecolor=bg_color)
            ax1.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, textprops={'color': text_color})
            ax1.axis('equal')
            FigureCanvasTkAgg(fig1, master=self.threat_chart_frame).get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
        # Protocol Chart
        for widget in self.protocol_chart_frame.winfo_children(): widget.destroy()
        if self.monitor.packet_count > 0:
            ps = stats['packet_stats']
            labels = ['TCP', 'UDP', 'ICMP']
            sizes = [ps.get('tcp',0), ps.get('udp',0), ps.get('icmp',0)]
            fig2, ax2 = plt.subplots(figsize=(5, 3), dpi=100, facecolor=bg_color)
            ax2.bar(labels, sizes, color=THEME_COLORS[self.current_theme]['highlight'])
            ax2.tick_params(colors=text_color)
            ax2.set_ylabel('Packets', color=text_color)
            ax2.set_facecolor(THEME_COLORS[self.current_theme]['text_bg'])
            FigureCanvasTkAgg(fig2, master=self.protocol_chart_frame).get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def _update_alerts(self):
        try:
            with open(self.monitor.log_file, "r") as f: content = f.read()
            current_log = self.log_text.get(1.0, tk.END)
            if content != current_log:
                self.log_text.delete(1.0, tk.END)
                self.log_text.insert(tk.END, content)
                self.log_text.see(tk.END)
        except FileNotFoundError:
            pass # Log file not created yet
        except Exception as e:
            print(f"Error reading log file: {e}")
            
    def _export_data(self):
        if not self.monitor.monitoring and self.monitor.packet_count == 0:
            messagebox.showwarning("Export Data", "No data to export. Start monitoring first.")
            return
        filename = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if filename:
            if self.monitor.export_data(filename): messagebox.showinfo("Success", "Live data snapshot exported successfully.")
            else: messagebox.showerror("Error", "Failed to export data.")
                
    def _show_port_scanner(self):
        win = tk.Toplevel(self.root); win.title("Port Scanner"); win.geometry("500x400")
        top_frame = ttk.Frame(win); top_frame.pack(fill=tk.X, pady=5, padx=5)
        ttk.Label(top_frame, text="Target IP:").pack(side=tk.LEFT)
        ip_entry = ttk.Entry(top_frame, width=15); ip_entry.pack(side=tk.LEFT, padx=5)
        ttk.Label(top_frame, text="Ports:").pack(side=tk.LEFT)
        start_port = ttk.Entry(top_frame, width=6); start_port.pack(side=tk.LEFT, padx=2); start_port.insert(0, "1")
        end_port = ttk.Entry(top_frame, width=6); end_port.pack(side=tk.LEFT, padx=2); end_port.insert(0, "1024")
        
        results = scrolledtext.ScrolledText(win, bg=THEME_COLORS[self.current_theme]["text_bg"], fg=THEME_COLORS[self.current_theme]["text_fg"])
        results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        scan_btn = ttk.Button(top_frame, text="Start Scan", command=lambda: self._run_port_scan(ip_entry.get(), start_port.get(), end_port.get(), results))
        scan_btn.pack(side=tk.LEFT, padx=5)

    def _run_port_scan(self, ip, start, end, results_widget):
        try:
            socket.inet_aton(ip); start, end = int(start), int(end)
            if not (1 <= start <= end <= 65535): raise ValueError("Invalid Port Range")
            results_widget.delete(1.0, tk.END); results_widget.insert(tk.END, f"Scanning {ip} ports {start}-{end}...\n")
            threading.Thread(target=self._perform_port_scan, args=(ip, start, end, results_widget), daemon=True).start()
        except (socket.error, ValueError) as e: messagebox.showerror("Error", f"Invalid input: {e}")

    def _perform_port_scan(self, ip, start, end, results_widget):
        open_ports = 0
        for port in range(start, end + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((ip, port)) == 0:
                        open_ports += 1
                        service = "unknown"
                        try: service = socket.getservbyport(port, 'tcp')
                        except OSError: pass
                        results_widget.insert(tk.END, f"Port {port} ({service}) is open\n")
            except Exception: continue
        results_widget.insert(tk.END, f"\nScan complete. Found {open_ports} open ports.\n")

    def _show_packet_analyzer(self):
        win = tk.Toplevel(self.root); win.title("Packet Analyzer"); win.geometry("800x600")
        top_frame = ttk.Frame(win); top_frame.pack(fill=tk.X, pady=5, padx=5)
        ttk.Label(top_frame, text="BPF Filter:").pack(side=tk.LEFT, padx=5)
        filter_entry = ttk.Entry(top_frame, width=30); filter_entry.pack(side=tk.LEFT, padx=5)
        
        results = scrolledtext.ScrolledText(win, bg=THEME_COLORS[self.current_theme]["text_bg"], fg=THEME_COLORS[self.current_theme]["text_fg"])
        results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        start_btn = ttk.Button(top_frame, text="Start Capture", command=lambda: self._start_capture(filter_entry.get(), start_btn, stop_btn, results))
        start_btn.pack(side=tk.LEFT, padx=5)
        stop_btn = ttk.Button(top_frame, text="Stop Capture", command=lambda: self._stop_capture(start_btn, stop_btn), state=tk.DISABLED)
        stop_btn.pack(side=tk.LEFT, padx=5)

    def _start_capture(self, filter_str, start_btn, stop_btn, results):
        if self.capture_running: return
        start_btn.config(state=tk.DISABLED); stop_btn.config(state=tk.NORMAL)
        results.delete(1.0, tk.END)
        self.capture_running = True
        self.capture_thread = threading.Thread(
            target=lambda: sniff(prn=lambda pkt: self._process_packet(pkt, results), filter=filter_str, store=False, stop_filter=lambda p: not self.capture_running),
            daemon=True
        )
        self.capture_thread.start()

    def _stop_capture(self, start_btn, stop_btn):
        self.capture_running = False
        start_btn.config(state=tk.NORMAL); stop_btn.config(state=tk.DISABLED)
        if self.capture_thread:
            self.capture_thread.join(timeout=1.0)

    def _process_packet(self, packet, results):
        if IP in packet:
            proto = packet.sprintf('%IP.proto%')
            info = f"{datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]} | {packet[IP].src} -> {packet[IP].dst} | {proto}\n"
            results.insert(tk.END, info)
            results.see(tk.END)

    def _show_about(self):
        messagebox.showinfo("About", f"Realtime Network Threat Detection v{VERSION}\n\nAn educational tool for demonstrating network monitoring and threat detection concepts.")