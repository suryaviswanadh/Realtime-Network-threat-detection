import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext # Added filedialog
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import socket
import threading
import datetime
import queue
from pathlib import Path

from monitoring.monitor import NetworkMonitor
from utils.constants import VERSION, THEME_COLORS
from utils.helpers import format_bytes
from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap # <--- Added wrpcap

# Ensure Matplotlib uses the Agg backend for Tkinter compatibility
import matplotlib
matplotlib.use('Agg')

class CyberSecurityTool:
    def __init__(self, root):
        self.root = root
        self.root.title(f"Realtime Network Threat Detection v{VERSION}")
        self.root.geometry("1200x800")
        self.current_theme = "purple"
        self.monitor = NetworkMonitor()
        self.capture_running = False # Flag for main monitor capture (DEPRECATED - use monitor.monitoring)
        self.analyzer_capture_running = False # Separate flag for analyzer capture
        self.capture_thread = None # For analyzer

        # Thread-safe queues
        self.packet_analyzer_queue = queue.Queue()
        self.port_scan_queue = queue.Queue()
        self.port_scan_running = False

        # For efficient log reading
        self.log_file_path = Path(self.monitor.log_file)
        self.log_file_position = 0

        # --- Packet Saving Additions ---
        self.analyzer_packets = [] # List to store packets for the analyzer
        self.analyzer_packet_limit = 5000 # Limit packets stored in memory (adjust as needed)
        # -----------------------------

        self._stats_after_id = None # Store the ID for the main update loop timer

        self._setup_menu()
        self._setup_theme()
        self._setup_main_frame()
        self._setup_dashboard()
        self._setup_status_bar()
        self._update_stats_loop() # Start the loop

        # Handle window close event gracefully
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)

    def _on_closing(self):
        """Handle window closing: stop monitoring and destroy."""
        print("Closing application...")
        if self.monitor.monitoring:
            print("Stopping monitor...")
            self._stop_monitoring() # Gracefully stop main monitoring

        # Stop analyzer capture if running
        self.analyzer_capture_running = False
        self.port_scan_running = False

        # Cancel pending GUI updates
        if self._stats_after_id:
            try:
                self.root.after_cancel(self._stats_after_id)
                print("Cancelled stats update loop.")
            except tk.TclError:
                pass # Ignore if already cancelled or invalid

        print("Destroying root window.")
        self.root.destroy()

    # --- Menu Setup ---
    def _setup_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File Menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Export Data", command=self._export_data)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_closing) # Use graceful close
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
        advanced_menu.add_command(label="ML Dashboard", command=self._show_ml_dashboard)
        menubar.add_cascade(label="Advanced", menu=advanced_menu)

        # Help Menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self._show_about)
        help_menu.add_command(label="Documentation", command=self._show_docs)
        menubar.add_cascade(label="Help", menu=help_menu)

    # --- Theme Setup ---
    def _setup_theme(self):
        colors = THEME_COLORS[self.current_theme]
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except tk.TclError:
             style.theme_use('default') # Fallback

        self.root.config(bg=colors["bg"])

        # Configure styles
        style.configure("TFrame", background=colors["bg"])
        style.configure("TLabel", background=colors["bg"], foreground=colors["fg"], font=("Consolas", 10))
        style.configure("TButton", background=colors["button_bg"], foreground=colors["button_fg"], font=("Consolas", 10), padding=5, borderwidth=0)
        style.map("TButton", background=[("active", colors["highlight"])])
        style.configure("TEntry", fieldbackground=colors["text_bg"], foreground=colors["text_fg"], insertcolor=colors["fg"], font=("Consolas", 10), borderwidth=1)
        style.configure("TLabelframe", background=colors["bg"], foreground=colors["fg"], font=("Consolas", 10, "bold"), borderwidth=1, relief="groove")
        style.configure("TLabelframe.Label", background=colors["bg"], foreground=colors["fg"], font=("Consolas", 10, "bold"))
        style.configure("TNotebook", background=colors["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=colors["button_bg"], foreground=colors["button_fg"], padding=[5, 2], font=('Consolas', 10), borderwidth=0)
        style.map("TNotebook.Tab", background=[("selected", colors["highlight"])])
        style.configure("Treeview", background=colors["text_bg"], foreground=colors["text_fg"], fieldbackground=colors["text_bg"], font=('Consolas', 9), borderwidth=0)
        style.map("Treeview", background=[("selected", colors["highlight"])])
        style.configure("Treeview.Heading", background=colors["button_bg"], foreground=colors["button_fg"], font=('Consolas', 10, 'bold'), relief="flat")
        style.map("Treeview.Heading", relief=[('active','groove'),('pressed','sunken')])
        style.configure("Vertical.TScrollbar", background=colors["button_bg"], troughcolor=colors["text_bg"], borderwidth=0, arrowcolor=colors["fg"])
        style.map("Vertical.TScrollbar", background=[("active", colors["highlight"])])

    # --- Main Frame Setup ---
    def _setup_main_frame(self):
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.rowconfigure(1, weight=1)

    # --- Dashboard Setup ---
    def _setup_dashboard(self):
        frame = self.main_frame

        controls_frame = ttk.Frame(frame)
        controls_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        ttk.Label(controls_frame, text="Target IP:").pack(side=tk.LEFT, padx=(0, 5))
        self.ip_entry = ttk.Entry(controls_frame, width=20)
        self.ip_entry.pack(side=tk.LEFT, padx=5)
        self.start_btn = ttk.Button(controls_frame, text="Start Monitoring", command=self._start_monitoring, style="TButton")
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = ttk.Button(controls_frame, text="Stop Monitoring", command=self._stop_monitoring, state=tk.DISABLED, style="TButton")
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        paned_window = ttk.PanedWindow(frame, orient=tk.HORIZONTAL)
        paned_window.grid(row=1, column=0, sticky="nsew")

        left_panel = ttk.Frame(paned_window, padding=5)
        left_panel.rowconfigure(1, weight=1)
        left_panel.columnconfigure(0, weight=1)
        paned_window.add(left_panel, weight=1)

        stats_lf = ttk.LabelFrame(left_panel, text="Live Statistics", padding=5)
        stats_lf.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
        stats_lf.columnconfigure(0, weight=1)
        self.stats_text = tk.Text(stats_lf, font=("Consolas", 10), wrap=tk.WORD, height=10,
                                  bg=THEME_COLORS[self.current_theme]["text_bg"], fg=THEME_COLORS[self.current_theme]["text_fg"],
                                  borderwidth=0, highlightthickness=0, relief="flat", state=tk.DISABLED)
        self.stats_text.pack(fill=tk.BOTH, expand=True)

        log_lf = ttk.LabelFrame(left_panel, text="Security Alerts", padding=5)
        log_lf.grid(row=1, column=0, sticky="nsew")
        log_lf.columnconfigure(0, weight=1)
        log_lf.rowconfigure(0, weight=1)
        self.log_text = scrolledtext.ScrolledText(log_lf, font=("Consolas", 9), wrap=tk.WORD,
                                                  bg=THEME_COLORS[self.current_theme]["text_bg"], fg=THEME_COLORS[self.current_theme]["text_fg"],
                                                  borderwidth=0, highlightthickness=0, relief="flat", state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        right_panel = ttk.Frame(paned_window, padding=5)
        paned_window.add(right_panel, weight=1)
        right_panel.rowconfigure(0, weight=1)
        right_panel.rowconfigure(1, weight=1)
        right_panel.columnconfigure(0, weight=1)

        self.threat_chart_frame = ttk.LabelFrame(right_panel, text="Threat Distribution", padding=5)
        self.threat_chart_frame.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
        self.threat_chart_frame.columnconfigure(0, weight=1)
        self.threat_chart_frame.rowconfigure(0, weight=1)

        self.protocol_chart_frame = ttk.LabelFrame(right_panel, text="Protocol Distribution", padding=5)
        self.protocol_chart_frame.grid(row=1, column=0, sticky="nsew")
        self.protocol_chart_frame.columnconfigure(0, weight=1)
        self.protocol_chart_frame.rowconfigure(0, weight=1)

    # --- Status Bar Setup ---
    def _setup_status_bar(self):
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, font=("Consolas", 9), padding=2)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    # --- Main Monitoring Control ---
    def _start_monitoring(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Error", "Please provide a target IP address for context.")
            return

        try:
            socket.inet_aton(ip) # Validate IP format
            self.log_file_position = 0
            self.log_text.config(state=tk.NORMAL)
            self.log_text.delete(1.0, tk.END)
            self.log_text.config(state=tk.DISABLED)

            self.monitor.start_monitoring(ip)
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.status_var.set(f"Monitoring active. Filter: 'ip'")
            # Start the update loop if it wasn't running
            if not self._stats_after_id:
                self._update_stats_loop()

        except socket.error:
            messagebox.showerror("Error", "Invalid IP address format.")
            self.status_var.set("Ready")
        except PermissionError:
             messagebox.showerror("Permission Error", "Admin/root privileges required for packet capture.")
             self.status_var.set("Monitoring failed: Permission denied.")
        except Exception as e:
             messagebox.showerror("Error", f"Failed to start monitoring: {e}")
             self.status_var.set("Monitoring failed to start.")

    def _stop_monitoring(self):
        if self.monitor.monitoring:
            self.monitor.stop_monitoring()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("Monitoring stopped.")
        # Cancel the next scheduled update loop
        if self._stats_after_id:
            try:
                self.root.after_cancel(self._stats_after_id)
                self._stats_after_id = None # Clear the ID
            except tk.TclError:
                pass # Ignore if already cancelled or invalid


    # --- Periodic Update Loop ---
    def _update_stats_loop(self):
        # Check if the root window still exists before proceeding
        if not self.root.winfo_exists():
            print("Update loop: Root window destroyed, stopping.")
            self._stats_after_id = None # Ensure loop doesn't restart
            return

        # Check if monitoring is supposed to be active
        if self.monitor.monitoring:
            try:
                stats = self.monitor.get_stats()

                # Update Stats Text
                self.stats_text.config(state=tk.NORMAL)
                self.stats_text.delete(1.0, tk.END)
                data_str = format_bytes(stats.get('total_bytes', 0))
                stats_display = (f"Uptime: {stats.get('uptime', '0:00:00')}\n"
                                f"Packets Captured: {stats.get('packet_count', 0)}\n"
                                f"Data Transferred: {data_str}\n"
                                f"Threats Detected: {stats.get('threats_detected', 0)}\n"
                                f"  - DoS Attacks: {stats.get('dos_count', 0)}\n"
                                f"  - Port Scans: {stats.get('port_scan_count', 0)}\n"
                                f"  - ML Anomalies: {stats.get('ml_anomalies', 0)}\n\n"
                                "Top Source IPs:\n" + "\n".join([f"  - {ip}: {count} pkts" for ip, count in stats.get('top_ips', {}).items()]))
                self.stats_text.insert(tk.END, stats_display)
                self.stats_text.config(state=tk.DISABLED)

                self._update_charts(stats)
                self._update_alerts()

            except Exception as e:
                print(f"Error in _update_stats_loop: {e}")

        # Schedule next update ONLY if monitoring is still active and window exists
        if self.root.winfo_exists() and self.monitor.monitoring:
             try:
                 # Cancel previous timer just in case (safer)
                 if self._stats_after_id:
                     self.root.after_cancel(self._stats_after_id)
                 self._stats_after_id = self.root.after(2000, self._update_stats_loop)
             except (tk.TclError, RuntimeError) as e:
                  print(f"Error scheduling next update: {e}")
                  self._stats_after_id = None # Reset ID on error
        else:
             print("Update loop: Monitoring stopped or window closed, not rescheduling.")
             self._stats_after_id = None # Clear the ID if monitoring stopped


    # --- Chart Updates ---
    def _update_charts(self, stats):
        bg_color = THEME_COLORS[self.current_theme]['bg']
        text_color = THEME_COLORS[self.current_theme]['fg']
        highlight_color = THEME_COLORS[self.current_theme]['highlight']
        text_bg_color = THEME_COLORS[self.current_theme]['text_bg']

        # --- Threat Chart ---
        fig1 = None
        try:
            # Check if frame exists before clearing/drawing
            if not self.threat_chart_frame.winfo_exists(): return
            for widget in self.threat_chart_frame.winfo_children(): widget.destroy()

            threats_detected = stats.get('threats_detected', 0)
            if threats_detected > 0:
                labels = ['DoS', 'Port Scans', 'ML Anomalies']
                sizes = [stats.get('dos_count', 0), stats.get('port_scan_count', 0), stats.get('ml_anomalies', 0)]
                filtered_data = [(l, s) for l, s in zip(labels, sizes) if s > 0]

                if filtered_data:
                    labels, sizes = zip(*filtered_data)
                    fig1, ax1 = plt.subplots(figsize=(5, 3), dpi=100, facecolor=bg_color)
                    ax1.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, textprops={'color': text_color, 'fontsize': 9})
                    ax1.axis('equal')
                    fig1.tight_layout()
                    canvas = FigureCanvasTkAgg(fig1, master=self.threat_chart_frame)
                    canvas_widget = canvas.get_tk_widget()
                    canvas_widget.pack(fill=tk.BOTH, expand=True)
                    canvas.draw()
                else:
                     ttk.Label(self.threat_chart_frame, text="No specific threat types recorded.", anchor="center").pack(fill=tk.BOTH, expand=True)
            else:
                ttk.Label(self.threat_chart_frame, text="No threats detected yet.", anchor="center").pack(fill=tk.BOTH, expand=True)
        except Exception as e: print(f"Error updating threat chart: {e}")
        finally:
            if fig1 is not None: plt.close(fig1)

        # --- Protocol Chart ---
        fig2 = None
        try:
            # Check if frame exists
            if not self.protocol_chart_frame.winfo_exists(): return
            for widget in self.protocol_chart_frame.winfo_children(): widget.destroy()

            packet_count = stats.get('packet_count', 0)
            if packet_count > 0:
                ps = stats.get('packet_stats', {})
                labels = ['TCP', 'UDP', 'ICMP', 'Other']
                sizes = [ps.get('tcp', 0), ps.get('udp', 0), ps.get('icmp', 0)]
                known_sum = sum(sizes)
                other_count = max(0, stats.get('packet_count', 0) - known_sum)
                sizes.append(other_count)
                filtered_data = [(l, s) for l, s in zip(labels, sizes) if s > 0]

                if filtered_data:
                    labels, sizes = zip(*filtered_data)
                    fig2, ax2 = plt.subplots(figsize=(5, 3), dpi=100, facecolor=bg_color)
                    ax2.bar(labels, sizes, color=highlight_color)
                    ax2.tick_params(axis='x', colors=text_color, labelsize=9)
                    ax2.tick_params(axis='y', colors=text_color, labelsize=9)
                    ax2.set_ylabel('Packets', color=text_color, fontsize=10)
                    ax2.set_facecolor(text_bg_color)
                    fig2.tight_layout()
                    canvas = FigureCanvasTkAgg(fig2, master=self.protocol_chart_frame)
                    canvas_widget = canvas.get_tk_widget()
                    canvas_widget.pack(fill=tk.BOTH, expand=True)
                    canvas.draw()
                else:
                     ttk.Label(self.protocol_chart_frame, text="No specific protocols recorded.", anchor="center").pack(fill=tk.BOTH, expand=True)
            else:
                ttk.Label(self.protocol_chart_frame, text="No packets captured yet.", anchor="center").pack(fill=tk.BOTH, expand=True)
        except Exception as e: print(f"Error updating protocol chart: {e}")
        finally:
            if fig2 is not None: plt.close(fig2)

    # --- Log Update ---
    def _update_alerts(self):
        if not hasattr(self, 'log_text') or not self.log_text.winfo_exists(): return
        try:
            if not self.log_file_path.exists():
                self.log_file_position = 0
                return

            with self.log_file_path.open("r", encoding='utf-8') as f:
                f.seek(self.log_file_position)
                new_content = f.read()
                if new_content:
                    self.log_text.config(state=tk.NORMAL)
                    self.log_text.insert(tk.END, new_content)
                    self.log_text.see(tk.END)
                    self.log_text.config(state=tk.DISABLED)
                self.log_file_position = f.tell()
        except tk.TclError as e: print(f"Error updating log text (widget likely destroyed): {e}")
        except Exception as e: print(f"Error reading log file: {e}")

    # --- File Menu Action ---
    def _export_data(self):
        # ... (Unchanged) ...
        if not self.monitor.monitoring and self.monitor.packet_count == 0:
            messagebox.showwarning("Export Data", "No data to export. Start monitoring first.")
            return
        filename = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if filename:
            if self.monitor.export_data(filename):
                messagebox.showinfo("Success", "Data exported successfully.")
            else:
                messagebox.showerror("Error", "Failed to export data.")

    # --- Port Scanner Functions ---
    def _show_port_scanner(self):
        # ... (Unchanged) ...
        win = tk.Toplevel(self.root)
        win.title("Port Scanner")
        win.geometry("500x450") # Slightly taller
        win.configure(bg=THEME_COLORS[self.current_theme]["bg"])

        top_frame = ttk.Frame(win)
        top_frame.pack(fill=tk.X, pady=10, padx=10)

        ttk.Label(top_frame, text="Target IP:").pack(side=tk.LEFT, padx=(0, 5))
        ip_entry = ttk.Entry(top_frame, width=15)
        ip_entry.pack(side=tk.LEFT, padx=5)

        ttk.Label(top_frame, text="Ports (e.g., 1-1024):").pack(side=tk.LEFT, padx=(10, 5))
        ports_entry = ttk.Entry(top_frame, width=15)
        ports_entry.pack(side=tk.LEFT, padx=5)
        ports_entry.insert(0, "1-1024")

        # Use ScrolledText for results
        results_frame = ttk.Frame(win)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        results = scrolledtext.ScrolledText(
            results_frame,
            bg=THEME_COLORS[self.current_theme]["text_bg"],
            fg=THEME_COLORS[self.current_theme]["text_fg"],
            font=("Consolas", 9),
            borderwidth=0,
            highlightthickness=0,
            relief="flat"
        )
        results.pack(fill=tk.BOTH, expand=True)
        results.config(state=tk.DISABLED) # Start read-only

        # Status Label and Scan Button in a bottom frame
        bottom_frame = ttk.Frame(win)
        bottom_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        scan_status_label = ttk.Label(bottom_frame, text="Ready") # Local variable is fine
        scan_status_label.pack(side=tk.LEFT, padx=(0, 10))

        scan_btn = ttk.Button(
            bottom_frame,
            text="Start Scan",
            command=lambda: self._run_port_scan(ip_entry.get(), ports_entry.get(), results, scan_btn, scan_status_label) # Pass labels/buttons
        )
        scan_btn.pack(side=tk.RIGHT)

        # Clear queue when window opens
        with self.port_scan_queue.mutex:
            self.port_scan_queue.queue.clear()
        self.port_scan_running = False

        # Handle window close for port scanner
        def on_scan_close():
            self.port_scan_running = False # Stop polling if window is closed
            win.destroy()
        win.protocol("WM_DELETE_WINDOW", on_scan_close)


    def _run_port_scan(self, ip, ports_str, results_widget, scan_button, status_label):
        # ... (Unchanged) ...
        if self.port_scan_running:
            messagebox.showwarning("Scan in Progress", "A port scan is already running.")
            return

        try:
            socket.inet_aton(ip) # Validate IP

            # --- Parse Port Range ---
            ports_to_scan = []
            parts = ports_str.split(',')
            for part in parts:
                part = part.strip()
                if '-' in part:
                    start_str, end_str = part.split('-', 1)
                    start, end = int(start_str), int(end_str)
                    if not (1 <= start <= end <= 65535):
                        raise ValueError(f"Invalid Port Range '{part}' (1-65535)")
                    ports_to_scan.extend(range(start, end + 1))
                elif part.isdigit():
                    port = int(part)
                    if not (1 <= port <= 65535):
                        raise ValueError(f"Invalid Port '{part}' (1-65535)")
                    ports_to_scan.append(port)
                else:
                    raise ValueError(f"Invalid Port Format '{part}' (use 'X', 'X-Y', or 'X,Y,Z-A')")

            if not ports_to_scan:
                 raise ValueError("No ports specified for scanning.")

            # Remove duplicates and sort
            ports_to_scan = sorted(list(set(ports_to_scan)))
            port_range_display = ports_str # Keep original display string

            results_widget.config(state=tk.NORMAL)
            results_widget.delete(1.0, tk.END)
            results_widget.insert(tk.END, f"Starting scan on {ip} for ports {port_range_display}...\n")
            results_widget.config(state=tk.DISABLED)

            scan_button.config(state=tk.DISABLED) # Disable button during scan
            status_label.config(text="Scanning...")
            self.port_scan_running = True

            # Clear queue before starting
            with self.port_scan_queue.mutex:
                self.port_scan_queue.queue.clear()

            # Start the background thread for scanning
            threading.Thread(
                target=self._perform_port_scan,
                args=(ip, ports_to_scan), # Don't pass button directly
                daemon=True
            ).start()

            # Start the queue poller in the main thread
            self._poll_port_scan_queue(results_widget, scan_button, status_label) # Pass necessary widgets

        except (socket.error, ValueError) as e:
            messagebox.showerror("Input Error", f"Invalid input: {e}")
            if status_label.winfo_exists(): status_label.config(text="Error")
            self.port_scan_running = False # Ensure flag is reset
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")
            if status_label.winfo_exists(): status_label.config(text="Error")
            self.port_scan_running = False # Ensure flag is reset

    def _perform_port_scan(self, ip, ports_to_scan):
        # ... (Unchanged) ...
        open_ports_count = 0
        total_ports = len(ports_to_scan)
        ports_scanned = 0

        for port in ports_to_scan:
            # Check if the main loop requested a stop (e.g., window closed)
            if not self.port_scan_running:
                 try: self.port_scan_queue.put("Scan aborted.\n")
                 except queue.Full: pass # Ignore if queue full on abort
                 try: self.port_scan_queue.put("DONE")
                 except queue.Full: pass
                 return # Exit thread early

            ports_scanned += 1
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.6) # Slightly longer timeout?
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        open_ports_count += 1
                        service = "unknown"
                        try:
                            socket.setdefaulttimeout(0.5) # Timeout for getservbyport
                            service = socket.getservbyport(port, 'tcp')
                            socket.setdefaulttimeout(None) # Reset global timeout
                        except (OSError, TypeError, socket.timeout):
                            pass # Ignore errors, keep 'unknown'
                        self.port_scan_queue.put(f"Port {port:<5} ({service}) is OPEN\n")

                    if ports_scanned % 100 == 0 or ports_scanned == total_ports:
                       progress_percent = (ports_scanned / total_ports) * 100
                       self.port_scan_queue.put(f"PROGRESS:{progress_percent:.0f}% ({ports_scanned}/{total_ports})")

            except socket.gaierror:
                 self.port_scan_queue.put(f"ERROR: Cannot resolve hostname '{ip}'\n")
                 break # Stop scan if hostname resolution fails
            except Exception as e:
                 print(f"Error scanning port {port} on {ip}: {e}")
                 continue

        # Signal scan completion
        try:
             self.port_scan_queue.put(f"\nScan complete. Found {open_ports_count} open ports on {ip}.\n")
             self.port_scan_queue.put("DONE")
        except queue.Full:
             print("Port scan queue full on completion.")


    def _poll_port_scan_queue(self, results_widget, scan_button, status_label):
        # ... (Unchanged) ...
        if not results_widget.winfo_exists():
            self.port_scan_running = False
            return

        try:
            while not self.port_scan_queue.empty():
                message = self.port_scan_queue.get_nowait()
                if message == "DONE":
                    self.port_scan_running = False
                    if status_label.winfo_exists(): status_label.config(text="Scan Complete")
                    if scan_button.winfo_exists(): scan_button.config(state=tk.NORMAL)
                    return # Stop polling this cycle
                elif isinstance(message, str) and message.startswith("PROGRESS:"):
                    if status_label.winfo_exists(): status_label.config(text=f"Scanning... {message.split(':')[1]}")
                elif isinstance(message, str):
                    results_widget.config(state=tk.NORMAL)
                    results_widget.insert(tk.END, message)
                    results_widget.see(tk.END)
                    results_widget.config(state=tk.DISABLED)

        except queue.Empty: pass
        except tk.TclError as e:
             print(f"TclError polling port scan queue (widget likely destroyed): {e}")
             self.port_scan_running = False
             return

        if self.port_scan_running:
             if results_widget.winfo_exists():
                self.root.after(100, lambda rw=results_widget, sb=scan_button, sl=status_label: self._poll_port_scan_queue(rw, sb, sl))
             else:
                  self.port_scan_running = False

    # --- Packet Analyzer Functions (with Saving) ---
    def _show_packet_analyzer(self):
        # ... (Code as provided in the previous response - unchanged) ...
        win = tk.Toplevel(self.root)
        win.title("Packet Analyzer")
        win.geometry("800x600")
        win.configure(bg=THEME_COLORS[self.current_theme]["bg"])

        top_frame = ttk.Frame(win)
        top_frame.pack(fill=tk.X, pady=5, padx=5)
        ttk.Label(top_frame, text="BPF Filter:").pack(side=tk.LEFT, padx=5)
        filter_entry = ttk.Entry(top_frame, width=30)
        filter_entry.pack(side=tk.LEFT, padx=5)

        results = scrolledtext.ScrolledText(
            win, bg=THEME_COLORS[self.current_theme]["text_bg"], fg=THEME_COLORS[self.current_theme]["text_fg"],
            font=("Consolas", 9), borderwidth=0, highlightthickness=0, relief="flat", state=tk.DISABLED)
        results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Frame for buttons on the right
        button_frame = ttk.Frame(top_frame)
        button_frame.pack(side=tk.RIGHT)

        start_btn = ttk.Button(button_frame, text="Start Capture", command=lambda: self._start_capture(filter_entry.get(), start_btn, stop_btn, save_btn, results))
        start_btn.pack(side=tk.LEFT, padx=5)
        stop_btn = ttk.Button(button_frame, text="Stop Capture", command=lambda: self._stop_capture(start_btn, stop_btn, save_btn), state=tk.DISABLED)
        stop_btn.pack(side=tk.LEFT, padx=5)
        # --- Add Save Button ---
        save_btn = ttk.Button(button_frame, text="Save Capture", command=lambda: self._save_packet_capture(win), state=tk.DISABLED) # Pass window as parent
        save_btn.pack(side=tk.LEFT, padx=5)
        # ----------------------

        with self.packet_analyzer_queue.mutex: self.packet_analyzer_queue.queue.clear()
        self.analyzer_packets = [] # Clear packet list
        self.analyzer_capture_running = False # Reset capture flag

        def on_analyzer_close():
            if self.analyzer_capture_running: self._stop_capture(start_btn, stop_btn, save_btn)
            win.destroy()
        win.protocol("WM_DELETE_WINDOW", on_analyzer_close)


    def _start_capture(self, filter_str, start_btn, stop_btn, save_btn, results):
        # ... (Code as provided in the previous response - unchanged) ...
        if self.analyzer_capture_running:
             messagebox.showwarning("Capture Running", "Packet capture is already in progress.")
             return

        start_btn.config(state=tk.DISABLED)
        stop_btn.config(state=tk.NORMAL)
        save_btn.config(state=tk.DISABLED) # Disable save while capturing
        results.config(state=tk.NORMAL)
        results.delete(1.0, tk.END)
        results.config(state=tk.DISABLED)

        self.analyzer_packets = [] # Reset packet list
        self.analyzer_capture_running = True
        # Update status bar or analyzer window title if needed
        # self.status_var.set(f"Packet Analyzer running. Filter: '{filter_str or 'ip'}'")

        with self.packet_analyzer_queue.mutex: self.packet_analyzer_queue.queue.clear()
        effective_filter = filter_str if filter_str else "ip"

        try:
            self.capture_thread = threading.Thread(
                # Use the combined process and store function
                target=lambda: sniff(prn=self._process_and_store_packet_for_analyzer,
                                     filter=effective_filter,
                                     store=False, # We store manually
                                     stop_filter=lambda p: not self.analyzer_capture_running),
                daemon=True
            )
            self.capture_thread.start()
            self._poll_packet_analyzer_queue(results) # Start poller
        except Exception as e:
            # Catch potential Scapy filter errors or other issues
            messagebox.showerror("Capture Error", f"Failed to start packet capture:\n{e}\n\nFilter used: '{effective_filter}'")
            self._stop_capture(start_btn, stop_btn, save_btn) # Reset state on error


    def _stop_capture(self, start_btn, stop_btn, save_btn):
        # ... (Code as provided in the previous response - unchanged) ...
        if not self.analyzer_capture_running: return
        self.analyzer_capture_running = False # Signal thread and poller to stop

        # Check if widgets exist before configuring
        if start_btn.winfo_exists(): start_btn.config(state=tk.NORMAL)
        if stop_btn.winfo_exists(): stop_btn.config(state=tk.DISABLED)
        # Enable save only if packets were captured
        if save_btn.winfo_exists(): save_btn.config(state=tk.NORMAL if self.analyzer_packets else tk.DISABLED)
        # self.status_var.set("Packet Analyzer stopped.")

    def _poll_packet_analyzer_queue(self, results_widget):
        # ... (Code as provided in the previous response - unchanged) ...
        if not results_widget.winfo_exists():
            self.analyzer_capture_running = False
            return

        try:
            while not self.packet_analyzer_queue.empty():
                info = self.packet_analyzer_queue.get_nowait()
                results_widget.config(state=tk.NORMAL)
                results_widget.insert(tk.END, info)
                # Simple line limiting: Check line count and delete from start if too large
                line_count = int(results_widget.index('end-1c').split('.')[0])
                max_lines = 2000 # Keep roughly 2000 lines
                if line_count > max_lines + 100: # Delete in chunks once limit exceeded
                     results_widget.delete('1.0', f'{line_count - max_lines}.0')

                results_widget.see(tk.END)
                results_widget.config(state=tk.DISABLED)
        except queue.Empty:
            pass
        except tk.TclError as e:
             print(f"TclError polling packet analyzer queue (widget likely destroyed): {e}")
             self.analyzer_capture_running = False
             return

        if self.analyzer_capture_running:
             if results_widget.winfo_exists():
                # Pass widget explicitly using lambda
                self.root.after(100, lambda rw=results_widget: self._poll_packet_analyzer_queue(rw))
             else:
                  self.analyzer_capture_running = False

    def _process_packet_for_analyzer(self, packet):
        # ... (Code as provided in the previous response - unchanged) ...
         # --- This function ONLY puts summary in queue ---
        try:
            timestamp = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
            layer_info = ""
            if IP in packet:
                 src = packet[IP].src
                 dst = packet[IP].dst
                 proto = packet.sprintf('%IP.proto%') # Use sprintf for common cases
                 layer_info = f"{src} -> {dst} | {proto}"
                 if TCP in packet:
                     sport = packet[TCP].sport
                     dport = packet[TCP].dport
                     flags = packet[TCP].sprintf('%TCP.flags%') # Use sprintf
                     layer_info += f" | {sport}->{dport} [{flags}]"
                 elif UDP in packet:
                     sport = packet[UDP].sport
                     dport = packet[UDP].dport
                     layer_info += f" | {sport}->{dport}"
                 elif ICMP in packet:
                     icmp_type = packet.sprintf('%ICMP.type%') # Use sprintf
                     icmp_code = packet.sprintf('%ICMP.code%') # Use sprintf
                     layer_info += f" | Type:{icmp_type} Code:{icmp_code}"
            else:
                 layer_info = packet.summary() # Fallback

            info = f"{timestamp} | {layer_info}\n"
            # Add to queue only if capture is still running
            if self.analyzer_capture_running:
                 # Check queue size before putting? Optional.
                 # if self.packet_analyzer_queue.qsize() < 1000:
                 self.packet_analyzer_queue.put(info)
                 # else: print("Analyzer queue full, dropping display info.")

        except Exception as e:
            print(f"Error processing packet for analyzer display: {e}")

    def _process_and_store_packet_for_analyzer(self, packet):
        """
        Processes packet for display queue AND stores the raw packet object.
        Called by the sniff function in the Packet Analyzer.
        """
        # --- Store the packet (with limit) ---
        # Check flag before storing
        if self.analyzer_capture_running:
            # This block starts the indentation level
            if len(self.analyzer_packets) < self.analyzer_packet_limit:
                self.analyzer_packets.append(packet)
            # Optional: Rotation
            # else:
            #     self.analyzer_packets.pop(0)
            #     self.analyzer_packets.append(packet)

            # --- Process for display queue ---
            # THIS LINE must be indented to match the 'if len(...)' block above
            self._process_packet_for_analyzer(packet)
        # The 'if' block ends here. Anything outside is not part of the 'if'.


    def _save_packet_capture(self, parent_window):
        # ... (Code as provided in the previous response - unchanged) ...
        if not self.analyzer_packets:
            messagebox.showwarning("Save Capture", "No packets have been captured to save.", parent=parent_window)
            return
        if self.analyzer_capture_running:
             messagebox.showwarning("Save Capture", "Please stop the capture before saving.", parent=parent_window)
             return

        # Propose a default filename based on timestamp
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        initial_file = f"capture_{timestamp}.pcap"

        filename = filedialog.asksaveasfilename(
            parent=parent_window,
            title="Save Packet Capture As",
            initialfile=initial_file,
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )

        if filename:
            # Check if parent_window (the analyzer Toplevel) still exists
            if not parent_window.winfo_exists():
                 print("Save cancelled: Analyzer window closed.")
                 return

            # Find the save button to disable/re-enable it
            save_btn = None
            try:
                # Assuming button layout: top_frame -> button_frame -> save_btn
                button_frame = parent_window.winfo_children()[0].winfo_children()[-1]
                # Find by text might be safer if layout changes
                for widget in button_frame.winfo_children():
                    if isinstance(widget, ttk.Button) and "Save Capture" in widget.cget("text"):
                        save_btn = widget
                        break
                if save_btn: save_btn.config(state=tk.DISABLED)
            except (IndexError, AttributeError): pass


            # self.status_var.set(f"Saving capture...") # Update main status bar?
            parent_window.title(f"Packet Analyzer - Saving...") # Update analyzer title
            parent_window.update_idletasks()

            def save_task():
                status = "Save failed." # Default status
                message = f"Failed to save packet capture." # Default message
                msg_type = "error"
                packet_count_to_save = len(self.analyzer_packets) # Get count before potentially clearing list later
                try:
                    # Save a copy in case the list is modified while saving
                    packets_to_save = list(self.analyzer_packets)
                    wrpcap(filename, packets_to_save)
                    status = "Capture saved."
                    message = f"Capture saved successfully ({packet_count_to_save} packets)."
                    msg_type = "info"
                except Exception as e:
                    message = f"Failed to save packet capture:\n{e}"
                    print(f"Error saving pcap: {e}") # Log detailed error

                # Schedule GUI update back on main thread
                def update_gui():
                     # Check parent window still exists
                     if parent_window.winfo_exists():
                         if msg_type == "info":
                             messagebox.showinfo("Save Capture", message, parent=parent_window)
                         else:
                             messagebox.showerror("Save Error", message, parent=parent_window)
                         parent_window.title("Packet Analyzer") # Reset title
                         # Re-enable save button if it was found and still exists
                         if save_btn and save_btn.winfo_exists():
                             # Keep enabled if packets still exist, else disable
                             save_btn.config(state=tk.NORMAL if self.analyzer_packets else tk.DISABLED)
                         # Optionally update main status bar: self.status_var.set(status)

                # Ensure self.root still exists before calling 'after'
                if self.root.winfo_exists():
                     self.root.after(0, update_gui)

            save_thread = threading.Thread(target=save_task, daemon=True)
            save_thread.start()


    # --- Other Menu Functions ---
    def _show_bandwidth_monitor(self):
        try: from gui.bandwidth_window import BandwidthWindow
        except ImportError as e: messagebox.showerror("Import Error", f"Could not load Bandwidth Monitor module:\n{e}"); return
        except Exception as e: messagebox.showerror("Error", f"Failed to open Bandwidth Monitor:\n{e}"); return
        BandwidthWindow(self.root, self.monitor)

    def _show_threat_intel(self):
        try: from gui.threat_intel_window import ThreatIntelWindow
        except ImportError as e: messagebox.showerror("Import Error", f"Could not load Threat Intelligence module:\n{e}"); return
        except Exception as e: messagebox.showerror("Error", f"Failed to open Threat Intelligence:\n{e}"); return
        ThreatIntelWindow(self.root, self.monitor)

    def _show_firewall(self):
        try: from gui.firewall_window import FirewallWindow
        except ImportError as e: messagebox.showerror("Import Error", f"Could not load Firewall Manager module:\n{e}"); return
        except Exception as e: messagebox.showerror("Error", f"Failed to open Firewall Manager:\n{e}"); return
        FirewallWindow(self.root, self.monitor)

    def _show_ml_dashboard(self):
        try: from gui.ml_dashboard import MLDashboard
        except ImportError as e: messagebox.showerror("Import Error", f"Could not load ML Dashboard module:\n{e}"); return
        except Exception as e: messagebox.showerror("Error", f"Failed to open ML Dashboard:\n{e}"); return
        MLDashboard(self.root, self.monitor)

    def _show_about(self):
        about_text = f"""Realtime Network Threat Detection v{VERSION}
An educational tool for demonstrating network monitoring and threat detection concepts.
Features:
• Real-time packet capture and analysis
• ML-powered threat detection (Isolation Forest)
• DoS/DDoS attack detection (rate-based)
• Port scan identification
• Dynamic firewall management
• Threat intelligence tracking (basic)
⚠️ Educational Use Only
© 2024 Your Name/Project"""
        messagebox.showinfo("About", about_text)

    def _show_docs(self):
        docs_text = """📖 Quick Start Guide
1. Enter Target IP (Optional Context)
   - e.g., your router's IP (192.168.0.1).
2. Start Monitoring
   - Click "Start Monitoring" (Requires Admin/root).
3. View Statistics & Alerts
   - Main dashboard shows live stats and security alerts.
4. Explore Tools & Advanced Features
   - Tools → Port Scanner: Scan IPs for open ports.
   - Tools → Packet Analyzer: View summaries & Save captures!
   - Tools → Bandwidth Monitor: Live traffic graphs.
   - Advanced → Threat Intelligence: Manage threats.
   - Advanced → Firewall Manager: Manage rules.
   - Advanced → ML Dashboard: Monitor ML model.
5. Stop Monitoring
6. Export Data (File Menu)
Troubleshooting: Run as Admin/root. Check library installs."""
        win = tk.Toplevel(self.root)
        win.title("Documentation")
        win.geometry("600x550")
        win.configure(bg=THEME_COLORS[self.current_theme]["bg"])
        text = scrolledtext.ScrolledText(
            win, wrap=tk.WORD, font=("Consolas", 10), bg=THEME_COLORS[self.current_theme]["text_bg"],
            fg=THEME_COLORS[self.current_theme]["text_fg"], borderwidth=0, highlightthickness=0, relief="flat")
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text.insert(tk.END, docs_text)
        text.config(state=tk.DISABLED)