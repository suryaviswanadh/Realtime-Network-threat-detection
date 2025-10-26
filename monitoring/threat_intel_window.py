"""
Threat Intelligence Window
Display detailed threat information and statistics
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
from utils.constants import THEME_COLORS


class ThreatIntelWindow:
    """Window for displaying threat intelligence"""
    
    def __init__(self, parent, monitor):
        self.monitor = monitor
        self.window = tk.Toplevel(parent)
        self.window.title("Threat Intelligence Dashboard")
        self.window.geometry("900x700")
        
        self.current_theme = "purple"
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
            text="🔍 Threat Intelligence Dashboard",
            font=("Consolas", 16, "bold")
        )
        title_label.pack(side=tk.LEFT)
        
        refresh_btn = ttk.Button(
            title_frame,
            text="Refresh",
            command=self._refresh_data
        )
        refresh_btn.pack(side=tk.RIGHT)
        
        # Main content
        content_frame = ttk.Frame(self.window)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Statistics Frame
        stats_frame = ttk.LabelFrame(content_frame, text="Threat Statistics")
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.stats_text = tk.Text(
            stats_frame,
            height=8,
            font=("Consolas", 10),
            bg=colors["text_bg"],
            fg=colors["text_fg"]
        )
        self.stats_text.pack(fill=tk.X, padx=5, pady=5)
        
        # Active Threats Frame
        threats_frame = ttk.LabelFrame(content_frame, text="Active Threats")
        threats_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview for threats
        columns = ("IP", "Type", "Severity", "Count", "Last Seen")
        self.threats_tree = ttk.Treeview(
            threats_frame,
            columns=columns,
            show="tree headings",
            height=15
        )
        
        # Configure columns
        self.threats_tree.column("#0", width=50)
        self.threats_tree.heading("#0", text="#")
        
        for col in columns:
            self.threats_tree.column(col, width=150)
            self.threats_tree.heading(col, text=col)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(
            threats_frame,
            orient=tk.VERTICAL,
            command=self.threats_tree.yview
        )
        self.threats_tree.configure(yscrollcommand=scrollbar.set)
        
        self.threats_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Context menu
        self.context_menu = tk.Menu(self.window, tearoff=0)
        self.context_menu.add_command(label="Block IP", command=self._block_selected_ip)
        self.context_menu.add_command(label="View Details", command=self._view_details)
        
        self.threats_tree.bind("<Button-3>", self._show_context_menu)
    
    def _refresh_data(self):
        """Refresh threat intelligence data"""
        if not self.monitor.enhanced_features_available:
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(tk.END, "Enhanced features not available.\nInstall required dependencies.")
            return
        
        # Get threat intelligence report
        report = self.monitor.threat_intel.get_threat_report()
        
        # Update statistics
        self.stats_text.delete(1.0, tk.END)
        stats_display = f"""Total Threats Detected: {report['total_threats']}
Critical Threats: {report['critical']}
High Priority: {report['high']}
Medium Priority: {report['medium']}
Low Priority: {report['low']}

IP Reputation Database: {len(self.monitor.threat_intel.reputation_db)} entries
Firewall Blocked IPs: {len(self.monitor.firewall.blocked_ips)}
"""
        self.stats_text.insert(tk.END, stats_display)
        
        # Update threats tree
        self.threats_tree.delete(*self.threats_tree.get_children())
        
        for idx, (ip, data) in enumerate(report['top_threats'], 1):
            self.threats_tree.insert(
                "",
                tk.END,
                text=str(idx),
                values=(
                    ip,
                    data['type'],
                    data['severity'].upper(),
                    data['count'],
                    data['timestamp'].strftime("%H:%M:%S")
                ),
                tags=(data['severity'],)
            )
        
        # Color code by severity
        self.threats_tree.tag_configure('critical', background='#ff4444')
        self.threats_tree.tag_configure('high', background='#ff8844')
        self.threats_tree.tag_configure('medium', background='#ffbb44')
        self.threats_tree.tag_configure('low', background='#88ff88')
    
    def _update_loop(self):
        """Periodic update loop"""
        if self.window.winfo_exists():
            self._refresh_data()
            self.window.after(5000, self._update_loop)
    
    def _show_context_menu(self, event):
        """Show context menu on right-click"""
        item = self.threats_tree.identify_row(event.y)
        if item:
            self.threats_tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def _block_selected_ip(self):
        """Block selected IP address"""
        selection = self.threats_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        values = self.threats_tree.item(item)['values']
        ip = values[0]
        
        success = self.monitor.block_ip(ip, "Manual block from Threat Intel")
        if success:
            tk.messagebox.showinfo("Success", f"Blocked IP: {ip}")
            self._refresh_data()
        else:
            tk.messagebox.showerror("Error", "Failed to block IP")
    
    def _view_details(self):
        """View detailed information about selected threat"""
        selection = self.threats_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        values = self.threats_tree.item(item)['values']
        
        details = f"""IP Address: {values[0]}
Threat Type: {values[1]}
Severity: {values[2]}
Detection Count: {values[3]}
Last Seen: {values[4]}

Reputation Score: {self.monitor.threat_intel.check_ip_reputation(values[0])}/100
"""
        
        # Show in message box
        tk.messagebox.showinfo("Threat Details", details)

