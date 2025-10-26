"""
Firewall Management Window
Manage firewall rules and blocked IPs
"""

import tkinter as tk
from tkinter import ttk, messagebox
from utils.constants import THEME_COLORS


class FirewallWindow:
    """Window for managing firewall rules"""
    
    def __init__(self, parent, monitor):
        self.monitor = monitor
        self.window = tk.Toplevel(parent)
        self.window.title("Firewall Manager")
        self.window.geometry("1000x600")
        
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
            text="🛡️ Firewall Manager",
            font=("Consolas", 16, "bold")
        )
        title_label.pack(side=tk.LEFT)
        
        # Control buttons
        ttk.Button(
            title_frame,
            text="Add Rule",
            command=self._add_rule_dialog
        ).pack(side=tk.RIGHT, padx=5)
        
        ttk.Button(
            title_frame,
            text="Clear All",
            command=self._clear_all_rules
        ).pack(side=tk.RIGHT, padx=5)
        
        ttk.Button(
            title_frame,
            text="Refresh",
            command=self._refresh_data
        ).pack(side=tk.RIGHT, padx=5)
        
        # Main content
        content_frame = ttk.Frame(self.window)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Statistics Frame
        stats_frame = ttk.LabelFrame(content_frame, text="Firewall Statistics")
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.stats_text = tk.Text(
            stats_frame,
            height=4,
            font=("Consolas", 10),
            bg=colors["text_bg"],
            fg=colors["text_fg"]
        )
        self.stats_text.pack(fill=tk.X, padx=5, pady=5)
        
        # Rules Frame
        rules_frame = ttk.LabelFrame(content_frame, text="Active Firewall Rules")
        rules_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview for rules
        columns = ("ID", "Type", "Value", "Action", "Priority", "Hits", "Created")
        self.rules_tree = ttk.Treeview(
            rules_frame,
            columns=columns,
            show="tree headings",
            height=20
        )
        
        # Configure columns
        self.rules_tree.column("#0", width=30)
        self.rules_tree.heading("#0", text="#")
        
        widths = [50, 80, 150, 80, 70, 60, 150]
        for col, width in zip(columns, widths):
            self.rules_tree.column(col, width=width)
            self.rules_tree.heading(col, text=col)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(
            rules_frame,
            orient=tk.VERTICAL,
            command=self.rules_tree.yview
        )
        self.rules_tree.configure(yscrollcommand=scrollbar.set)
        
        self.rules_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Context menu
        self.context_menu = tk.Menu(self.window, tearoff=0)
        self.context_menu.add_command(label="Delete Rule", command=self._delete_rule)
        self.context_menu.add_command(label="View Details", command=self._view_rule_details)
        
        self.rules_tree.bind("<Button-3>", self._show_context_menu)
    
    def _refresh_data(self):
        """Refresh firewall data"""
        if not self.monitor.enhanced_features_available:
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(tk.END, "Enhanced features not available.")
            return
        
        # Get firewall report
        report = self.monitor.firewall.get_rules_report()
        
        # Update statistics
        self.stats_text.delete(1.0, tk.END)
        stats_display = f"""Total Rules: {report['total_rules']}
Blocked IPs: {report['blocked_ips']}
Allowed IPs: {report['allowed_ips']}
"""
        self.stats_text.insert(tk.END, stats_display)
        
        # Update rules tree
        self.rules_tree.delete(*self.rules_tree.get_children())
        
        for idx, rule in enumerate(report['rules'], 1):
            self.rules_tree.insert(
                "",
                tk.END,
                text=str(idx),
                values=(
                    rule['id'],
                    rule['type'].upper(),
                    rule['value'],
                    rule['action'].upper(),
                    rule['priority'],
                    rule['hits'],
                    rule['created'].strftime("%Y-%m-%d %H:%M")
                ),
                tags=(rule['action'],)
            )
        
        # Color code by action
        self.rules_tree.tag_configure('block', background='#ff6666')
        self.rules_tree.tag_configure('allow', background='#66ff66')
        self.rules_tree.tag_configure('log', background='#ffff66')
    
    def _update_loop(self):
        """Periodic update loop"""
        if self.window.winfo_exists():
            self._refresh_data()
            self.window.after(3000, self._update_loop)
    
    def _show_context_menu(self, event):
        """Show context menu on right-click"""
        item = self.rules_tree.identify_row(event.y)
        if item:
            self.rules_tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def _add_rule_dialog(self):
        """Show dialog to add new rule"""
        if not self.monitor.enhanced_features_available:
            messagebox.showerror("Error", "Enhanced features not available")
            return
        
        dialog = tk.Toplevel(self.window)
        dialog.title("Add Firewall Rule")
        dialog.geometry("400x300")
        
        # Rule Type
        ttk.Label(dialog, text="Rule Type:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        type_var = tk.StringVar(value="ip")
        type_combo = ttk.Combobox(dialog, textvariable=type_var, values=["ip", "port", "protocol"], state="readonly")
        type_combo.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        
        # Value
        ttk.Label(dialog, text="Value:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        value_entry = ttk.Entry(dialog)
        value_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")
        
        # Action
        ttk.Label(dialog, text="Action:").grid(row=2, column=0, padx=10, pady=10, sticky="w")
        action_var = tk.StringVar(value="block")
        action_combo = ttk.Combobox(dialog, textvariable=action_var, values=["block", "allow", "log"], state="readonly")
        action_combo.grid(row=2, column=1, padx=10, pady=10, sticky="ew")
        
        # Priority
        ttk.Label(dialog, text="Priority (1-10):").grid(row=3, column=0, padx=10, pady=10, sticky="w")
        priority_var = tk.IntVar(value=5)
        priority_spin = ttk.Spinbox(dialog, from_=1, to=10, textvariable=priority_var)
        priority_spin.grid(row=3, column=1, padx=10, pady=10, sticky="ew")
        
        def add_rule():
            rule_type = type_var.get()
            value = value_entry.get().strip()
            action = action_var.get()
            priority = priority_var.get()
            
            if not value:
                messagebox.showerror("Error", "Value cannot be empty")
                return
            
            rule_id = self.monitor.firewall.add_rule(rule_type, value, action, priority)
            messagebox.showinfo("Success", f"Rule added with ID: {rule_id}")
            dialog.destroy()
            self._refresh_data()
        
        ttk.Button(dialog, text="Add Rule", command=add_rule).grid(row=4, column=0, columnspan=2, pady=20)
        
        dialog.columnconfigure(1, weight=1)
    
    def _delete_rule(self):
        """Delete selected rule"""
        selection = self.rules_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        values = self.rules_tree.item(item)['values']
        rule_id = values[0]
        
        if messagebox.askyesno("Confirm", f"Delete rule ID {rule_id}?"):
            self.monitor.firewall.remove_rule(rule_id)
            self._refresh_data()
    
    def _view_rule_details(self):
        """View detailed information about selected rule"""
        selection = self.rules_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        values = self.rules_tree.item(item)['values']
        
        details = f"""Rule ID: {values[0]}
Type: {values[1]}
Value: {values[2]}
Action: {values[3]}
Priority: {values[4]}
Hits: {values[5]}
Created: {values[6]}
"""
        
        messagebox.showinfo("Rule Details", details)
    
    def _clear_all_rules(self):
        """Clear all firewall rules"""
        if messagebox.askyesno("Confirm", "Clear all firewall rules?"):
            self.monitor.clear_all_blocks()
            self._refresh_data()
            messagebox.showinfo("Success", "All rules cleared")
