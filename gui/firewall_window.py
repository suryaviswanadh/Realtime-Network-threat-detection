# D:\cyber_security_tool\Realtime-Network-threat-detection\gui\firewall_window.py

import tkinter as tk
from tkinter import ttk, messagebox

class FirewallWindow(tk.Toplevel):
    def __init__(self, parent, monitor_instance):
        super().__init__(parent)
        self.title("Firewall Manager")
        self.geometry("800x600")
        self.parent = parent
        self.monitor = monitor_instance
        self.protocol("WM_DELETE_WINDOW", self.on_close) # Handle window close event

        self.create_widgets()
        self.refresh_rules()

        # Center the window
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (self.winfo_width() // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (self.winfo_height() // 2)
        self.geometry(f"+{x}+{y}")

    def create_widgets(self):
        # Frame for controls
        control_frame = ttk.Frame(self)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)

        ttk.Label(control_frame, text="IP Address:").pack(side=tk.LEFT, padx=(0, 5))
        self.ip_entry = ttk.Entry(control_frame, width=20)
        self.ip_entry.pack(side=tk.LEFT, padx=(0, 10))

        ttk.Label(control_frame, text="Reason:").pack(side=tk.LEFT, padx=(0, 5))
        self.reason_entry = ttk.Entry(control_frame, width=30)
        self.reason_entry.insert(0, "Manual Block")
        self.reason_entry.pack(side=tk.LEFT, padx=(0, 10))

        ttk.Button(control_frame, text="Block IP", command=self.block_ip).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(control_frame, text="Unblock IP", command=self.unblock_selected_ip).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(control_frame, text="Clear All Blocks", command=self.clear_all_blocks).pack(side=tk.LEFT)
        ttk.Button(control_frame, text="Refresh", command=self.refresh_rules).pack(side=tk.RIGHT)

        # Treeview for displaying rules
        columns = ("IP Address", "Action", "Protocol", "Port", "Reason", "Timestamp")
        self.rules_tree = ttk.Treeview(self, columns=columns, show="headings", selectmode="browse")

        for col in columns:
            self.rules_tree.heading(col, text=col, anchor=tk.W)
            self.rules_tree.column(col, width=ttk.Font().measure(col) + 20, stretch=True)

        self.rules_tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.rules_tree, orient=tk.VERTICAL, command=self.rules_tree.yview)
        self.rules_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def block_ip(self):
        ip = self.ip_entry.get().strip()
        reason = self.reason_entry.get().strip()
        if not ip:
            messagebox.showwarning("Input Error", "Please enter an IP address to block.")
            return

        # Basic IP validation (can be enhanced)
        if not self.is_valid_ip(ip):
            messagebox.showwarning("Input Error", "Invalid IP address format.")
            return

        if self.monitor and self.monitor.enhanced_features_available and hasattr(self.monitor, 'firewall'):
            success = self.monitor.block_ip(ip, reason)
            if success:
                messagebox.showinfo("Success", f"IP {ip} blocked successfully.")
                self.ip_entry.delete(0, tk.END) # Clear IP entry
                self.reason_entry.delete(0, tk.END)
                self.reason_entry.insert(0, "Manual Block")
                self.refresh_rules()
            else:
                messagebox.showerror("Error", f"Failed to block IP {ip}. Firewall might not be active or an error occurred.")
        else:
            messagebox.showwarning("Firewall Not Available", "Firewall engine is not initialized or available.")

    def unblock_selected_ip(self):
        selected_item = self.rules_tree.selection()
        if not selected_item:
            messagebox.showwarning("Selection Error", "Please select a rule from the list to unblock.")
            return

        ip_address = self.rules_tree.item(selected_item, "values")[0] # Get IP from the first column

        if messagebox.askyesno("Confirm Unblock", f"Are you sure you want to unblock {ip_address}?"):
            if self.monitor and self.monitor.enhanced_features_available and hasattr(self.monitor, 'firewall'):
                success = self.monitor.unblock_ip(ip_address)
                if success:
                    messagebox.showinfo("Success", f"IP {ip_address} unblocked successfully.")
                    self.refresh_rules()
                else:
                    messagebox.showerror("Error", f"Failed to unblock IP {ip_address}.")
            else:
                messagebox.showwarning("Firewall Not Available", "Firewall engine is not initialized or available.")

    def clear_all_blocks(self):
        if messagebox.askyesno("Confirm Clear", "Are you sure you want to clear ALL firewall blocks? This cannot be undone."):
            if self.monitor and self.monitor.enhanced_features_available and hasattr(self.monitor, 'firewall'):
                success = self.monitor.clear_all_blocks()
                if success:
                    messagebox.showinfo("Success", "All firewall blocks cleared successfully.")
                    self.refresh_rules()
                else:
                    messagebox.showerror("Error", "Failed to clear all blocks.")
            else:
                messagebox.showwarning("Firewall Not Available", "Firewall engine is not initialized or available.")

    def refresh_rules(self):
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)

        if self.monitor and self.monitor.enhanced_features_available and hasattr(self.monitor, 'firewall'):
            rules = self.monitor.firewall.get_rules_report().get('rules', [])
            for ip, rule_data in rules.items():
                self.rules_tree.insert("", tk.END, values=(
                    ip,
                    rule_data.get('action', 'N/A'),
                    rule_data.get('protocol', 'Any'),
                    rule_data.get('port', 'Any'),
                    rule_data.get('reason', 'N/A'),
                    rule_data.get('timestamp', 'N/A')
                ))
            if not rules:
                self.rules_tree.insert("", tk.END, values=("No active rules", "", "", "", "", ""))
        else:
            self.rules_tree.insert("", tk.END, values=("Firewall not available", "", "", "", "", ""))

    def is_valid_ip(self, ip_string):
        parts = ip_string.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            try:
                num = int(part)
                if not (0 <= num <= 255):
                    return False
            except ValueError:
                return False
        return True

    def on_close(self):
        # Optional: You can add cleanup here if needed
        self.destroy()