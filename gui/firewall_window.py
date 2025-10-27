"""
Firewall Engine Module
Dynamic firewall rule management and packet filtering
"""

from datetime import datetime
import bisect

class FirewallEngine:
    """Dynamic firewall rule management"""
    
    def __init__(self):
        # self.rules is a list of tuples: (priority, rule_id, rule_dict)
        # We add rule_id to ensure unique, comparable elements for bisect.
        self.rules = []
        self.blocked_ips = set()
        self.allowed_ips = set()
        self.rule_id_counter = 0
        
    def add_rule(self, rule_type, value, action='block', priority=5):
        """
        Add firewall rule
        
        Args:
            rule_type: 'ip', 'port', or 'protocol'
            value: The value to match (IP address, port number, or protocol name)
            action: 'block', 'allow', or 'log'
            priority: Lower number = higher priority (1-10)
        
        Returns:
            rule_id: Unique identifier for the rule
        """
        self.rule_id_counter += 1
        rule_id = self.rule_id_counter # Get the unique ID
        
        rule = {
            'id': rule_id, # Use the ID here
            'type': rule_type,
            'value': value,
            'action': action,
            'priority': priority,
            'created': datetime.now(),
            'hits': 0
        }
        
        # --- FIX: Insert (priority, rule_id, rule) ---
        # rule_id ensures uniqueness if priorities are the same, preventing
        # the TypeError when comparing dictionaries.
        bisect.insort(self.rules, (priority, rule_id, rule))
        
        return rule_id
    
    def remove_rule(self, rule_id):
        """Remove firewall rule by ID"""
        rule_found = False
        # Iterate through a copy in case we modify the list
        for i, (priority, r_id, rule) in enumerate(list(self.rules)):
            if r_id == rule_id: # Compare using rule_id
                self.rules.pop(i)
                rule_found = True
                # If removing a blocked IP rule, update the blocked_ips set
                if rule['type'] == 'ip' and rule['action'] == 'block':
                    if rule['value'] in self.blocked_ips:
                        # Check if any other rule still blocks this IP before removing
                        still_blocked = any(
                            prio == rule['priority'] and other_rule['type'] == 'ip' and other_rule['value'] == rule['value'] and other_rule['action'] == 'block'
                            for prio, other_id, other_rule in self.rules if other_id != rule_id
                        )
                        if not still_blocked:
                           self.blocked_ips.discard(rule['value'])

                break # Assume rule IDs are unique
        return rule_found
    
    def check_packet(self, src_ip, dst_port, protocol):
        """
        Check if packet should be blocked
        
        Args:
            src_ip: Source IP address
            dst_port: Destination port
            protocol: Protocol name ('TCP', 'UDP', 'ICMP')
        
        Returns:
            'block', 'allow', or 'log'
        """
        # Check rules in priority order (list is already sorted)
        for priority, rule_id, rule in self.rules: # Unpack the tuple correctly
            match = False
            # Ensure type matching for comparison (e.g., port is int vs string)
            try:
                if rule['type'] == 'ip' and rule['value'] == src_ip:
                    match = True
                elif rule['type'] == 'port' and int(rule['value']) == dst_port: # Compare as int
                    match = True
                elif rule['type'] == 'protocol' and rule['value'].upper() == protocol.upper():
                    match = True
            except (ValueError, TypeError):
                 # Handle cases where rule value might not be convertible (e.g., invalid port rule)
                 continue # Skip this rule if types mismatch

            if match:
                rule['hits'] += 1
                return rule['action']

        # Default action: allow
        return 'allow'
    
    def auto_block_threat(self, ip_address, reason):
        """
        Automatically block a threatening IP
        
        Args:
            ip_address: IP to block
            reason: Reason for blocking
        
        Returns:
            True if successfully added a block rule, False otherwise
        """
        # Check if this specific IP is already blocked by *any* rule
        already_blocked_by_rule = any(
            rule['type'] == 'ip' and rule['value'] == ip_address and rule['action'] == 'block'
            for _, _, rule in self.rules
        )
        
        if not already_blocked_by_rule:
            self.blocked_ips.add(ip_address)
            # Add high-priority block rule
            self.add_rule('ip', ip_address, 'block', priority=1)
            print(f"[FIREWALL] Added block rule for {ip_address}: {reason}")
            return True
        else:
             # Optionally print that it was already blocked if needed for debugging
             # print(f"[FIREWALL] IP {ip_address} is already blocked by an existing rule.")
             pass

        # Return False if we didn't add a *new* rule, even if logically blocked
        return False

    def unblock_ip(self, ip_address):
        """Unblock an IP address by removing ALL rules blocking it."""
        rules_removed = False
        # Find all rules blocking this specific IP
        rules_to_remove = [r_id for prio, r_id, rule in self.rules
                           if rule['type'] == 'ip' and rule['value'] == ip_address and rule['action'] == 'block']
        
        if not rules_to_remove:
            print(f"[FIREWALL] No block rules found for {ip_address}")
            return False # No rules found to remove

        for rule_id in rules_to_remove:
            if self.remove_rule(rule_id):
                rules_removed = True
        
        # Update the set after removing rules
        self.blocked_ips.discard(ip_address)

        if rules_removed:
            print(f"[FIREWALL] Removed block rules for {ip_address}")
            return True
        
        return False
    
    def get_rules_report(self):
        """Generate firewall rules report"""
        # Extract just the rule dictionaries from the (priority, id, rule) tuples
        rule_list = [rule for priority, rule_id, rule in self.rules]
        # Recalculate blocked_ips set based on current rules for accuracy
        current_blocked_ips = {rule['value'] for _, _, rule in self.rules if rule['type'] == 'ip' and rule['action'] == 'block'}
        self.blocked_ips = current_blocked_ips

        return {
            'total_rules': len(rule_list),
            'blocked_ips': len(self.blocked_ips),
            # 'allowed_ips': len(self.allowed_ips), # This set wasn't really being used/updated
            'rules': sorted(rule_list, key=lambda x: (x['priority'], x['id'])), # Sort for display
            'top_hit_rules': sorted(
                rule_list,
                key=lambda x: x['hits'],
                reverse=True
            )[:10]
        }
    
    def clear_all_rules(self):
        """Clear all firewall rules"""
        self.rules.clear()
        self.blocked_ips.clear()
        # self.allowed_ips.clear() # This set wasn't really being used
        self.rule_id_counter = 0
        print("[FIREWALL] Cleared all rules.")