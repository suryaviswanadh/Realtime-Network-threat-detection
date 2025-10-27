"""
Firewall Engine Module
Dynamic firewall rule management and packet filtering
"""

from datetime import datetime
import bisect

class FirewallEngine:
    """Dynamic firewall rule management"""
    
    def __init__(self):
        # self.rules is a list of tuples: (priority, rule_dict)
        # This keeps it sorted by priority for efficient insertion.
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
        
        rule = {
            'id': self.rule_id_counter,
            'type': rule_type,
            'value': value,
            'action': action,
            'priority': priority,
            'created': datetime.now(),
            'hits': 0
        }
        
        # Use bisect to insert the rule while keeping the list sorted by priority.
        # This is more efficient than appending and re-sorting every time.
        bisect.insort(self.rules, (priority, rule))
        
        return rule['id']
    
    def remove_rule(self, rule_id):
        """Remove firewall rule by ID"""
        rule_found = False
        for i, (priority, rule) in enumerate(self.rules):
            if rule['id'] == rule_id:
                self.rules.pop(i)
                rule_found = True
                break
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
        for priority, rule in self.rules:
            match = False
            if rule['type'] == 'ip' and rule['value'] == src_ip:
                match = True
            elif rule['type'] == 'port' and str(rule['value']) == str(dst_port):
                match = True
            elif rule['type'] == 'protocol' and rule['value'].upper() == protocol.upper():
                match = True
            
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
            True if successfully blocked, False if already blocked
        """
        if ip_address not in self.blocked_ips:
            self.blocked_ips.add(ip_address)
            # Add high-priority block rule
            self.add_rule('ip', ip_address, 'block', priority=1)
            print(f"[FIREWALL] Blocked {ip_address}: {reason}")
            return True
        
        return False
    
    def unblock_ip(self, ip_address):
        """Unblock an IP address"""
        if ip_address in self.blocked_ips:
            self.blocked_ips.remove(ip_address)
            
            # Find and remove associated rules
            rules_to_remove = [rule['id'] for priority, rule in self.rules 
                             if rule['type'] == 'ip' and rule['value'] == ip_address]
            
            for rule_id in rules_to_remove:
                self.remove_rule(rule_id)
            
            print(f"[FIREWALL] Unblocked {ip_address}")
            return True
        
        return False
    
    def get_rules_report(self):
        """Generate firewall rules report"""
        # Extract just the rule dictionaries from the (priority, rule) tuples
        rule_list = [rule for priority, rule in self.rules]
        return {
            'total_rules': len(rule_list),
            'blocked_ips': len(self.blocked_ips),
            'allowed_ips': len(self.allowed_ips),
            'rules': rule_list,
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
        self.allowed_ips.clear()
        self.rule_id_counter = 0