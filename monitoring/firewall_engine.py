"""
Firewall Engine Module
Dynamic firewall rule management and packet filtering
"""

from datetime import datetime


class FirewallEngine:
    """Dynamic firewall rule management"""
    
    def __init__(self):
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
        
        self.rules.append(rule)
        
        # Sort by priority (lower number = higher priority)
        self.rules.sort(key=lambda x: x['priority'])
        
        return rule['id']
    
    def remove_rule(self, rule_id):
        """Remove firewall rule by ID"""
        self.rules = [r for r in self.rules if r['id'] != rule_id]
        return True
    
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
        # Check rules in priority order
        for rule in self.rules:
            if rule['type'] == 'ip' and rule['value'] == src_ip:
                rule['hits'] += 1
                return rule['action']
            
            elif rule['type'] == 'port' and rule['value'] == dst_port:
                rule['hits'] += 1
                return rule['action']
            
            elif rule['type'] == 'protocol' and rule['value'].upper() == protocol.upper():
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
            
            # Remove associated rules
            rules_to_remove = [r['id'] for r in self.rules 
                             if r['type'] == 'ip' and r['value'] == ip_address]
            
            for rule_id in rules_to_remove:
                self.remove_rule(rule_id)
            
            print(f"[FIREWALL] Unblocked {ip_address}")
            return True
        
        return False
    
    def get_rules_report(self):
        """Generate firewall rules report"""
        return {
            'total_rules': len(self.rules),
            'blocked_ips': len(self.blocked_ips),
            'allowed_ips': len(self.allowed_ips),
            'rules': self.rules,
            'top_hit_rules': sorted(
                self.rules,
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
