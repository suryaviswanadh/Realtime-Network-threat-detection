"""
Threat Intelligence Module
Tracks and analyzes IP reputation and threat patterns
"""

import re
from datetime import datetime
from collections import defaultdict


class ThreatIntelligence:
    """Advanced threat detection with reputation scoring"""
    
    def __init__(self):
        self.known_threats = {}
        self.reputation_db = {}
        self.suspicious_patterns = {
            'sql_injection': [
                r"(\bunion\b.*\bselect\b)", 
                r"(\bor\b.*=.*)", 
                r"(--)", 
                r"(;.*)"
            ],
            'xss': [
                r"(<script.*?>)", 
                r"(javascript:)", 
                r"(onerror=)", 
                r"(onload=)"
            ],
            'command_injection': [
                r"(;.*\bcat\b)", 
                r"(\|.*\bls\b)", 
                r"(&.*\bwhoami\b)"
            ],
            'path_traversal': [
                r"(\.\./)", 
                r"(\.\.\\)"
            ]
        }
        
    def check_ip_reputation(self, ip_address):
        """
        Check IP reputation score (0-100)
        Lower score = more suspicious
        """
        if ip_address in self.reputation_db:
            return self.reputation_db[ip_address]
        
        # Start with perfect score
        score = 100
        
        # Check against known threat lists
        if ip_address in self.known_threats:
            threat_level = self.known_threats[ip_address]['severity']
            if threat_level == 'critical':
                score -= 80
            elif threat_level == 'high':
                score -= 60
            elif threat_level == 'medium':
                score -= 40
            elif threat_level == 'low':
                score -= 20
        
        self.reputation_db[ip_address] = max(0, score)
        return self.reputation_db[ip_address]
    
    def add_threat(self, ip, threat_type, severity='medium'):
        """Add an IP to the threat database"""
        if ip not in self.known_threats:
            self.known_threats[ip] = {
                'type': threat_type,
                'severity': severity,
                'timestamp': datetime.now(),
                'count': 1
            }
        else:
            self.known_threats[ip]['count'] += 1
            # Escalate severity if repeated threats
            if self.known_threats[ip]['count'] > 10:
                self.known_threats[ip]['severity'] = 'critical'
        
    def detect_payload_attack(self, payload):
        """Detect malicious patterns in payload"""
        detected_attacks = []
        
        for attack_type, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                if re.search(pattern, str(payload), re.IGNORECASE):
                    detected_attacks.append(attack_type)
                    break
        
        return detected_attacks
    
    def get_threat_report(self):
        """Generate threat intelligence report"""
        report = {
            'total_threats': len(self.known_threats),
            'critical': sum(1 for t in self.known_threats.values() 
                          if t['severity'] == 'critical'),
            'high': sum(1 for t in self.known_threats.values() 
                       if t['severity'] == 'high'),
            'medium': sum(1 for t in self.known_threats.values() 
                         if t['severity'] == 'medium'),
            'low': sum(1 for t in self.known_threats.values() 
                      if t['severity'] == 'low'),
            'top_threats': sorted(
                self.known_threats.items(),
                key=lambda x: x[1]['count'],
                reverse=True
            )[:10]
        }
        return report
    
    def clear_threats(self):
        """Clear all threat data"""
        self.known_threats.clear()
        self.reputation_db.clear()
