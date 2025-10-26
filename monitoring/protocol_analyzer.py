"""
Protocol Analyzer Module
Deep packet inspection for different protocols
"""

from datetime import datetime


class ProtocolAnalyzer:
    """Deep packet inspection for different protocols"""
    
    def __init__(self):
        self.http_requests = []
        self.dns_queries = []
        self.suspicious_paths = [
            '/admin', 
            '/phpmyadmin', 
            '/.env', 
            '/config',
            '/wp-admin',
            '/.git',
            '/backup',
            '/database'
        ]
        self.suspicious_domains = [
            'malware',
            'phishing',
            'spam',
            'exploit'
        ]
        
    def analyze_http(self, packet_info):
        """
        Analyze HTTP traffic for suspicious patterns
        
        Args:
            packet_info: Dictionary with packet information
        
        Returns:
            Dictionary with alert info, or None if no issues
        """
        try:
            # Create HTTP request record
            http_info = {
                'timestamp': datetime.now(),
                'method': packet_info.get('method', 'GET'),
                'host': packet_info.get('host', 'unknown'),
                'path': packet_info.get('path', '/'),
                'user_agent': packet_info.get('user_agent', 'unknown')
            }
            
            self.http_requests.append(http_info)
            
            # Keep only recent requests (limit memory)
            if len(self.http_requests) > 1000:
                self.http_requests = self.http_requests[-1000:]
            
            # Check for suspicious patterns
            return self._check_http_suspicious(http_info)
            
        except Exception as e:
            print(f"[Protocol Analyzer] HTTP analysis error: {e}")
            return None
    
    def _check_http_suspicious(self, http_info):
        """Check for suspicious HTTP patterns"""
        path = http_info.get('path', '').lower()
        
        # Check for suspicious paths
        for suspicious_path in self.suspicious_paths:
            if suspicious_path in path:
                return {
                    'type': 'suspicious_http_path',
                    'severity': 'medium',
                    'details': f"Suspicious path accessed: {suspicious_path}"
                }
        
        # Check for SQL injection attempts in path
        sql_patterns = ['union', 'select', 'drop', 'insert', '--', ';']
        for pattern in sql_patterns:
            if pattern in path:
                return {
                    'type': 'sql_injection_attempt',
                    'severity': 'high',
                    'details': f"Possible SQL injection: {pattern} in path"
                }
        
        # Check for directory traversal
        if '../' in path or '..\\' in path:
            return {
                'type': 'directory_traversal',
                'severity': 'high',
                'details': "Directory traversal attempt detected"
            }
        
        return None
    
    def analyze_dns(self, packet_info):
        """
        Analyze DNS queries for suspicious patterns
        
        Args:
            packet_info: Dictionary with DNS query information
        
        Returns:
            Dictionary with alert info, or None if no issues
        """
        try:
            dns_info = {
                'timestamp': datetime.now(),
                'query': packet_info.get('query', ''),
                'type': packet_info.get('type', 'A')
            }
            
            self.dns_queries.append(dns_info)
            
            # Keep only recent queries
            if len(self.dns_queries) > 1000:
                self.dns_queries = self.dns_queries[-1000:]
            
            # Check for suspicious patterns
            return self._check_dns_suspicious(dns_info)
            
        except Exception as e:
            print(f"[Protocol Analyzer] DNS analysis error: {e}")
            return None
    
    def _check_dns_suspicious(self, dns_info):
        """Check for suspicious DNS patterns"""
        query = dns_info.get('query', '').lower()
        
        # Check for DNS tunneling (unusually long domain names)
        if len(query) > 50:
            return {
                'type': 'dns_tunneling',
                'severity': 'high',
                'details': f"Unusually long DNS query: {query[:50]}... ({len(query)} chars)"
            }
        
        # Check for suspicious domain keywords
        for keyword in self.suspicious_domains:
            if keyword in query:
                return {
                    'type': 'suspicious_domain',
                    'severity': 'medium',
                    'details': f"Suspicious domain keyword: {keyword} in {query}"
                }
        
        # Check for excessive subdomain levels (potential DGA)
        subdomain_count = query.count('.')
        if subdomain_count > 5:
            return {
                'type': 'dga_pattern',
                'severity': 'medium',
                'details': f"Excessive subdomain levels: {subdomain_count}"
            }
        
        return None
    
    def get_statistics(self):
        """Get protocol analysis statistics"""
        return {
            'total_http_requests': len(self.http_requests),
            'total_dns_queries': len(self.dns_queries),
            'recent_http': self.http_requests[-10:] if self.http_requests else [],
            'recent_dns': self.dns_queries[-10:] if self.dns_queries else []
        }
    
    def clear_history(self):
        """Clear all stored protocol data"""
        self.http_requests.clear()
        self.dns_queries.clear()
