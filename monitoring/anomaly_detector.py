"""
Anomaly Detection Module
Statistical analysis for detecting unusual network patterns
"""

from collections import deque
from datetime import datetime


class AnomalyDetector:
    """Statistical anomaly detection for network traffic"""
    
    def __init__(self, window_size=100):
        self.window_size = window_size
        self.packet_sizes = deque(maxlen=window_size)
        self.packet_intervals = deque(maxlen=window_size)
        self.port_distribution = deque(maxlen=window_size)
        self.last_packet_time = None
        
    def add_packet(self, size, port):
        """Add packet data for analysis"""
        current_time = datetime.now()
        
        # Track packet size
        self.packet_sizes.append(size)
        
        # Track packet interval
        if self.last_packet_time:
            interval = (current_time - self.last_packet_time).total_seconds()
            self.packet_intervals.append(interval)
        
        self.last_packet_time = current_time
        
        # Track port distribution
        self.port_distribution.append(port)
        
    def detect_anomaly(self):
        """Detect anomalies using statistical analysis"""
        anomalies = []
        
        # Check packet size anomaly (3-sigma rule)
        if len(self.packet_sizes) >= self.window_size:
            avg_size = sum(self.packet_sizes) / len(self.packet_sizes)
            variance = sum((x - avg_size) ** 2 for x in self.packet_sizes) / len(self.packet_sizes)
            std_size = variance ** 0.5
            
            recent_size = list(self.packet_sizes)[-10:]
            for size in recent_size:
                if std_size > 0 and abs(size - avg_size) > 3 * std_size:
                    anomalies.append({
                        'type': 'unusual_packet_size',
                        'severity': 'medium',
                        'details': f'Packet size {size} deviates significantly from average {avg_size:.0f}'
                    })
                    break
        
        # Check for traffic burst
        if len(self.packet_intervals) >= self.window_size:
            avg_interval = sum(self.packet_intervals) / len(self.packet_intervals)
            recent_intervals = list(self.packet_intervals)[-10:]
            
            if recent_intervals:
                avg_recent = sum(recent_intervals) / len(recent_intervals)
                
                # Sudden burst: intervals become much smaller
                if avg_interval > 0 and avg_recent < avg_interval * 0.1:
                    anomalies.append({
                        'type': 'traffic_burst',
                        'severity': 'high',
                        'details': f'Unusual traffic burst detected (interval dropped from {avg_interval:.3f}s to {avg_recent:.3f}s)'
                    })
        
        # Check for port scanning pattern
        if len(self.port_distribution) >= 20:
            recent_ports = list(self.port_distribution)[-20:]
            unique_ports = len(set(recent_ports))
            
            # More than 15 different ports in last 20 packets
            if unique_ports > 15:
                anomalies.append({
                    'type': 'port_scanning',
                    'severity': 'high',
                    'details': f'Port scanning pattern detected ({unique_ports} unique ports in 20 packets)'
                })
        
        return anomalies
    
    def reset(self):
        """Reset all statistics"""
        self.packet_sizes.clear()
        self.packet_intervals.clear()
        self.port_distribution.clear()
        self.last_packet_time = None
