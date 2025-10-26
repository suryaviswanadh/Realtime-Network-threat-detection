"""
Enhanced Network Monitor with ML Integration
Version: 2.0.0
"""

import threading
import datetime
import json
import warnings
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Suppress Scapy warnings
warnings.filterwarnings("ignore", category=RuntimeWarning)

class NetworkMonitor:
    """
    Main network monitoring class with integrated ML and advanced features
    """
    
    def __init__(self):
        # Basic monitoring state
        self.monitoring = False
        self.target_ip = ""
        self.packet_count = 0
        self.start_time = None
        self.sniffer_thread = None
        self.last_packet_time = None
        
        # Threat tracking
        self.threats_detected = 0
        self.dos_count = 0
        self.ddos_count = 0
        self.port_scan_count = 0
        self.ml_anomalies = 0
        
        # Statistics
        self.packet_stats = defaultdict(int)
        self.ip_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        
        # Detection parameters
        self.alert_threshold = 100  # Packets per second for DoS
        self.port_scan_threshold = 20  # Unique ports in 60s
        self.ip_scan_window = {}
        self.last_alert_time = {}
        
        # Files
        self.log_file = "security_log.txt"
        
        # Initialize enhanced features
        self._init_enhanced_features()
        
    def _init_enhanced_features(self):
        """Initialize ML and advanced detection features"""
        try:
            from monitoring.threat_intel import ThreatIntelligence
            from monitoring.anomaly_detector import AnomalyDetector
            from monitoring.firewall_engine import FirewallEngine
            from monitoring.protocol_analyzer import ProtocolAnalyzer
            from utils.geo_tracker import GeoIPTracker
            
            self.threat_intel = ThreatIntelligence()
            self.anomaly_detector = AnomalyDetector()
            self.firewall = FirewallEngine()
            self.protocol_analyzer = ProtocolAnalyzer()
            self.geo_tracker = GeoIPTracker()
            
            print("[✓] Enhanced features loaded successfully")
            self.enhanced_features_available = True
            
        except ImportError as e:
            print(f"[!] Enhanced features not available: {e}")
            print("[!] Running in basic mode. Install all requirements for full features.")
            self.enhanced_features_available = False
            
            # Create dummy objects to prevent errors
            class DummyFeature:
                def __getattr__(self, name):
                    return lambda *args, **kwargs: None
            
            self.threat_intel = DummyFeature()
            self.anomaly_detector = DummyFeature()
            self.firewall = DummyFeature()
            self.protocol_analyzer = DummyFeature()
            self.geo_tracker = DummyFeature()
        
        # Try to load ML engine
        try:
            from monitoring.ml_engine import MLSecurityEngine
            self.ml_engine = MLSecurityEngine()
            print("[✓] ML Engine loaded successfully")
            self.ml_available = True
        except ImportError:
            print("[!] ML Engine not available. Install scikit-learn and tensorflow.")
            self.ml_available = False
            self.ml_engine = None
        
    def start_monitoring(self, ip):
        """Start packet sniffing on target IP"""
        self.target_ip = ip
        self.monitoring = True
        self.start_time = datetime.datetime.now()
        
        # Clear previous session data
        self._clear_session_data()
        
        # Start sniffer thread
        self.sniffer_thread = threading.Thread(target=self._start_sniffing, daemon=True)
        self.sniffer_thread.start()
        
        self._log_event(f"Monitoring started for {ip}")
        print(f"[✓] Monitoring started: {ip}")
        
    def stop_monitoring(self):
        """Stop packet sniffing"""
        self.monitoring = False
        
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=2)
        
        self._log_event("Monitoring stopped")
        print("[✓] Monitoring stopped")
        
    def _clear_session_data(self):
        """Clear statistics for new session"""
        self.packet_count = 0
        self.threats_detected = 0
        self.dos_count = 0
        self.ddos_count = 0
        self.port_scan_count = 0
        self.ml_anomalies = 0
        self.packet_stats.clear()
        self.ip_stats.clear()
        self.port_stats.clear()
        self.ip_scan_window.clear()
        self.last_alert_time.clear()
        
    def _start_sniffing(self):
        """Start Scapy packet capture"""
        try:
            sniff(
                prn=self._packet_handler,
                filter=f"host {self.target_ip}",
                store=False,
                stop_filter=lambda p: not self.monitoring
            )
        except PermissionError:
            print("[✗] Permission denied. Run as administrator/root.")
        except Exception as e:
            print(f"[✗] Sniffing error: {e}")
            
    def _packet_handler(self, packet):
        """Process each captured packet"""
        if not self.monitoring:
            return
        
        self.packet_count += 1
        current_time = datetime.datetime.now()
        
        # Calculate inter-arrival time
        inter_arrival = 0
        if self.last_packet_time:
            inter_arrival = (current_time - self.last_packet_time).total_seconds()
        self.last_packet_time = current_time
        
        # Basic packet analysis
        if IP not in packet:
            return
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_size = len(packet)
        
        # Update statistics
        self.packet_stats["total"] += 1
        self.ip_stats[src_ip] += 1
        
        # Extract packet features
        packet_info = {
            'size': packet_size,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'ttl': packet[IP].ttl,
            'inter_arrival_time': inter_arrival,
            'timestamp': current_time
        }
        
        # Protocol-specific handling
        protocol_num = 0
        dst_port = 0
        
        if TCP in packet:
            self.packet_stats["tcp"] += 1
            dst_port = packet[TCP].dport
            self.port_stats[dst_port] += 1
            protocol_num = 6
            packet_info.update({
                'port': dst_port,
                'protocol': 'TCP',
                'protocol_num': protocol_num,
                'flags': packet[TCP].flags,
                'window_size': packet[TCP].window
            })
            
            # Check for SYN flood (DoS)
            if packet[TCP].flags.S and not packet[TCP].flags.A:
                if self._check_dos_attack(src_ip, current_time):
                    self._handle_threat("DoS_Attack", src_ip, "SYN flood detected")
            
            # Check for port scanning
            if self._check_port_scan(src_ip, dst_port, current_time):
                self._handle_threat("Port_Scan", src_ip, "Multiple port scan detected")
                
        elif UDP in packet:
            self.packet_stats["udp"] += 1
            dst_port = packet[UDP].dport
            self.port_stats[dst_port] += 1
            protocol_num = 17
            packet_info.update({
                'port': dst_port,
                'protocol': 'UDP',
                'protocol_num': protocol_num
            })
            
        elif ICMP in packet:
            self.packet_stats["icmp"] += 1
            protocol_num = 1
            packet_info.update({
                'port': 0,
                'protocol': 'ICMP',
                'protocol_num': protocol_num
            })
        
        # Enhanced features (if available)
        if self.enhanced_features_available:
            self._enhanced_analysis(packet_info, src_ip, dst_port, protocol_num)
        
        # ML Analysis (if available)
        if self.ml_available and self.ml_engine:
            self._ml_analysis(packet_info, src_ip)
    
    def _enhanced_analysis(self, packet_info, src_ip, dst_port, protocol_num):
        """Run enhanced feature analysis"""
        try:
            # 1. IP Reputation Check
            reputation = self.threat_intel.check_ip_reputation(src_ip)
            if reputation < 50:  # Low reputation threshold
                self.threat_intel.add_threat(src_ip, 'low_reputation', 'high')
                self._handle_threat("Low_Reputation_IP", src_ip, 
                                  f"Reputation score: {reputation}/100")
            
            # 2. Geographic Tracking
            geo_info = self.geo_tracker.lookup_ip(src_ip)
            
            # 3. Firewall Check
            action = self.firewall.check_packet(src_ip, dst_port, 
                                               packet_info.get('protocol', 'Unknown'))
            if action == 'block':
                return  # Packet blocked by firewall
            
            # 4. Anomaly Detection
            self.anomaly_detector.add_packet(packet_info['size'], dst_port)
            anomalies = self.anomaly_detector.detect_anomaly()
            
            for anomaly in anomalies:
                self.ml_anomalies += 1
                self.threats_detected += 1
                self._log_threat(anomaly['type'], src_ip, anomaly['details'])
            
            # 5. Protocol Analysis
            if packet_info.get('protocol') == 'TCP' and dst_port in [80, 443, 8080]:
                suspicious = self.protocol_analyzer.analyze_http(packet_info)
                if suspicious:
                    self._handle_threat(suspicious['type'], src_ip, 
                                      suspicious['details'])
                    
        except Exception as e:
            print(f"[!] Enhanced analysis error: {e}")
    
    def _ml_analysis(self, packet_info, src_ip):
        """Run ML-based threat analysis"""
        try:
            # Calculate additional features for ML
            elapsed_time = (datetime.datetime.now() - self.start_time).total_seconds()
            packet_info.update({
                'packet_rate': self.packet_count / max(elapsed_time, 1),
                'unique_ports': len(set(self.port_stats.keys())),
                'entropy': 0  # Simplified - can calculate payload entropy
            })
            
            # Run ML analysis
            ml_results = self.ml_engine.analyze_packet(packet_info)
            
            # Check threat level
            if ml_results.get('overall_threat_level', 0) > 0.7:
                self.ml_anomalies += 1
                self.threats_detected += 1
                
                threat_class = ml_results.get('threat_class', {}).get('class', 'Unknown')
                confidence = ml_results.get('overall_threat_level', 0)
                
                self._log_threat(
                    "ML_Threat_Detection",
                    src_ip,
                    f"Class: {threat_class}, Confidence: {confidence:.2f}"
                )
                
                # Auto-block high-confidence threats
                if confidence > 0.85:
                    self.firewall.auto_block_threat(src_ip, 
                                                   f"ML detected: {threat_class}")
                    
        except Exception as e:
            print(f"[!] ML analysis error: {e}")
    
    def _check_dos_attack(self, src_ip, current_time):
        """Detect DoS attack by packet rate"""
        if src_ip not in self.last_alert_time:
            self.last_alert_time[src_ip] = (0, current_time)
        
        count, last_time = self.last_alert_time[src_ip]
        time_diff = (current_time - last_time).total_seconds()
        
        if time_diff < 1.0:
            count += 1
        else:
            count = 1
            last_time = current_time
        
        self.last_alert_time[src_ip] = (count, last_time)
        
        if count > self.alert_threshold:
            self.last_alert_time[src_ip] = (0, current_time)  # Reset
            return True
        
        return False
    
    def _check_port_scan(self, src_ip, dst_port, current_time):
        """Detect port scanning activity"""
        if src_ip not in self.ip_scan_window:
            self.ip_scan_window[src_ip] = {
                'ports': set(),
                'start_time': current_time
            }
        
        window = self.ip_scan_window[src_ip]
        time_diff = (current_time - window['start_time']).total_seconds()
        
        # Reset window after 60 seconds
        if time_diff > 60:
            self.ip_scan_window[src_ip] = {
                'ports': {dst_port},
                'start_time': current_time
            }
            return False
        
        window['ports'].add(dst_port)
        
        # Trigger if too many unique ports accessed
        if len(window['ports']) > self.port_scan_threshold:
            self.ip_scan_window.pop(src_ip, None)  # Reset
            return True
        
        return False
    
    def _handle_threat(self, threat_type, source_ip, details):
        """Handle detected threat"""
        self.threats_detected += 1
        
        # Update counters
        if 'DoS' in threat_type or 'SYN' in threat_type:
            self.dos_count += 1
        elif 'DDoS' in threat_type:
            self.ddos_count += 1
        elif 'Port_Scan' in threat_type or 'Scan' in threat_type:
            self.port_scan_count += 1
        
        # Log the threat
        self._log_threat(threat_type, source_ip, details)
        
        # Auto-response for critical threats
        if self.enhanced_features_available:
            if threat_type in ['DoS_Attack', 'DDoS_Attack', 'Port_Scan']:
                self.firewall.auto_block_threat(source_ip, threat_type)
    
    def _log_threat(self, threat_type, source, message):
        """Log threat to file"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {threat_type.upper()} from {source}: {message}\n"
        
        try:
            with open(self.log_file, "a", encoding='utf-8') as f:
                f.write(log_entry)
        except IOError as e:
            print(f"[✗] Logging error: {e}")
    
    def _log_event(self, message):
        """Log general event"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] INFO: {message}\n"
        
        try:
            with open(self.log_file, "a", encoding='utf-8') as f:
                f.write(log_entry)
        except IOError:
            pass
    
    def get_stats(self):
        """Return current monitoring statistics"""
        uptime = datetime.datetime.now() - self.start_time if self.start_time else datetime.timedelta(0)
        
        stats = {
            "monitoring": self.monitoring,
            "target_ip": self.target_ip,
            "packet_count": self.packet_count,
            "threats_detected": self.threats_detected,
            "dos_count": self.dos_count,
            "ddos_count": self.ddos_count,
            "port_scan_count": self.port_scan_count,
            "ml_anomalies": self.ml_anomalies,
            "uptime": str(uptime).split('.')[0],
            "packet_stats": dict(self.packet_stats),
            "top_ips": dict(sorted(self.ip_stats.items(), 
                                  key=lambda x: x[1], reverse=True)[:5]),
            "top_ports": dict(sorted(self.port_stats.items(), 
                                    key=lambda x: x[1], reverse=True)[:5])
        }
        
        # Add enhanced stats if available
        if self.enhanced_features_available:
            try:
                stats.update({
                    "threat_intel": self.threat_intel.get_threat_report(),
                    "firewall": self.firewall.get_rules_report(),
                    "geo": self.geo_tracker.get_geographic_report()
                })
            except Exception:
                pass
        
        # Add ML stats if available
        if self.ml_available and self.ml_engine:
            try:
                stats["ml_stats"] = self.ml_engine.get_ml_stats()
            except Exception:
                pass
        
        return stats
    
    def export_data(self, filename):
        """Export statistics to JSON file"""
        try:
            data = self.get_stats()
            with open(filename, "w", encoding='utf-8') as f:
                json.dump(data, f, indent=4, default=str)
            print(f"[✓] Data exported to {filename}")
            return True
        except Exception as e:
            print(f"[✗] Export error: {e}")
            return False
    
    def get_active_threats(self):
        """Get list of currently active threats"""
        threats = []
        
        if self.enhanced_features_available:
            try:
                # Get threats from threat intelligence
                report = self.threat_intel.get_threat_report()
                for ip, data in report.get('top_threats', [])[:10]:
                    threats.append({
                        'ip': ip,
                        'type': data['type'],
                        'severity': data['severity'],
                        'count': data['count'],
                        'timestamp': str(data['timestamp'])
                    })
            except Exception:
                pass
        
        return threats
    
    def block_ip(self, ip_address, reason="Manual block"):
        """Manually block an IP address"""
        if self.enhanced_features_available:
            success = self.firewall.auto_block_threat(ip_address, reason)
            if success:
                self._log_event(f"Manually blocked IP: {ip_address} - {reason}")
                return True
        return False
    
    def unblock_ip(self, ip_address):
        """Unblock an IP address"""
        if self.enhanced_features_available:
            # Remove from firewall blocked list
            if ip_address in self.firewall.blocked_ips:
                self.firewall.blocked_ips.remove(ip_address)
                
                # Remove related rules
                rules_to_remove = [r['id'] for r in self.firewall.rules 
                                 if r['type'] == 'ip' and r['value'] == ip_address]
                for rule_id in rules_to_remove:
                    self.firewall.remove_rule(rule_id)
                
                self._log_event(f"Unblocked IP: {ip_address}")
                return True
        return False
    
    def clear_all_blocks(self):
        """Clear all blocked IPs"""
        if self.enhanced_features_available:
            self.firewall.blocked_ips.clear()
            self.firewall.rules.clear()
            self._log_event("Cleared all firewall blocks")
            return True
        return False


# For backward compatibility
class NetworkMonitorBasic:
    """
    Basic version without ML features for systems that can't install TensorFlow
    """
    def __init__(self):
        print("[!] Running in basic mode (no ML features)")
        # Implement basic features only
        pass
