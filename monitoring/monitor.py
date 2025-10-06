import threading
import datetime
import json
import warnings
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Suppress runtime warnings from Scapy
warnings.filterwarnings("ignore", category=RuntimeWarning)

class NetworkMonitor:
    """Handles the backend packet sniffing and threat analysis."""
    def __init__(self):
        self.monitoring = False
        self.target_ip = ""
        self.packet_count = 0
        self.threats_detected = 0
        self.dos_count = 0
        self.port_scan_count = 0
        self.packet_stats = defaultdict(int)
        self.ip_stats = defaultdict(int)
        self.start_time = None
        self.sniffer_thread = None
        self.alert_threshold = 100  # Packets per second for DoS
        self.port_scan_threshold = 20  # Unique ports in 60s for scan
        self.ip_scan_window = {}
        self.last_alert_time = {}
        self.log_file = "security_log.txt"
        
    def start_monitoring(self, ip):
        """Starts the packet sniffing thread."""
        self.target_ip = ip
        self.monitoring = True
        self.start_time = datetime.datetime.now()
        self.sniffer_thread = threading.Thread(target=self._start_sniffing, daemon=True)
        self.sniffer_thread.start()
        
    def stop_monitoring(self):
        """Stops the packet sniffing thread."""
        self.monitoring = False
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=1)
            
    def _start_sniffing(self):
        """Uses Scapy to sniff packets and passes them to the handler."""
        try:
            sniff(prn=self._packet_handler, filter=f"host {self.target_ip}", store=False, stop_filter=lambda p: not self.monitoring)
        except Exception as e:
            print(f"Sniffing error: {e}")
            
    def _packet_handler(self, packet):
        """Processes each captured packet to check for threats."""
        if not self.monitoring: return
        
        self.packet_count += 1
        current_time = datetime.datetime.now()
        
        if IP in packet:
            src_ip = packet[IP].src
            self.ip_stats[src_ip] += 1
            
            if TCP in packet:
                self.packet_stats["tcp"] += 1
                dst_port = packet[TCP].dport
                # Check for SYN Flood (DoS)
                if packet[TCP].flags.S and not packet[TCP].flags.A:
                    if self._check_dos_attack(src_ip, current_time):
                        self._log_threat("DoS Attack", src_ip, "Possible SYN Flood detected")
                # Check for Port Scanning
                if self._check_port_scan(src_ip, dst_port, current_time):
                    self._log_threat("Port Scan", src_ip, "Scan detected across multiple ports")
            elif UDP in packet:
                self.packet_stats["udp"] += 1
            elif ICMP in packet:
                self.packet_stats["icmp"] += 1
                    
    def _check_dos_attack(self, src_ip, current_time):
        """Detects if packet rate from a single IP exceeds a threshold."""
        if src_ip not in self.last_alert_time:
            self.last_alert_time[src_ip] = (0, current_time)
        
        count, last_time = self.last_alert_time[src_ip]
        if (current_time - last_time).total_seconds() < 1.0:
            count += 1
        else:
            count = 1
            last_time = current_time
        
        self.last_alert_time[src_ip] = (count, last_time)

        if count > self.alert_threshold:
            self.dos_count += 1
            self.threats_detected += 1
            self.last_alert_time[src_ip] = (0, current_time) # Reset to prevent log spam
            return True
        return False
        
    def _check_port_scan(self, src_ip, dst_port, current_time):
        """Detects if an IP connects to many unique ports in a short time."""
        if src_ip not in self.ip_scan_window:
            self.ip_scan_window[src_ip] = {'ports': set(), 'start_time': current_time}
        
        window = self.ip_scan_window[src_ip]
        if (current_time - window['start_time']).total_seconds() > 60:
            window['ports'] = {dst_port}
            window['start_time'] = current_time
            return False
            
        window['ports'].add(dst_port)
        if len(window['ports']) > self.port_scan_threshold:
            self.port_scan_count += 1
            self.threats_detected += 1
            self.ip_scan_window.pop(src_ip, None) # Reset after detection
            return True
        return False
        
    def _log_threat(self, threat_type, source, message):
        """Writes detected threats to a log file."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {threat_type.upper()} ALERT from {source}: {message}\n"
        try:
            with open(self.log_file, "a") as f:
                f.write(log_entry)
        except IOError as e:
            print(f"Error writing to log file: {e}")
            
    def get_stats(self):
        """Returns a dictionary of the latest statistics."""
        uptime = datetime.datetime.now() - self.start_time if self.start_time else datetime.timedelta(0)
        return {
            "monitoring": self.monitoring, "target_ip": self.target_ip, "packet_count": self.packet_count,
            "threats_detected": self.threats_detected, "dos_count": self.dos_count, "port_scan_count": self.port_scan_count,
            "uptime": str(uptime).split('.')[0], "packet_stats": dict(self.packet_stats),
            "top_ips": dict(sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:5])
        }
        
    def export_data(self, filename):
        """Exports the current statistics to a JSON file."""
        try:
            with open(filename, "w") as f:
                json.dump(self.get_stats(), f, indent=4)
            return True
        except Exception as e:
            print(f"Export error: {e}")
            return False