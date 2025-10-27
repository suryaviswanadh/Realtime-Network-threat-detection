# monitoring/monitor.py
import threading
import datetime
import json
import warnings
import queue
import logging
import time
import math
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, Packet

# Import the new flow classes
from .flow import Flow
from .flow_packet import FlowPacket

# Suppress Scapy warnings
warnings.filterwarnings("ignore", category=RuntimeWarning)

class NetworkMonitor:
    """
    Main network monitoring class.
    - Captures packets
    - Performs packet-level checks (Firewall, DPI, basic DoS/Scan)
    - Assembles packets into Flows
    - Sends terminated Flows to the ML Engine for analysis
    """

    def __init__(self):
        self.monitoring = False
        self.target_ip = "" # Contextual IP
        self.packet_count = 0 # Overall packets sniffed
        self.total_bytes = 0
        self.start_time = None
        self.sniffer_thread = None
        self.analysis_thread = None
        self.timeout_thread = None # Thread for checking flow timeouts
        self.packet_queue = queue.Queue(maxsize=4096)
        self._stop_event = threading.Event() # For stopping threads cleanly
        
        # --- Flow Management ---
        self.current_flows = {}
        self.flow_timeout = 60.0 # Expire flows after 60s of inactivity
        self.flow_lock = threading.Lock() # Lock for accessing current_flows
        # ---------------------

        # Stats & Threat Tracking
        self.threats_detected = 0
        self.dos_count = 0; self.ddos_count = 0; self.port_scan_count = 0; self.ml_anomalies = 0
        self.packet_stats = defaultdict(int); self.ip_stats = defaultdict(int); self.port_stats = defaultdict(int)
        self.ip_scan_window = {}; self.last_alert_time = {} # For packet-level checks

        # Logging
        self.log_file = "security_log.txt"
        self._setup_logging()

        # DPI Data
        self.malicious_domains = {"evil-domain-example.com", "phishing-site-sample.org"}
        self.suspicious_http_patterns = {b"../", b"/etc/passwd", b"cmd.exe", b"<script"}
        self.malware_signatures = {b'\xDE\xAD\xBE\xEF', b'SIMPLE_MALWARE_STRING'}

        # Detection parameters from old file (for packet-level checks)
        self.alert_threshold = 100  # Packets per second for DoS
        self.port_scan_threshold = 20  # Unique ports in 60s
        
        # Initialize enhanced features (ML Engine, Firewall, etc.)
        self._init_enhanced_features()


    def _setup_logging(self):
        self.logger = logging.getLogger('NetworkMonitor')
        self.logger.setLevel(logging.INFO)
        # Prevent duplicate handlers if re-initialized
        if not self.logger.handlers:
            try:
                handler = logging.FileHandler(self.log_file, mode='w', encoding='utf-8')
                handler.setLevel(logging.INFO)
                formatter = logging.Formatter('[%(asctime)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
                handler.setFormatter(formatter)
                self.logger.addHandler(handler)
            except PermissionError:
                 print(f"[ERROR] Permission denied to write to log file: {self.log_file}. Logs will not be saved.")
            except Exception as e:
                 print(f"[ERROR] Failed to set up logger: {e}")


    def _init_enhanced_features(self):
        # Load ML Engine first
        try:
            from monitoring.ml_engine import MLSecurityEngine
            self.ml_engine = MLSecurityEngine() # Now loads the RF model
            print("[✓] ML Engine loaded successfully")
            self.ml_available = True
        except ImportError:
            print("[!] ML Engine module not found.")
            self.ml_available = False
        except Exception as e:
             print(f"[!] Error initializing ML Engine: {e}")
             self.ml_available = False

        # Load other features
        try:
            from monitoring.threat_intel import ThreatIntelligence
            from monitoring.firewall_engine import FirewallEngine
            from monitoring.protocol_analyzer import ProtocolAnalyzer # Keep for non-DPI HTTP
            from utils.geo_tracker import GeoIPTracker

            self.threat_intel = ThreatIntelligence()
            self.firewall = FirewallEngine()
            self.protocol_analyzer = ProtocolAnalyzer()
            self.geo_tracker = GeoIPTracker()
            print("[✓] Enhanced non-ML features loaded successfully")
            self.enhanced_features_available = True

        except ImportError as e:
            print(f"[!] Some enhanced features not available: {e}")
            self.enhanced_features_available = False 
            class DummyFeature:
                def __getattr__(self, name): return lambda *args, **kwargs: None
            if not hasattr(self, 'threat_intel'): self.threat_intel = DummyFeature()
            if not hasattr(self, 'firewall'): self.firewall = DummyFeature()
            if not hasattr(self, 'protocol_analyzer'): self.protocol_analyzer = DummyFeature()
            if not hasattr(self, 'geo_tracker'): self.geo_tracker = DummyFeature()

        # Assign dummy ML engine if loading failed
        if not self.ml_available or not hasattr(self, 'ml_engine'):
             class DummyMLEngine:
                  def analyze_flow(self, features): return {'overall_threat_level': 0.0, 'threat_class': {'class': 'Benign', 'confidence': 1.0}}
                  def get_ml_stats(self): return {'models_available': False, 'models_trained': False, 'rf_available': False, 'training_samples': 'N/A', 'predictions_made': 0, 'model_types': []}
             self.ml_engine = DummyMLEngine()
             self.ml_available = False # Ensure flag is false


    def start_monitoring(self, ip):
        if self.monitoring:
             print("[!] Monitoring is already active.")
             return
        self.target_ip = ip
        self.monitoring = True
        self.start_time = datetime.datetime.now()
        self._clear_session_data() # This also resets the logger

        # Start threads
        self.sniffer_thread = threading.Thread(target=self._start_sniffing, daemon=True)
        self.analysis_thread = threading.Thread(target=self._analysis_worker, daemon=True)
        self.timeout_thread = threading.Thread(target=self._check_flow_timeouts_periodically, daemon=True)

        self.sniffer_thread.start()
        self.analysis_thread.start()
        self.timeout_thread.start()

        self.logger.info(f"INFO: Monitoring started (Target: {ip}, Filter: 'ip')")
        print(f"[✓] Monitoring started: {ip}")


    def stop_monitoring(self):
        if not self.monitoring:
             return
        print("[!] Stopping monitoring...")
        self.monitoring = False # Signal sniffing thread
        self._stop_event.set() # Signal threads to stop
        self.packet_queue.put(None) # Unblock analysis worker
        
        if self.sniffer_thread and self.sniffer_thread.is_alive(): self.sniffer_thread.join(timeout=2)
        if self.analysis_thread and self.analysis_thread.is_alive(): self.analysis_thread.join(timeout=2)
        if self.timeout_thread and self.timeout_thread.is_alive(): self.timeout_thread.join(timeout=2)

        print("Processing remaining flows...")
        self._process_remaining_flows() # Process any flows left after threads stop

        self.logger.info("INFO: Monitoring stopped")
        print("[✓] Monitoring stopped")
        # Close logger file handle
        try:
             if self.logger.handlers:
                 self.logger.handlers[0].close()
                 self.logger.removeHandler(self.logger.handlers[0])
        except Exception as e:
             print(f"Error closing logger: {e}")


    def _clear_session_data(self):
        self.packet_count = 0; self.total_bytes = 0
        self.threats_detected = 0; self.dos_count = 0; self.ddos_count = 0; self.port_scan_count = 0; self.ml_anomalies = 0
        self.packet_stats.clear(); self.ip_stats.clear(); self.port_stats.clear()
        self.ip_scan_window.clear(); self.last_alert_time.clear()
        with self.packet_queue.mutex: self.packet_queue.queue.clear()
        with self.flow_lock: self.current_flows.clear()
        self._stop_event.clear() # Reset stop event

        if self.logger.handlers:
            handler = self.logger.handlers[0]; handler.close(); self.logger.removeHandler(handler)
        self._setup_logging()

    def _start_sniffing(self):
        try:
            sniff_filter = "ip"
            sniff(prn=self._packet_handler, filter=sniff_filter, store=False,
                  stop_filter=lambda p: not self.monitoring)
        except PermissionError: 
             print("[✗] Permission denied. Run as administrator/root.")
             self.monitoring = False # Trigger stop
             self._stop_event.set()
             self.packet_queue.put(None)
        except Exception as e: 
             print(f"[✗] Sniffing error: {e}")
             self.monitoring = False # Trigger stop
             self._stop_event.set()
             self.packet_queue.put(None)
        finally: 
             print("Sniffer thread finished.")


    def _packet_handler(self, packet: Packet):
        if not self.monitoring: return
        self.packet_count += 1
        self.total_bytes += len(packet)
        try: self.packet_queue.put(packet, block=False, timeout=0.1)
        except queue.Full: pass # Silently drop packet


    def _analysis_worker(self):
        """Consumes packets, performs packet-level checks, and updates flows."""
        print("Analysis worker started.")
        while True: # Loop driven by queue/stop flag
            try:
                packet = self.packet_queue.get(timeout=1.0)
                if packet is None: # Shutdown signal
                     print("Analysis worker received stop signal.")
                     break
                self._process_packet_for_flow(packet)
            except queue.Empty:
                 if not self.monitoring and self.packet_queue.empty(): # Check again
                      print("Analysis worker stopping (queue empty, monitoring off).")
                      break # Exit loop
                 continue # No packet, check monitoring flag again
            except Exception as e:
                 print(f"[!!!] FATAL ERROR in analysis worker: {e}")
                 import traceback
                 traceback.print_exc()
        print("Analysis worker finished.")

    def _process_packet_for_flow(self, packet: Packet):
        """Processes a single packet, updating or creating a flow."""
        try:
            flow_pkt = FlowPacket(packet)
            if flow_pkt.ip_src is None: return

            # --- Update basic stats ---
            self.ip_stats[flow_pkt.ip_src] += 1
            if flow_pkt.protocol == 6: self.packet_stats["tcp"] += 1
            elif flow_pkt.protocol == 17: self.packet_stats["udp"] += 1
            elif flow_pkt.protocol == 1: self.packet_stats["icmp"] += 1
            else: self.packet_stats["other"] += 1
            if flow_pkt.port_dst > 0: self.port_stats[flow_pkt.port_dst] += 1
            # --- End stats update ---

            is_blocked = self._perform_packet_level_checks(flow_pkt, packet)
            if is_blocked:
                 return # Don't add blocked packets to flows

            flow_key = flow_pkt.get_flow_key()
            flow_terminated = False
            terminated_flow = None # Initialize
            
            with self.flow_lock:
                if flow_key in self.current_flows:
                    self.current_flows[flow_key].add_packet(flow_pkt)
                else:
                    self.current_flows[flow_key] = Flow(flow_pkt, flow_key)
                
                if flow_pkt.is_flag_set('F') or flow_pkt.is_flag_set('R'):
                    if flow_key in self.current_flows:
                        terminated_flow = self.current_flows.pop(flow_key)
                        flow_terminated = True
            
            if flow_terminated and terminated_flow:
                self._analyze_terminated_flow(terminated_flow)

        except Exception as e:
            print(f"[!!!] Error processing packet for flow: {e}")

    def _perform_packet_level_checks(self, flow_pkt: FlowPacket, raw_packet: Packet):
        """Performs Firewall, DPI, DoS, PortScan checks. Returns True if blocked."""
        src_ip = flow_pkt.ip_src
        dst_port = flow_pkt.port_dst
        protocol_num = flow_pkt.protocol
        protocol_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(protocol_num, "Other")
        current_time = flow_pkt.timestamp # This is a float (Scapy timestamp)

        # 1. Firewall Check
        if self.enhanced_features_available and hasattr(self, 'firewall'):
            action = self.firewall.check_packet(src_ip, dst_port, protocol_name)
            if action == 'block':
                return True # Packet is blocked

        # 2. DoS Check (SYN flood)
        if protocol_name == "TCP" and flow_pkt.is_flag_set('S') and not flow_pkt.is_flag_set('A'):
             if self._check_dos_attack(src_ip, current_time):
                  self._handle_threat("DoS_Attack", src_ip, "SYN flood detected (packet check)")

        # 3. Port Scan Check
        if protocol_name == "TCP":
             if self._check_port_scan(src_ip, dst_port, current_time):
                  self._handle_threat("Port_Scan", src_ip, "Multiple port scan detected (packet check)")

        # 4. Basic DPI Checks
        try:
            payload = None
            if protocol_name == "UDP" and dst_port == 53 and raw_packet.haslayer(DNS):
                if raw_packet[DNS].qr == 0 and raw_packet.haslayer(DNSQR):
                    qname = raw_packet[DNSQR].qname.decode('utf-8', errors='ignore').lower().rstrip('.')
                    if any(bad_domain in qname for bad_domain in self.malicious_domains):
                        self._handle_threat("Malicious_DNS_Query", src_ip, f"Query to known bad domain: {qname}")
            elif protocol_name == "TCP" and (dst_port == 80 or flow_pkt.port_src == 80):
                if raw_packet.haslayer(Raw):
                    payload = bytes(raw_packet[Raw].load)
                    if any(pattern in payload[:1024] for pattern in self.suspicious_http_patterns):
                        self._handle_threat("Suspicious_HTTP_Payload", src_ip, "Suspicious pattern in HTTP payload")
            
            if payload is None and raw_packet.haslayer(Raw): payload = bytes(raw_packet[Raw].load)
            if payload:
                 for signature in self.malware_signatures:
                     if signature in payload:
                         self._handle_threat("Malware_Signature_Match", src_ip, f"Found signature: {signature.hex()}")
                         break
        except Exception as e: print(f"[DPI-Packet] Error: {e}")

        # 5. IP Reputation
        if self.enhanced_features_available and hasattr(self, 'threat_intel'):
             reputation = self.threat_intel.check_ip_reputation(src_ip)
             if reputation < 50:
                 self.threat_intel.add_threat(src_ip, 'low_reputation', 'high')
                 self._handle_threat("Low_Reputation_IP", src_ip, f"Reputation score: {reputation}/100")
        
        return False # Packet was not blocked

    def _check_flow_timeouts_periodically(self):
        """Runs in a separate thread to check for and expire old flows."""
        print("Flow timeout checker started.")
        sleep_interval = max(5.0, self.flow_timeout / 4) # Check every 1/4 or 5s
        
        while not self._stop_event.wait(timeout=sleep_interval):
            if not self.monitoring: break
            
            try:
                 current_time = time.time()
                 timed_out_keys = []
                 timed_out_flows = []
                 with self.flow_lock:
                      flow_keys = list(self.current_flows.keys())
                      for key in flow_keys:
                           flow = self.current_flows.get(key)
                           if flow and (current_time - flow.last_seen) > self.flow_timeout:
                                timed_out_keys.append(key)
                      
                      for key in timed_out_keys:
                           terminated_flow = self.current_flows.pop(key, None)
                           if terminated_flow:
                                timed_out_flows.append(terminated_flow)
                 
                 if timed_out_flows:
                      # print(f"Timing out {len(timed_out_flows)} flows...") # Debug
                      for flow in timed_out_flows:
                           self._analyze_terminated_flow(flow)
            except Exception as e:
                 print(f"[!!!] Error in flow timeout checker: {e}")
                 time.sleep(5)
        print("Flow timeout checker finished.")


    def _analyze_terminated_flow(self, flow: Flow):
        """Calculates features for a terminated flow and sends to ML."""
        try:
            flow_features = flow.get_features()
            if not flow_features: return
            
            if self.ml_available and self.ml_engine:
                 src_ip_for_log = flow_features.get('ip_src', 'UnknownIP')
                 self._run_ml_on_flow(flow_features, src_ip_for_log)
            
        except Exception as e:
            print(f"[!!!] Error analyzing terminated flow {flow.flow_key}: {e}")

    def _process_remaining_flows(self):
        """Processes all flows remaining in current_flows when stopping."""
        with self.flow_lock:
             keys = list(self.current_flows.keys())
             print(f"Processing {len(keys)} remaining flows...")
             remaining_flows = []
             for key in keys:
                  terminated_flow = self.current_flows.pop(key, None)
                  if terminated_flow:
                       remaining_flows.append(terminated_flow)
             self.current_flows.clear()
        
        for flow in remaining_flows:
            self._analyze_terminated_flow(flow)
        print("Finished processing remaining flows.")

    def _run_ml_on_flow(self, flow_features, src_ip):
        """Run ML-based threat analysis on calculated flow features."""
        try:
            ml_results = self.ml_engine.analyze_flow(flow_features) 

            threat_level = ml_results.get('overall_threat_level', 0)
            threat_class = ml_results.get('threat_class', {}).get('class', 'Benign')
            confidence = ml_results.get('threat_class', {}).get('confidence', 0)

            if threat_class.upper() != 'BENIGN' and threat_level > 0.5:
                self.ml_anomalies += 1 # Count ML detections
                log_message = f"Class: {threat_class}, Confidence: {confidence:.2f} (Level: {threat_level:.2f})"
                self._handle_threat(f"ML_{threat_class}", src_ip, log_message)

        except Exception as e:
            print(f"[!!!] Error in _run_ml_on_flow: {e}")

    # --- ADDING MISSING FUNCTIONS HERE ---

    def _check_dos_attack(self, src_ip, current_time):
        """
        Detect DoS attack by packet rate.
        current_time is a float (timestamp), not a datetime object.
        """
        if src_ip not in self.last_alert_time:
            self.last_alert_time[src_ip] = (0, current_time) # Store float timestamp
        
        count, last_time = self.last_alert_time[src_ip] # last_time is a float
        
        # --- FIX: Use simple float subtraction ---
        time_diff = current_time - last_time
        
        if time_diff < 1.0: # Check if within 1 second window
            count += 1
        else:
            count = 1 # Reset count
            last_time = current_time # Reset window start
        
        self.last_alert_time[src_ip] = (count, last_time)
        
        if count > self.alert_threshold:
            self.last_alert_time[src_ip] = (0, current_time)  # Reset count after triggering
            return True
        
        return False

    def _check_port_scan(self, src_ip, dst_port, current_time):
        """
        Detect port scanning activity.
        current_time is a float (timestamp), not a datetime object.
        """
        if src_ip not in self.ip_scan_window:
            self.ip_scan_window[src_ip] = {
                'ports': set(),
                'start_time': current_time # Store float timestamp
            }
        
        window = self.ip_scan_window[src_ip]
        
        # --- FIX: Use simple float subtraction ---
        time_diff = current_time - window['start_time']
        
        # Reset window after 60 seconds
        if time_diff > 60.0:
            self.ip_scan_window[src_ip] = {
                'ports': {dst_port}, # Start new set with current port
                'start_time': current_time
            }
            return False
        
        # Add current port to the set
        window['ports'].add(dst_port)
        
        # Trigger if too many unique ports accessed
        if len(window['ports']) > self.port_scan_threshold:
            self.ip_scan_window.pop(src_ip, None)  # Reset
            return True
        
        return False
    
    # --- END ADDED FUNCTIONS ---

    def _handle_threat(self, threat_type, source_ip, details):
        """Handle detected threat: update counters, log, and potentially block."""
        log_key = (threat_type, source_ip)
        now = datetime.datetime.now()
        last_log_time = getattr(self, '_last_log_times', {}).get(log_key)
        if last_log_time and (now - last_log_time).total_seconds() < 10: # Suppress same log for 10 sec
             return

        if not hasattr(self, '_last_log_times'): self._last_log_times = {}
        self._last_log_times[log_key] = now

        self.threats_detected += 1

        # Update specific counters
        if 'ML_' in threat_type:
            pass # ml_anomalies already incremented in _run_ml_on_flow
        elif 'DoS' in threat_type or 'SYN' in threat_type: self.dos_count += 1
        elif 'Port_Scan' in threat_type: self.port_scan_count += 1

        self.logger.warning(f"{threat_type.upper()} from {source_ip}: {details}")

        # Auto-response for critical threats
        if self.enhanced_features_available and hasattr(self, 'firewall') and hasattr(self, 'ml_engine'):
            critical_packet_types = ['DoS_Attack', 'Port_Scan', 'Malware_Signature_Match']
            # Use the actual classes loaded from the model
            critical_ml_classes = [cls for cls in (self.ml_engine.rf_classes or []) if str(cls).upper() != 'BENIGN']

            should_block = False
            block_reason = threat_type

            if threat_type in critical_packet_types:
                should_block = True
            elif threat_type.startswith('ML_'):
                 ml_class = threat_type.split('ML_')[-1]
                 if ml_class in critical_ml_classes:
                     should_block = True
                     block_reason = f"ML {ml_class}"

            if should_block:
                self.firewall.auto_block_threat(source_ip, f"Auto-block: {block_reason}")

    def get_stats(self):
        with self.flow_lock:
            active_flows_count = len(self.current_flows)
            packet_stats_copy = dict(self.packet_stats)
            top_ips_copy = dict(sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:5])
            top_ports_copy = dict(sorted(self.port_stats.items(), key=lambda x: x[1], reverse=True)[:5])

        uptime = datetime.datetime.now() - self.start_time if self.start_time else datetime.timedelta(0)
        
        stats = {
            "monitoring": self.monitoring, "target_ip": self.target_ip,
            "packet_count": self.packet_count, "total_bytes": self.total_bytes,
            "threats_detected": self.threats_detected, "dos_count": self.dos_count,
            "ddos_count": self.ddos_count, "port_scan_count": self.port_scan_count,
            "ml_anomalies": self.ml_anomalies,
            "active_flows": active_flows_count,
            "uptime": str(uptime).split('.')[0],
            "packet_stats": packet_stats_copy,
            "top_ips": top_ips_copy,
            "top_ports": top_ports_copy
        }
        
        if self.enhanced_features_available:
            try: stats["threat_intel"] = self.threat_intel.get_threat_report()
            except Exception: pass
            try: stats["firewall"] = self.firewall.get_rules_report()
            except Exception: pass
            try: stats["geo"] = self.geo_tracker.get_geographic_report()
            except Exception: pass
        if self.ml_available and self.ml_engine:
            try: stats["ml_stats"] = self.ml_engine.get_ml_stats()
            except Exception as e: print(f"Error getting ML stats: {e}")
        return stats

    def export_data(self, filename):
        try:
            data = self.get_stats()
            with open(filename, "w", encoding='utf-8') as f: json.dump(data, f, indent=4, default=str)
            print(f"[✓] Data exported to {filename}")
            return True
        except Exception as e: print(f"[✗] Export error: {e}"); return False

    def get_active_threats(self):
        threats = []
        if self.enhanced_features_available and hasattr(self, 'threat_intel'):
            try:
                report = self.threat_intel.get_threat_report()
                for ip, data in report.get('top_threats', [])[:10]:
                    threats.append({'ip': ip, 'type': data['type'], 'severity': data['severity'],
                                    'count': data['count'], 'timestamp': str(data['timestamp'])})
            except Exception as e: print(f"Error getting active threats: {e}")
        return threats

    def block_ip(self, ip_address, reason="Manual block"):
        if self.enhanced_features_available and hasattr(self, 'firewall'):
            success = self.firewall.auto_block_threat(ip_address, reason)
            if success: self.logger.info(f"INFO: Manually blocked IP: {ip_address} - {reason}"); return True
        else: print("[!] Firewall not available for manual block.")
        return False

    def unblock_ip(self, ip_address):
        if self.enhanced_features_available and hasattr(self, 'firewall'):
            return self.firewall.unblock_ip(ip_address)
        else: print("[!] Firewall not available for unblock."); return False

    def clear_all_blocks(self):
        if self.enhanced_features_available and hasattr(self, 'firewall'):
            self.firewall.clear_all_rules()
            self.logger.info("INFO: Cleared all firewall blocks")
            return True
        else: print("[!] Firewall not available for clear blocks."); return False