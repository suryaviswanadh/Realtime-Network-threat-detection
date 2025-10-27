# monitoring/flow.py
import time
import math
import statistics
from .flow_packet import FlowPacket
from collections import deque 

class Flow:
    """Represents a network flow and calculates its features."""

    def __init__(self, first_packet: FlowPacket, flow_key):
        self.flow_key = flow_key
        self.start_time = first_packet.timestamp
        self.last_seen = first_packet.timestamp
        self.start_active_time = self.start_time
        self.last_active_time = self.start_time
        self._idle_threshold = 1.0 # 1 second idle threshold (1,000,000 us)

        # Packet Timestamps
        self.all_timestamps = [first_packet.timestamp]
        self.fwd_timestamps = []
        self.bwd_timestamps = []

        # Packet Lengths (use payload_length for consistency with training features like 'Avg Fwd Segment Size')
        self.fwd_payload_lengths = []
        self.bwd_payload_lengths = []
        self.all_payload_lengths = [] # For 'Packet Length Mean/Std/Var'
        self.all_packet_lengths_total = [] # For 'Average Packet Size' (uses total length)

        # Stats
        self.flow_packet_count = 0
        self.fwd_packet_count = 0
        self.bwd_packet_count = 0
        
        self.total_fwd_bytes = 0 # Total bytes of IP layer
        self.total_bwd_bytes = 0 # Total bytes of IP layer
        
        self.active_periods_us = []
        self.idle_periods_us = []

        # Flag counts
        self.fwd_psh_flags = 0
        self.bwd_psh_flags = 0
        self.fwd_urg_flags = 0
        self.bwd_urg_flags = 0
        self.fin_flag_count = 0
        self.syn_flag_count = 0
        self.rst_flag_count = 0
        self.psh_flag_count = 0
        self.ack_flag_count = 0
        self.urg_flag_count = 0
        self.cwe_flag_count = 0
        self.ece_flag_count = 0
        
        # Initial packet info
        self.init_win_bytes_forward = -1
        self.init_win_bytes_backward = -1
        self.act_data_pkt_fwd = 0
        
        self.min_seg_size_forward = 0 # Placeholder
        self.fwd_header_length_total = 0 # Placeholder
        self.bwd_header_length_total = 0 # Placeholder

        self.add_packet(first_packet) # Add the initial packet

    def add_packet(self, packet: FlowPacket):
        """Update flow statistics with a new packet."""
        current_time = packet.timestamp
        is_forward = packet.is_forward(self.flow_key)

        # Active/Idle calculation
        time_since_last_us = (current_time - self.last_seen) * 1e6 # Microseconds
        if time_since_last_us > (self._idle_threshold * 1e6):
            active_duration_us = (self.last_active_time - self.start_active_time) * 1e6
            if active_duration_us > 0:
                self.active_periods_us.append(active_duration_us)
            self.idle_periods_us.append(time_since_last_us)
            self.start_active_time = current_time
        self.last_active_time = current_time

        # Update Timestamps
        self.all_timestamps.append(current_time)
        self.last_seen = current_time
        
        self.flow_packet_count += 1
        self.all_payload_lengths.append(packet.payload_length)
        self.all_packet_lengths_total.append(packet.length)

        # Update directional stats
        if is_forward:
            self.fwd_packet_count += 1
            self.total_fwd_bytes += packet.length
            self.fwd_payload_lengths.append(packet.payload_length)
            self.fwd_timestamps.append(current_time)
            if packet.is_flag_set('P'): self.fwd_psh_flags += 1
            if packet.is_flag_set('U'): self.fwd_urg_flags += 1
            if self.init_win_bytes_forward == -1 and packet.protocol == 6: # TCP
                self.init_win_bytes_forward = packet.win_bytes
            if packet.payload_length > 0:
                self.act_data_pkt_fwd += 1
        else: # Backward
            self.bwd_packet_count += 1
            self.total_bwd_bytes += packet.length
            self.bwd_payload_lengths.append(packet.payload_length)
            self.bwd_timestamps.append(current_time)
            if packet.is_flag_set('P'): self.bwd_psh_flags += 1
            if packet.is_flag_set('U'): self.bwd_urg_flags += 1
            if self.init_win_bytes_backward == -1 and packet.protocol == 6: # TCP
                self.init_win_bytes_backward = packet.win_bytes

        # Update total flag counts
        if packet.is_flag_set('F'): self.fin_flag_count += 1
        if packet.is_flag_set('S'): self.syn_flag_count += 1
        if packet.is_flag_set('R'): self.rst_flag_count += 1
        if packet.is_flag_set('P'): self.psh_flag_count += 1
        if packet.is_flag_set('A'): self.ack_flag_count += 1
        if packet.is_flag_set('U'): self.urg_flag_count += 1
        if packet.is_flag_set('C'): self.cwe_flag_count += 1
        if packet.is_flag_set('E'): self.ece_flag_count += 1

    def _safe_stat(self, data, stat_func_name, default=0.0):
        """Helper to calculate statistics safely on potentially empty lists."""
        if not data: return default
        try:
            if stat_func_name == 'mean':
                val = statistics.mean(data)
            elif stat_func_name == 'stdev':
                if len(data) < 2: return default
                val = statistics.stdev(data)
            elif stat_func_name == 'max':
                val = max(data)
            elif stat_func_name == 'min':
                val = min(data)
            elif stat_func_name == 'variance':
                if len(data) < 2: return default
                val = statistics.variance(data)
            elif stat_func_name == 'sum':
                 val = sum(data)
            else:
                 return default
            return val if math.isfinite(val) else default
        except Exception:
            return default

    def _get_iat_stats(self, timestamps):
        """Calculate IAT stats from a list of timestamps."""
        iat_list = []
        if len(timestamps) > 1:
            iat_list = [(timestamps[i] - timestamps[i-1]) * 1e6 for i in range(1, len(timestamps))]
        
        return {
            'Total': sum(iat_list),
            'Mean': self._safe_stat(iat_list, 'mean'),
            'Std': self._safe_stat(iat_list, 'stdev'),
            'Max': self._safe_stat(iat_list, 'max', 0),
            'Min': self._safe_stat(iat_list, 'min', 0)
        }

    def get_features(self):
        """Calculate and return the final flow features as a dictionary."""
        active_duration_us = (self.last_active_time - self.start_active_time) * 1e6
        if active_duration_us > 0:
            self.active_periods_us.append(active_duration_us)

        duration_us = (self.last_seen - self.start_time) * 1e6
        duration_sec = duration_us / 1e6 if duration_us > 0 else 1e-9

        features = {}
        
        flow_iat_stats = self._get_iat_stats(self.all_timestamps)
        fwd_iat_stats = self._get_iat_stats(self.fwd_timestamps)
        bwd_iat_stats = self._get_iat_stats(self.bwd_timestamps)

        # --- Map features to match the training list ---
        features['Destination Port'] = self.flow_key[3]
        features['Flow Duration'] = duration_us
        features['Total Fwd Packets'] = self.fwd_packet_count
        features['Total Backward Packets'] = self.bwd_packet_count
        features['Total Length of Fwd Packets'] = self.total_fwd_bytes
        features['Total Length of Bwd Packets'] = self.total_bwd_bytes
        features['Fwd Packet Length Max'] = self._safe_stat(self.fwd_payload_lengths, 'max', 0)
        features['Fwd Packet Length Min'] = self._safe_stat(self.fwd_payload_lengths, 'min', 0)
        features['Fwd Packet Length Mean'] = self._safe_stat(self.fwd_payload_lengths, 'mean')
        features['Fwd Packet Length Std'] = self._safe_stat(self.fwd_payload_lengths, 'stdev')
        features['Bwd Packet Length Max'] = self._safe_stat(self.bwd_payload_lengths, 'max', 0)
        features['Bwd Packet Length Min'] = self._safe_stat(self.bwd_payload_lengths, 'min', 0)
        features['Bwd Packet Length Mean'] = self._safe_stat(self.bwd_payload_lengths, 'mean')
        features['Bwd Packet Length Std'] = self._safe_stat(self.bwd_payload_lengths, 'stdev')
        features['Flow Bytes/s'] = (self.total_fwd_bytes + self.total_bwd_bytes) / duration_sec
        features['Flow Packets/s'] = self.flow_packet_count / duration_sec
        features['Flow IAT Mean'] = flow_iat_stats['Mean']
        features['Flow IAT Std'] = flow_iat_stats['Std']
        features['Flow IAT Max'] = flow_iat_stats['Max']
        features['Flow IAT Min'] = flow_iat_stats['Min']
        features['Fwd IAT Total'] = fwd_iat_stats['Total']
        features['Fwd IAT Mean'] = fwd_iat_stats['Mean']
        features['Fwd IAT Std'] = fwd_iat_stats['Std']
        features['Fwd IAT Max'] = fwd_iat_stats['Max']
        features['Fwd IAT Min'] = fwd_iat_stats['Min']
        features['Bwd IAT Total'] = bwd_iat_stats['Total']
        features['Bwd IAT Mean'] = bwd_iat_stats['Mean']
        features['Bwd IAT Std'] = bwd_iat_stats['Std']
        features['Bwd IAT Max'] = bwd_iat_stats['Max']
        features['Bwd IAT Min'] = bwd_iat_stats['Min']
        features['Fwd PSH Flags'] = self.fwd_psh_flags
        features['Bwd PSH Flags'] = self.bwd_psh_flags
        features['Fwd URG Flags'] = self.fwd_urg_flags
        features['Bwd URG Flags'] = self.bwd_urg_flags
        features['Fwd Header Length'] = self.fwd_header_length_total 
        features['Bwd Header Length'] = self.bwd_header_length_total 
        features['Fwd Packets/s'] = self.fwd_packet_count / duration_sec
        features['Bwd Packets/s'] = self.bwd_packet_count / duration_sec
        features['Min Packet Length'] = self._safe_stat(self.all_payload_lengths, 'min', 0)
        features['Max Packet Length'] = self._safe_stat(self.all_payload_lengths, 'max', 0)
        features['Packet Length Mean'] = self._safe_stat(self.all_payload_lengths, 'mean')
        features['Packet Length Std'] = self._safe_stat(self.all_payload_lengths, 'stdev')
        features['Packet Length Variance'] = self._safe_stat(self.all_payload_lengths, 'variance')
        features['FIN Flag Count'] = self.fin_flag_count
        features['SYN Flag Count'] = self.syn_flag_count
        features['RST Flag Count'] = self.rst_flag_count
        features['PSH Flag Count'] = self.psh_flag_count
        features['ACK Flag Count'] = self.ack_flag_count
        features['URG Flag Count'] = self.urg_flag_count
        features['CWE Flag Count'] = self.cwe_flag_count
        features['ECE Flag Count'] = self.ece_flag_count
        features['Down/Up Ratio'] = self.bwd_packet_count / self.fwd_packet_count if self.fwd_packet_count > 0 else 0
        features['Average Packet Size'] = self._safe_stat(self.all_packet_lengths_total, 'mean') 
        features['Avg Fwd Segment Size'] = self._safe_stat(self.fwd_payload_lengths, 'mean')
        features['Avg Bwd Segment Size'] = self._safe_stat(self.bwd_payload_lengths, 'mean')
        features['Fwd Header Length.1'] = self.fwd_header_length_total # Using same placeholder
        features['Fwd Avg Bytes/Bulk'] = 0 
        features['Fwd Avg Packets/Bulk'] = 0
        features['Fwd Avg Bulk Rate'] = 0
        features['Bwd Avg Bytes/Bulk'] = 0
        features['Bwd Avg Packets/Bulk'] = 0
        features['Bwd Avg Bulk Rate'] = 0
        features['Subflow Fwd Packets'] = 0
        features['Subflow Fwd Bytes'] = 0
        features['Subflow Bwd Packets'] = 0
        features['Subflow Bwd Bytes'] = 0
        features['Init_Win_bytes_forward'] = self.init_win_bytes_forward
        features['Init_Win_bytes_backward'] = self.init_win_bytes_backward
        features['act_data_pkt_fwd'] = self.act_data_pkt_fwd
        features['min_seg_size_forward'] = self.min_seg_size_forward
        features['Active Mean'] = self._safe_stat(self.active_periods_us, 'mean')
        features['Active Std'] = self._safe_stat(self.active_periods_us, 'stdev')
        features['Active Max'] = self._safe_stat(self.active_periods_us, 'max', 0)
        features['Active Min'] = self._safe_stat(self.active_periods_us, 'min', 0)
        features['Idle Mean'] = self._safe_stat(self.idle_periods_us, 'mean')
        features['Idle Std'] = self._safe_stat(self.idle_periods_us, 'stdev')
        features['Idle Max'] = self._safe_stat(self.idle_periods_us, 'max', 0)
        features['Idle Min'] = self._safe_stat(self.idle_periods_us, 'min', 0)
        
        # Add flow key info for logging/display
        features['ip_src'] = self.flow_key[0]
        features['port_src'] = self.flow_key[1]
        features['ip_dst'] = self.flow_key[2]
        
        # Clean for NaN/inf which can break ML models
        for key, value in features.items():
             if isinstance(value, (int, float)):
                 if math.isnan(value) or math.isinf(value):
                      features[key] = 0.0 # Replace NaN/inf with 0
        
        return features