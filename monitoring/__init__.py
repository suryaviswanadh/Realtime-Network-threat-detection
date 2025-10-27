"""
Monitoring Module
Network traffic monitoring and threat detection components
"""

from .monitor import NetworkMonitor
from .threat_intel import ThreatIntelligence
# from .anomaly_detector import AnomalyDetector  <-- REMOVED
from .firewall_engine import FirewallEngine
from .protocol_analyzer import ProtocolAnalyzer

# --- ADD THE NEW FILES ---
from .flow_packet import FlowPacket
from .flow import Flow
from .ml_engine import MLSecurityEngine
# -------------------------

__all__ = [
    'NetworkMonitor',
    'ThreatIntelligence',
    # 'AnomalyDetector', # <-- REMOVED
    'FirewallEngine',
    'ProtocolAnalyzer',
    'Flow',           # <-- ADDED
    'FlowPacket',     # <-- ADDED
    'MLSecurityEngine'# <-- ADDED
]

__version__ = '2.0.0'