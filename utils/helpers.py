"""
Helper Utilities
Common utility functions used across the application
"""

import socket
import ipaddress
import platform
import subprocess


def validate_ip_address(ip_string):
    """
    Validate if string is a valid IP address
    
    Args:
        ip_string: String to validate
    
    Returns:
        True if valid, False otherwise
    """
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False


def validate_port(port):
    """
    Validate if port number is valid
    
    Args:
        port: Port number (int or string)
    
    Returns:
        True if valid (1-65535), False otherwise
    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


def get_local_ip():
    """
    Get the local IP address of this machine
    
    Returns:
        Local IP address string
    """
    try:
        # Create a socket to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def get_hostname():
    """
    Get the hostname of this machine
    
    Returns:
        Hostname string
    """
    try:
        return socket.gethostname()
    except Exception:
        return "Unknown"


def resolve_hostname(hostname):
    """
    Resolve hostname to IP address
    
    Args:
        hostname: Hostname to resolve
    
    Returns:
        IP address string or None if resolution fails
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def reverse_dns_lookup(ip_address):
    """
    Perform reverse DNS lookup
    
    Args:
        ip_address: IP address to lookup
    
    Returns:
        Hostname or None if lookup fails
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except (socket.herror, socket.gaierror):
        return None


def is_private_ip(ip_address):
    """
    Check if IP address is private/local
    
    Args:
        ip_address: IP address string
    
    Returns:
        True if private, False if public
    """
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        return ip_obj.is_private
    except ValueError:
        return False


def format_bytes(bytes_value):
    """
    Format bytes into human-readable format
    
    Args:
        bytes_value: Number of bytes
    
    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"


def format_duration(seconds):
    """
    Format seconds into human-readable duration
    
    Args:
        seconds: Number of seconds
    
    Returns:
        Formatted string (e.g., "1h 23m 45s")
    """
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    
    if hours > 0:
        return f"{hours}h {minutes}m {secs}s"
    elif minutes > 0:
        return f"{minutes}m {secs}s"
    else:
        return f"{secs}s"


def get_service_name(port, protocol='tcp'):
    """
    Get service name for a port number
    
    Args:
        port: Port number
        protocol: Protocol type ('tcp' or 'udp')
    
    Returns:
        Service name or 'unknown'
    """
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        # Common ports dictionary
        common_ports = {
            20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet',
            25: 'smtp', 53: 'dns', 80: 'http', 110: 'pop3',
            143: 'imap', 443: 'https', 445: 'smb', 3306: 'mysql',
            3389: 'rdp', 5432: 'postgresql', 6379: 'redis',
            8080: 'http-alt', 8443: 'https-alt', 27017: 'mongodb'
        }
        return common_ports.get(port, 'unknown')


def ping_host(host, count=1):
    """
    Ping a host to check if it's reachable
    
    Args:
        host: Hostname or IP address
        count: Number of ping packets
    
    Returns:
        True if host is reachable, False otherwise
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    
    try:
        command = ['ping', param, str(count), host]
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


def get_protocol_name(protocol_num):
    """
    Get protocol name from protocol number
    
    Args:
        protocol_num: IP protocol number
    
    Returns:
        Protocol name string
    """
    protocols = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        41: 'IPv6',
        47: 'GRE',
        50: 'ESP',
        51: 'AH',
        89: 'OSPF',
        132: 'SCTP'
    }
    return protocols.get(protocol_num, f'Unknown({protocol_num})')


def calculate_checksum(data):
    """
    Calculate Internet checksum
    
    Args:
        data: Bytes to checksum
    
    Returns:
        Checksum value
    """
    if len(data) % 2 != 0:
        data += b'\x00'
    
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
    
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum += (checksum >> 16)
    
    return ~checksum & 0xFFFF


def sanitize_filename(filename):
    """
    Sanitize filename by removing invalid characters
    
    Args:
        filename: Original filename
    
    Returns:
        Sanitized filename
    """
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    return filename


def get_network_info():
    """
    Get comprehensive network information
    
    Returns:
        Dictionary with network info
    """
    return {
        'hostname': get_hostname(),
        'local_ip': get_local_ip(),
        'platform': platform.system(),
        'architecture': platform.machine()
    }
