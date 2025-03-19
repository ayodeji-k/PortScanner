import socket
from dataclasses import dataclass
from typing import List, Optional
import time
import re
from typing import Dict

@dataclass
class ScanResult:
    port: int
    service: str
    response_time: float

# Common ports and their services
SERVICE_MAP: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB"
}

def validate_target(target: str) -> str:
    """Validate and resolve target hostname/IP."""
    try:
        socket.gethostbyname(target)
        return target
    except socket.gaierror:
        raise ValueError(f"Invalid target: {target}")

def parse_port_range(port_range: str) -> List[int]:
    """Parse port range string into list of ports."""
    if not re.match(r'^\d+(-\d+)?$', port_range):
        raise ValueError("Invalid port range format")
    
    if '-' in port_range:
        start, end = map(int, port_range.split('-'))
        if start < 1 or end > 65535 or start > end:
            raise ValueError("Invalid port range")
        return list(range(start, end + 1))
    else:
        port = int(port_range)
        if port < 1 or port > 65535:
            raise ValueError("Invalid port")
        return [port]

def get_common_ports() -> List[int]:
    """Return list of common ports to scan."""
    return sorted(SERVICE_MAP.keys())

def scan_port(target: str, port: int, timeout: float = 1.0) -> Optional[ScanResult]:
    """Scan a single port and return result if open."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    start_time = time.time()
    try:
        result = sock.connect_ex((target, port))
        response_time = time.time() - start_time
        
        if result == 0:
            service = SERVICE_MAP.get(port, "Unknown")
            return ScanResult(port=port, service=service, response_time=response_time)
        return None
    
    except socket.error:
        return None
    finally:
        sock.close() 