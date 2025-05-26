"""
Syslog Receiver for Maritime Network Management System
Provides functionality to receive, parse, and store Syslog messages from network devices
"""
import socketserver
import re
import logging
import threading
import datetime
import json
from app import db
from models import SyslogEntry, Vessel, CBSAsset, SecurityLog, EventType

# Regular expression to parse standard Syslog messages
# Format: <Priority>Timestamp Hostname Process[PID]: Message
SYSLOG_REGEX = re.compile(r'<(\d+)>(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([^:]+):\s+(.*)')

# Another regex for BSD Syslog format
# Format: <Priority>Timestamp Hostname Process[PID]: Message
BSD_SYSLOG_REGEX = re.compile(r'<(\d+)>(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([^\[]+)(?:\[(\d+)\])?:\s+(.*)')

# Cisco format regex
# Format: <Priority>Sequence: Timestamp: %Facility-Severity-MNEMONIC: Message
CISCO_SYSLOG_REGEX = re.compile(r'<(\d+)>(\d+):\s+(.+?):\s+%([^-]+)-(\d)-([^:]+):\s+(.*)')

# List of security-related keywords to match in Syslog messages
SECURITY_KEYWORDS = [
    'fail', 'failed', 'failure', 'error', 'denied', 'deny', 'reject', 'blocked',
    'attack', 'intrusion', 'malware', 'virus', 'trojan', 'exploit', 'hack', 'breach',
    'unauthorized', 'invalid', 'violation', 'suspicious', 'anomaly', 'unusual',
    'security', 'firewall', 'auth', 'login', 'password', 'credential', 'access',
    'connection', 'refused', 'timeout', 'overflow', 'buffer', 'injection', 'xss',
    'sql', 'script', 'overflow', 'brute', 'force', 'spoofing', 'spoof', 'poison',
    'illegal', 'admin', 'root', 'sudo', 'su', 'permission', 'threat'
]

# Define facility codes (RFC 5424)
FACILITIES = {
    0: "kern",
    1: "user",
    2: "mail",
    3: "daemon",
    4: "auth",
    5: "syslog",
    6: "lpr",
    7: "news",
    8: "uucp",
    9: "cron",
    10: "authpriv",
    11: "ftp",
    12: "ntp",
    13: "security",
    14: "console",
    15: "cron",
    16: "local0",
    17: "local1",
    18: "local2",
    19: "local3",
    20: "local4",
    21: "local5",
    22: "local6",
    23: "local7"
}

# Define severity codes (RFC 5424)
SEVERITIES = {
    0: "emergency",
    1: "alert",
    2: "critical",
    3: "error",
    4: "warning",
    5: "notice",
    6: "informational",
    7: "debug"
}

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    """
    Handler for Syslog UDP messages
    """
    
    def handle(self):
        """Handle incoming Syslog message"""
        data = bytes.decode(self.request[0].strip())
        sender = self.client_address[0]
        logging.debug(f"Syslog message from {sender}: {data}")
        
        # Parse and store the message
        try:
            process_syslog_message(data, sender)
        except Exception as e:
            logging.error(f"Error processing Syslog message: {str(e)}")

def parse_syslog_message(message, sender_ip):
    """
    Parse a Syslog message into its components
    
    Args:
        message (str): The raw Syslog message
        sender_ip (str): IP address of the sender
        
    Returns:
        dict: Parsed message components or None if parsing failed
    """
    # Try standard Syslog format
    match = SYSLOG_REGEX.match(message)
    if match:
        priority, timestamp, hostname, process, msg = match.groups()
        return process_match(priority, timestamp, hostname, process, None, msg, sender_ip)
    
    # Try BSD Syslog format
    match = BSD_SYSLOG_REGEX.match(message)
    if match:
        priority, timestamp, hostname, process, pid, msg = match.groups()
        return process_match(priority, timestamp, hostname, process, pid, msg, sender_ip)
    
    # Try Cisco format
    match = CISCO_SYSLOG_REGEX.match(message)
    if match:
        priority, seq, timestamp, facility, severity, mnemonic, msg = match.groups()
        process = f"{facility}-{mnemonic}"
        return process_match(priority, timestamp, sender_ip, process, seq, msg, sender_ip)
    
    # If no format matches, create a basic entry with the raw message
    return {
        "priority": 0,
        "facility": "unknown",
        "severity": "unknown",
        "timestamp": datetime.datetime.utcnow(),
        "hostname": sender_ip,
        "process": "unknown",
        "pid": None,
        "message": message,
        "is_security_related": is_security_related(message)
    }

def process_match(priority, timestamp, hostname, process, pid, message, sender_ip):
    """Process a regex match and return structured data"""
    # Convert priority to facility and severity
    try:
        priority = int(priority)
        facility_code = priority >> 3
        severity_code = priority & 7
        
        facility = FACILITIES.get(facility_code, "unknown")
        severity = SEVERITIES.get(severity_code, "unknown")
    except (ValueError, TypeError):
        facility = "unknown"
        severity = "unknown"
    
    # Try to parse timestamp (this is simplified, would need more robust parsing)
    try:
        # This is a simplistic approach - a real implementation would need more robust timestamp parsing
        current_year = datetime.datetime.utcnow().year
        parsed_timestamp = datetime.datetime.strptime(f"{current_year} {timestamp}", "%Y %b %d %H:%M:%S")
        
        # Handle year rollover - if parsed date is in the future, it's probably from last year
        if parsed_timestamp > datetime.datetime.utcnow() + datetime.timedelta(days=1):
            parsed_timestamp = datetime.datetime.strptime(f"{current_year-1} {timestamp}", "%Y %b %d %H:%M:%S")
    except ValueError:
        parsed_timestamp = datetime.datetime.utcnow()
    
    return {
        "priority": priority,
        "facility": facility,
        "severity": severity,
        "timestamp": parsed_timestamp,
        "hostname": hostname,
        "process": process,
        "pid": pid,
        "message": message,
        "is_security_related": is_security_related(message)
    }

def is_security_related(message):
    """
    Check if a message is security-related based on keywords
    
    Args:
        message (str): The message to check
        
    Returns:
        bool: True if the message contains security-related keywords
    """
    message_lower = message.lower()
    for keyword in SECURITY_KEYWORDS:
        if keyword in message_lower:
            return True
    return False

def process_syslog_message(message, sender_ip):
    """
    Process and store a Syslog message
    
    Args:
        message (str): The raw Syslog message
        sender_ip (str): IP address of the sender
    """
    parsed = parse_syslog_message(message, sender_ip)
    if not parsed:
        return
    
    # Lookup the asset based on the hostname or IP
    asset = find_asset(parsed['hostname'], sender_ip)
    
    # Create a new SyslogEntry
    entry = SyslogEntry()
    entry.facility = parsed['facility']
    entry.severity = parsed['severity']
    entry.timestamp = parsed['timestamp']
    entry.hostname = parsed['hostname']
    entry.process = parsed['process']
    entry.pid = parsed['pid']
    entry.message = parsed['message']
    entry.sender_ip = sender_ip
    
    if asset:
        entry.cbs_id = asset.id
        entry.vessel_id = asset.vessel_id
    
    # Save to database
    db.session.add(entry)
    
    # If security-related, also log to SecurityLog
    if parsed['is_security_related'] and asset:
        security_log = SecurityLog()
        security_log.event_type = get_event_type(parsed)
        security_log.vessel_id = asset.vessel_id
        security_log.cbs_id = asset.id
        security_log.ip_address = sender_ip
        security_log.description = f"Security event: {parsed['message']}"
        security_log.data = json.dumps({
            "facility": parsed['facility'],
            "severity": parsed['severity'],
            "process": parsed['process'],
            "pid": parsed['pid']
        })
        
        db.session.add(security_log)
    
    db.session.commit()

def get_event_type(parsed_message):
    """Determine the appropriate event type based on the message content"""
    facility = parsed_message['facility']
    message = parsed_message['message'].lower()
    
    # Map facility and message content to appropriate event types
    if facility == "auth" or facility == "authpriv" or "auth" in message or "login" in message:
        return EventType.ACCESS_CONTROL
    elif facility == "kern" or "kernel" in message:
        return EventType.OS_EVENT
    elif "backup" in message or "restore" in message or "recovery" in message:
        return EventType.BACKUP_RECOVERY
    elif "config" in message or "configuration" in message or "change" in message:
        return EventType.CONFIG_CHANGE
    elif "disconnect" in message or "connection" in message or "timeout" in message:
        return EventType.COMM_LOSS
    elif "alarm" in message or "alert" in message or "security" in message:
        return EventType.SECURITY_ALARM
    elif "integrity" in message or "corruption" in message or "corrupt" in message:
        return EventType.DATA_INTEGRITY
    elif "malware" in message or "virus" in message or "trojan" in message:
        return EventType.MALWARE_DETECTION
    else:
        # Default to OS_EVENT for unclassified messages
        return EventType.OS_EVENT

def find_asset(hostname, ip_address):
    """
    Find an asset in the database by hostname or IP address
    
    Args:
        hostname (str): Hostname to search for
        ip_address (str): IP address to search for
        
    Returns:
        CBSAsset: The matching asset or None if no match found
    """
    # First try by IP address (most reliable)
    asset = CBSAsset.query.filter_by(ip_address=ip_address).first()
    if asset:
        return asset
    
    # Then try by hostname (could be in name or other fields)
    asset = CBSAsset.query.filter(CBSAsset.name.like(f"%{hostname}%")).first()
    if asset:
        return asset
    
    # Try by physical_location field as well
    asset = CBSAsset.query.filter(CBSAsset.physical_location.like(f"%{hostname}%")).first()
    if asset:
        return asset
    
    return None

class SyslogServer:
    """
    Syslog server class to manage the UDP server
    """
    def __init__(self, host='0.0.0.0', port=514):
        self.host = host
        self.port = port
        self.server = None
        self.server_thread = None
        self.running = False
    
    def start(self):
        """Start the Syslog server"""
        if self.running:
            return False
        
        try:
            # Create the UDP server
            self.server = socketserver.UDPServer((self.host, self.port), SyslogUDPHandler)
            
            # Start the server in a separate thread
            self.server_thread = threading.Thread(target=self.server.serve_forever)
            self.server_thread.daemon = True
            self.server_thread.start()
            
            self.running = True
            logging.info(f"Syslog server started on {self.host}:{self.port}")
            return True
        
        except Exception as e:
            logging.error(f"Error starting Syslog server: {str(e)}")
            return False
    
    def stop(self):
        """Stop the Syslog server"""
        if not self.running:
            return False
        
        try:
            self.server.shutdown()
            self.server.server_close()
            self.running = False
            logging.info("Syslog server stopped")
            return True
        
        except Exception as e:
            logging.error(f"Error stopping Syslog server: {str(e)}")
            return False
    
    def is_running(self):
        """Check if the server is running"""
        return self.running

# Global server instance
syslog_server = SyslogServer()

def start_syslog_server(host='0.0.0.0', port=514):
    """
    Start the Syslog server
    
    Args:
        host (str): Host to bind to
        port (int): Port to listen on
        
    Returns:
        bool: True if server started successfully, False otherwise
    """
    global syslog_server
    return syslog_server.start()

def stop_syslog_server():
    """
    Stop the Syslog server
    
    Returns:
        bool: True if server stopped successfully, False otherwise
    """
    global syslog_server
    return syslog_server.stop()

def get_syslog_server_status():
    """
    Get the status of the Syslog server
    
    Returns:
        dict: Server status information
    """
    global syslog_server
    return {
        "running": syslog_server.is_running(),
        "host": syslog_server.host,
        "port": syslog_server.port
    }