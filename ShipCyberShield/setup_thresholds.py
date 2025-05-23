"""
Setup Alert Thresholds for Maritime Network Management System
This script creates sample vessels, security zones, and assets to enable threshold configuration
"""
from app import app, db
from models import Vessel, SecurityZone, CBSAsset, AlertThreshold, NotificationSetting, AlertSeverity

def create_sample_data():
    """Create sample vessels, zones, and assets if they don't exist"""
    # Check if we already have data
    if Vessel.query.count() > 0:
        print("Sample data already exists")
        return False
        
    # Create sample vessel
    vessel = Vessel(
        name="MV Northern Star",
        imo_number="9876543",
        call_sign="MVNS1",
        vessel_type="Container Ship",
        flag="Panama"
    )
    db.session.add(vessel)
    db.session.flush()  # Get vessel ID
    
    # Create security zones
    zones = {
        "bridge": SecurityZone(
            name="Bridge Systems", 
            description="Navigation and command systems",
            risk_level="High",
            vessel_id=vessel.id
        ),
        "comms": SecurityZone(
            name="Communication Systems",
            description="External and internal communication systems",
            risk_level="High",
            vessel_id=vessel.id
        ),
        "engine": SecurityZone(
            name="Engine Control Systems",
            description="Propulsion and power management systems",
            risk_level="High",
            vessel_id=vessel.id
        ),
        "crew": SecurityZone(
            name="Crew Network",
            description="Crew internet and entertainment systems",
            risk_level="Medium",
            vessel_id=vessel.id
        )
    }
    
    for zone in zones.values():
        db.session.add(zone)
    
    db.session.flush()  # Get zone IDs
    
    # Create assets
    assets = [
        # Bridge/Navigation systems
        CBSAsset(
            name="ECDIS System",
            function="Electronic Chart Display and Information System",
            asset_type="Hardware",
            manufacturer="Wärtsilä",
            model="NACOS Platinum",
            ip_address="192.168.10.11",
            status="online",
            vessel_id=vessel.id,
            security_zone_id=zones["bridge"].id
        ),
        CBSAsset(
            name="Radar Processing Unit",
            function="Radar signal processing and display",
            asset_type="Hardware",
            manufacturer="Furuno",
            model="FAR-2228",
            ip_address="192.168.10.12",
            status="online",
            vessel_id=vessel.id,
            security_zone_id=zones["bridge"].id
        ),
        CBSAsset(
            name="Autopilot System",
            function="Vessel course control",
            asset_type="Hardware",
            manufacturer="Raytheon",
            model="Anschütz NautoPilot 5000",
            ip_address="192.168.10.13",
            status="online",
            vessel_id=vessel.id,
            security_zone_id=zones["bridge"].id
        ),
        
        # Communication systems
        CBSAsset(
            name="VSAT Terminal",
            function="Satellite communication",
            asset_type="Hardware",
            manufacturer="Intellian",
            model="v100",
            ip_address="192.168.20.11",
            status="online",
            vessel_id=vessel.id,
            security_zone_id=zones["comms"].id
        ),
        CBSAsset(
            name="VoIP Server",
            function="Voice over IP communications",
            asset_type="Hardware",
            manufacturer="Cisco",
            model="Unified Communications Manager",
            ip_address="192.168.20.12",
            status="online",
            vessel_id=vessel.id,
            security_zone_id=zones["comms"].id
        ),
        
        # Engine control systems
        CBSAsset(
            name="Main Engine Control Unit",
            function="Engine monitoring and control",
            asset_type="Hardware",
            manufacturer="Kongsberg",
            model="K-Chief 600",
            ip_address="192.168.30.11",
            status="online",
            vessel_id=vessel.id,
            security_zone_id=zones["engine"].id
        ),
        CBSAsset(
            name="Power Management System",
            function="Electrical load distribution",
            asset_type="Hardware",
            manufacturer="ABB",
            model="PEMS",
            ip_address="192.168.30.12",
            status="online",
            vessel_id=vessel.id,
            security_zone_id=zones["engine"].id
        ),
        
        # Crew network
        CBSAsset(
            name="Crew Internet Server",
            function="Internet access for crew",
            asset_type="Hardware",
            manufacturer="Dell",
            model="PowerEdge",
            ip_address="192.168.40.11",
            status="online",
            vessel_id=vessel.id,
            security_zone_id=zones["crew"].id
        )
    ]
    
    for asset in assets:
        db.session.add(asset)
    
    db.session.commit()
    print("Sample data created successfully!")
    return True

def create_maritime_thresholds():
    """Create recommended thresholds for maritime systems"""
    # Get vessel and assets
    vessel = Vessel.query.first()
    if not vessel:
        print("No vessel found. Please run create_sample_data() first.")
        return False
    
    # Get assets by zone
    nav_zone = SecurityZone.query.filter_by(name="Bridge Systems").first()
    comm_zone = SecurityZone.query.filter_by(name="Communication Systems").first()
    engine_zone = SecurityZone.query.filter_by(name="Engine Control Systems").first()
    
    # Get specific assets
    ecdis = CBSAsset.query.filter_by(name="ECDIS System").first()
    vsat = CBSAsset.query.filter_by(name="VSAT Terminal").first()
    engine_control = CBSAsset.query.filter_by(name="Main Engine Control Unit").first()
    power_mgmt = CBSAsset.query.filter_by(name="Power Management System").first()
    
    # CATEGORY 1: NAVIGATION SYSTEMS
    
    # CPU Usage for Navigation Systems
    nav_cpu_threshold = AlertThreshold(
        name="Navigation Systems - High CPU",
        description="Critical alert for high CPU usage on navigation systems",
        metric_type="cpu_usage",
        comparison=">",
        threshold_value=80,
        duration_minutes=5,
        vessel_id=vessel.id,
        cbs_id=None,  # Apply to all navigation assets
        enabled=True
    )
    
    # Memory Usage for Navigation Systems
    nav_mem_threshold = AlertThreshold(
        name="Navigation Systems - High Memory",
        description="Alert for excessive memory consumption on navigation systems",
        metric_type="memory_usage",
        comparison=">",
        threshold_value=85,
        duration_minutes=5,
        vessel_id=vessel.id,
        cbs_id=None,  # Apply to all navigation assets
        enabled=True
    )
    
    # Disk Usage for Navigation Systems
    nav_disk_threshold = AlertThreshold(
        name="Navigation Systems - Disk Space Critical",
        description="Alert when disk space is running low on navigation systems",
        metric_type="disk_usage",
        comparison=">",
        threshold_value=90,
        duration_minutes=1,
        vessel_id=vessel.id,
        cbs_id=None,  # Apply to all navigation assets
        enabled=True
    )
    
    # CATEGORY 2: COMMUNICATION SYSTEMS
    
    # Network Traffic for Communication Systems
    comm_network_threshold = AlertThreshold(
        name="Communication Systems - High Network Traffic",
        description="Alert for excessive network utilization on communication systems",
        metric_type="network_in",
        comparison=">",
        threshold_value=90,
        duration_minutes=10,
        vessel_id=vessel.id,
        cbs_id=None,  # Apply to all communication assets
        enabled=True
    )
    
    # Communication Services Availability
    comm_response_threshold = AlertThreshold(
        name="Communication Services - Connectivity Loss",
        description="Alert when critical communication services are unavailable",
        metric_type="response_time",
        comparison=">",
        threshold_value=5000,
        duration_minutes=2,
        vessel_id=vessel.id,
        cbs_id=None,  # Apply to all communication assets
        enabled=True
    )
    
    # Packet Loss for Communication Systems
    comm_packet_loss_threshold = AlertThreshold(
        name="Communication Systems - Packet Loss",
        description="Alert for excessive packet loss on communication links",
        metric_type="packet_loss",
        comparison=">",
        threshold_value=5,
        duration_minutes=5,
        vessel_id=vessel.id,
        cbs_id=None,  # Apply to all communication assets
        enabled=True
    )
    
    # CATEGORY 3: ENGINE/MACHINERY CONTROL SYSTEMS
    
    # CPU Usage for Engine Control Systems
    engine_cpu_threshold = AlertThreshold(
        name="Engine Control Systems - High CPU",
        description="Alert for high CPU usage on engine control and power management systems",
        metric_type="cpu_usage",
        comparison=">",
        threshold_value=85,
        duration_minutes=3,
        vessel_id=vessel.id,
        cbs_id=None,  # Apply to all engine control assets
        enabled=True
    )
    
    # Response Time for Engine Control Systems
    engine_response_threshold = AlertThreshold(
        name="Engine Control Systems - Response Delay",
        description="Critical alert for slow response time in real-time control systems",
        metric_type="response_time",
        comparison=">",
        threshold_value=500,
        duration_minutes=2,
        vessel_id=vessel.id,
        cbs_id=None,  # Apply to all engine control assets
        enabled=True
    )
    
    # Memory Usage for Engine Control Systems
    engine_mem_threshold = AlertThreshold(
        name="Engine Systems - Memory Usage",
        description="Alert for high memory consumption on engine control systems",
        metric_type="memory_usage",
        comparison=">",
        threshold_value=80,
        duration_minutes=5,
        vessel_id=vessel.id,
        cbs_id=None,  # Apply to all engine control assets
        enabled=True
    )
    
    # CATEGORY 4: GENERAL SYSTEM MONITORING
    
    # System-wide CPU Usage
    system_cpu_threshold = AlertThreshold(
        name="System-wide CPU Usage",
        description="Alert for high CPU usage across all vessel systems",
        metric_type="cpu_usage",
        comparison=">",
        threshold_value=90,
        duration_minutes=10,
        vessel_id=None,  # Apply to all vessels
        cbs_id=None,     # Apply to all assets
        enabled=True
    )
    
    # Memory Leak Detection
    memory_leak_threshold = AlertThreshold(
        name="Memory Leak Detection",
        description="Alert for potential memory leaks in long-running services",
        metric_type="memory_growth_rate",
        comparison=">",
        threshold_value=5,
        duration_minutes=60,
        vessel_id=None,  # Apply to all vessels
        cbs_id=None,     # Apply to all assets
        enabled=True
    )
    
    # Disk Growth Rate
    disk_growth_threshold = AlertThreshold(
        name="Abnormal Disk Usage Growth",
        description="Alert for unusually rapid disk space consumption",
        metric_type="disk_growth_rate",
        comparison=">",
        threshold_value=10,
        duration_minutes=1440,  # 24 hours
        vessel_id=None,  # Apply to all vessels
        cbs_id=None,     # Apply to all assets
        enabled=True
    )
    
    # System Reboot Detection
    reboot_threshold = AlertThreshold(
        name="System Reboot Detection",
        description="Alert when any system reboots unexpectedly",
        metric_type="uptime",
        comparison="<",
        threshold_value=10,
        duration_minutes=1,
        vessel_id=None,  # Apply to all vessels
        cbs_id=None,     # Apply to all assets
        enabled=True
    )
    
    # Add all thresholds to the session
    thresholds = [
        # Navigation
        nav_cpu_threshold, nav_mem_threshold, nav_disk_threshold,
        # Communication
        comm_network_threshold, comm_response_threshold, comm_packet_loss_threshold,
        # Engine Control
        engine_cpu_threshold, engine_response_threshold, engine_mem_threshold,
        # General
        system_cpu_threshold, memory_leak_threshold, disk_growth_threshold, reboot_threshold
    ]
    
    for threshold in thresholds:
        db.session.add(threshold)
    
    db.session.commit()
    print("Maritime thresholds created successfully!")
    return True

def create_notification_profiles():
    """Create recommended notification profiles for maritime vessel teams"""
    # Create notification settings for different teams
    
    # Bridge Team (Navigation Officers)
    bridge_notification = NotificationSetting(
        name="Bridge Team - Critical Alerts",
        description="Send critical navigation system alerts to bridge team",
        notification_type="email",
        recipient="bridge@example.com",
        severity_filter="critical,high", 
        enabled=True
    )
    
    # IT Support Team (All alerts)
    it_notification = NotificationSetting(
        name="IT Support - All Alerts",
        description="Send all system alerts to IT support team",
        notification_type="email",
        recipient="it-support@example.com",
        severity_filter=None,  # All severities
        enabled=True
    )
    
    # Communications Team
    comms_notification = NotificationSetting(
        name="Communications Team Alerts",
        description="Send alerts related to communication systems to the comms team",
        notification_type="email",
        recipient="comms@example.com",
        severity_filter="critical,high,medium",
        enabled=True
    )
    
    # Engineering Team
    engineering_notification = NotificationSetting(
        name="Engineering Team - Engine System Alerts",
        description="Send alerts related to engine and machinery control systems to engineering team",
        notification_type="email",
        recipient="engineering@example.com",
        severity_filter="critical,high",
        enabled=True
    )
    
    notifications = [
        bridge_notification,
        it_notification,
        comms_notification,
        engineering_notification
    ]
    
    for notification in notifications:
        db.session.add(notification)
    
    db.session.commit()
    print("Notification profiles created successfully!")
    return True

if __name__ == "__main__":
    with app.app_context():
        # Create sample vessel and assets if they don't exist
        create_sample_data()
        
        # Create maritime-specific thresholds
        create_maritime_thresholds()
        
        # Create notification profiles
        create_notification_profiles()
        
        print("Alert threshold setup complete!")