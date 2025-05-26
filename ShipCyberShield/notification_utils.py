"""
Notification utilities for Maritime Network Management System
Handles email notifications and other alert channels
"""
import os
import logging
import json
from typing import List, Dict, Any, Optional
from datetime import datetime
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content
from flask import render_template_string

from app import db
from models import Alert, NotificationSetting, SecurityLog, EventType


# Email templates
ALERT_EMAIL_HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Maritime NMS Alert</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            background-color: {{ header_color }};
            color: white;
            padding: 10px 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .footer {
            margin-top: 30px;
            font-size: 12px;
            color: #777;
            border-top: 1px solid #eee;
            padding-top: 10px;
        }
        .alert-details {
            background-color: #f9f9f9;
            border: 1px solid #ddd;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .alert-details table {
            width: 100%;
            border-collapse: collapse;
        }
        .alert-details table td {
            padding: 5px;
            border-bottom: 1px solid #eee;
        }
        .alert-details table td:first-child {
            font-weight: bold;
            width: 140px;
        }
        .cta-button {
            display: inline-block;
            background-color: #007bff;
            color: white;
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 5px;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h2>{{ alert_title }}</h2>
    </div>
    
    <p>{{ alert_message }}</p>
    
    <div class="alert-details">
        <table>
            <tr>
                <td>Alert ID:</td>
                <td>{{ alert.id }}</td>
            </tr>
            <tr>
                <td>Severity:</td>
                <td>{{ alert.severity.value }}</td>
            </tr>
            <tr>
                <td>Status:</td>
                <td>{{ alert.status.value }}</td>
            </tr>
            <tr>
                <td>Created:</td>
                <td>{{ alert.created_at.strftime('%Y-%m-%d %H:%M:%S') }}</td>
            </tr>
            {% if alert.vessel %}
            <tr>
                <td>Vessel:</td>
                <td>{{ alert.vessel.name }}</td>
            </tr>
            {% endif %}
            {% if alert.cbs_asset %}
            <tr>
                <td>Asset:</td>
                <td>{{ alert.cbs_asset.name }}</td>
            </tr>
            {% endif %}
        </table>
    </div>
    
    <p>Please take appropriate action to address this alert.</p>
    
    <div class="footer">
        <p>This is an automated message from your Maritime Network Management System.</p>
        <p>© {{ current_year }} Maritime NMS. All rights reserved.</p>
    </div>
</body>
</html>
"""

ALERT_EMAIL_TEXT_TEMPLATE = """
MARITIME NMS ALERT: {{ alert_title }}

{{ alert_message }}

Alert Details:
- Alert ID: {{ alert.id }}
- Severity: {{ alert.severity.value }}
- Status: {{ alert.status.value }}
- Created: {{ alert.created_at.strftime('%Y-%m-%d %H:%M:%S') }}
{% if alert.vessel %}
- Vessel: {{ alert.vessel.name }}
{% endif %}
{% if alert.cbs_asset %}
- Asset: {{ alert.cbs_asset.name }}
{% endif %}

Please take appropriate action to address this alert.

This is an automated message from your Maritime Network Management System.
© {{ current_year }} Maritime NMS. All rights reserved.
"""


def get_severity_color(severity: str) -> str:
    """Get appropriate color for alert severity level"""
    colors = {
        'critical': '#d9534f',  # red
        'high': '#f0ad4e',      # orange
        'medium': '#5bc0de',    # blue
        'low': '#5cb85c',       # green
        'info': '#5bc0de'       # light blue
    }
    return colors.get(severity.lower(), '#5bc0de')


def send_email_notification(alert: Alert) -> bool:
    """
    Send email notification for an alert
    
    Args:
        alert (Alert): The alert to send notification for
        
    Returns:
        bool: True if notification sent successfully, False otherwise
    """
    # Get active email notification settings
    notification_settings = NotificationSetting.query.filter_by(
        notification_type='email',
        enabled=True
    ).all()
    
    if not notification_settings:
        logging.info("No active email notification settings found")
        return False
    
    # Get SendGrid API key
    api_key = os.environ.get('SENDGRID_API_KEY')
    if not api_key:
        logging.error("SendGrid API key not configured")
        return False
    
    # Check which notification settings apply to this alert's severity
    sent_count = 0
    
    for setting in notification_settings:
        # Check severity filter if it exists
        if setting.severity_filter:
            severity_list = [s.strip().lower() for s in setting.severity_filter.split(',')]
            if alert.severity.value.lower() not in severity_list:
                continue
        
        # Get recipients
        recipients = [email.strip() for email in setting.recipient.split(',')]
        
        # Skip if no recipients
        if not recipients:
            continue
        
        # Prepare email content
        current_year = datetime.now().year
        header_color = get_severity_color(alert.severity.value)
        
        # Format alert title and message
        alert_title = f"{alert.severity.value.upper()} Alert: {alert.title}"
        alert_message = alert.message
        
        # Render templates
        html_content = render_template_string(
            ALERT_EMAIL_HTML_TEMPLATE,
            alert=alert,
            alert_title=alert_title,
            alert_message=alert_message,
            header_color=header_color,
            current_year=current_year
        )
        
        text_content = render_template_string(
            ALERT_EMAIL_TEXT_TEMPLATE,
            alert=alert,
            alert_title=alert_title,
            alert_message=alert_message,
            current_year=current_year
        )
        
        # Prepare default sender
        sender = "nms@maritimecybersecurity.com"
        
        # Try to send to all recipients
        for recipient in recipients:
            message = Mail(
                from_email=Email(sender),
                to_emails=To(recipient),
                subject=alert_title
            )
            message.content = Content("text/plain", text_content)
            message.content = Content("text/html", html_content)
            
            try:
                sg = SendGridAPIClient(api_key)
                response = sg.send(message)
                
                if response.status_code >= 200 and response.status_code < 300:
                    sent_count += 1
                    logging.info(f"Email alert sent to {recipient} for alert ID {alert.id}")
                    
                    # Log notification to security log
                    security_log = SecurityLog()
                    security_log.event_type = EventType.SECURITY_ALARM
                    security_log.vessel_id = alert.vessel_id
                    security_log.cbs_id = alert.cbs_id
                    security_log.description = f"Email notification sent to {recipient} for alert ID {alert.id}"
                    security_log.data = json.dumps({
                        "alert_id": alert.id,
                        "notification_setting_id": setting.id,
                        "recipient": recipient,
                        "severity": alert.severity.value
                    })
                    
                    db.session.add(security_log)
                    db.session.commit()
                else:
                    logging.error(f"Failed to send email to {recipient}: {response.status_code} {response.body}")
            
            except Exception as e:
                logging.error(f"Error sending email to {recipient}: {str(e)}")
        
    return sent_count > 0


def send_webhook_notification(alert: Alert) -> bool:
    """
    Send webhook notification for an alert
    
    Args:
        alert (Alert): The alert to send notification for
        
    Returns:
        bool: True if notification sent successfully, False otherwise
    """
    # This is a placeholder for future webhook implementation
    # Will integrate with other systems like Slack, Teams, etc.
    return False


def process_alert_notifications(alert: Alert) -> bool:
    """
    Process all appropriate notifications for a new alert
    
    Args:
        alert (Alert): The newly created alert
        
    Returns:
        bool: True if any notifications were sent successfully
    """
    success = False
    
    # Email notifications
    email_success = send_email_notification(alert)
    if email_success:
        success = True
    
    # Webhook notifications (for future expansion)
    # webhook_success = send_webhook_notification(alert)
    # if webhook_success:
    #     success = True
    
    return success


def check_alert_thresholds(data: Dict[str, Any], asset_id: int, vessel_id: int) -> Optional[Alert]:
    """
    Check if sensor data exceeds any configured thresholds and create alert if needed
    
    Args:
        data (dict): Performance metric data
        asset_id (int): ID of the asset being monitored
        vessel_id (int): ID of the vessel
        
    Returns:
        Alert: Created alert if threshold exceeded, None otherwise
    """
    from models import AlertThreshold, CBSAsset, Alert, AlertSeverity, AlertStatus
    
    if not data or 'metric_type' not in data or 'value' not in data:
        return None
    
    metric_type = data['metric_type']
    value = float(data['value'])
    
    # Look for applicable thresholds - specific to this asset first, then vessel-wide, then global
    thresholds_query = AlertThreshold.query.filter_by(metric_type=metric_type, enabled=True)
    asset_thresholds = thresholds_query.filter_by(cbs_id=asset_id).all()
    vessel_thresholds = thresholds_query.filter_by(vessel_id=vessel_id, cbs_id=None).all()
    global_thresholds = thresholds_query.filter_by(vessel_id=None, cbs_id=None).all()
    
    # Combine all applicable thresholds, with asset-specific taking precedence
    all_thresholds = asset_thresholds + vessel_thresholds + global_thresholds
    
    for threshold in all_thresholds:
        is_exceeded = False
        
        # Check if threshold is exceeded
        if threshold.comparison == '>':
            is_exceeded = value > threshold.threshold_value
        elif threshold.comparison == '>=':
            is_exceeded = value >= threshold.threshold_value
        elif threshold.comparison == '<':
            is_exceeded = value < threshold.threshold_value
        elif threshold.comparison == '<=':
            is_exceeded = value <= threshold.threshold_value
        elif threshold.comparison == '==':
            is_exceeded = value == threshold.threshold_value
        
        if is_exceeded:
            # Get asset details
            asset = CBSAsset.query.get(asset_id)
            
            # Create alert
            alert = Alert()
            alert.title = f"{threshold.name} threshold exceeded"
            alert.message = f"{metric_type.capitalize()} value of {value} has {threshold.comparison} threshold of {threshold.threshold_value} for asset {asset.name}"
            alert.status = AlertStatus.NEW
            alert.severity = AlertSeverity.HIGH  # Default to HIGH, could be configurable in the threshold
            alert.vessel_id = vessel_id
            alert.cbs_id = asset_id
            
            db.session.add(alert)
            db.session.commit()
            
            # Log to security log
            security_log = SecurityLog()
            security_log.event_type = EventType.SECURITY_ALARM
            security_log.vessel_id = vessel_id
            security_log.cbs_id = asset_id
            security_log.description = f"Alert triggered: {threshold.name} threshold exceeded"
            security_log.data = json.dumps({
                "threshold_id": threshold.id,
                "alert_id": alert.id,
                "metric_type": metric_type,
                "value": value,
                "threshold_value": threshold.threshold_value,
                "comparison": threshold.comparison
            })
            
            db.session.add(security_log)
            db.session.commit()
            
            # Process notifications
            process_alert_notifications(alert)
            
            return alert
    
    return None