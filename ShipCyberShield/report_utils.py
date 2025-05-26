"""
Reporting Utilities for Maritime Network Management System
Provides functionality for generating performance and historical reports
"""
import csv
import io
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from sqlalchemy import func, desc, and_, distinct
from flask import Response

from app import db
from models import SensorData, Alert, SecurityLog, CBSAsset, Vessel


def get_performance_report(asset_id: int, time_range: str) -> Tuple[Dict[str, Any], Dict[str, List[Dict[str, Any]]]]:
    """
    Generate a performance report for a specific asset within a time range
    
    Args:
        asset_id: ID of the asset to report on
        time_range: Time range string ('24h', '7d', '30d', 'custom')
        
    Returns:
        Tuple containing:
            - Summary metrics dictionary
            - Raw data points dictionary by metric type
    """
    # Calculate start time based on time range
    end_time = datetime.utcnow()
    if time_range == '24h':
        start_time = end_time - timedelta(hours=24)
    elif time_range == '7d':
        start_time = end_time - timedelta(days=7)
    elif time_range == '30d':
        start_time = end_time - timedelta(days=30)
    else:
        # Default to 24 hours if invalid range
        start_time = end_time - timedelta(hours=24)
    
    # Get the asset details
    asset = CBSAsset.query.get(asset_id)
    if not asset:
        return {}, {}
        
    # Query sensor data for this asset within the time range
    sensor_data = SensorData.query.filter(
        SensorData.cbs_id == asset_id,
        SensorData.timestamp >= start_time,
        SensorData.timestamp <= end_time
    ).order_by(SensorData.timestamp).all()
    
    # Group data by sensor type
    data_by_type = {}
    for data in sensor_data:
        if data.sensor_type not in data_by_type:
            data_by_type[data.sensor_type] = []
        
        data_by_type[data.sensor_type].append({
            'timestamp': data.timestamp.isoformat(),
            'value': data.value,
            'unit': data.unit
        })
    
    # Calculate summary statistics
    summary = {
        'asset_name': asset.name,
        'asset_id': asset.id,
        'vessel_name': asset.vessel.name if asset.vessel else None,
        'start_time': start_time.isoformat(),
        'end_time': end_time.isoformat(),
        'data_points': len(sensor_data),
        'metrics': {}
    }
    
    # Calculate metrics for each sensor type
    for sensor_type, data_points in data_by_type.items():
        if not data_points:
            continue
            
        values = [d['value'] for d in data_points]
        
        summary['metrics'][sensor_type] = {
            'min': min(values),
            'max': max(values),
            'avg': sum(values) / len(values),
            'count': len(values),
            'unit': data_points[0]['unit'] if data_points[0]['unit'] else None,
            'last_value': values[-1]
        }
    
    return summary, data_by_type


def get_alert_report(vessel_id: Optional[int] = None, 
                    asset_id: Optional[int] = None, 
                    severity: Optional[str] = None,
                    status: Optional[str] = None,
                    start_date: Optional[datetime] = None,
                    end_date: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """
    Generate a report of historical alerts with optional filtering
    
    Args:
        vessel_id: Optional vessel ID to filter by
        asset_id: Optional asset ID to filter by
        severity: Optional severity level to filter by
        status: Optional alert status to filter by
        start_date: Optional start date for report
        end_date: Optional end date for report
        
    Returns:
        List of alert data dictionaries
    """
    # Build query with filters
    query = Alert.query
    
    if vessel_id:
        query = query.filter(Alert.vessel_id == vessel_id)
    
    if asset_id:
        query = query.filter(Alert.cbs_id == asset_id)
    
    if severity:
        query = query.filter(Alert.severity == severity)
    
    if status:
        query = query.filter(Alert.status == status)
    
    if start_date:
        query = query.filter(Alert.created_at >= start_date)
    
    if end_date:
        # Add one day to end_date to include the entire day
        end_date_inclusive = end_date + timedelta(days=1) if end_date else None
        query = query.filter(Alert.created_at < end_date_inclusive)
    
    # Execute query and order by date (newest first)
    alerts = query.order_by(desc(Alert.created_at)).all()
    
    # Convert to dictionary format
    alert_data = []
    for alert in alerts:
        alert_dict = {
            'id': alert.id,
            'title': alert.title,
            'message': alert.message,
            'severity': alert.severity.value,
            'status': alert.status.value,
            'created_at': alert.created_at.isoformat(),
            'vessel_name': alert.vessel.name if alert.vessel else None,
            'asset_name': alert.cbs_asset.name if alert.cbs_asset else None
        }
        
        if alert.acknowledged_at:
            alert_dict['acknowledged_at'] = alert.acknowledged_at.isoformat()
            alert_dict['acknowledged_by'] = alert.acknowledger.username if alert.acknowledger else None
        
        if alert.resolved_at:
            alert_dict['resolved_at'] = alert.resolved_at.isoformat()
            alert_dict['resolved_by'] = alert.resolver.username if alert.resolver else None
        
        alert_data.append(alert_dict)
    
    return alert_data


def generate_csv_response(data: List[Dict[str, Any]], filename: str) -> Response:
    """
    Generate a CSV response from a list of dictionaries
    
    Args:
        data: List of dictionaries to convert to CSV
        filename: Name for the downloaded file
        
    Returns:
        Flask Response object with CSV data
    """
    if not data:
        return Response("No data available", mimetype="text/plain")
    
    # Create in-memory file for CSV data
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=data[0].keys())
    
    # Write header and data rows
    writer.writeheader()
    for row in data:
        writer.writerow(row)
    
    # Create response with CSV as attachment
    response = Response(output.getvalue(), mimetype="text/csv")
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    
    return response


def get_retention_statistics() -> Dict[str, Any]:
    """
    Get statistics about current data in the database for retention planning
    
    Returns:
        Dictionary with counts and date ranges for each data type
    """
    stats = {}
    
    # SensorData statistics
    sensor_data_count = SensorData.query.count()
    oldest_sensor_data = SensorData.query.order_by(SensorData.timestamp).first()
    newest_sensor_data = SensorData.query.order_by(desc(SensorData.timestamp)).first()
    
    stats['sensor_data'] = {
        'count': sensor_data_count,
        'oldest': oldest_sensor_data.timestamp.isoformat() if oldest_sensor_data else None,
        'newest': newest_sensor_data.timestamp.isoformat() if newest_sensor_data else None,
    }
    
    # Alert statistics
    alert_count = Alert.query.count()
    oldest_alert = Alert.query.order_by(Alert.created_at).first()
    newest_alert = Alert.query.order_by(desc(Alert.created_at)).first()
    
    stats['alerts'] = {
        'count': alert_count,
        'oldest': oldest_alert.created_at.isoformat() if oldest_alert else None,
        'newest': newest_alert.created_at.isoformat() if newest_alert else None,
    }
    
    # SecurityLog statistics
    log_count = SecurityLog.query.count()
    oldest_log = SecurityLog.query.order_by(SecurityLog.timestamp).first()
    newest_log = SecurityLog.query.order_by(desc(SecurityLog.timestamp)).first()
    
    stats['security_logs'] = {
        'count': log_count,
        'oldest': oldest_log.timestamp.isoformat() if oldest_log else None,
        'newest': newest_log.timestamp.isoformat() if newest_log else None,
    }
    
    return stats


def cleanup_old_data(sensor_data_days: int = 90, 
                    security_log_days: int = 365,
                    alert_days: int = 180) -> Dict[str, int]:
    """
    Clean up old data based on retention policy
    
    Args:
        sensor_data_days: Days to keep detailed sensor data
        security_log_days: Days to keep security logs
        alert_days: Days to keep alerts
        
    Returns:
        Dictionary with count of records deleted by type
    """
    current_time = datetime.utcnow()
    deleted_counts = {}
    
    # Delete old sensor data
    sensor_cutoff = current_time - timedelta(days=sensor_data_days)
    sensor_result = db.session.query(SensorData).filter(
        SensorData.timestamp < sensor_cutoff
    ).delete(synchronize_session=False)
    deleted_counts['sensor_data'] = sensor_result
    
    # Delete old security logs, but keep critical security events longer
    # Critical security events are typically kept for compliance/auditing purposes
    log_cutoff = current_time - timedelta(days=security_log_days)
    log_result = db.session.query(SecurityLog).filter(
        SecurityLog.timestamp < log_cutoff,
        # Keep certain critical event types longer (example: don't delete access_control logs)
        SecurityLog.event_type != 'access_control',
        SecurityLog.event_type != 'security_alarm'
    ).delete(synchronize_session=False)
    deleted_counts['security_logs'] = log_result
    
    # Delete old resolved/closed alerts
    alert_cutoff = current_time - timedelta(days=alert_days)
    alert_result = db.session.query(Alert).filter(
        Alert.created_at < alert_cutoff,
        Alert.status.in_(['resolved', 'closed'])  # Only delete resolved/closed alerts
    ).delete(synchronize_session=False)
    deleted_counts['alerts'] = alert_result
    
    # Commit the changes
    db.session.commit()
    
    return deleted_counts