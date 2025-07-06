#!/usr/bin/env python3
"""
NAPALM CMDB Admin Dashboard with Pipeline Management
Flask application with blueprints for network device management and real-time pipeline execution
"""
import traceback

from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from datetime import datetime, timedelta
import os
import sqlite3
import json
import logging

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///napalm_cmdb.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pipeline.log'),
        logging.StreamHandler()
    ]
)


# Database helper functions
def get_db_connection():
    """Get database connection with row factory"""
    conn = sqlite3.connect('napalm_cmdb.db')
    conn.row_factory = sqlite3.Row
    return conn


def execute_query(query, params=None):
    """Execute query and return results"""
    conn = get_db_connection()
    try:
        if params:
            cursor = conn.execute(query, params)
        else:
            cursor = conn.execute(query)
        results = cursor.fetchall()
        conn.commit()
        return [dict(row) for row in results]
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()


# Import blueprints
from blueprints.dashboard import dashboard_bp
from blueprints.devices import devices_bp
from blueprints.network import network_bp
from blueprints.config import config_bp
from blueprints.reports import reports_bp

from blueprints.drawio import drawio_bp

# Register the Draw.io blueprint
app.register_blueprint(drawio_bp)
from blueprints.pipeline import pipeline_bp, init_socketio
from blueprints.topology import topology_bp

init_socketio(socketio)

# Register blueprints
app.register_blueprint(dashboard_bp, url_prefix='/')
app.register_blueprint(devices_bp, url_prefix='/devices')
app.register_blueprint(network_bp, url_prefix='/network')
app.register_blueprint(config_bp, url_prefix='/config')
app.register_blueprint(reports_bp, url_prefix='/reports')
app.register_blueprint(pipeline_bp, url_prefix='/pipeline')
app.register_blueprint(topology_bp, url_prefix='/topology')

@app.context_processor
def inject_globals():
    """Inject global variables into all templates"""
    return {
        'app_name': 'NAPALM CMDB',
        'version': '1.0.0',
        'current_year': datetime.now().year,
        'now': datetime.now
    }


@app.template_filter('number_format')
def number_format_filter(value):
    """Format numbers with thousands separators"""
    if value is None:
        return 'N/A'
    try:
        return f"{int(value):,}"
    except (ValueError, TypeError):
        return value


@app.template_filter('datetime')
def datetime_filter(value):
    """Format datetime for templates"""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except:
            return value
    if isinstance(value, datetime):
        return value.strftime('%Y-%m-%d %H:%M:%S')
    return value


@app.template_filter('relative_time')
def relative_time_filter(value):
    """Show relative time (e.g., '2 hours ago')"""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except:
            return value

    if isinstance(value, datetime):
        now = datetime.now()
        diff = now - value

        if diff.days > 0:
            return f"{diff.days} days ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} hours ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} minutes ago"
        else:
            return "Just now"
    return value


@app.template_filter('file_size')
def file_size_filter(value):
    """Format file size in human readable format"""
    if not value:
        return "0 B"

    for unit in ['B', 'KB', 'MB', 'GB']:
        if value < 1024.0:
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} TB"


# API endpoints for dashboard data
@app.route('/api/metrics')
def api_metrics():
    """API endpoint for dashboard metrics"""
    try:
        # Device statistics
        device_stats = execute_query("""
            SELECT 
                COUNT(*) as total,
                COUNT(CASE WHEN is_active = 1 THEN 1 END) as active,
                COUNT(CASE WHEN first_discovered > datetime('now', '-7 days') THEN 1 END) as recent
            FROM devices
        """)[0]

        # Vendor distribution
        vendor_dist = execute_query("""
            SELECT vendor, COUNT(*) as count 
            FROM devices 
            WHERE is_active = 1 
            GROUP BY vendor 
            ORDER BY count DESC
        """)

        # Role distribution
        role_dist = execute_query("""
            SELECT device_role, COUNT(*) as count 
            FROM devices 
            WHERE is_active = 1 
            GROUP BY device_role 
            ORDER BY count DESC
        """)

        # Collection statistics
        collection_stats = execute_query("""
            SELECT 
                AVG(CASE WHEN success = 1 THEN 100.0 ELSE 0.0 END) as success_rate,
                AVG(collection_duration) as avg_duration
            FROM collection_runs 
            WHERE collection_time > datetime('now', '-24 hours')
        """)

        success_rate = collection_stats[0]['success_rate'] if collection_stats else 0
        avg_duration = collection_stats[0]['avg_duration'] if collection_stats else 0

        # Health metrics
        health_stats = execute_query("""
            SELECT 
                AVG(cpu_usage) as avg_cpu,
                AVG(CASE 
                    WHEN memory_total > 0 THEN (memory_used * 100.0 / memory_total)
                    WHEN memory_available > 0 THEN (memory_used * 100.0 / (memory_used + memory_available))
                    ELSE NULL
                END) as avg_memory,
                COUNT(DISTINCT device_id) as monitored_devices
            FROM environment_data 
            WHERE created_at > datetime('now', '-24 hours')
        """)

        health_metrics = health_stats[0] if health_stats else {}

        return {
            'device_stats': {
                'total': device_stats['total'],
                'recent': device_stats['recent'],
                'vendors': vendor_dist,
                'roles': role_dist
            },
            'collection_stats': {
                'success_rate': success_rate or 0,
                'avg_duration': avg_duration or 0
            },
            'health_metrics': {
                'avg_cpu': health_metrics.get('avg_cpu', 0) or 0,
                'avg_memory': health_metrics.get('avg_memory', 0) or 0,
                'monitored_devices': health_metrics.get('monitored_devices', 0) or 0
            }
        }
    except Exception as e:
        logging.error(f"Error fetching metrics: {e}")
        return {'error': str(e)}, 500


@app.route('/api/alerts')
def api_alerts():
    """API endpoint for system alerts"""
    try:
        alerts = []

        # Check for failed collections
        failed_collections = execute_query("""
            SELECT COUNT(*) as count
            FROM collection_runs 
            WHERE success = 0 AND collection_time > datetime('now', '-24 hours')
        """)[0]['count']

        if failed_collections > 0:
            alerts.append({
                'type': 'warning',
                'title': 'Collection Failures',
                'message': f'{failed_collections} devices failed collection in last 24h',
                'count': failed_collections
            })

        # Check for devices not seen recently
        stale_devices = execute_query("""
            SELECT COUNT(*) as count
            FROM devices 
            WHERE is_active = 1 AND last_updated < datetime('now', '-7 days')
        """)[0]['count']

        if stale_devices > 0:
            alerts.append({
                'type': 'info',
                'title': 'Stale Devices',
                'message': f'{stale_devices} devices not updated in 7+ days',
                'count': stale_devices
            })

        # Check for high CPU usage
        high_cpu_devices = execute_query("""
            SELECT COUNT(DISTINCT device_id) as count
            FROM environment_data 
            WHERE cpu_usage > 80 AND created_at > datetime('now', '-1 hour')
        """)[0]['count']

        if high_cpu_devices > 0:
            alerts.append({
                'type': 'danger',
                'title': 'High CPU Usage',
                'message': f'{high_cpu_devices} devices with CPU > 80%',
                'count': high_cpu_devices
            })

        return {'alerts': alerts}
    except Exception as e:
        logging.error(f"Error fetching alerts: {e}")
        return {'error': str(e)}, 500


@app.route('/api/activities')
def api_activities():
    """API endpoint for recent activities"""
    try:
        activities = []

        # Recent device discoveries
        recent_devices = execute_query("""
            SELECT device_name, first_discovered
            FROM devices 
            WHERE first_discovered > datetime('now', '-7 days')
            ORDER BY first_discovered DESC
            LIMIT 10
        """)

        for device in recent_devices:
            activities.append({
                'activity_type': 'device_discovery',
                'device_name': device['device_name'],
                'description': 'New device discovered',
                'timestamp': device['first_discovered']
            })

        # Recent config changes
        config_changes = execute_query("""
            SELECT d.device_name, cc.change_type, cc.detected_at, cc.change_size
            FROM config_changes cc
            JOIN devices d ON cc.device_id = d.id
            WHERE cc.detected_at > datetime('now', '-7 days')
            ORDER BY cc.detected_at DESC
            LIMIT 10
        """)

        for change in config_changes:
            activities.append({
                'activity_type': 'config_change',
                'device_name': change['device_name'],
                'description': f'Configuration {change["change_type"]} ({change["change_size"]} lines)',
                'timestamp': change['detected_at']
            })

        # Sort by timestamp
        activities.sort(key=lambda x: x['timestamp'], reverse=True)

        return {'activities': activities[:10]}
    except Exception as e:
        logging.error(f"Error fetching activities: {e}")
        return {'error': str(e)}, 500


# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template('errors/500.html'), 500


# Health check endpoint
@app.route('/health')
def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Test database connection
        conn = get_db_connection()
        conn.execute('SELECT 1')
        conn.close()

        return {
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'database': 'connected',
            'pipeline': 'available'
        }, 200
    except Exception as e:
        return {
            'status': 'unhealthy',
            'timestamp': datetime.now().isoformat(),
            'error': str(e)
        }, 500


# Pipeline logs endpoint
@app.route('/logs')
def view_logs():
    """View pipeline logs"""
    try:
        with open('pipeline.log', 'r') as f:
            logs = f.readlines()

        # Get last 500 lines
        recent_logs = logs[-500:] if len(logs) > 500 else logs

        return render_template('logs.html', logs=recent_logs)
    except FileNotFoundError:
        return render_template('logs.html', logs=['No logs available'])
    except Exception as e:
        return render_template('logs.html', logs=[f'Error reading logs: {str(e)}'])


# WebSocket event handlers for real-time updates
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('connection_response', {'data': 'Connected to pipeline server'})
    logging.info(f'Client connected: {request.sid}')


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logging.info(f'Client disconnected: {request.sid}')


# Development and production considerations
if __name__ == '__main__':
    # Ensure database exists
    try:
        if not os.path.exists('napalm_cmdb.db'):
            logging.warning("Database file not found. Please create the database using cmdb.sql")
            print("Warning: Database file not found. Please create the database using cmdb.sql")

        # Create necessary directories
        os.makedirs('captures', exist_ok=True)
        os.makedirs('logs', exist_ok=True)

        # Check if running in PyCharm debugger
        import sys

        is_debugging = 'pydevd' in sys.modules or '--debug' in sys.argv

        # Run with SocketIO for real-time features
        # Disable reloader when debugging to avoid path issues
        socketio.run(
            app,
            debug=True,
            host='0.0.0.0',
            port=5000,
            allow_unsafe_werkzeug=True,
            use_reloader=not is_debugging  # Disable reloader when debugging
        )
    except Exception as e:
        traceback.print_exc()
        print(e)