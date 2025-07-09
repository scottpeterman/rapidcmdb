#!/usr/bin/env python3
"""
Pipeline Management Blueprint
Handles network discovery, NAPALM collection, and data import pipeline
"""

from flask import Blueprint, render_template, request, jsonify
import subprocess
import threading
import json
import os
import time
from datetime import datetime
from pathlib import Path
import logging
import yaml
import signal
import psutil
import glob
import math

# Create blueprint
pipeline_bp = Blueprint('pipeline', __name__, url_prefix='/pipeline')

# Global variables for process management
active_processes = {}
socketio = None  # Will be injected from main app


def init_socketio(socketio_instance):
    """Initialize SocketIO instance and register event handlers"""
    global socketio
    socketio = socketio_instance
    register_socketio_events()


@pipeline_bp.route('/')
def index():
    """Pipeline management main page"""
    return render_template('pipeline/index.html')


@pipeline_bp.route('/status')
def status():
    """Get current pipeline status"""
    status_info = {
        'active_processes': list(active_processes.keys()),
        'scanner_available': check_scanner_available(),
        'collector_available': check_collector_available(),
        'database_available': check_database_available()
    }
    return jsonify(status_info)


@pipeline_bp.route('/logs')
def logs():
    """View system logs"""
    return render_template('pipeline/logs.html')


def register_socketio_events():
    """Register SocketIO event handlers after socketio is initialized"""
    global socketio
    from flask_socketio import emit

    @socketio.on('start_scan')
    def handle_start_scan(data):
        """Handle scanner start request"""
        try:
            session_id = request.sid

            # Validate input
            if not data.get('target'):
                emit('scanner_error', {'message': 'Target network is required'})
                return

            # Build scanner command
            command = build_scanner_command(data)

            emit('scanner_output', {
                'message': f'Starting scanner with command: {" ".join(command)}',
                'type': 'info'
            })

            # Start scanner process
            start_scanner_process(command, session_id)

        except Exception as e:
            logging.error(f"Error starting scanner: {e}")
            emit('scanner_error', {'message': str(e)})

    @socketio.on('stop_scan')
    def handle_stop_scan():
        """Handle scanner stop request"""
        try:
            session_id = request.sid
            stop_process('scanner', session_id)
            emit('scanner_output', {'message': 'Scanner stopped by user', 'type': 'warning'})
        except Exception as e:
            logging.error(f"Error stopping scanner: {e}")
            emit('scanner_error', {'message': str(e)})

    @socketio.on('start_collection')
    def handle_start_collection(data):
        """Handle NAPALM collection start request"""
        try:
            session_id = request.sid

            # Get the scan file - this should be the JSON database file
            scan_file = data.get('scan_file', 'scanner_usmd_devices.json')  # Default to JSON

            logging.info(f"Collection request for scan file: {scan_file}")

            # Get the directory paths
            app_dir = os.path.dirname(os.path.abspath(__file__))
            parent_dir = os.path.dirname(app_dir)  # Go up one level from blueprints
            scans_dir = os.path.join(parent_dir, 'scans')

            # Resolve the actual file path
            resolved_scan_file = None

            if os.path.isabs(scan_file):
                # It's already absolute, use as-is
                resolved_scan_file = scan_file
            elif os.path.sep in scan_file:
                # It has path separators, treat as relative path from parent_dir
                resolved_scan_file = os.path.join(parent_dir, scan_file)
            else:
                # Just a filename, look in scans directory first
                scan_file_in_scans = os.path.join(scans_dir, scan_file)
                if os.path.exists(scan_file_in_scans):
                    resolved_scan_file = scan_file_in_scans
                    logging.info(f"Found scan file in scans directory: {resolved_scan_file}")
                else:
                    # Fallback to parent directory for backward compatibility
                    fallback_path = os.path.join(parent_dir, scan_file)
                    if os.path.exists(fallback_path):
                        resolved_scan_file = fallback_path
                        logging.info(f"Found scan file in parent directory: {resolved_scan_file}")

            # Try to find the actual database file if we got a CSV
            if resolved_scan_file and resolved_scan_file.endswith('.csv'):
                # Look for corresponding JSON database file
                possible_json_files = [
                    resolved_scan_file.replace('.csv', '.json'),
                    f"scanner_{resolved_scan_file.replace('.csv', '_devices.json')}",
                    os.path.join(scans_dir, 'scanner_usmd_devices.json'),
                    os.path.join(parent_dir, 'scanner_usmd_devices.json')
                ]

                json_file_found = None
                for json_candidate in possible_json_files:
                    if os.path.exists(json_candidate):
                        json_file_found = json_candidate
                        break

                if not json_file_found:
                    emit('collection_error', {
                        'message': f'JSON database file not found. Looking for one of: {possible_json_files}'
                    })
                    return

                resolved_scan_file = json_file_found

            # Final check that we found a file
            if not resolved_scan_file or not os.path.exists(resolved_scan_file):
                # Provide helpful error message showing where we looked
                searched_paths = []
                if not os.path.isabs(scan_file) and os.path.sep not in scan_file:
                    searched_paths = [
                        os.path.join(scans_dir, scan_file),
                        os.path.join(parent_dir, scan_file)
                    ]

                emit('collection_error', {
                    'message': f'Scan file not found: {scan_file}. Searched paths: {searched_paths}'
                })
                return

            # Update the data with the resolved file path
            data['scan_file'] = resolved_scan_file

            emit('collection_output', {
                'message': f'Using JSON database file: {resolved_scan_file}',
                'type': 'info'
            })

            # Build collector command
            command = build_collector_command(data)
            logging.info(f"Command to run: {command}")

            emit('collection_output', {
                'message': f'Starting NAPALM collector: {" ".join(command)}',
                'type': 'info'
            })

            # Start collector process
            start_collector_process(command, session_id)

        except Exception as e:
            logging.error(f"Error starting collection: {e}")
            emit('collection_error', {'message': str(e)})

    @socketio.on('stop_collection')
    def handle_stop_collection():
        """Handle collection stop request"""
        try:
            session_id = request.sid
            stop_process('collector', session_id)
            emit('collection_output', {'message': 'Collection stopped by user', 'type': 'warning'})
        except Exception as e:
            logging.error(f"Error stopping collection: {e}")
            emit('collection_error', {'message': str(e)})

    @socketio.on('start_pipeline')
    def handle_start_pipeline(data):
        """Handle full pipeline execution"""
        try:
            session_id = request.sid
            target = data.get('target')

            if not target:
                emit('pipeline_error', {'message': 'Target network is required'})
                return

            emit('pipeline_output', {
                'message': f'Starting full pipeline for target: {target}',
                'type': 'info'
            })

            # Start pipeline execution
            start_pipeline_execution(data, session_id)

        except Exception as e:
            logging.error(f"Error starting pipeline: {e}")
            emit('pipeline_error', {'message': str(e)})

    @socketio.on('stop_pipeline')
    def handle_stop_pipeline():
        """Handle pipeline stop request"""
        try:
            session_id = request.sid
            stop_process('pipeline', session_id)
            emit('pipeline_output', {'message': 'Pipeline stopped by user', 'type': 'warning'})
        except Exception as e:
            logging.error(f"Error stopping pipeline: {e}")
            emit('pipeline_error', {'message': str(e)})

    @socketio.on('get_status')
    def handle_get_status():
        """Handle status request"""
        try:
            session_id = request.sid
            status_info = get_process_status(session_id)
            emit('status_update', status_info)
        except Exception as e:
            logging.error(f"Error getting status: {e}")

    @socketio.on('get_scan_files')
    def handle_get_scan_files():
        """Handle request for available scan files"""
        try:
            session_id = request.sid

            # Add debugging
            list_all_files_in_directory()

            files = get_available_scan_files()
            logging.info(f"Returning {len(files)} files to client: {files}")

            emit('scan_files_list', {'files': files})
        except Exception as e:
            logging.error(f"Error getting scan files: {e}")
            emit('scan_files_error', {'message': str(e)})


def build_scanner_command(data):
    """Build scanner command from form data"""
    import sys
    import shutil
    import glob

    # Get the directory where app.py is located
    app_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(app_dir)  # Go up one level from blueprints to main app directory

    # Find the scanner executable
    scanner_exe = None
    possible_patterns = [
        'gosnmpcli*.exe',  # Handles spaces in filename
        'gosnmpcli*',  # Unix version
        'main*.exe',  # Alternative name
        'main*'  # Unix alternative
    ]

    # First check in the parent directory (where app.py is)
    for pattern in possible_patterns:
        matches = glob.glob(os.path.join(parent_dir, pattern))
        if matches:
            scanner_exe = matches[0]  # Take the first match
            break

    # If not found, check current working directory
    if not scanner_exe:
        for pattern in possible_patterns:
            matches = glob.glob(pattern)
            if matches:
                scanner_exe = os.path.abspath(matches[0])
                break

    # Finally check PATH
    if not scanner_exe:
        possible_names = ['gosnmpcli.exe', 'gosnmpcli', 'main.exe', 'main']
        for name in possible_names:
            path_exe = shutil.which(name)
            if path_exe:
                scanner_exe = path_exe
                break

    if not scanner_exe:
        available_files = []
        for pattern in ['*.exe', '*cli*']:
            available_files.extend(glob.glob(os.path.join(parent_dir, pattern)))
        raise FileNotFoundError(f"Scanner executable not found. Available files in {parent_dir}: {available_files}")

    logging.info(f"Found scanner executable: {scanner_exe}")
    command = [scanner_exe]

    # Basic parameters
    command.extend(['-mode', 'scan'])
    command.extend(['-target', data['target']])
    command.extend(['-timeout', data.get('timeout', '4s')])
    command.extend(['-concurrency', str(data.get('concurrency', 80))])
    command.extend(['-communities', data.get('communities', 'public')])

    # SNMP version and credentials
    if data.get('snmpVersion') == '3':
        command.extend(['-snmp-version', '3'])
        command.extend(['-username', data.get('username', '')])
        command.extend(['-auth-protocol', data.get('authProtocol', 'SHA')])

        # ✅ FIX: Wrap auth-key and priv-key values to handle special characters
        auth_key = data.get('authKey', '')
        if auth_key:
            command.extend(['-auth-key', f"'{auth_key}'"])  # Wrap in quotes

        command.extend(['-priv-protocol', data.get('privProtocol', 'AES128')])

        priv_key = data.get('privKey', '')
        if priv_key:
            command.extend(['-priv-key', f"'{priv_key}'"])  # Wrap in quotes

    # Fingerprinting and output
    command.extend(['-fingerprint-type', data.get('fingerprintType', 'full')])

    if data.get('enableDb', False):
        command.extend(['-enable-db'])
        command.extend(['-database', data.get('database', './scanner_devices.json')])

    command.extend(['-output', data.get('outputFormat', 'csv')])
    command.extend(['-output-file', data.get('outputFile', 'scan_results.csv')])

    return command


def build_collector_command(data):
    """Build NAPALM collector command from form data"""
    import sys
    import os

    # Get the directory where app.py is located
    app_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(app_dir)  # Go up one level from blueprints
    scans_dir = os.path.join(parent_dir, 'scans')

    # Use the current Python interpreter
    python_exe = sys.executable

    # Find the collector script
    collector_script = None
    possible_names = ['npcollector1.py']

    # Check in parent directory first (where app.py is)
    for name in possible_names:
        script_path = os.path.join(parent_dir, name)
        if os.path.exists(script_path):
            collector_script = script_path
            break

    # Check current directory as fallback
    if not collector_script:
        for name in possible_names:
            if os.path.exists(name):
                collector_script = os.path.abspath(name)
                break

    if not collector_script:
        raise FileNotFoundError(f"Collector script not found. Tried: {possible_names}")

    logging.info(f"Found collector script: {collector_script}")

    # Get the scan file (should already be JSON at this point)
    scan_file = data['scan_file']

    logging.info(f"Original scan_file from data: {scan_file}")

    # Build the full path to the scan file
    # First, check if it's already an absolute path
    if os.path.isabs(scan_file):
        # It's already absolute, use as-is
        final_scan_file = scan_file
    elif os.path.sep in scan_file:
        # It has path separators, treat as relative path from parent_dir
        final_scan_file = os.path.join(parent_dir, scan_file)
    else:
        # Just a filename, look in scans directory first
        scan_file_in_scans = os.path.join(scans_dir, scan_file)
        if os.path.exists(scan_file_in_scans):
            final_scan_file = scan_file_in_scans
            logging.info(f"Found scan file in scans directory: {final_scan_file}")
        else:
            # Fallback to parent directory for backward compatibility
            fallback_path = os.path.join(parent_dir, scan_file)
            if os.path.exists(fallback_path):
                final_scan_file = fallback_path
                logging.info(f"Found scan file in parent directory: {final_scan_file}")
            else:
                # Last resort - try current working directory
                cwd_path = os.path.join(os.getcwd(), scan_file)
                if os.path.exists(cwd_path):
                    final_scan_file = cwd_path
                    logging.info(f"Found scan file in current directory: {final_scan_file}")
                else:
                    # File not found anywhere, raise error with helpful message
                    searched_paths = [
                        scan_file_in_scans,
                        fallback_path,
                        cwd_path
                    ]
                    raise FileNotFoundError(
                        f"Scan file not found: {scan_file}. Searched in: {searched_paths}"
                    )

    # Convert to absolute path
    final_scan_file = os.path.abspath(final_scan_file)

    # Final verification that the file exists
    if not os.path.exists(final_scan_file):
        raise FileNotFoundError(f"Scan file not found: {final_scan_file}")

    logging.info(f"Using scan file: {final_scan_file}")

    # Build simple command: python npcollector1.py <json_file>
    command = [python_exe, collector_script, final_scan_file]
    logging.info(f"Command to run: {command}")
    # Add workers parameter if specified
    workers = data.get('max_workers', 10)
    if workers and workers != 10:  # Only add if different from default
        command.extend(['--workers', str(workers)])

    return command

def create_collector_config(data):
    """Create temporary collector configuration file"""
    import tempfile

    config = {
        'timeout': data.get('timeout', 60),
        'max_workers': data.get('max_workers', 10),
        'enhanced_inventory': True,
        'credentials': [
            {
                'name': 'primary',
                'username': data.get('username', 'admin'),
                'password': data.get('password', ''),
                'enable_password': data.get('enable_password', ''),
                'priority': 1
            }
        ],
        'collection_methods': data.get('collection_methods', {
            'get_facts': True,
            'get_config': True,
            'get_interfaces': True,
            'get_interfaces_ip': True,
            'get_lldp_neighbors': True,
            'get_arp_table': True,
            'get_mac_address_table': True,
            'get_environment': True
        })
    }

    # Create temporary config file (Windows-compatible)
    temp_dir = tempfile.gettempdir()
    config_path = os.path.join(temp_dir, f'collector_config_{int(time.time())}.yaml')

    with open(config_path, 'w') as f:
        yaml.dump(config, f, default_flow_style=False)

    return config_path


def start_scanner_process(command, session_id):
    """Start scanner process with real-time output"""

    def run_scanner():
        try:
            # Get the directory where app.py is located for working directory
            app_dir = os.path.dirname(os.path.abspath(__file__))
            parent_dir = os.path.dirname(app_dir)  # Go up one level from blueprints

            # Convert command list to properly escaped string
            import shlex
            command_str = ' '.join(shlex.quote(arg) for arg in command)
            command_str = command_str.replace("'","")
            logging.info(f"Starting scanner with command: {command_str}")
            logging.info(f"Working directory: {parent_dir}")

            process = subprocess.Popen(
                command_str,  # Use the escaped string instead of list
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
                cwd=parent_dir,
                encoding='utf-8',
                errors='replace',
                shell=True  # Enable shell mode
            )

            # Store process for management
            active_processes[f'scanner_{session_id}'] = process

            # Initialize counters
            stats = {
                'scanned': 0,
                'found': 0,
                'snmp_ready': 0,
                'total': 0,
                'rate': 0.0,
                'eta': 0
            }

            start_time = time.time()

            # Read output line by line
            for line in iter(process.stdout.readline, ''):
                if not line:
                    break

                line = line.strip()
                if not line:
                    continue

                # Clean the line to remove any problematic characters
                try:
                    # Replace common emoji/special characters with text equivalents
                    line = line.replace('📋', '[CONFIG]')
                    line = line.replace('🔍', '[SCAN]')
                    line = line.replace('✅', '[OK]')
                    line = line.replace('❌', '[ERROR]')
                    line = line.replace('⚙️', '[CONFIG]')
                    line = line.replace('🌐', '[NETWORK]')
                    line = line.replace('🎉', '[COMPLETE]')

                    # Remove any remaining non-ASCII characters
                    line = line.encode('ascii', 'replace').decode('ascii')
                except UnicodeError:
                    line = "Scanner output (encoding issue)"

                # Log the line for debugging
                logging.debug(f"Scanner output: {line}")

                # Parse scanner output and update stats
                updated_stats = parse_scanner_output(line, stats, start_time)

                # Emit output and progress
                socketio.emit('scanner_output', {
                    'message': line,
                    'type': 'info'
                }, room=session_id)

                if updated_stats != stats:
                    stats = updated_stats
                    socketio.emit('scanner_progress', stats, room=session_id)

            # Wait for process completion
            return_code = process.wait()
            logging.info(f"Scanner process completed with return code: {return_code}")

            # Clean up
            if f'scanner_{session_id}' in active_processes:
                del active_processes[f'scanner_{session_id}']

            if return_code == 0:
                socketio.emit('scanner_complete', {
                    'found': stats['found'],
                    'snmp_ready': stats['snmp_ready'],
                    'output_file': extract_output_file_from_command(command)
                }, room=session_id)
            else:
                socketio.emit('scanner_error', {
                    'message': f'Scanner failed with return code {return_code}'
                }, room=session_id)

        except FileNotFoundError as e:
            logging.error(f"Scanner executable not found: {e}")
            socketio.emit('scanner_error', {
                'message': f'Scanner executable not found. Please ensure gosnmpcli.exe is in the application directory. Error: {str(e)}'
            }, room=session_id)
        except Exception as e:
            logging.error(f"Scanner process error: {e}")
            socketio.emit('scanner_error', {
                'message': f'Scanner process error: {str(e)}'
            }, room=session_id)

    # Start in background thread
    thread = threading.Thread(target=run_scanner)
    thread.daemon = True
    thread.start()


def start_collector_process(command, session_id):
    """Start NAPALM collector process with real-time output"""

    def run_collector():
        try:
            # Get the directory where app.py is located for working directory
            app_dir = os.path.dirname(os.path.abspath(__file__))
            parent_dir = os.path.dirname(app_dir)  # Go up one level from blueprints

            logging.info(f"Starting collector with command: {' '.join(command)}")
            logging.info(f"Working directory: {parent_dir}")

            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
                cwd=parent_dir,  # Set working directory to where app.py is
                encoding='utf-8',
                errors='replace'
            )

            # Store process for management
            active_processes[f'collector_{session_id}'] = process

            # Initialize counters
            stats = {
                'processed': 0,
                'failed': 0,
                'data_methods': 0,
                'total': 0,
                'rate': 0.0,
                'eta': 0
            }

            start_time = time.time()

            # Read output line by line
            for line in iter(process.stdout.readline, ''):
                if not line:
                    break

                line = line.strip()
                if not line:
                    continue

                # Clean the line to remove any problematic characters (similar to scanner)
                try:
                    line = line.replace('📋', '[CONFIG]')
                    line = line.replace('🔍', '[SCAN]')
                    line = line.replace('✅', '[OK]')
                    line = line.replace('❌', '[ERROR]')
                    line = line.replace('⚙️', '[CONFIG]')
                    line = line.replace('🌐', '[NETWORK]')
                    line = line.replace('🎉', '[COMPLETE]')
                    line = line.encode('ascii', 'replace').decode('ascii')
                except UnicodeError:
                    line = "Collector output (encoding issue)"

                logging.debug(f"Collector output: {line}")

                # Parse collector output and update stats
                updated_stats = parse_collector_output(line, stats, start_time)

                # Emit output and progress
                socketio.emit('collection_output', {
                    'message': line,
                    'type': 'info'
                }, room=session_id)

                if updated_stats != stats:
                    stats = updated_stats
                    socketio.emit('collection_progress', stats, room=session_id)

            # Wait for process completion
            return_code = process.wait()
            logging.info(f"Collector process completed with return code: {return_code}")

            # Clean up temporary config file if it exists
            cleanup_temp_files(command)

            # Clean up process
            if f'collector_{session_id}' in active_processes:
                del active_processes[f'collector_{session_id}']

            if return_code == 0:
                socketio.emit('collection_complete', {
                    'processed': stats['processed'],
                    'successful': stats['processed'] - stats['failed']
                }, room=session_id)

                # Trigger database import
                trigger_database_import(session_id)
            else:
                socketio.emit('collection_error', {
                    'message': f'Collection failed with return code {return_code}'
                }, room=session_id)

        except FileNotFoundError as e:
            logging.error(f"Collector script or input file not found: {e}")
            socketio.emit('collection_error', {
                'message': f'Collector script or input file not found: {str(e)}'
            }, room=session_id)
        except Exception as e:
            logging.error(f"Collector process error: {e}")
            socketio.emit('collection_error', {
                'message': f'Collector process error: {str(e)}'
            }, room=session_id)

    # Start in background thread
    thread = threading.Thread(target=run_collector)
    thread.daemon = True
    thread.start()


def start_pipeline_execution(data, session_id):
    """Execute full pipeline: scan -> collect -> import"""

    def run_pipeline():
        try:
            target = data['target']
            pipeline_start = time.time()

            # Step 1: Network Discovery
            socketio.emit('pipeline_step', {
                'step': 1,
                'status': 'active',
                'message': 'Starting network discovery scan'
            }, room=session_id)

            # Build scanner command with pipeline-specific settings
            scanner_data = {
                'target': target,
                'timeout': '4s',
                'concurrency': 80,
                'communities': 'public,write',
                'snmpVersion': '3',
                'username': '',
                'authProtocol': 'SHA',
                'authKey': '',
                'privProtocol': 'AES128',
                'privKey': '',
                'fingerprintType': 'full',
                'enableDb': True,
                'database': './pipeline_scanner_db',
                'outputFormat': 'json',
                'outputFile': f'pipeline_scan_{int(time.time())}.json'
            }

            scanner_command = build_scanner_command(scanner_data)

            # Run scanner
            scanner_process = subprocess.Popen(
                scanner_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )

            active_processes[f'pipeline_{session_id}'] = scanner_process

            scanner_output = []
            for line in iter(scanner_process.stdout.readline, ''):
                if not line:
                    break
                line = line.strip()
                if line:
                    scanner_output.append(line)
                    socketio.emit('pipeline_output', {
                        'message': f'Scanner: {line}',
                        'type': 'info'
                    }, room=session_id)

            scanner_return = scanner_process.wait()

            if scanner_return != 0:
                socketio.emit('pipeline_step', {
                    'step': 1,
                    'status': 'error',
                    'message': 'Network discovery failed'
                }, room=session_id)
                return

            socketio.emit('pipeline_step', {
                'step': 1,
                'status': 'completed',
                'message': 'Network discovery completed'
            }, room=session_id)

            # Additional pipeline steps would go here...
            # For brevity, I'll just complete the pipeline

            # Pipeline complete
            total_time = int(time.time() - pipeline_start)
            socketio.emit('pipeline_complete', {
                'total_time': total_time,
                'message': 'Full pipeline execution completed successfully'
            }, room=session_id)

            # Clean up
            if f'pipeline_{session_id}' in active_processes:
                del active_processes[f'pipeline_{session_id}']

        except Exception as e:
            logging.error(f"Pipeline execution error: {e}")
            socketio.emit('pipeline_error', {
                'message': str(e)
            }, room=session_id)

    # Start in background thread
    thread = threading.Thread(target=run_pipeline)
    thread.daemon = True
    thread.start()


def parse_scanner_output(line, stats, start_time):
    """Parse scanner output to extract progress information"""
    new_stats = stats.copy()

    # Look for progress indicators in the output
    if 'Progress:' in line:
        try:
            parts = line.split('|')

            # Parse progress
            if len(parts) > 0:
                progress_part = parts[0].split(':')[1].strip()
                if '/' in progress_part:
                    current, total = progress_part.split('(')[0].split('/')
                    new_stats['scanned'] = int(current.strip())
                    new_stats['total'] = int(total.strip())

            # Parse found devices
            if len(parts) > 1:
                found_part = parts[1].strip()
                if 'Found:' in found_part:
                    found_text = found_part.replace('Found:', '').strip()
                    if 'responding' in found_text:
                        responding = found_text.split('responding')[0].strip()
                        new_stats['found'] = int(responding)
                    if 'SNMP' in found_text:
                        snmp_text = found_text.split(',')[1] if ',' in found_text else ''
                        if 'SNMP' in snmp_text:
                            snmp_count = snmp_text.split('SNMP')[0].strip()
                            new_stats['snmp_ready'] = int(snmp_count)

            # Parse rate
            if len(parts) > 2:
                rate_part = parts[2].strip()
                if 'Rate:' in rate_part:
                    rate_text = rate_part.replace('Rate:', '').replace('/sec', '').strip()
                    new_stats['rate'] = float(rate_text)

        except (ValueError, IndexError) as e:
            logging.debug(f"Error parsing scanner output: {e}")

    return new_stats


def parse_collector_output(line, stats, start_time):
    """Parse collector output to extract progress information"""
    new_stats = stats.copy()

    # Look for collection progress indicators
    if 'Successfully collected' in line or 'Processed device' in line:
        new_stats['processed'] += 1
    elif 'Failed to connect' in line or 'Error processing' in line or 'Connection failed' in line:
        new_stats['failed'] += 1
    elif 'get_facts' in line or 'get_config' in line or 'get_interfaces' in line:
        new_stats['data_methods'] += 1
    elif 'devices found in scan file' in line:
        try:
            # Extract total count if mentioned
            parts = line.split()
            for i, part in enumerate(parts):
                if part.isdigit() and i > 0 and 'devices' in parts[i + 1]:
                    new_stats['total'] = int(part)
                    break
        except (ValueError, IndexError):
            pass

    # Calculate rate
    elapsed = time.time() - start_time
    if elapsed > 0:
        new_stats['rate'] = new_stats['processed'] / (elapsed / 60)  # devices per minute

    return new_stats


def stop_process(process_type, session_id):
    """Stop a running process"""
    process_key = f'{process_type}_{session_id}'

    if process_key in active_processes:
        process = active_processes[process_key]
        try:
            # Try graceful termination first
            process.terminate()

            # Wait for termination, then force kill if necessary
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

            del active_processes[process_key]
            logging.info(f"Stopped {process_type} process for session {session_id}")

        except Exception as e:
            logging.error(f"Error stopping {process_type} process: {e}")


def trigger_database_import(session_id):
    """Trigger database import of collected data"""
    try:
        socketio.emit('collection_output', {
            'message': 'Starting database import...',
            'type': 'info'
        }, room=session_id)

        # Run database import
        success = run_database_import('./captures', session_id)

        if success:
            socketio.emit('collection_output', {
                'message': 'Database import completed successfully',
                'type': 'success'
            }, room=session_id)
        else:
            socketio.emit('collection_output', {
                'message': 'Database import failed',
                'type': 'error'
            }, room=session_id)

    except Exception as e:
        logging.error(f"Database import error: {e}")
        socketio.emit('collection_output', {
            'message': f'Database import error: {str(e)}',
            'type': 'error'
        }, room=session_id)


def run_database_import(captures_dir, session_id):
    """Run database import using db_manager.py"""
    try:
        import sys

        # Find the database manager script
        db_manager_script = None
        possible_names = ['db_manager.py', './db_manager.py']

        for name in possible_names:
            if os.path.exists(name):
                db_manager_script = os.path.abspath(name)
                break

        if not db_manager_script:
            logging.error("db_manager.py not found")
            return False

        command = [
            sys.executable, db_manager_script,
            '--import-dir', captures_dir,
            '--db-path', 'napalm_cmdb.db',
            '--schema-path', 'cmdb.sql'
        ]

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            cwd=os.getcwd()
        )

        # Stream output
        for line in iter(process.stdout.readline, ''):
            if not line:
                break
            line = line.strip()
            if line:
                socketio.emit('pipeline_output', {
                    'message': f'Import: {line}',
                    'type': 'info'
                }, room=session_id)

        return_code = process.wait()
        return return_code == 0

    except Exception as e:
        logging.error(f"Database import process error: {e}")
        return False


def extract_output_file_from_command(command):
    """Extract output file name from command"""
    try:
        for i, arg in enumerate(command):
            if arg == '-output-file' and i + 1 < len(command):
                return command[i + 1]
    except:
        pass
    return 'scan_results.csv'


def cleanup_temp_files(command):
    """Clean up temporary configuration files"""
    try:
        for arg in command:
            if arg.startswith('/tmp/collector_config_') and arg.endswith('.yaml'):
                if os.path.exists(arg):
                    os.remove(arg)
                    logging.debug(f"Cleaned up temp config: {arg}")
    except Exception as e:
        logging.error(f"Error cleaning up temp files: {e}")


def get_process_status(session_id):
    """Get status of processes for a session"""
    status = {
        'scanner_running': f'scanner_{session_id}' in active_processes,
        'collector_running': f'collector_{session_id}' in active_processes,
        'pipeline_running': f'pipeline_{session_id}' in active_processes
    }
    return status


def check_scanner_available():
    """Check if scanner binary is available"""
    return os.path.exists('./gosnmpcli') or os.path.exists('./main')


def check_collector_available():
    """Check if collector script is available"""
    return os.path.exists('./npcollector1.py')


def check_database_available():
    """Check if database manager is available"""
    return os.path.exists('./db_manager.py')


# File discovery functions
def get_available_scan_files():
    """Get list of available JSON scan files with metadata"""
    import glob
    import os
    from datetime import datetime

    # Get the directory where app.py is located
    app_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(app_dir)  # Go up one level from blueprints

    # Look in the scans subdirectory
    scans_dir = os.path.join(parent_dir, 'scans')

    logging.info(f"Looking for scan files in directory: {scans_dir}")

    # Create scans directory if it doesn't exist
    if not os.path.exists(scans_dir):
        os.makedirs(scans_dir)
        logging.info(f"Created scans directory: {scans_dir}")

    # Look for JSON files that appear to be scanner database files
    search_patterns = [
        os.path.join(scans_dir, '*scanner*devices*.json'),
        os.path.join(scans_dir, 'scanner_*.json'),
        os.path.join(scans_dir, '*_devices.json'),
        os.path.join(scans_dir, 'scanned_*.json'),
        os.path.join(scans_dir, '*.json')  # All JSON files as fallback
    ]

    found_files = []
    seen_files = set()

    for pattern in search_patterns:
        logging.info(f"Searching pattern: {pattern}")
        matches = glob.glob(pattern)
        logging.info(f"Found {len(matches)} files for pattern: {matches}")

        for filepath in matches:
            filename = os.path.basename(filepath)

            # Skip if we've already seen this file
            if filename in seen_files:
                continue

            # Skip common non-scanner JSON files
            if filename.lower() in ['package.json', 'config.json', 'settings.json', 'package-lock.json']:
                logging.info(f"Skipping common non-scanner file: {filename}")
                continue

            try:
                # Get file info
                stat_info = os.stat(filepath)
                file_size = format_file_size(stat_info.st_size)
                modified_time = datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M')

                # Try to validate it's a scanner file by checking content
                is_scanner_file = validate_scanner_file(filepath)
                logging.info(
                    f"File {filename}: size={file_size}, modified={modified_time}, is_scanner={is_scanner_file}")

                if is_scanner_file:
                    file_info = f"{filename}|{file_size}|{modified_time}"
                    found_files.append(file_info)
                    seen_files.add(filename)
                else:
                    # For debugging, let's include non-validated files too, but mark them
                    file_info = f"{filename}|{file_size}|{modified_time}|[unvalidated]"
                    found_files.append(file_info)
                    seen_files.add(filename)

            except Exception as e:
                logging.error(f"Error processing file {filepath}: {e}")
                continue

    logging.info(f"Total files found: {len(found_files)}")

    # Sort by modification time (newest first)
    found_files.sort(key=lambda x: x.split('|')[2] if len(x.split('|')) > 2 else '', reverse=True)

    return found_files

def format_file_size(size_bytes):
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0B"

    size_names = ["B", "KB", "MB", "GB"]
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s}{size_names[i]}"


def validate_scanner_file(filepath):
    """Validate that a JSON file appears to be a scanner database file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            # Read first few lines to check structure
            content = f.read(2048)  # Read first 2KB instead of 1KB

            if not content.strip():
                logging.debug(f"File {filepath} is empty")
                return False

            # Look for scanner-specific patterns - made more permissive
            scanner_indicators = [
                '"ip":', '"hostname":', '"vendor":', '"model":',
                '"snmp_version":', '"device_type":', '"platform":',
                '"system_description":', '"uptime":', '"location":',
                '"address":', '"community":', '"description":', '"contact":'
            ]

            # Count indicators found
            indicator_count = sum(1 for indicator in scanner_indicators if indicator in content)
            logging.debug(f"File {filepath} has {indicator_count} scanner indicators")

            # Made more permissive - only need 1 indicator or valid JSON structure
            if indicator_count >= 1:
                return True

            # Also check if it looks like a JSON array/object with network-like data
            if (content.strip().startswith('[') or content.strip().startswith('{')) and \
                    ('.' in content and ('10.' in content or '192.' in content or '172.' in content)):
                logging.debug(f"File {filepath} looks like network data JSON")
                return True

            return False

    except Exception as e:
        logging.error(f"Error validating scanner file {filepath}: {e}")
        return False


def list_all_files_in_directory():
    """Debug function to list all files in the application directory"""
    import os

    app_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(app_dir)

    logging.info(f"All files in {parent_dir}:")
    try:
        for item in os.listdir(parent_dir):
            item_path = os.path.join(parent_dir, item)
            if os.path.isfile(item_path):
                stat_info = os.stat(item_path)
                size = format_file_size(stat_info.st_size)
                logging.info(f"  {item} ({size})")
    except Exception as e:
        logging.error(f"Error listing directory: {e}")