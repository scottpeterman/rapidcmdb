#!/usr/bin/env python3
"""
Reports Blueprint - Scan file analysis and reporting
"""

from flask import Blueprint, render_template, jsonify, request, send_file, flash, redirect, url_for
import os
import json
import sqlite3
from datetime import datetime, timedelta
import logging
from collections import defaultdict, Counter
import re
from typing import Dict, List, Tuple
import tempfile
from io import StringIO

reports_bp = Blueprint('reports', __name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SCANS_FOLDER = 'scans'


class DeviceAnalyzer:
    """Analyzes network devices from scan data - adapted from discover_types.py"""

    def __init__(self):
        # ORDER MATTERS - Most specific patterns first
        self.vendor_patterns = {
            'lexmark': [
                r'lexmark\s+\w+',
                r'lexmark.*version'
            ],
            'arista': [
                r'arista\s+networks',
                r'arista.*eos',
                r'eos\s+version',
                r'dcs-\d+',
                r'ccs-\d+'
            ],
            'cisco': [
                r'cisco\s+ios',
                r'cisco\s+nx-os',
                r'cisco\s+systems',
                r'catalyst\s+l3\s+switch',
                r'catalyst.*switch',
                r'cisco\s+catalyst',
                r'cisco\s+asr',
                r'cisco\s+isr',
                r'cisco\s+nexus',
                r'cisco\s+ucs',
                r'cisco\s+asa',
                r'cisco\s+wlc'
            ],
            'palo_alto': [
                r'palo\s+alto\s+networks',
                r'palo\s+alto.*firewall',
                r'palo\s+alto.*panorama',
                r'pan-os',
                r'pa-\d+\s+series'
            ],
            'palo_alto_sdwan': [
                r'ion\s+\d+\s*\(',
                r'ion\s+\d+\s+\(',
                r'silver\s+peak'
            ],
            'aruba': [
                r'aruba\s*os',
                r'clearpass',
                r'mobility\s+master',
                r'aruba.*controller',
                r'aruba\d+'
            ],
            'fortinet': [
                r'fortinet',
                r'fortigate',
                r'fortios'
            ],
            'juniper': [
                r'juniper\s+networks',
                r'junos',
                r'srx\d+',
                r'mx\d+',
                r'ex\d+'
            ],
            'dell': [
                r'dell\s+emc',
                r'openmanage',
                r'powerswitch',
                r'dell.*networking'
            ],
            'apc': [
                r'apc\s+web/snmp',
                r'apc\s+management\s+card',
                r'smart-ups',
                r'american\s+power\s+conversion'
            ],
            'hp': [
                r'hewlett.?packard',
                r'hp\s+j\d+',
                r'hp\s+procurve',
                r'hpe\s+',
                r'procurve',
                r'formerly\s+procurve'
            ],
            'xerox': [
                r'xerox',
                r'xerox.*printer',
                r'xerox.*color'
            ],
            'samsung': [
                r'samsung',
                r'samsung\s+ipolis'
            ],
            'zebra': [
                r'zebra\s+technologies',
                r'zebra\s+wired'
            ],
            'brother': [
                r'brother\s+nc-'
            ],
            'vmware': [
                r'vmware',
                r'esxi',
                r'vcenter'
            ],
            'bluecat': [
                r'bluecat',
                r'ddi\s+server'
            ],
            'f5': [
                r'f5\s+networks',
                r'big-ip'
            ],
            'checkpoint': [
                r'check\s+point',
                r'checkpoint'
            ]
        }

        # ORDER MATTERS - Most specific patterns first
        self.device_type_patterns = {
            'switch': [
                r'catalyst\s+l3\s+switch',
                r'catalyst.*switch',
                r'switch\s+software',
                r'eos\s+version.*running\s+on',
                r'arista\s+networks.*running\s+on',
                r'dcs-\d+',
                r'ccs-\d+',
                r'nexus\s+\d+',
                r'nx-os',
                r'powerswitch',
                r'procurve',
                r'formerly\s+procurve',
                r'switch'  # Generic switch - put last
            ],
            'printer': [
                r'lexmark\s+\w+',
                r'xerox.*printer',
                r'brother\s+nc-',
                r'printer'  # Generic printer - put last
            ],
            'firewall': [
                r'palo\s+alto.*firewall',
                r'pa-\d+\s+series\s+firewall',
                r'fortigate',
                r'asa\s+\d+',
                r'checkpoint',
                r'srx\d+',
                r'firewall'  # Generic firewall - put last
            ],
            'wireless_controller': [
                r'mobility\s+master',
                r'mobility\s+controller',
                r'wireless\s+controller',
                r'wlc\s+\d+',
                r'clearpass',
                r'aruba\d+.*controller'
            ],
            'sdwan': [
                r'ion\s+\d+',
                r'silver\s+peak',
                r'sd-wan',
                r'viptela'
            ],
            'router': [
                r'isr\s*\d+',
                r'asr\s*\d+',
                r'ios\s+software.*router',
                r'routeros',
                r'router'  # Generic router - put last
            ],
            'ups': [
                r'apc\s+web/snmp\s+management\s+card',
                r'smart-ups',
                r'uninterruptible\s+power',
                r'ups'  # Generic UPS - put last
            ],
            'camera': [
                r'samsung\s+ipolis',
                r'ipolis',
                r'camera'
            ],
            'label_printer': [
                r'zebra\s+technologies',
                r'zebra.*wired'
            ],
            'server': [
                r'openmanage',
                r'ddi\s+server',
                r'bluecat',
                r'vmware\s+esxi',
                r'vcenter',
                r'linux.*x86_64'
            ],
            'load_balancer': [
                r'big-ip',
                r'f5.*ltm',
                r'netscaler'
            ],
            'fabric_interconnect': [
                r'ucs\s+fabric',
                r'fabric\s+interconnect'
            ]
        }

    def enhance_vendor_detection(self, device_info: Dict) -> str:
        """Enhanced vendor detection using pattern matching"""
        vendor = str(device_info.get('vendor', 'unknown')).lower()
        sys_descr = str(device_info.get('sys_descr', '')).lower()

        # Pattern matching on system description (ORDER MATTERS - most specific first)
        for vendor_name, patterns in self.vendor_patterns.items():
            for pattern in patterns:
                if re.search(pattern, sys_descr, re.IGNORECASE):
                    return vendor_name

        # Check original vendor if not unknown
        if vendor != 'unknown':
            return vendor

        return 'unknown'

    def determine_device_type(self, vendor: str, sys_descr: str, ip: str) -> str:
        """Determine device type from system description and vendor"""
        sys_descr_lower = str(sys_descr).lower()
        vendor = str(vendor)
        ip = str(ip) if ip else ''

        # Pattern matching for device types (ORDER MATTERS - most specific first)
        for device_type, patterns in self.device_type_patterns.items():
            for pattern in patterns:
                if re.search(pattern, sys_descr_lower, re.IGNORECASE):
                    return device_type

        # Vendor-based device type mapping (only for specific cases)
        vendor_device_map = {
            'palo_alto_sdwan': 'sdwan',
            'palo_alto': 'firewall',
            'fortinet': 'firewall',
            'checkpoint': 'firewall',
            'f5': 'load_balancer',
            'apc': 'ups',
            'lexmark': 'printer',
            'xerox': 'printer',
            'samsung': 'camera',
            'zebra': 'label_printer',
            'brother': 'printer',
            'bluecat': 'server'
        }

        if vendor in vendor_device_map:
            return vendor_device_map[vendor]

        # IP-based heuristics (last resort)
        if ip and (ip.endswith('.1') or ip.endswith('.254')):
            return 'router'

        return 'unknown'

    def calculate_confidence(self, device_info: Dict, enhanced_vendor: str, device_type: str) -> int:
        """Calculate enhanced confidence score"""
        base_confidence = device_info.get('confidence_score', 50)
        sys_descr = device_info.get('sys_descr', '')

        confidence = base_confidence

        # Vendor identification boost
        if enhanced_vendor != 'unknown':
            confidence += 20

        # High-quality vendor boost
        quality_vendors = ['cisco', 'arista', 'palo_alto', 'palo_alto_sdwan', 'juniper', 'fortinet', 'aruba']
        if enhanced_vendor in quality_vendors:
            confidence += 10

        # Device type identification boost
        if device_type != 'unknown':
            confidence += 15

        # Network infrastructure boost
        network_types = ['router', 'switch', 'firewall', 'sdwan', 'load_balancer']
        if device_type in network_types:
            confidence += 10

        # System description quality boost
        if len(sys_descr) > 50:
            confidence += 10
        elif len(sys_descr) > 20:
            confidence += 5

        # Specific pattern boosts
        if re.search(r'version\s+\d+\.\d+', sys_descr, re.IGNORECASE):
            confidence += 10
        if re.search(r'software\s+\([^)]+\)', sys_descr, re.IGNORECASE):
            confidence += 10
        if re.search(r'copyright', sys_descr, re.IGNORECASE):
            confidence += 5

        # Detection method boost
        detection_method = device_info.get('detection_method', '')
        if detection_method == 'snmp':
            confidence += 10
        elif detection_method == 'ssh':
            confidence += 15

        return min(confidence, 100)

    def normalize_sys_descr(self, sys_descr: str) -> str:
        """Normalize system description for grouping similar devices"""
        if not sys_descr:
            return ''

        normalized = sys_descr

        # Remove specific version numbers but keep major.minor
        normalized = re.sub(r'Version\s+(\d+\.\d+)\.\d+[\.\d]*', r'Version \1.x', normalized, flags=re.IGNORECASE)
        normalized = re.sub(r'(\d+\.\d+)\.\d+[\.\d]*', r'\1.x', normalized)

        # Remove build dates and compilation info
        normalized = re.sub(r'\b\d{4}-\d{2}-\d{2}\b', '[DATE]', normalized)
        normalized = re.sub(r'Compiled\s+\w+\s+\d+.*', '[BUILD_INFO]', normalized, flags=re.IGNORECASE)

        # Remove serial numbers and specific IDs
        normalized = re.sub(r'\b[A-Z0-9]{8,}\b', '[ID]', normalized)

        return normalized.strip()

    def is_napalm_supported(self, vendor: str, device_type: str) -> bool:
        """Check if device is supported by NAPALM"""

        # Debug logging
        print(f"DEBUG: Checking NAPALM support for vendor='{vendor}', type='{device_type}'")

        # Normalize inputs
        vendor = str(vendor).lower().strip()
        device_type = str(device_type).lower().strip()

        # NAPALM supported vendors (updated list)
        napalm_vendors = [
            'cisco', 'arista', 'juniper', 'fortinet',
            'palo_alto', 'palo_alto_sdwan',  # Add your custom vendor names
            'dell', 'extreme', 'vyos', 'hp', 'hpe',
            'eos',  # Arista EOS
            'nxos',  # Cisco NX-OS
            'ios'  # Cisco IOS
        ]

        # NAPALM supported device types (broader list)
        napalm_device_types = [
            'router', 'switch', 'firewall', 'load_balancer',
            'sdwan', 'wireless_controller'  # Some wireless controllers are supported
        ]

        # Check vendor support
        vendor_supported = any(v in vendor for v in napalm_vendors)

        # Check device type support
        type_supported = any(dt in device_type for dt in napalm_device_types)

        # Special cases
        if vendor == 'palo_alto' and device_type == 'firewall':
            print(f"DEBUG: Palo Alto firewall - NAPALM supported")
            return True

        if vendor == 'cisco' and device_type in ['router', 'switch']:
            print(f"DEBUG: Cisco {device_type} - NAPALM supported")
            return True

        if vendor == 'arista' and device_type == 'switch':
            print(f"DEBUG: Arista switch - NAPALM supported")
            return True

        result = vendor_supported and type_supported
        print(f"DEBUG: vendor_supported={vendor_supported}, type_supported={type_supported}, result={result}")

        return result

    def analyze_scan_file(self, scan_file_path: str) -> Dict:
        """Analyze scan file and return device signatures"""
        logger.info(f"Analyzing scan file: {scan_file_path}")

        with open(scan_file_path, 'r', encoding='utf-8') as f:
            scan_data = json.load(f)

        devices = scan_data.get('devices', {})
        logger.info(f"Found {len(devices)} total devices")

        # Group devices by normalized system description
        sys_descr_groups = defaultdict(list)

        for device_id, device_info in devices.items():
            sys_descr = device_info.get('sys_descr', '').strip()

            # Skip devices without system description
            if not sys_descr or sys_descr.lower() in ['', 'unknown', 'none']:
                continue

            # Normalize and group
            normalized = self.normalize_sys_descr(sys_descr)
            sys_descr_groups[normalized].append({
                'device_id': device_id,
                'device_info': device_info,
                'original_sys_descr': sys_descr
            })

        logger.info(f"Grouped into {len(sys_descr_groups)} unique device signatures")

        # Analyze each group
        signatures = {}

        for normalized_descr, device_group in sys_descr_groups.items():
            # Use first device as representative
            representative = device_group[0]
            device_info = representative['device_info']

            # Enhanced analysis
            enhanced_vendor = self.enhance_vendor_detection(device_info)
            device_type = self.determine_device_type(
                enhanced_vendor,
                representative['original_sys_descr'],
                device_info.get('primary_ip', '')
            )
            enhanced_confidence = self.calculate_confidence(
                device_info, enhanced_vendor, device_type
            )

            # Check if NAPALM supported
            napalm_supported = self.is_napalm_supported(enhanced_vendor, device_type)

            signature = {
                'sys_descr': representative['original_sys_descr'] or '',
                'normalized_sys_descr': normalized_descr or '',
                'count': len(device_group),
                'original_vendor': device_info.get('vendor', 'unknown') or 'unknown',
                'enhanced_vendor': enhanced_vendor or 'unknown',
                'device_type': device_type or 'unknown',
                'original_confidence': device_info.get('confidence_score', 50) or 50,
                'enhanced_confidence': enhanced_confidence or 50,
                'napalm_supported': bool(napalm_supported),
                'detection_method': device_info.get('detection_method', 'unknown') or 'unknown',
                'sample_ips': [d['device_info'].get('primary_ip', '') for d in device_group[:5] if
                               d['device_info'].get('primary_ip')]
            }

            signatures[normalized_descr] = signature

        # Extract scan metadata
        scan_metadata = scan_data.get('scan_metadata', {})

        return {
            'scan_file': scan_file_path,
            'scan_metadata': scan_metadata,
            'total_devices': len(devices),
            'unique_signatures': len(signatures),
            'signatures': signatures,
            'analysis_timestamp': datetime.now().isoformat()
        }


def get_scan_files():
    """Get list of scan files with metadata"""
    scan_files = []

    if not os.path.exists(SCANS_FOLDER):
        return scan_files

    for filename in os.listdir(SCANS_FOLDER):
        if filename.endswith('.json'):
            filepath = os.path.join(SCANS_FOLDER, filename)
            try:
                # Get file stats
                stat = os.stat(filepath)

                # Try to read basic metadata from file
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                devices_count = len(data.get('devices', {}))
                scan_metadata = data.get('scan_metadata', {})

                scan_files.append({
                    'filename': filename,
                    'filepath': filepath,
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime),
                    'devices_count': devices_count,
                    'scan_metadata': scan_metadata
                })

            except Exception as e:
                logger.error(f"Error reading scan file {filename}: {e}")
                continue

    # Sort by modification date (newest first)
    scan_files.sort(key=lambda x: x['modified'], reverse=True)
    return scan_files


@reports_bp.route('/')
def index():
    """Reports index page - list scan files"""
    try:
        scan_files = get_scan_files()
        logger.info(f"Found {len(scan_files)} scan files")
        logger.info(f"Template should be at: templates/reports/index.html")

        # Test if template exists
        from flask import current_app
        template_path = os.path.join(current_app.root_path, 'templates', 'reports', 'index.html')
        logger.info(f"Looking for template at: {template_path}")
        logger.info(f"Template exists: {os.path.exists(template_path)}")

        return render_template('reports/index.html', scan_files=scan_files)
    except Exception as e:
        logger.error(f"Error in reports index: {e}")
        import traceback
        logger.error(traceback.format_exc())

        # Return a simple HTML response if template fails
        return f"""
        <h1>Reports Debug</h1>
        <p>Error: {str(e)}</p>
        <p>Found {len(get_scan_files()) if 'get_scan_files' in locals() else 0} scan files</p>
        <p>Please check that templates/reports/index.html exists</p>
        """


@reports_bp.route('/analyze/<filename>')
def analyze_scan(filename):
    """Analyze a specific scan file"""
    try:
        # Validate filename
        if not filename.endswith('.json'):
            flash('Invalid file type', 'error')
            return redirect(url_for('reports.index'))

        filepath = os.path.join(SCANS_FOLDER, filename)
        if not os.path.exists(filepath):
            flash('Scan file not found', 'error')
            return redirect(url_for('reports.index'))

        # Analyze the scan file
        analyzer = DeviceAnalyzer()
        analysis_results = analyzer.analyze_scan_file(filepath)

        # Calculate summary statistics for template
        signatures = analysis_results['signatures']
        vendor_counts = {}
        device_type_counts = {}

        for sig_key, sig_data in signatures.items():
            vendor = sig_data.get('enhanced_vendor', 'unknown')
            device_type = sig_data.get('device_type', 'unknown')
            count = sig_data.get('count', 0)

            vendor_counts[vendor] = vendor_counts.get(vendor, 0) + count
            device_type_counts[device_type] = device_type_counts.get(device_type, 0) + count

        # Add calculated stats to analysis results
        analysis_results['vendor_counts'] = vendor_counts
        analysis_results['device_type_counts'] = device_type_counts

        # Clean the data to ensure JSON serialization works
        def clean_for_json(obj):
            """Clean object to ensure JSON serialization, handling Jinja2 Undefined objects"""
            from jinja2 import Undefined

            if obj is None or isinstance(obj, Undefined):
                return ''
            elif isinstance(obj, (str, int, float, bool)):
                return obj
            elif isinstance(obj, dict):
                return {k: clean_for_json(v) for k, v in obj.items() if not isinstance(v, Undefined)}
            elif isinstance(obj, list):
                return [clean_for_json(item) for item in obj if not isinstance(item, Undefined)]
            else:
                return str(obj)

        # Clean the analysis results
        analysis_results = clean_for_json(analysis_results)
        vendor_counts = clean_for_json(vendor_counts)
        device_type_counts = clean_for_json(device_type_counts)

        # Debug logging
        logger.info(f"Analysis results keys: {list(analysis_results.keys())}")
        logger.info(f"Vendor counts: {vendor_counts}")
        logger.info(f"Device type counts: {device_type_counts}")
        logger.info(
            f"First signature sample: {list(analysis_results['signatures'].items())[:1] if analysis_results.get('signatures') else 'None'}")

        # Additional JSON serialization test with detailed error checking
        try:
            import json
            json.dumps(analysis_results)
            logger.info("Analysis results are JSON serializable")
        except Exception as json_error:
            logger.error(f"JSON serialization test failed: {json_error}")
            # Try to identify the problematic data
            for key, value in analysis_results.items():
                try:
                    json.dumps(value)
                except Exception as e:
                    logger.error(f"Problem with analysis key '{key}': {e}")
                    # Try to clean this specific field more aggressively
                    if key == 'signatures':
                        logger.info("Cleaning signatures data more aggressively...")
                        cleaned_signatures = {}
                        for sig_key, sig_data in value.items():
                            try:
                                cleaned_sig = clean_for_json(sig_data)
                                json.dumps(cleaned_sig)  # Test if this signature is serializable
                                cleaned_signatures[sig_key] = cleaned_sig
                            except Exception as sig_error:
                                logger.error(f"Problem with signature '{sig_key}': {sig_error}")
                                # Skip this signature or provide minimal data
                                cleaned_signatures[sig_key] = {
                                    'enhanced_vendor': 'unknown',
                                    'device_type': 'unknown',
                                    'count': 0,
                                    'enhanced_confidence': 0,
                                    'napalm_supported': False,
                                    'sys_descr': 'Error processing signature',
                                    'sample_ips': []
                                }
                        analysis_results[key] = cleaned_signatures

        # Test again after cleaning
        try:
            json.dumps(analysis_results)
            logger.info("Analysis results are now JSON serializable after cleaning")
        except Exception as json_error:
            logger.error(f"Still can't serialize after cleaning: {json_error}")
            # Create minimal fallback data
            analysis_results = {
                'scan_file': filepath,
                'total_devices': 0,
                'unique_signatures': 0,
                'signatures': {},
                'vendor_counts': {},
                'device_type_counts': {},
                'analysis_timestamp': datetime.now().isoformat()
            }

        try:
            json.dumps(vendor_counts)
            logger.info("Vendor counts are JSON serializable")
        except Exception as json_error:
            logger.error(f"Vendor counts JSON error: {json_error}")

        try:
            json.dumps(device_type_counts)
            logger.info("Device type counts are JSON serializable")
        except Exception as json_error:
            logger.error(f"Device type counts JSON error: {json_error}")

        return render_template('reports/analysis.html',
                               analysis=analysis_results,
                               filename=filename,
                               vendor_counts=vendor_counts,
                               device_type_counts=device_type_counts)

    except Exception as e:
        logger.error(f"Error analyzing scan file {filename}: {e}")
        import traceback
        logger.error(traceback.format_exc())
        flash(f'Error analyzing scan file: {str(e)}', 'error')
        return redirect(url_for('reports.index'))


@reports_bp.route('/api/analyze/<filename>')
def api_analyze_scan(filename):
    """API endpoint to analyze scan file"""
    try:
        filepath = os.path.join(SCANS_FOLDER, filename)
        if not os.path.exists(filepath):
            return jsonify({'error': 'File not found'}), 404

        analyzer = DeviceAnalyzer()
        analysis_results = analyzer.analyze_scan_file(filepath)

        return jsonify(analysis_results)

    except Exception as e:
        logger.error(f"API error analyzing {filename}: {e}")
        return jsonify({'error': str(e)}), 500


@reports_bp.route('/download/<filename>')
def download_report(filename):
    """Download analysis report as text file"""
    try:
        filepath = os.path.join(SCANS_FOLDER, filename)
        if not os.path.exists(filepath):
            flash('Scan file not found', 'error')
            return redirect(url_for('reports.index'))

        # Analyze the scan file
        analyzer = DeviceAnalyzer()
        analysis_results = analyzer.analyze_scan_file(filepath)

        # Generate text report
        report_text = generate_text_report(analysis_results)

        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            f.write(report_text)
            temp_path = f.name

        # Generate download filename
        base_name = os.path.splitext(filename)[0]
        download_filename = f"{base_name}_analysis_report.txt"

        return send_file(temp_path, as_attachment=True, download_name=download_filename,
                         mimetype='text/plain')

    except Exception as e:
        logger.error(f"Error generating report for {filename}: {e}")
        flash(f'Error generating report: {str(e)}', 'error')
        return redirect(url_for('reports.index'))


def generate_text_report(analysis_results: Dict) -> str:
    """Generate comprehensive analysis report text"""
    signatures = analysis_results['signatures']

    # Sort signatures by enhanced confidence and count
    sorted_signatures = sorted(
        signatures.items(),
        key=lambda x: (x[1]['enhanced_confidence'], x[1]['count']),
        reverse=True
    )

    lines = []
    lines.append("NETWORK DISCOVERY ANALYSIS REPORT")
    lines.append("=" * 80)
    lines.append(f"Analysis Date: {analysis_results['analysis_timestamp']}")
    lines.append(f"Scan File: {analysis_results['scan_file']}")
    lines.append(f"Total Devices: {analysis_results['total_devices']:,}")
    lines.append(f"Unique Device Signatures: {analysis_results['unique_signatures']:,}")
    lines.append("")

    # Add scan metadata if available
    scan_metadata = analysis_results.get('scan_metadata', {})
    if scan_metadata:
        lines.append("SCAN METADATA")
        lines.append("-" * 40)
        for key, value in scan_metadata.items():
            lines.append(f"{key}: {value}")
        lines.append("")

    # Calculate summary statistics
    vendor_counts = Counter()
    device_type_counts = Counter()
    high_confidence_count = 0
    napalm_supported_count = 0

    for sig_key, sig_data in signatures.items():
        vendor_counts[sig_data['enhanced_vendor']] += sig_data['count']
        device_type_counts[sig_data['device_type']] += sig_data['count']

        if sig_data['enhanced_confidence'] >= 80:
            high_confidence_count += sig_data['count']
        if sig_data['napalm_supported']:
            napalm_supported_count += sig_data['count']

    lines.append("SUMMARY STATISTICS")
    lines.append("-" * 40)
    lines.append(f"High Confidence Devices (>=80%): {high_confidence_count:,}")
    lines.append(f"NAPALM Supported Devices: {napalm_supported_count:,}")
    lines.append(
        f"Network Infrastructure: {sum(device_type_counts[dt] for dt in ['router', 'switch', 'firewall', 'sdwan', 'load_balancer']):,}")
    lines.append("")

    lines.append("VENDOR DISTRIBUTION")
    lines.append("-" * 40)
    for vendor, count in vendor_counts.most_common(15):
        percentage = (count / analysis_results['total_devices']) * 100
        lines.append(f"{vendor:<20}: {count:>5,} devices ({percentage:>5.1f}%)")
    lines.append("")

    lines.append("DEVICE TYPE DISTRIBUTION")
    lines.append("-" * 40)
    for device_type, count in device_type_counts.most_common(15):
        percentage = (count / analysis_results['total_devices']) * 100
        lines.append(f"{device_type:<20}: {count:>5,} devices ({percentage:>5.1f}%)")
    lines.append("")

    lines.append("TOP DEVICE DISCOVERIES")
    lines.append("=" * 90)
    lines.append(f"{'#':<3} {'Vendor':<15} {'Type':<15} {'Count':<7} {'Conf':<6} {'NAPALM':<6} {'Sample IPs'}")
    lines.append("-" * 90)

    for i, (sig_key, sig_data) in enumerate(sorted_signatures[:20], 1):
        vendor = sig_data['enhanced_vendor'][:14]
        device_type = sig_data['device_type'][:14]
        count = f"{sig_data['count']:,}"
        confidence = f"{sig_data['enhanced_confidence']}%"
        napalm = "Yes" if sig_data['napalm_supported'] else "No"
        sample_ips = ", ".join(sig_data['sample_ips'][:2])

        lines.append(f"{i:<3} {vendor:<15} {device_type:<15} {count:<7} {confidence:<6} {napalm:<6} {sample_ips}")

    lines.append("")
    lines.append("DETAILED DEVICE SIGNATURES")
    lines.append("=" * 80)

    for i, (sig_key, sig_data) in enumerate(sorted_signatures[:10], 1):
        lines.append(f"\n[{i}] {sig_data['enhanced_vendor'].upper()} - {sig_data['device_type'].upper()}")
        lines.append(f"    Device Count: {sig_data['count']:,}")
        lines.append(f"    Confidence: {sig_data['original_confidence']}% -> {sig_data['enhanced_confidence']}%")
        lines.append(f"    NAPALM Support: {'Yes' if sig_data['napalm_supported'] else 'No'}")
        lines.append(f"    Detection Method: {sig_data['detection_method']}")
        lines.append(f"    Sample IPs: {', '.join(sig_data['sample_ips'])}")
        lines.append(f"    System Description:")
        lines.append(f"        {sig_data['sys_descr']}")

    return '\n'.join(lines)


@reports_bp.route('/compare')
def compare_scans():
    """Compare multiple scan files"""
    return render_template('reports/compare.html')


@reports_bp.route('/summary')
def summary():
    """Summary of all scan files"""
    try:
        scan_files = get_scan_files()

        summary_data = {
            'total_scans': len(scan_files),
            'total_devices': sum(f['devices_count'] for f in scan_files),
            'latest_scan': scan_files[0] if scan_files else None,
            'scan_files': scan_files[:10]  # Latest 10 scans
        }

        return render_template('reports/summary.html', summary=summary_data)

    except Exception as e:
        logger.error(f"Error in summary: {e}")
        flash(f'Error generating summary: {str(e)}', 'error')
        return redirect(url_for('reports.index'))