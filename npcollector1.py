#!/usr/bin/env python3
"""
Concurrent NAPALM Device Collector with Enhanced Inventory and Runtime Tracking
Collects configuration, inventory, and version information from network devices
"""

import json
import yaml
import os
import logging
import argparse
import time
import re
from datetime import datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any
import napalm
from napalm.base.exceptions import ConnectionException, CommandErrorException


class CollectionStats:
    """Track collection statistics and timing"""

    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.device_times = {}
        self.collection_results = []
        self.error_summary = {}

    def start_collection(self):
        """Mark collection start time"""
        self.start_time = datetime.now()

    def end_collection(self):
        """Mark collection end time"""
        self.end_time = datetime.now()

    def start_device_collection(self, device_ip: str):
        """Mark start time for individual device"""
        self.device_times[device_ip] = {'start': datetime.now()}

    def end_device_collection(self, device_ip: str):
        """Mark end time for individual device"""
        if device_ip in self.device_times:
            self.device_times[device_ip]['end'] = datetime.now()
            self.device_times[device_ip]['duration'] = (
                    self.device_times[device_ip]['end'] -
                    self.device_times[device_ip]['start']
            ).total_seconds()

    def add_result(self, result: Dict):
        """Add a collection result"""
        self.collection_results.append(result)

    def get_total_runtime(self) -> float:
        """Get total collection runtime in seconds"""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0

    def get_average_device_time(self) -> float:
        """Get average time per device"""
        times = [d['duration'] for d in self.device_times.values() if 'duration' in d]
        return sum(times) / len(times) if times else 0



class DeviceCollector:
    """Main collector class for NAPALM-based device data collection"""

    def __init__(self, config_file: str = "collector_config.yaml", max_workers: int = 10):
        self.config_file = config_file
        self.max_workers = max_workers
        self.config = self._load_config()
        self.capture_dir = Path(self.config.get('capture_directory', 'captures'))
        self.setup_logging()

        # Initialize statistics tracking
        self.stats = CollectionStats()


        # Create capture directory if it doesn't exist
        self.capture_dir.mkdir(exist_ok=True)

        # NAPALM driver mapping for different vendors
        self.driver_mapping = {
            'cisco': 'ios',
            'arista': 'eos',
            'paloalto': 'panos',
            'hp': 'procurve',
            'aruba': 'arubaos',
            'fortinet': 'fortios',
            'juniper': 'junos'
        }

    def _load_config(self) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(self.config_file, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logging.error(f"Config file {self.config_file} not found. Creating template...")
            self._create_config_template()
            raise

    def _create_config_template(self):
        """Create a template configuration file"""
        template_config = {
            'capture_directory': 'captures',
            'timeout': 60,
            'max_workers': 10,
            'enhanced_inventory': True,
            'inventory_cli_fallback': True,
            'inventory_parsing': True,
            'detailed_timing': True,
            'performance_metrics': True,
            'credentials': [
                {
                    'name': 'primary',
                    'username': 'admin',
                    'password': 'password123',
                    'enable_password': '',
                    'priority': 1
                }
            ],
            'collection_methods': {
                'get_config': True,
                'get_facts': True,
                'get_inventory': True,
                'get_interfaces': True,
                'get_interfaces_ip': True,
                'get_arp_table': True,
                'get_mac_address_table': True,
                'get_lldp_neighbors': True,
                'get_environment': True,
                'get_users': True,
                'get_optics': True,  # NEW: Add optics collection
                'get_network_instances': True  # NEW: Add network instances collection
            },
            'vendor_overrides': {
                'hp_procurve': 'procurve',
                'hp_aruba_cx': 'arubaos',
                'cisco_ios': 'ios',
                'cisco_nxos': 'nxos',
                'cisco_asa': 'asa'
            },
            'vendor_cli_commands': {
                'cisco': {
                    'ios': ['show inventory', 'show version', 'show module'],
                    'nxos': ['show inventory', 'show version', 'show module'],
                    'asa': ['show inventory', 'show version']
                },
                'arista': {
                    'eos': ['show inventory', 'show version detail']
                },
                'juniper': {
                    'junos': ['show chassis hardware', 'show version']
                }
            }
        }

        with open(self.config_file, 'w') as f:
            yaml.dump(template_config, f, default_flow_style=False, indent=2)
        print(f"Created template config file: {self.config_file}")

    def setup_logging(self):
        """Setup logging configuration"""
        log_level = self.config.get('log_level', 'INFO')
        logging.basicConfig(
            level=getattr(logging, log_level),
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('collector.log'),
                logging.StreamHandler()
            ]
        )

    def get_napalm_driver(self, device: Dict) -> Optional[str]:
        """Determine the appropriate NAPALM driver for a device"""
        vendor = device.get('vendor', '').lower()
        device_type = device.get('device_type', '').lower()

        # Check vendor overrides first
        vendor_overrides = self.config.get('vendor_overrides', {})
        for override_key, driver in vendor_overrides.items():
            if override_key.lower() in f"{vendor}_{device_type}":
                return driver

        # Check sys_descr for more specific identification
        sys_descr = device.get('sys_descr', '').lower()

        # Cisco specific logic
        if vendor == 'cisco':
            if 'nx-os' in sys_descr or 'nexus' in sys_descr:
                return 'nxos'
            elif 'asa' in sys_descr:
                return 'asa'
            elif 'xe' in sys_descr or 'ios' in sys_descr:
                return 'ios'

        # HP/Aruba logic
        elif vendor == 'hp' or vendor == 'aruba':
            if 'procurve' in sys_descr or 'j' in device.get('sys_name', '').lower():
                return 'procurve'
            elif 'arubaos' in sys_descr or 'cx' in sys_descr:
                return 'arubaos'

        # Default mapping
        return self.driver_mapping.get(vendor)

    def insert_hardware_inventory(self, device_id: int, run_id: int, hardware_data: Dict):
        """Insert hardware inventory data including optics"""
        cursor = self.connection.cursor()

        # Process optical transceivers from get_optics data
        if 'optics' in hardware_data:
            for interface_name, optics_info in hardware_data['optics'].items():
                # Extract optical metrics from the nested structure
                physical_channels = optics_info.get('physical_channels', {})
                channels = physical_channels.get('channel', [])

                if channels:
                    channel_data = channels[0]  # Most interfaces have single channel
                    state = channel_data.get('state', {})

                    # Extract power and current measurements
                    input_power = state.get('input_power', {})
                    output_power = state.get('output_power', {})
                    laser_bias = state.get('laser_bias_current', {})

                    # Create comprehensive optics data
                    optics_metrics = {
                        'input_power_dbm': input_power.get('instant'),
                        'output_power_dbm': output_power.get('instant'),
                        'laser_bias_current_ma': laser_bias.get('instant'),
                        'interface_name': interface_name
                    }

                    # Determine transceiver status based on power levels
                    status = 'operational'
                    if input_power.get('instant', 0) < -30:  # Very low input power
                        status = 'failed'
                    elif input_power.get('instant', 0) < -20:  # Low input power
                        status = 'unknown'

                    # Insert as transceiver component
                    cursor.execute("""
                        INSERT INTO hardware_inventory (
                            device_id, collection_run_id, component_type, slot_position,
                            description, status, additional_data
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        device_id, run_id, 'transceiver', interface_name,
                        f"Optical transceiver for {interface_name}",
                        status,
                        json.dumps(optics_metrics)
                    ))

        # Process power supplies from environment data
        if 'power_supplies' in hardware_data:
            for psu_name, psu_info in hardware_data['power_supplies'].items():
                cursor.execute("""
                    INSERT INTO hardware_inventory (
                        device_id, collection_run_id, component_type, slot_position,
                        part_number, serial_number, description, status,
                        vendor, model, additional_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    device_id, run_id, 'psu', psu_name,
                    psu_info.get('part_number'),
                    psu_info.get('serial_number'),
                    psu_info.get('description'),
                    'operational' if psu_info.get('status') == 'ok' else 'failed',
                    psu_info.get('vendor'),
                    psu_info.get('model'),
                    json.dumps(psu_info)
                ))

        # Process fans from environment data
        if 'fans' in hardware_data:
            for fan_name, fan_info in hardware_data['fans'].items():
                cursor.execute("""
                    INSERT INTO hardware_inventory (
                        device_id, collection_run_id, component_type, slot_position,
                        description, status, additional_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    device_id, run_id, 'fan', fan_name,
                    fan_info.get('description'),
                    'operational' if fan_info.get('status') == 'ok' else 'failed',
                    json.dumps(fan_info)
                ))

        self.connection.commit()

    def get_hardware_inventory(self, device_name: str = None) -> List[Dict]:
        """Get complete hardware inventory including optics"""
        cursor = self.connection.cursor()

        base_query = """
            SELECT 
                d.device_name,
                d.site_code,
                hi.component_type,
                hi.slot_position,
                hi.part_number,
                hi.serial_number,
                hi.description,
                hi.firmware_version,
                hi.hardware_version,
                hi.status,
                hi.vendor,
                hi.model,
                hi.additional_data,
                cr.collection_time,
                ROW_NUMBER() OVER (PARTITION BY d.id, hi.component_type, hi.slot_position ORDER BY cr.collection_time DESC) as rn
            FROM hardware_inventory hi
            JOIN devices d ON hi.device_id = d.id
            JOIN collection_runs cr ON hi.collection_run_id = cr.id
        """

        if device_name:
            cursor.execute(base_query + " WHERE d.device_name = ?", (device_name,))
        else:
            cursor.execute(base_query)

        results = []
        for row in cursor.fetchall():
            if row['rn'] == 1:  # Only latest data per component
                row_dict = dict(row)
                # For transceivers, add optics data to the display
                if row['component_type'] == 'transceiver' and row['additional_data']:
                    try:
                        metrics = json.loads(row['additional_data'])
                        # Add key optics metrics to the main record
                        row_dict['input_power'] = metrics.get('input_power_dbm')
                        row_dict['output_power'] = metrics.get('output_power_dbm')
                        row_dict['laser_bias'] = metrics.get('laser_bias_current_ma')
                    except json.JSONDecodeError:
                        pass
                results.append(row_dict)

        return results

    def collect_device_data(self, device: Dict, credentials: List[Dict]) -> Dict:
        """Collect data from a single device using NAPALM with enhanced inventory"""
        device_ip = device['primary_ip']

        # Start with IP as temporary name
        temp_device_name = device_ip

        # Start timing for this device
        self.stats.start_device_collection(device_ip)

        result = {
            'device_ip': device_ip,
            'device_name': temp_device_name,  # Will be updated after get_facts
            'success': False,
            'data': {},
            'errors': [],
            'credential_used': None,
            'collection_time': datetime.now().isoformat(),
            'collection_duration': 0,
            'methods_collected': [],
            'methods_failed': []
        }

        # Determine NAPALM driver
        napalm_driver = self.get_napalm_driver(device)
        if not napalm_driver:
            result['errors'].append(f"No NAPALM driver found for vendor: {device.get('vendor', 'unknown')}")
            return result

        logging.info(f"Collecting data from {device_ip} using driver: {napalm_driver}")

        # Try each credential set
        for cred in sorted(credentials, key=lambda x: x.get('priority', 999)):
            try:
                # Setup device connection parameters
                device_params = {
                    'hostname': device_ip,
                    'username': cred['username'],
                    'password': cred['password'],
                    'timeout': self.config.get('timeout', 60),
                    'optional_args': {}
                }

                # Add enable password if provided
                if cred.get('enable_password'):
                    device_params['optional_args']['secret'] = cred['enable_password']

                # **FIX: Force SSH transport for Arista EOS devices**
                if napalm_driver == 'eos':
                    device_params['optional_args']['transport'] = 'ssh'
                    logging.info(f"Using SSH transport for Arista device {device_ip}")

                # Apply driver-specific options from config
                driver_options = self.config.get('driver_options', {})
                if napalm_driver in driver_options:
                    device_params['optional_args'].update(driver_options[napalm_driver])

                # Initialize NAPALM driver
                driver = napalm.get_network_driver(napalm_driver)
                device_conn = driver(**device_params)

                # Connect to device
                device_conn.open()
                logging.info(f"Successfully connected to {device_ip} with credentials: {cred['name']}")

                # Collect data based on configuration
                collection_methods = self.config.get('collection_methods', {})
                method_timeouts = self.config.get('method_timeouts', {})

                # Prioritize get_facts to get hostname first
                methods_to_collect = []
                if collection_methods.get('get_facts', False):
                    methods_to_collect.append('get_facts')

                # Add other methods
                for method_name, enabled in collection_methods.items():
                    if enabled and method_name != 'get_facts':
                        methods_to_collect.append(method_name)

                print(f"collecting methods: {methods_to_collect}")

                # Actually collect the data for each method
                for method_name in methods_to_collect:
                    method_start_time = time.time()
                    try:
                        logging.info(f"Collecting {method_name} from {device_ip}")

                        # Handle special collection methods
                        if method_name == 'get_inventory' and self.config.get('enhanced_inventory', False):
                            # Use enhanced inventory collection
                            method_data = self.inventory_collector.collect_comprehensive_inventory(
                                device_conn, device_ip,
                                device.get('vendor', 'unknown'),
                                napalm_driver
                            )
                        else:
                            # Standard NAPALM method collection
                            method_func = getattr(device_conn, method_name, None)
                            if method_func:
                                method_data = method_func()
                            else:
                                raise AttributeError(f"Method {method_name} not available for driver {napalm_driver}")

                        # Calculate method timing and data size
                        method_duration = time.time() - method_start_time
                        data_size = len(json.dumps(method_data, default=str)) if method_data else 0

                        result['data'][method_name] = method_data
                        result['methods_collected'].append({
                            'method': method_name,
                            'duration': method_duration,
                            'data_size': data_size,
                            'success': True
                        })

                        # **FIX: Update device name after collecting facts**
                        if method_name == 'get_facts' and method_data:
                            # Get hostname from facts and clean it
                            hostname = method_data.get('hostname', method_data.get('fqdn', device_ip))
                            if hostname and hostname != device_ip:
                                clean_hostname = self._clean_device_name(hostname)
                                result['device_name'] = clean_hostname
                                logging.info(f"Updated device name from facts: {device_ip} -> {clean_hostname}")

                        logging.info(f"Successfully collected {method_name} from {device_ip} in {method_duration:.2f}s")

                    except Exception as method_error:
                        method_duration = time.time() - method_start_time
                        error_msg = f"Failed to collect {method_name}: {str(method_error)}"

                        result['methods_failed'].append({
                            'method': method_name,
                            'duration': method_duration,
                            'error': str(method_error),
                            'success': False
                        })

                        logging.warning(f"Failed to collect {method_name} from {device_ip}: {str(method_error)}")

                        # Continue with other methods even if one fails
                        continue

                # Close connection
                device_conn.close()

                result['success'] = True
                result['credential_used'] = cred['name']
                break

            except (ConnectionException, CommandErrorException) as e:
                logging.warning(f"Failed to connect to {device_ip} with credentials {cred['name']}: {str(e)}")
                result['errors'].append(f"Credential {cred['name']}: {str(e)}")
                continue
            except Exception as e:
                logging.error(f"Unexpected error connecting to {device_ip}: {str(e)}")
                result['errors'].append(f"Unexpected error: {str(e)}")
                continue

        # End timing for this device
        self.stats.end_device_collection(device_ip)
        if device_ip in self.stats.device_times:
            result['collection_duration'] = self.stats.device_times[device_ip].get('duration', 0)

        return result

    def _clean_device_name(self, device_name: str) -> str:
        """Clean device name by removing domain and making filesystem-safe"""
        if not device_name:
            return "unknown_device"

        # Don't split IP addresses - only split actual hostnames with domains
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', device_name):
            # Strip domain name (everything after first dot) only if it's not an IP
            if '.' in device_name:
                device_name = device_name.split('.')[0]

        # Replace filesystem-unsafe characters
        unsafe_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|', ' ']
        for char in unsafe_chars:
            device_name = device_name.replace(char, '_')

        # Remove consecutive underscores and strip leading/trailing underscores
        while '__' in device_name:
            device_name = device_name.replace('__', '_')
        device_name = device_name.strip('_')

        # Ensure we have a valid name
        if not device_name:
            device_name = "unknown_device"

        return device_name
    def save_device_data(self, device_result: Dict):
        """Save collected device data to files"""
        if not device_result['success']:
            logging.error(f"Skipping save for {device_result['device_ip']} - collection failed")
            return

        device_name = device_result['device_name']
        device_ip = device_result['device_ip']

        # Clean device name for filesystem safety
        safe_device_name = device_name.replace('/', '_').replace('\\', '_').replace(':', '_')

        device_dir = self.capture_dir / safe_device_name
        device_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save complete result as JSON
        result_file = device_dir / f"{safe_device_name}_complete.json"
        with open(result_file, 'w') as f:
            json.dump(device_result, f, indent=2, default=str)

        # Save individual data types as separate files
        for data_type, data in device_result['data'].items():
            if data_type == 'get_config':
                # Save configs as text files
                if isinstance(data, dict):
                    for config_type, config_content in data.items():
                        config_file = device_dir / f"{safe_device_name}_{config_type}_config.txt"
                        with open(config_file, 'w') as f:
                            f.write(config_content)
                else:
                    config_file = device_dir / f"{safe_device_name}_config.txt"
                    with open(config_file, 'w') as f:
                        f.write(str(data))

            else:
                # Save other data as JSON
                data_file = device_dir / f"{safe_device_name}_{data_type}.json"
                with open(data_file, 'w') as f:
                    json.dump(data, f, indent=2, default=str)

        logging.info(f"Saved data for {device_name} ({device_ip}) to {device_dir}")

    def generate_comprehensive_summary(self, results: List[Dict]):
        """Generate comprehensive collection summary with runtime statistics"""

        # Calculate summary statistics
        total_devices = len(results)
        successful = sum(1 for r in results if r['success'])
        failed = total_devices - successful

        # Vendor analysis
        vendors = {}
        device_types = {}
        credential_usage = {}
        error_analysis = {}
        method_statistics = {}

        for result in results:
            # Vendor statistics
            if result['success'] and 'get_facts' in result['data']:
                facts = result['data']['get_facts']
                vendor = facts.get('vendor', 'unknown')
                vendors[vendor] = vendors.get(vendor, 0) + 1

                # Device type statistics
                device_type = facts.get('model', 'unknown')
                device_types[device_type] = device_types.get(device_type, 0) + 1

            # Credential usage
            if result.get('credential_used'):
                cred = result['credential_used']
                credential_usage[cred] = credential_usage.get(cred, 0) + 1

            # Error analysis
            for error in result.get('errors', []):
                error_type = error.split(':')[0] if ':' in error else 'unknown'
                error_analysis[error_type] = error_analysis.get(error_type, 0) + 1

            # Method statistics
            for method_info in result.get('methods_collected', []):
                method_name = method_info['method']
                if method_name not in method_statistics:
                    method_statistics[method_name] = {
                        'success_count': 0,
                        'total_duration': 0,
                        'avg_duration': 0,
                        'total_data_size': 0
                    }
                method_statistics[method_name]['success_count'] += 1
                method_statistics[method_name]['total_duration'] += method_info['duration']
                method_statistics[method_name]['total_data_size'] += method_info['data_size']

        # Calculate averages
        for method_name, stats in method_statistics.items():
            if stats['success_count'] > 0:
                stats['avg_duration'] = stats['total_duration'] / stats['success_count']

        # Performance statistics
        device_times = [self.stats.device_times[ip].get('duration', 0)
                        for ip in self.stats.device_times.keys()]

        summary = {
            'collection_summary': {
                'start_time': self.stats.start_time.isoformat() if self.stats.start_time else None,
                'end_time': self.stats.end_time.isoformat() if self.stats.end_time else None,
                'total_runtime_seconds': self.stats.get_total_runtime(),
                'total_runtime_formatted': str(timedelta(seconds=int(self.stats.get_total_runtime()))),
                'devices_per_minute': (successful / (
                            self.stats.get_total_runtime() / 60)) if self.stats.get_total_runtime() > 0 else 0
            },
            'collection_results': {
                'total_devices': total_devices,
                'successful_collections': successful,
                'failed_collections': failed,
                'success_rate': (successful / total_devices * 100) if total_devices > 0 else 0
            },
            'performance_metrics': {
                'average_device_time': self.stats.get_average_device_time(),
                'fastest_device_time': min(device_times) if device_times else 0,
                'slowest_device_time': max(device_times) if device_times else 0,
                'concurrent_workers': self.max_workers
            },
            'vendor_breakdown': vendors,
            'device_types': device_types,
            'credential_usage': credential_usage,
            'error_analysis': error_analysis,
            'method_statistics': method_statistics,
            'configuration_used': {
                'max_workers': self.max_workers,
                'timeout': self.config.get('timeout', 60),
                'enhanced_inventory': self.config.get('enhanced_inventory', False),
                'collection_methods': self.config.get('collection_methods', {})
            }
        }

        # Save comprehensive summary
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        summary_file = self.capture_dir / f"collection_summary.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2, default=str)

        logging.info(f"Comprehensive summary saved to {summary_file}")

        return summary

    def filter_collectible_devices(self, devices: Dict) -> List[Dict]:
        """Filter devices that can be collected via NAPALM"""
        collectible_devices = []

        for device_id, device in devices.items():
            # Skip devices without vendor info or unknown device types
            if not device.get('vendor') or device.get('device_type') == 'unknown':
                logging.debug(f"Skipping {device['primary_ip']} - no vendor or unknown device type")
                continue

            # Skip non-network devices
            device_type = device.get('device_type', '').lower()
            if device_type in ['printer', 'ups', 'server', 'workstation']:
                logging.debug(f"Skipping {device['primary_ip']} - non-network device ({device_type})")
                continue

            # Check if we have a NAPALM driver for this device
            if self.get_napalm_driver(device):
                collectible_devices.append(device)
            else:
                logging.debug(f"Skipping {device['primary_ip']} - no NAPALM driver available")

        return collectible_devices

    def run_collection(self, scan_file: str):
        """Main collection runner with enhanced timing and inventory"""

        # Start collection timing
        self.stats.start_collection()

        logging.info(f"Starting collection from scan file: {scan_file}")

        # Load scan data
        with open(scan_file, 'r') as f:
            scan_data = json.load(f)

        devices = scan_data.get('devices', {})
        logging.info(f"Loaded {len(devices)} devices from scan file")

        # Filter collectible devices
        collectible_devices = self.filter_collectible_devices(devices)
        logging.info(f"Found {len(collectible_devices)} collectible network devices")

        if not collectible_devices:
            logging.warning("No collectible devices found")
            return

        # Load credentials
        credentials = self.config.get('credentials', [])
        if not credentials:
            logging.error("No credentials configured")
            return

        # Collect data concurrently
        results = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all collection tasks
            future_to_device = {
                executor.submit(self.collect_device_data, device, credentials): device
                for device in collectible_devices
            }

            # Process completed tasks
            for future in as_completed(future_to_device):
                device = future_to_device[future]
                try:
                    result = future.result()
                    results.append(result)
                    self.stats.add_result(result)
                    self.save_device_data(result)

                except Exception as e:
                    logging.error(f"Error processing device {device['primary_ip']}: {str(e)}")
                    # Create failed result entry
                    failed_result = {
                        'device_ip': device['primary_ip'],
                        'success': False,
                        'errors': [str(e)],
                        'collection_time': datetime.now().isoformat()
                    }
                    results.append(failed_result)
                    self.stats.add_result(failed_result)

        # End collection timing
        self.stats.end_collection()

        # Generate comprehensive summary
        summary = self.generate_comprehensive_summary(results)

        # Log final summary
        logging.info(f"Collection complete in {summary['collection_summary']['total_runtime_formatted']}")
        logging.info(f"Success: {summary['collection_results']['successful_collections']}, "
                     f"Failed: {summary['collection_results']['failed_collections']}")
        logging.info(f"Average time per device: {summary['performance_metrics']['average_device_time']:.2f}s")

        return summary


def main():
    parser = argparse.ArgumentParser(description='NAPALM Device Collector with Enhanced Inventory')
    parser.add_argument('scan_file', help='JSON scan file from SNMP scanner')
    parser.add_argument('--config', default='collector_config.yaml', help='Configuration file')
    parser.add_argument('--workers', type=int, default=10, help='Maximum concurrent workers')
    parser.add_argument('--create-config', action='store_true', help='Create template configuration file')

    args = parser.parse_args()

    if args.create_config:
        collector = DeviceCollector(args.config, args.workers)
        collector._create_config_template()
        return

    if not os.path.exists(args.scan_file):
        print(f"Error: Scan file {args.scan_file} not found")
        return

    try:
        collector = DeviceCollector(args.config, args.workers)
        collector.run_collection(args.scan_file)
    except Exception as e:
        print(f"Error: {str(e)}")


if __name__ == "__main__":
    main()