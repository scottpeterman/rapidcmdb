# RapidCMDB: Network Asset Discovery & CMDB Reconciliation

![RapidCMDB Dashboard](screenshots/slides1.gif)

RapidCMDB is a **Proof of Concept (POC)** demonstrating an innovative approach to rapidly gain deep insight into network environments that may lack an accurate Configuration Management Database (CMDB) through automated discovery and data collection. This project aims to transform weeks of manual asset auditing into hours of automated intelligence. While currently designed for **single-user deployment** as an early release, it offers highly useful capabilities for efficient network asset management and reconciliation.

## Overview

RapidCMDB provides a centralized, reliable, and scalable platform for managing multi-vendor network infrastructure data. It integrates specialized tools to discover, collect, and analyze network information, offering deep insights and actionable intelligence through an intuitive web interface.

## The Data Ingestion Pipeline

RapidCMDB implements a sophisticated, multi-stage data ingestion pipeline to populate and maintain its CMDB:

### 1. High-Speed Network Discovery (via `gosnmptk` scanner)

The initial phase begins with a highly optimized, low-impact network scanner built upon the Go-based `gosnmptk` SNMP toolkit.
* **Targeted Scanning**: The scanner performs rapid TCP scans of standard network device ports. Only on hosts that respond to this initial TCP scan does it proceed with more detailed SNMP fingerprinting. This focused approach ensures high speed and low network impact.
* **Extensible Fingerprinting**: Its intelligence is driven by a configurable `vendor_fingerprints.yaml` file. This YAML defines:
    * **Common and Generic OIDs**: Standard OIDs (e.g., `1.3.6.1.2.1.1.1.0` for system description) and generic fallbacks.
    * **Vendor-Specific Profiles**: Detailed profiles for numerous vendors (e.g., Cisco, Aruba, Palo Alto, Fortinet, Juniper, Dell, HP, Lexmark, Zebra, Rockwell, Eaton, APC, Samsung, VMware, BlueCat, F5, Check Point, Xerox), including specific `detection_patterns`, `oid_patterns`, and `exclusion_patterns` to accurately identify and differentiate devices. This allows for fine-grained classification, even distinguishing between similar vendors or device types (e.g., separating Cisco core devices from Cisco SD-WAN, or preventing Aruba APs from being misclassified as Palo Alto firewalls).
    * **Prioritized Fingerprint OIDs**: Specific OIDs are queried with assigned priorities to extract precise model, version, and serial number information for each detected vendor.
    * **Prioritized Detection Rules**: An explicit `priority_order` ensures that more specific or common vendors are identified first, optimizing the detection process.
* **Configurable Behavior**: The `vendor_fingerprints.yaml` also dictates scanning parameters such as `default_timeout`, `oid_query_timeout`, `delay_between_queries`, `max_concurrent_queries`, and `retry` settings for fine-tuning.
* **Output**: The scanner outputs its findings as structured JSON files (e.g., `scanner_usmd_devices.json`), which serve as the input for the subsequent stages.

### 2. Initial Scan Data Import and Deduplication (via `db_scan_import.py`)

The `db_scan_import.py` tool processes the raw SNMP discovery data from `gosnmptk` scans and imports it into the core SQLite CMDB.
* **Intelligent Device Parsing**: It extracts, cleans, and normalizes device data, generating a stable `device_key` (SHA256 hash of vendor|serial|model) for reliable identification. It includes logic for enhanced serial number and model extraction from system descriptions or SNMP data if initial values are missing.
* **Automated Site and Role Assignment**: The importer automatically extracts `site_code` from device hostnames or IP address ranges (e.g., `10.67.x.x` maps to `FRC`) and assigns a `device_role` (e.g., router, switch, firewall, UPS, printer, camera, server, wireless, load_balancer) based on internal mapping rules.
* **Deduplication & Updates**: It intelligently identifies existing devices using `device_key` or a combination of `serial_number` and `vendor` for deduplication. Existing device records are updated with the latest information, while new devices are inserted.
* **Filtering**: Supports optional filtering of devices by vendor, device type, site, and a minimum confidence score during import.
* **Dry-Run Mode**: Allows for a dry-run to preview import actions without modifying the database.
* **Result**: This stage populates the `devices` table in `napalm_cmdb.db`, establishing the initial inventory of discovered devices.

### 3. Detailed Data Collection (via `npcollector1.py`)

The `npcollector1.py` script is a concurrent NAPALM device collector that performs in-depth data collection from network devices, using the inventory established in the CMDB (or directly from `gosnmptk` scan outputs).
* **Intelligent Driver Selection**: Dynamically determines the appropriate NAPALM driver (e.g., `ios`, `eos`, `panos`, `procurve`, `arubaoss`, `fortios`, `junos`, `nxos`, `asa`) based on the device's vendor, model, and system description, with support for configurable overrides.
* **Concurrent Execution**: Utilizes a `ThreadPoolExecutor` for efficient, concurrent data collection from multiple devices, with a configurable `max_workers` limit.
* **Comprehensive Data Retrieval**: Collects a rich set of operational data via NAPALM methods, including:
    * `get_facts`: Hostname, OS version, uptime, vendor, model, serial number.
    * `get_config`: Running, startup, and candidate configurations.
    * `get_inventory`: Detailed hardware components.
    * `get_interfaces` & `get_interfaces_ip`: Physical and logical interface details, including IP assignments.
    * `get_lldp_neighbors`: Data for network topology discovery.
    * `get_arp_table` & `get_mac_address_table`: Layer 2 and Layer 3 forwarding information.
    * `get_environment`: CPU usage, memory, temperature sensors, power supplies, and fans.
    * `get_users`: Local user accounts.
    * `get_vlans`: VLAN database information.
    * `get_route_to`: Routing table entries.
    * `get_optics`: Detailed optical transceiver metrics (input/output power, laser bias).
    * `get_network_instances`: Network instance information.
* **Error Handling & Statistics**: Tracks collection success/failure, errors encountered, and detailed timing statistics for each device and the overall collection run.
* **Local Data Storage**: All collected NAPALM data is saved in a structured `captures` directory, with each device having its own subdirectory containing JSON files for each data type and text files for configurations. This creates a valuable raw data archive.

### 4. Detailed Collected Data Import (via `db_manager.py`)

The `db_manager.py` script is central to importing the detailed NAPALM collection data (from the `captures` directory) into the comprehensive SQLite CMDB (`napalm_cmdb.db`).
* **Schema Enforcement**: Operates on a robust database schema (`cmdb.sql`), which includes tables for `devices`, `device_ips`, `collection_runs`, `interfaces`, `lldp_neighbors`, `arp_entries`, `mac_address_table`, `environment_data`, `device_configs`, `device_users`, `vlans`, `routes`, and `hardware_inventory`.
* **Device Management**: Updates existing device records with richer information from NAPALM facts (e.g., FQDN, OS version, uptime) and ensures accurate management of associated IP addresses.
* **Comprehensive Data Population**: Populates various CMDB tables with the granular data collected by NAPALM, including detailed hardware inventory (transceiver metrics, PSU info, fan status), configurations, user accounts, VLANs, and routing table entries.
* **Audit Trail**: Records each collection run in the `collection_runs` table, linking all imported data to a specific collection attempt, its success status, and collected methods. Triggers automatically update the `last_updated` timestamp of devices when new collection data is imported.
* **Change Detection**: Automatically calculates configuration hashes and detects changes between collection runs, facilitating change tracking.
* **CLI Functionality**: The `db_manager.py` script also provides command-line utilities for:
    * Importing NAPALM JSON files from a directory.
    * Generating summaries of devices, network topology, device health, and site overviews.
    * Searching for MAC addresses.
    * Checking for duplicate device names.

This structured pipeline ensures that RapidCMDB captures, processes, and maintains an accurate and in-depth view of the network environment.

## Key Capabilities

### Centralized Configuration Management Database (CMDB)
* **Robust SQLite Backend**: Uses a local SQLite database (`napalm_cmdb.db`) for efficient and reliable data storage.
* **Data Integrity & Validation**: Ensures high data quality through comprehensive SQL constraints (e.g., VLAN ID ranges, MAC address formats, CPU usage ranges) and robust input validation at the application layer.
* **Temporal Tracking**: Maintains a complete audit trail of all data collection runs, linking inventory data to specific collection times, enabling historical analysis and troubleshooting.
* **Multi-Vendor Support**: Designed with vendor-agnostic data models and flexible JSON storage for vendor-specific data, ensuring broad compatibility.

### Advanced Network Topology Visualization
* **LLDP-based Topology Mapping**: Automatically builds network topology maps based on LLDP neighbor data collected from devices.
* **Intelligent Interface Normalization**: Normalizes interface names (e.g., "GigabitEthernet0/1" to "Gi0/1") across different vendors and platforms (Cisco IOS, NX-OS, Arista) for consistent visualization.
* **Bidirectional Consistency Enforcement**: Ensures that topology maps are bidirectionally consistent, meaning if device A sees B, device B also sees A, even if LLDP data is incomplete or asymmetric.
* **Flexible Filtering**: Users can filter topology views by site, device role, and include/exclude patterns to focus on specific network segments.
* **Multiple Export Formats**:
    * **Mermaid Diagrams**: Generates code for Mermaid diagrams, allowing for quick visualization within documentation or web interfaces.
    * **Standard JSON**: Exports topology data in a standardized JSON format, compatible with external mapping applications.
    * **Draw.io Integration**: Exports topology directly to Draw.io (`.drawio` XML format), facilitating professional network diagramming with support for various layout types (e.g., `tree`, `balloon`) and device icons.
* **Network-Only View**: An option to display only core network infrastructure devices (those appearing as both source and peer in LLDP data), simplifying complex diagrams.

### Automated Reconciliation & Change Detection
* **Configuration Change Tracking**: Automatically detects and tracks configuration changes between collections using SHA256 hashes, storing diffs and metrics like size and line count.
* **Topology Auto-Population**: Uses database triggers to automatically populate network topology from discovered LLDP data.
* **Duplicate Prevention**: The stable `device_key` prevents duplicate device entries even if device names or IPs change.

### Interactive Web Dashboard (Flask Application)
The Flask-based web application (`app.py`) provides an intuitive user interface for managing and interacting with the CMDB, organized into modular blueprints. The navigation sidebar provides quick access to various sections:
* **Dashboard**: Offers a high-level summary of the network, including "Total Devices" (e.g., 140 devices), "Collection Success" rate (e.g., 0.0%), "Avg CPU Usage" (e.g., 10.5% across 33 monitored devices), and "Avg Memory Usage" (e.g., 18.5%). It visually distributes devices by vendor and role using charts.
* **Devices**: Allows users to browse and search the full device inventory, displaying key metrics like "Total Devices," "Online," "Errors," and "Stale Data." It offers filtering by Vendor, Role, Site, and Status, and supports exporting data to CSV.
* **Network**: Visualizes network data and topology.
* **Configurations**: Manages device configurations and changes.
* **Reports**: Provides comprehensive analysis of scan data.
    * **Scan Analysis Report**: Displays summaries of total devices, unique signatures, and metrics for "High Confidence" and "NAPALM Supported" devices. It includes graphical distributions of devices by vendor and device type, and a table of "Top Device Discoveries".
* **Pipeline Management**: Offers dedicated interfaces for managing the data ingestion pipeline.
    * **Network Scanner Tab**: Allows users to configure and initiate network discovery scans with fields for "Network Target," "Timeout," "Concurrency," "Communities," and detailed SNMPv3 settings. A "Scanner Output" panel provides real-time feedback.
    * **Data Collection Tab**: Enables users to select a JSON database file (from scanner output) to start NAPALM data collection, with a "Collection Output" panel showing progress and status.
* **Real-time Monitoring**: Utilizes WebSockets (Flask-SocketIO) for real-time updates on pipeline execution, allowing users to monitor progress and identify issues instantly.
* **API Endpoints**: Exposes a rich set of API endpoints for programmatic access to metrics, alerts, activities, topology data (raw, Mermaid, Draw.io), and scan analysis results, enabling seamless integration with other tools.
* **Health Checks & Logging**: Includes endpoints for application health checks and viewing pipeline logs for troubleshooting and monitoring.

### Performance & Scalability
* **Optimized Indexing**: Strategic database indexing for fast lookups (device name, IP, MAC), time-series data, and relationships.
* **Efficient Storage**: Uses JSON compression for large data structures and appropriate SQLite data types.
* **Batch Operations**: Supports efficient bulk import and update operations for collected data.

### Security & Maintainability
* **Data Protection**: Focuses on not storing credentials directly in configurations, relying on local SQLite access, and using parameterized queries to prevent SQL injection.
* **Audit Trail**: All data collection and import operations are tracked for accountability.
* **Robust Error Handling**: Comprehensive exception handling, graceful recovery from partial imports, and detailed logging ensure system stability and aid in troubleshooting.
* **Extensible Architecture**: Designed with extension points for custom data types, new integrations (APIs, monitoring, reporting), and automation workflows, allowing for future growth and customization.

## Getting Started

*(Further sections like Installation, Usage, Configuration, etc., would typically follow here.)*

## Source Repositories

* **RapidCMDB**: [https://github.com/scottpeterman/rapidcmdb](https://github.com/scottpeterman/rapidcmdb)
* **GoSNMPtk (Scanner)**: [https://github.com/scottpeterman/gosnmptk](https://github.com/scottpeterman/gosnmptk)