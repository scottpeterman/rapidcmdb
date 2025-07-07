# RapidCMDB - Network Discovery & CMDB Reconciliation Tool

A network discovery and device correlation tool built with Flask, NAPALM, and SNMP for CMDB reconciliation projects. This solution provides automated network discovery, device data collection, and a web-based dashboard for managing network inventory data.

![RapidCMDB Dashboard](https://raw.githubusercontent.com/scottpeterman/rapidcmdb/refs/heads/main/screenshots/slides1.gif)

## Screenshots


![Pipeline](https://raw.githubusercontent.com/scottpeterman/rapidcmdb/refs/heads/main/screenshots/scan_redacted.png)

## What RapidCMDB Does

RapidCMDB helps network administrators and IT teams:
- **Discover network devices** using SNMP scanning across subnets
- **Collect detailed device information** via NAPALM (facts, interfaces, LLDP neighbors, configurations)
- **Compare discovered devices** against existing CMDB data to find discrepancies
- **Visualize network topology** from LLDP neighbor data
- **Generate reports** on device inventory and network status

This tool is designed for **network discovery and basic CMDB reconciliation** - it's not a full CMDB replacement but helps identify what's actually on your network versus what's documented.

## Key Features

### Network Discovery
- SNMP-based scanning with v2c and v3 support
- **High-performance scanning**: 48+ hosts/second discovery rates
- Real-time progress tracking with detailed statistics
- Concurrent scanning with configurable timeout settings (4+ second response times)
- **Large network capability**: Successfully scans 65,000+ IP ranges
- Automated device fingerprinting and vendor identification
- **Impressive discovery rates**: 350+ responding devices from 25,000+ host scans
- Multiple output formats (CSV, JSON database)

### Device Data Collection
- NAPALM integration supporting multiple network vendors
- Comprehensive data gathering including:
  - Device facts and system information
  - Interface configurations and status
  - LLDP neighbor discovery for topology mapping
  - ARP and MAC address tables
  - Environmental data (CPU, memory, temperature)
  - Full device configurations

### Real-Time Pipeline Management
- **Live scanning interface** with real-time progress updates
- **Performance monitoring**: hosts/second rates, ETA calculations, response statistics
- Interactive terminal output with detailed scan progress
- **Concurrent processing**: configurable worker threads and timeout values
- **Large-scale network discovery**: tested on 65,000+ IP ranges with 48+ hosts/sec rates
- WebSocket-based real-time updates and job status tracking
- Automated database import and processing

### Network Topology Visualization
- Interactive topology diagrams generated from LLDP data with interface normalization
- Multiple layout options (tree, balloon) and filtering capabilities  
- Export to JSON, Mermaid, or Draw.io format
- Site-based filtering and network-only mode for infrastructure focus
- Bidirectional consistency checking for accurate topology representation
- Enhanced interface normalization supporting Cisco IOS, NX-OS, and Arista platforms

## Project Structure

```
rapidcmdb/
├── app.py                      # Main Flask application
├── db_manager.py               # Database management utilities
├── npcollector1.py             # NAPALM data collector
├── gosnmpcli.exe              # SNMP scanner executable
├── rapidcmdb.db               # SQLite database
├── collector_config.yaml      # Collection configuration
├── 
├── blueprints/                 # Flask application modules
│   ├── dashboard.py           # Main dashboard
│   ├── devices.py             # Device management
│   ├── topology.py            # Topology visualization
│   ├── config.py              # Configuration management
│   ├── reports.py             # Basic reporting
│   └── pipeline.py            # Discovery pipeline
├── 
├── templates/                  # Web interface templates
├── captures/                   # Device data storage
├── config/                     # Configuration files
├── logs/                       # Application logs
└── scans/                      # Scan results
```

## Installation

### Prerequisites
- Python 3.8+
- SQLite3

### Setup
```bash
# Clone the repository
git clone https://github.com/scottpeterman/rapidcmdb.git
cd rapidcmdb

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install flask flask-sqlalchemy flask-socketio
pip install napalm netmiko pyyaml requests eventlet networkx

# Initialize database
python db_manager.py --create-schema
```

## Usage

### 1. Start the Application
```bash
python app.py
```
Access the web interface at http://localhost:5000

### 2. Network Discovery Process

#### Basic Workflow:
1. **Configure scan parameters** (target networks, SNMP communities)
2. **Run network discovery** to find devices via SNMP
3. **Collect device data** using NAPALM for detailed information
4. **Review results** in the web dashboard
5. **Export data** for CMDB import or further analysis

#### Command Line Usage:
```bash
# Discover devices
./gosnmpcli.exe -mode scan -target 192.168.1.0/24 -enable-db -database devices.json

# Collect detailed data
python npcollector1.py devices.json --config collector_config.yaml

# Import to database
python db_manager.py --import-dir ./captures
```

### 3. CMDB Reconciliation

The tool helps with reconciliation by:
- Providing accurate "ground truth" of network devices
- Comparing discovered devices against CMDB exports (CSV/Excel)
- Identifying missing, extra, or incorrectly documented devices
- Generating reports showing discrepancies

**Note**: Manual comparison and reconciliation is currently required - automated correlation is planned for future versions.

## Configuration

### SNMP Scanner Options
```bash
# Basic scan
./gosnmpcli.exe -mode scan -target 192.168.1.0/24

# SNMPv3 scan
./gosnmpcli.exe -mode scan -target 10.0.0.0/16 \
  -snmp-version 3 -username admin \
  -auth-protocol SHA -auth-key "your-key" \
  -priv-protocol AES128 -priv-key "your-key"
```

### NAPALM Collector Configuration
Edit `collector_config.yaml`:
```yaml
timeout: 60
max_workers: 10
enhanced_inventory: true

credentials:
  - name: primary
    username: admin
    password: your-password
    priority: 1

collection_methods:
  get_facts: true
  get_interfaces: true
  get_lldp_neighbors: true
  get_config: true
```

## Supported Devices

RapidCMDB works with devices supported by NAPALM and provides enhanced recognition for:

**Fully Supported (NAPALM + Enhanced Recognition):**
- Cisco IOS/IOS-XE/NX-OS devices with interface normalization
- Arista EOS switches with full topology support  
- Juniper JunOS devices
- Fortinet FortiGate firewalls

**Discovery and Classification (SNMP):**
- Palo Alto Networks firewalls and Panorama
- Silver Peak SD-WAN appliances  
- HP/HPE ProCurve switches
- Dell networking equipment
- APC UPS systems
- Various printers (Lexmark, Xerox, Brother)
- Security cameras and IoT devices

**Interface Normalization:** 
- Cisco: GigabitEthernet, TenGigabitEthernet, etc. → Gi, Te, etc.
- Arista: Ethernet → Et
- Platform-aware normalization for consistent topology diagrams

SNMP discovery works with most network devices that support SNMP v2c/v3.

## Performance Characteristics

Based on real-world testing:
- **Discovery Rate**: 48+ hosts per second scanning capability
- **Network Scale**: Successfully processes 65,000+ IP address ranges  
- **Response Handling**: Manages 350+ responding devices from large scans
- **Concurrent Processing**: 80+ concurrent SNMP requests with 4-second timeouts
- **Real-time Updates**: Live progress tracking with sub-second refresh rates
- **Database Performance**: Efficient SQLite storage with JSON export capabilities

*Performance varies based on network conditions, device response times, and hardware specifications.*

## Use Cases

## Use Cases

This tool is suitable for:
- **Large-scale network discovery** with 48+ hosts/second scanning rates
- **Enterprise network documentation** and topology mapping with professional diagrams
- **CMDB cleanup** initiatives requiring device discovery and classification
- **Configuration analysis** with full-text search and change tracking
- **Network audits** with enhanced device type recognition and reporting
- **Migration planning** where you need current state assessment and topology export
- **Multi-vendor environments** with normalized interface representation
- **Medium to large enterprise** networks (tested on 65,000+ IP ranges)
- **Professional network documentation** with Draw.io integration
- **Real-time network assessment** with live progress monitoring

## Current Limitations

- Manual CMDB correlation (automated matching planned for future)
- Limited to read-only device access
- SQLite database (not suitable for very large deployments)
- No user authentication (local use only)
- Interface normalization limited to Cisco and Arista platforms
- Draw.io export requires local installation for advanced features

## API Endpoints

### REST API
- `GET /api/metrics` - Dashboard statistics  
- `GET /api/alerts` - System alerts
- `GET /topology/api/topology/data` - Network topology data with interface normalization
- `GET /topology/api/topology/mermaid` - Mermaid diagram code
- `GET /topology/api/sites` - Available sites for filtering
- `GET /config/api/config/<id>` - Configuration content
- `GET /reports/api/analyze/<filename>` - Scan file analysis
- `POST /topology/api/topology/export/drawio` - Export topology to Draw.io format
- `GET /health` - Application health check

### Advanced Features
- **Configuration Search API** with multiple search modes
- **Topology Export** in JSON, Mermaid, and Draw.io formats  
- **Device Classification** with confidence scoring
- **Interface Normalization** for consistent topology representation

WebSocket events available for real-time pipeline monitoring.

## Contributing

This is an open-source project. Contributions welcome:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## Troubleshooting

### Common Issues:
- **SNMP timeouts**: Verify community strings and device accessibility
- **NAPALM connection failures**: Check SSH credentials and device compatibility  
- **Missing topology**: Ensure LLDP is enabled on network devices
- **Interface normalization issues**: Check vendor detection and platform mapping
- **Configuration search errors**: Verify database schema and file permissions
- **Performance issues**: Adjust worker threads and timeout values

### Debug Mode:
```bash
export FLASK_DEBUG=1
python app.py
```

## License

MIT License - see LICENSE file for details.

## Version History

- **v1.1** - Added topology visualization and improved web interface
- **v1.0** - Initial release with basic discovery and collection

## Roadmap

Planned features:
- [ ] Automated CMDB correlation and matching algorithms
- [ ] User authentication and multi-user support
- [ ] Enhanced interface normalization for additional vendors
- [ ] Advanced configuration templating and compliance checking
- [ ] API expansion for external integrations
- [ ] Real-time configuration change monitoring
- [ ] Advanced topology analytics and path analysis
- [ ] PostgreSQL database support for larger deployments
- [ ] Automated scheduling and monitoring capabilities

---

**RapidCMDB is a practical tool for network discovery and basic CMDB reconciliation.** While it's not an enterprise-scale CMDB platform, it provides valuable functionality for network administrators who need to understand what's actually deployed in their networks.