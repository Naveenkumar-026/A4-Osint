# A4 OSINT

A4 OSINT is a multi-function cybersecurity and intelligence tool built for network inspection, open-source intelligence gathering, and situational analysis. It combines host discovery, service inspection, identity lookups, geolocation utilities, and data export into a single workflow-oriented interface.

## Overview

The project is designed to help users collect, organize, and review technical and contextual information from multiple sources in one place. It supports both network-focused tasks and broader OSINT-style lookups, making it useful for research, lab work, and structured analysis.

## Core Capabilities

- **IP and Port Scanning**  
  Discover hosts across a target range and inspect ports to identify exposed services.

- **Geolocation Tracking**  
  Retrieve approximate geographic information from supported IP- or phone-based lookups.

- **Network Mapping**  
  Identify reachable systems, resolve hostnames, and build a clearer view of local network presence.

- **MAC Address Lookup**  
  Resolve vendor and manufacturer details from MAC address data.

- **Phone Number Analysis**  
  Extract metadata such as carrier, region, and number type where supported.

- **Email OSINT**  
  Validate addresses and retrieve related infrastructure details such as WHOIS and MX records.

- **Live Flight Monitoring**  
  Track live flights using filters such as country and callsign.

- **Route Calculation**  
  Compute travel routes across multiple locations.

- **Report Export**  
  Save findings in TXT, PDF, DOCX, and CSV formats.

## Feature Set

### Network Analysis
- IP range scanning
- Port scanning
- Host discovery
- Hostname resolution
- Network visibility support

### Intelligence and Lookup
- IP-based geolocation
- MAC vendor lookup
- Phone number metadata analysis
- Email validation
- WHOIS lookup
- MX record lookup

### Situational Tools
- Live flight filtering
- Multi-location route calculation

### Reporting
- Export results to:
  - TXT
  - PDF
  - DOCX
  - CSV

## Installation

### Prerequisites
- Python 3.x
- Internet connection for live lookups and external data sources

### Setup
1. Clone the repository or download the source files.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Launch the application:

```bash
python app.py
```

## Usage

1. Start the application.
2. Open the relevant tab for the workflow you want to run.
3. Enter the required input values.
4. Run the lookup, scan, or analysis function.
5. Review the results in the interface.
6. Export findings if needed.

## Requirements

- Python 3.x
- Network access for API-backed or live data features

## Main Dependencies

- `socket`
- `concurrent.futures`
- `nmap`
- `requests`
- `subprocess`
- `random`
- `threading`
- `scapy`
- `folium`
- `webbrowser`
- `geopy`
- `tkintermapview`
- `ttkbootstrap`
- `customtkinter`
- `fpdf`
- `python-docx`
- `phonenumbers`
- `email_validator`
- `whois`
- `dns.resolver`
- `csv`

## Intended Use

A4 OSINT is intended for cybersecurity research, network visibility, technical investigation, and open-source intelligence workflows conducted with proper authorization and within applicable legal and ethical boundaries.

## License

This project is licensed under the MIT License.
