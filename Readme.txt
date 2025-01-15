## readme.txt

# A4 Contraband

A4 Contraband is a comprehensive cybersecurity tool designed for network and system analysis. The tool offers several advanced features including IP scanning, port scanning, geolocation tracking, MAC address lookup, phone number analysis, email OSINT, live flight monitoring, and route calculations.

## Features

1. **IP and Port Scanning**: Scans a range of IP addresses and ports, identifying open and closed ports.
2. **Geolocation Tracking**: Provides detailed geolocation information based on IP or phone number.
3. **Network Mapping**: Displays active IPs and hostnames on the network.
4. **MAC Address Lookup**: Finds and identifies vendor details of a MAC address.
5. **Phone Number Analysis**: Provides carrier, location, and line type details for phone numbers.
6. **Email OSINT**: Validates emails, retrieves WHOIS information, and looks up MX records.
7. **Live Flight Monitoring**: Displays live flights filtered by country and callsign.
8. **Route Calculation**: Calculates and displays optimal routes between multiple locations.
9. **Data Export**: Allows exporting reports in TXT, PDF, DOCX, and CSV formats.

## Installation

1. Ensure Python 3.x is installed on your system.
2. Clone the repository or download the source code.
3. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Run the application:

   ```bash
   python app.py
   ```

## Usage

- Launch the application and navigate through different tabs for specific features.
- Enter the required input fields and click the respective buttons to perform tasks.
- Use the export options to save results for further analysis.

## Requirements
- Python 3.x
- Internet connection for live data fetching and geolocation APIs

## Dependencies
- socket
- concurrent.futures
- nmap
- requests
- subprocess
- random
- threading
- scapy
- folium
- webbrowser
- geopy
- tkintermapview
- ttkbootstrap
- customtkinter
- fpdf
- docx
- phonenumbers
- email_validator
- whois
- dns.resolver
- csv

## License
This project is licensed under the MIT License.
