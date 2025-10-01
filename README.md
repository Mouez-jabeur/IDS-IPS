# IDS-IPS

# Raspberry Pi Project

This project runs on a Raspberry Pi and includes:

- **Suricata Monitor** – Python script for network monitoring  
- **BMP180 Sensor Server** – Python HTTP server providing temperature, pressure, and altitude data  
- **Node-RED Flows** – Visualization of sensor data and integration

## How to Access

- BMP180 data: `http://<raspberry-pi-ip>:8000/sensor`  
- Node-RED editor: `http://<raspberry-pi-ip>:1880`  
- Node-RED dashboard (if installed): `http://<raspberry-pi-ip>:1880/ui`

## Usage

1. Run the BMP180 server:  
   ```bash
   python3 bmp_http_server.py
