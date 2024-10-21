# Catbee
Catbee is a tool designed for real-time ZigBee network analysis using a Catsniffer V3 to capture network traffic. It communicates with the catsniffer, processing the captured data with Scapy to identify specific ZigBee packet types.

>[!IMPORTANT]
> This PoC is still in development, so the tool may experience some bugs. I will be working on it over time.

## About the PoC
The PoC involves intercepting an OTA update by using the CatSniffer to sniff the connection and look for an *Association Request* packet. When the packet is detected, the jammer is activated, disrupting the channel and preventing communications from reaching their destination. After some time, the client loses the connection and becomes available, searching for a new one. This allows us to use a fake server to upload a custom firmware.

## Features
- Real-time Zigbee frame capture.
- Zigbee channel configuration between channels 11 and 26.
- Frequency tuning and modification.
- Uses a serial port for communication with the device.

> [!NOTE]
> This tool can help you understand how to use the packets collected by CatSniffer.

## Requirements
- Python 3.x
- System dependencies:
  - `pyserial`
  - `scapy`

## Installation
1. Clone this repository:
```bash
git clone https://github.com/JahazielLem/catbee.git
cd catbee
```
2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage
### Running the Sniffer
You can run CatBee using various command-line options to specify the CatSniffer and Jammer configurations. **Note:** The jamming functionality 
#### Command-Line Options
- `-cs`, `--catsniffer` : (Required) Serial path to the CatSniffer device.
- `-csch`, `--catsniffer-channel` : The Zigbee channel for the CatSniffer (default: 11).
- `-jm`, `--jammer` : Serial path to the Jammer device.
- `-jmb`, `--jammer-baudrate` : Baudrate for the Jammer device (default: 115200).
- `-v`, `--verbose` : Enable verbose mode to display all sniffed packets.

#### Example Usage
1. Show packets on Channel 15 with a CatSniffer (no jammer):
```bash
python3 catbee.py -cs /dev/ttyUSB0
```
2. Sniff and jam using CatSniffer and Jammer:
```bash
python3 catbee.py --cs /dev/ttyUSB0 --jm /dev/ttyUSB1 --v
```
## What It Does
- **Sniffing Zigbee Packets:** The CatSniffer captures Zigbee packets on the specified channel.
- **Jamming on Association Response:** If the tool detects an Association Response packet, it starts jamming the Zigbee network using the Jammer device.
- **Verbose Mode:** If enabled, the tool prints all captured packets to the console.

>[!NOTE]
> I am working on the jammer firmware and creating a more accessible version with fewer resource requirements. Once it is released, I will update the repository.