# EShark

**E**lastic**S**earch + Py**Shark** = **EShark**

This project is essentially a rewrite of the original [espcap](https://github.com/vichargrave/espcap) by [Vic Hargrave](https://github.com/vichargrave), built specifically for OPCUA applications.

This script was designed to run on a device that has visibility to all OPCUA traffic. Currently, the script looks for:
- WriteRequests
- WriteResponses
- ReadRequests
- ReadResponses

**Supported protocols**: ARP, IP, TCP, UDP, DNS, HTTP, OPCUA, Modbus

## Usage
- Clone the repository and enter the project directory
- Create and activate a new venv: `python3 -m venv venv && chmod +x venv/bin/activate && source venv/bin/activate`
  - If on Windows: `python3 -m venv venv && chmod +x venv/Scripts/activate && source venv/Scripts/activate`
- Install dependencies: `pip install -r requirements.txt`
- Set environment variables in .env.example and rename to .env: `mv .env.example .env`
- Run `main.py`

**PCAP File Playback** (load an existing PCAP file)
```python
python main.py -m file -f <path/to/pcap>
```

**Live Capture**
```python
python main.py -m live -i <interface> -b <bpf>
```
To capture on multiple interfaces, pass a string with the interface names separated by commas (don't include spaces):
```python
python main.py -m live -i "eth0, eth1"
```
