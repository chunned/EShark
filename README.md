# espcap-opcua
This project is essentially a rewrite of the original [espcap](https://github.com/vichargrave/espcap) by [Vic Hargrave](https://github.com/vichargrave), built specifically for OPCUA applications.

This script was designed to run on a device that has visibility to all OPCUA traffic. Currently, the script looks for:
- WriteRequests
- WriteResponses
- ReadRequests
- ReadResponses


## Usage
- Clone the repository and enter the project directory
- Create and activate a new venv: `python3 -m venv venv && chmod +x venv/bin/activate && source venv/bin/activate`
- Install dependencies: `pip install -r requirements.txt`
- Set environment variables in .env.example and rename to .env: `mv .env.example .env`
- Run `main.py`

**Live Capture**
```python
python main.py -m file -f <path/to/pcap>
```

**PCAP File Playback** (load an existing PCAP file)
```python
python main.py -m live -i <interface> -b <bpf>
```