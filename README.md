# espcap-opcua
This project is essentially a rewrite of the original [espcap](https://github.com/vichargrave/espcap) by [Vic Hargrave](https://github.com/vichargrave).

## Usage
- Clone the repository
- Install dependencies: `pip install -r requirements.txt`
- Set environment variables in .env.example and rename to .env
- Run `main.py`

**Live Capture**
```python
python main.py -m file -f <path/to/pcap>
```

**PCAP File Playback** (load an existing PCAP file)
```python
python main.py -m live -i <interface> -b <bpf>
```