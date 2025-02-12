import pyshark
from elasticsearch import Elasticsearch, helpers
import elasticsearch
import elastic_transport
from os import getenv
from dotenv import load_dotenv
import argparse
import logging
from datetime import datetime
import pytz
from tzlocal import get_localzone
import copy
import time


log = logging.getLogger(__name__)
now = datetime.now()
logfile = f'./logs/eshark-{now.strftime("%Y%m%d-%H%M%S")}.log'
logging.basicConfig(
    filename=logfile,
    format='%(asctime)s %(message)s',
    level=logging.DEBUG
)
# Load environment variables for required global variables
load_dotenv()
INDEX_NAME = getenv("INDEX_NAME")
ELASTIC_ENDPOINT = getenv("ELASTICSEARCH_ENDPOINT")
API_KEY = getenv("API_KEY")


def local_to_utc(timestamp):
    # Utility function that converts timestamp from local timezone to UTC
    if timestamp[-1] == 'Z':
        # If last char is Z, timestamp is already in UTC
        return timestamp
    sys_tz = get_localzone()
    local_tz = pytz.timezone(str(sys_tz))
    local_dt = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f")
    local_dt2 = local_tz.localize(local_dt)
    utc_dt = local_dt2.astimezone(pytz.UTC)
    utc_str = utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return utc_str


def parse_arguments():
    parser = argparse.ArgumentParser(description="ESpcap command-line arguments")
    parser.add_argument('-m', '--mode', type=str,
                        help='Mode: {live|file} - capture live packets or read from pcap file', required=True)
    parser.add_argument('-i', '--interface', type=str,
                        help="Network interface for live capture (required if mode is 'live')\n"
                             "To use a list of interfaces, simply enter the names separated by commas, i.e.: eth0,eth1")
    parser.add_argument('-f', '--file', type=str,
                        help="Path to pcap file (required if mode is 'file')")
    parser.add_argument('-b', '--bpf', type=str,
                        help='[optional] Berkeley Packet Filter to use for capturing packets')
    parser.add_argument('-pc', '--packet_count', type=int,
                        help="[optional] Packet count; limits the number of packets captured/read")

    args = parser.parse_args()
    if args.mode not in ['live', 'file']:
        parser.error("Unrecognized mode (-m, --mode). Valid modes: file, live")
    if args.mode == 'live' and not args.interface:
        parser.error("Interface (-i, --interface) must be set when using live mode")
    elif args.mode == 'file' and not args.file:
        parser.error("PCAP file path (-f, --file) must be set when using file mode")
    if args.packet_count and args.packet_count < 0:
        parser.error("Negative integers are not supported; use 0 for no limit or any positive integer to set a limit")

    return args


def create_index(es):
    # Create ElasticSearch index
    # Originally altered from: https://github.com/vichargrave/espcap/blob/master/scripts/packet_template-7.x.sh
    mappings = {
        "dynamic": "false",
        "properties": {
            "@timestamp": {
                "type": "date"
            },
            "interface": {
                "type": "keyword"
            },

            "eth": {
                "properties": {
                    "mac_src": {
                        "type": "text"
                    },
                    "mac_dst": {
                        "type": "text",
                    },
                    "type": {
                        "type": "text"
                    }
                }
            },
            "arp": {
                "properties": {
                    "opcode": {
                        "type": "integer"
                    },
                    "src_mac": {
                        "type": "text"
                    },
                    "src_ip": {
                        "type": "ip"
                    },
                    "dst_mac": {
                        "type": "text"
                    },
                    "dst_ip": {
                        "type": "ip"
                    },
                }
            },
            "ip": {
                "properties": {
                    "src": {
                        "type": "ip"
                    },
                    "dst": {
                        "type": "ip"
                    },
                    "protocol": {
                        "type": "integer"
                    }
                }
            },
            "tcp": {
                "properties": {
                    "port_src": {
                        "type": "integer"
                    },
                    "port_dst": {
                        "type": "integer"
                    },
                    "seq": {
                        "type": "text"
                    },
                    "stream": {
                        "type": "text"
                    },
                    "payload": {
                        "type": "text"
                    },
                    "flags": {
                        "type": "keyword"
                    }
                }
            },
            "udp": {
                "properties": {
                    "port_src": {
                        "type": "integer"
                    },
                    "port_dst": {
                        "type": "integer"
                    },
                    "stream": {
                        "type": "integer"
                    },
                    "payload": {
                        "type": "text"
                    }
                }
            },
            "opcua": {
                "properties": {
                    "secure_channel_id": {
                        "type": "integer"
                    },
                    "security_request_id": {
                        "type": "integer"
                    },
                    "security_sequence": {
                        "type": "integer"
                    },
                    "security_token_id": {
                        "type": "integer"
                    },
                    "status_code": {
                        "type": "text"
                    },
                    "message_type": {
                        "type": "keyword"
                    },
                    "index": { 
                        "type": "integer"
                    },
                    "request": {
                        "type": "object",
                        "properties": {
                            "identifier": { "type": "keyword" },
                            "value": { "type": "long" }
                        }
                    },
                    "response": {
                        "type": "object",
                        "properties": {
                            "value": {"type": "long"},
                        }
                    },
                }
            },
            "dns": {
                "properties": {
                    "queried_domain": {
                        "type": "text"
                    },
                    "query_type": {
                        "type": "text"
                    },
                    "response": {
                        "type": "nested"
                    },
                    "flags": {
                        "type": "text"
                    },
                    "type": {
                        "type": "text"
                    }
                }
            },
            "modbus": {
                "properties": {
                    "transaction_id": {
                        "type": "integer"
                    },
                    "unit_id": {
                        "type": "integer"
                    },
                    "length": {
                        "type": "integer"
                    },
                    "function_code": {
                        "type": "integer"
                    },
                    "register": {
                        "type": "nested"
                    }
                }
            },
            "http": {
                "properties": {
                    "connection": {
                        "type": "text"
                    },
                    "accept": {
                        "type": "text"
                    },
                    "method": {
                        "type": "text"
                    },
                    "request_headers": {
                        "type": "text"
                    },
                    "host": {
                        "type": "text"
                    },
                    "authorization": {
                        "type": "text"
                    },
                    "user_agent": {
                        "type": "text"
                    },
                    "request_uri": {
                        "type": "text"
                    },
                    "request_uri_full": {
                        "type": "text"
                    },
                    "version": {
                        "type": "text"
                    },
                    "uri": {
                        "type": "text"
                    },
                    "response_headers": {
                        "type": "text"
                    },
                    "response_code": {
                        "type": "integer"
                    },
                    "response_data": {
                        "type": "text"
                    }
                }
            }
        }
    }

    log.info(f'Attempting to create index: {INDEX_NAME}')
    try:
        resp = es.indices.create(index=INDEX_NAME, mappings=mappings)
        log.info(f'Index created successfully: {resp}')
    except elasticsearch.BadRequestError as err:
        if 'already exists' in str(err):
            print(f'Index already exists, moving on: {err}')
            log.info(f'Index already exists: {err}')


def capture(es, mode, interface, file, bpf, packet_count):
    log.info('-----------STARTING CAPTURE-----------\n\n')
    if mode == 'file':
        cap = pyshark.FileCapture(
            input_file=file,
            decode_as={"tcp.port==53530": "opcua"},
            use_ek=True,
        )
        cap.set_debug()
        packets = []
        for packet in cap:
            parsed = parse_packet(packet)
            if parsed["multi_packet"]:
                expanded = expand_multipacket(parsed)
                for i in expanded:
                    packets.append(i)
            else:
                packets.append(parsed)
            print(parsed)
            helpers.bulk(client=es, actions=index_packets(cap=packets))
            packets.clear()
    elif mode == 'live':
        interface = interface.split(',')

        cap = pyshark.LiveCapture(
            decode_as={"tcp.port==53530": "opcua"},
            use_ek=True,
            interface=interface,
            bpf_filter=bpf,
        )
        cap.set_debug()
        if packet_count == 0:
            packet_count = None
        packets = []
        for packet in cap.sniff_continuously(packet_count=packet_count):
            parsed = parse_packet(packet)
            if parsed["multi_packet"]:
                # Packet is flagged as a multi-packet, i.e. an object containing multiple packets
                multipacket = expand_multipacket(parsed)
                for p in multipacket:
                    packets.append(p)
            else:
                packets.append(parsed)
            helpers.bulk(client=es, actions=index_packets(cap=packets))
            packets.clear()

    cap.close()


def parse_packet(pkt):
    # Takes a Packet object received from Tshark and parses the relevant fields
    # Each layer is parsed in its own function
    log.debug('Parsing packet...')
    interface = pkt.frame_info.interface.name
    log.debug(f'Packet arrived on interface: {interface}')
    timestamp = pkt.sniff_timestamp
    try:
        # If timestamp arrives as raw epoch time instead of a datetime object, we need to convert it
        epoch = float(timestamp)
        localtime = datetime.fromtimestamp(epoch).astimezone()
        timestamp = localtime.strftime('%Y-%m-%dT%H:%M:%S.%f')
    except Exception:
        # Timestamp is in correct format; no need to convert
        pass
    timestamp_utc = local_to_utc(timestamp)
    log.debug(f'Packet timestamp: {timestamp_utc}')

    lowest_layer = pkt.layers[0].layer_name
    log.debug(f'Packet lowest layer: {lowest_layer}')

    if lowest_layer == 'eth':
        log.debug('Parsing Ethernet frame.')
        frame = parse_frame(pkt.eth)
    elif lowest_layer == 'sll':
        log.debug('Parsing SLL frame.')
        frame = parse_sll(pkt.sll)
    else:
        raise Exception(f'Unknown layer: {lowest_layer}')

    parsed = {"@timestamp": timestamp_utc, "interface": interface, "eth": frame, "multi_packet": False}
    log.debug(f'Parsed frame: {frame}')
    if frame['type'] == 'ARP':
        log.debug('ARP layer identified.')
        arp = parse_arp(pkt.arp)
        log.debug(f'Parsed ARP layer: {arp}')
        parsed['arp'] = arp

    elif frame['type'] == 'IP':
        log.debug('IP layer identified.')
        ip = parse_ip(pkt.ip)
        log.debug(f'Parsed IP layer: {ip}')
        parsed['ip'] = ip

        if ip["protocol"] == 6:
            log.debug('TCP layer identified.')
            tcp = parse_tcp(pkt.tcp)
            log.debug(f'Parsed TCP layer: {tcp}')
            parsed["tcp"] = tcp

        elif ip["protocol"] == 17:
            log.debug('UDP layer identified.')
            udp = parse_udp(pkt.udp)
            log.debug(f'Parsed UDP layer: {udp}')
            parsed["udp"] = udp

        applayer_protocol = pkt.highest_layer
        log.debug(f'Packet highest layer: {applayer_protocol}')
        if applayer_protocol in ["TCP", "UDP"]:
            log.debug('Highest layer is Transport/L4; parsing complete.')
            return parsed
        elif applayer_protocol == "OPCUA":
            log.debug('OPCUA layer identified.')
            opcua = parse_opcua(pkt.opcua)
            log.debug(f'Parsed OPCUA layer: {opcua}')
            if opcua["multi_packet"]:
                parsed["multi_packet"] = True
            parsed["opcua"] = opcua
        elif applayer_protocol == "DNS":
            log.debug('DNS layer identified.')
            dns = parse_dns(pkt.dns)
            log.debug(f'Parsed DNS layer: {dns}')
            parsed["dns"] = dns
        elif applayer_protocol == "MODBUS":
            log.debug('MODBUS layer identified.')
            modbus = parse_modbus([pkt.mbtcp, pkt.modbus])
            log.debug(f'Parsed MODBUS layer: {modbus}')
            parsed['modbus'] = modbus
        else:
            try:
                # highest_layer check doesn't work for HTTP data because POST data will show as highest layer 'MEDIA'
                http = parse_http(pkt.http)
                parsed["http"] = http
            except AttributeError:
                pass
    return parsed


def parse_frame(frame):
    # Parse frame (Ethernet layer) data
    frametype = frame.type
    ftype = check_frame_type(frametype)
    log.info(f'Ethernet frame type: {ftype}')
    parsed_frame = {
        "mac_src": frame.src.resolved,
        "mac_dst": frame.dst.resolved,
        "type": ftype,
    }
    log.info(f'Parsed Ethernet frame: {parsed_frame}')
    return parsed_frame


def parse_sll(sll):
    # Parse SLL layer data
    # SLL is the pseudo-protocol used by libpcap: https://wiki.wireshark.org/SLL
    frametype = sll.etype
    ftype = check_frame_type(frametype)
    log.info(f'SLL frame type: {ftype}')
    mac_src = sll.src.eth
    parsed_sll = {
        "mac_src": mac_src,
        "type": ftype
    }
    log.info(f'Parsed SLL frame: {parsed_sll}')
    return parsed_sll


def check_frame_type(frametype: int):
    # Check if frame is ARP or IP
    if frametype == 2054:
        ftype = 'ARP'
    elif frametype == 2048:
        ftype = 'IP'
    else:
        raise Exception(f'Unknown frame type: {frametype}')
    return ftype


def parse_arp(arp):
    opcode = arp.opcode
    log.debug(f'ARP opcode: {opcode}')
    src_mac = arp.src.hw.mac
    log.debug(f'ARP source MAC: {src_mac}')
    src_ip = arp.src.proto.ipv4
    log.debug(f'ARP source IP: {src_ip}')
    dst_mac = arp.dst.hw.mac
    log.debug(f'ARP destination MAC: {dst_mac}')
    dst_ip = arp.dst.proto.ipv4
    log.debug(f'ARP destination IP: {dst_ip}')
    parsed_arp = {
        "opcode": opcode,
        "src_mac": src_mac,
        "src_ip": src_ip,
        "dst_mac": dst_mac,
        "dst_ip": dst_ip
    }
    return parsed_arp


def parse_ip(ip):
    # Parse IP layer data
    parsed_ip = {
        "src": ip.src.host,
        "dst": ip.dst.host,
        "protocol": ip.proto,
    }
    return parsed_ip


def parse_tcp(tcp):
    try:
        payload = str(tcp.payload)
    except AttributeError:
        payload = ''
    log.debug(f'TCP payload: {payload}')
    # get TCP flags
    flags = tcp.flags
    active_flags = []
    possible_flags = ["syn", "ack", "urg", "push", "fin", "reset"]
    for f in possible_flags:
        if getattr(flags, f):
            # If attribute is True, append flag to list of active flags for this packet
            active_flags.append(f)
    log.debug(f'TCP flags: {active_flags}')
    parsed_tcp = {
        "port_src": tcp.srcport,
        "port_dst": tcp.dstport,
        "stream": tcp.stream,
        "seq": tcp.seq.raw,
        "payload_raw": payload,
        "flags": active_flags
    }
    return parsed_tcp


def parse_udp(udp):
    parsed_udp = {
        "port_src": udp.srcport,
        "port_dst": udp.dstport,
        "stream": udp.stream,
        "payload": str(udp.payload)
    }
    return parsed_udp


def parse_opcua(opc):
    # opc should be the OPCUA layer of a Packet object from PyShark
    message_type = ''
    try:
        security_token_id = opc.security.tokenid
        log.debug(f'Security token ID: {security_token_id}')
    except AttributeError:
        security_token_id = ''
        log.debug('No security token found')
            
    try:
        scid = opc.transport.scid
        log.debug(f'Secure channel ID: {scid}')
    except AttributeError:
        scid = ''
        log.debug('No secure channel ID found')
    
    try:
        rqid = opc.security.rqid
        log.debug(f'Security request ID: {rqid}')
    except AttributeError:
        rqid = ''
        log.debug('No security request ID found')

    try:
        seq = opc.security.seq
        log.debug(f'Security sequence ID: {seq}')
    except AttributeError:
        seq = ''
        log.debug('No security sequence ID found')

    parsed_opcua = {
        "multi_packet": False,
        "secure_channel_id": scid,
        "security_request_id": rqid,
        "security_sequence": seq,
        "security_token_id": security_token_id,
    }
    try:
        msg_type = opc.servicenodeid_numeric
    except AttributeError:
        msg_type = ''
        log.debug('No OPCUA message type found')
    try:
        status_code = get_statcode_string(opc.StatusCode)
    except AttributeError:
        status_code = None
    log.debug(f'OPCUA message type: {msg_type}')
    parsed_opcua["status_code"] = status_code

    if msg_type == 634:
        message_type = "ReadResponse"
        try:
            nodes_response_value = opc.Double
            if isinstance(nodes_response_value, float):
                parsed_opcua["response"] = {
                    "index": 0,
                    "value": nodes_response_value
                }
            else:
                nodes_list = [nodes_response_value[i] for i in range(len(nodes_response_value))]
                parsed_opcua["response"] = nodes_list
                parsed_opcua["multi_packet"] = True
        except AttributeError:
            parsed_opcua["response"] = None

    elif msg_type == 631:
        message_type = "ReadRequest"
        nodes_to_read = opc.nodeid.string
        if isinstance(nodes_to_read, str):
            parsed_opcua["request"] = {
                "index": 0,
                "identifier": nodes_to_read
            }
        else:
            nodes_list = [nodes_to_read[i] for i in range(len(nodes_to_read))]
            parsed_opcua["request"] = nodes_list
            parsed_opcua["multi_packet"] = True

    elif msg_type == 673:
        message_type = "WriteRequest"
        nodes_values = opc.Double
        nodes_identifiers = opc.nodeid.string
        if isinstance(nodes_identifiers, str):
            # only 1 node being written to
            parsed_opcua["request"] = {
                "index": 0,
                "identifier": nodes_identifiers,
                "value": nodes_values
            }
        else:
            # multiple nodes being written to
            nodes_to_write = [{"identifier": identifier, "value": value}
                              for j, (identifier, value) in enumerate(zip(nodes_identifiers, nodes_values))]
            parsed_opcua["request"] = nodes_to_write
            parsed_opcua["multi_packet"] = True

    elif msg_type == 676:
        message_type = "WriteResponse"
        results = opc.Results
        if isinstance(results, int):
            # Only 1 result returned
            parsed_opcua["response"] = {
                "index": 0,
                "value": results
            }
        else:
            write_result = [results[n] for n in range(len(results))]
            parsed_opcua["response"] = write_result
            parsed_opcua["multi_packet"] = True

    parsed_opcua["message_type"] = message_type

    return parsed_opcua


def parse_dns(dns):
    msg_type = 'request'
    is_response = dns.flags.response
    parsed_dns = {
        "flags_raw": dns.flags.value,
        # TODO: checks/formatting when multiple queries are contained in one packet
        "queried_domain": dns.qry.name.value,
        "query_type": dns.qry.type,
    }
    if is_response:
        msg_type = 'response'
        names = dns.resp.name
        try:
            records = dns.a    # TODO: support for other record types
        except AttributeError:
            records = dns.aaaa
        if isinstance(names, str):
            answers = {0: {"name": names, "record": records}}
        else:
            answers = {i: {"name": name, "record": record}
                       for i, (name, record) in enumerate(zip(names, records))}
        parsed_dns['response'] = answers

    parsed_dns['type'] = msg_type
    return parsed_dns


def parse_modbus(modbus):
    parsed_modbus = {
        "transaction_id": modbus[0].trans.id,
        "unit_id": modbus[0].unit.id,
        "length": modbus[0].len,
        "function_code": modbus[1].func.code
    }
    try:
        log.debug('Attempting to parse Modbus payload...')
        # try to parse query data
        register = modbus[1].regnum16
        log.debug(f'Register(s): {register}')
        register_val = modbus[1].regval.uint16
        log.debug(f'Register value(s): {register_val}')
        if isinstance(register, int):
            log.debug('Only one register found in query')
            # Only one register found in query
            register = {0: {"number": register, "value": register_val}}
        else:
            register = {i: {"number": number, "value": value}
                        for i, (number, value) in enumerate(zip(register, register_val))}
        parsed_modbus['register'] = register
    except AttributeError:
        pass
    return parsed_modbus


def parse_http(http):
    parsed_http = {
        "connection": http.connection,
        "accept": http.accept,
    }
    if http.request.value:
        # If above is true, packet is an HTTP request
        method = http.request.method
        parsed_http['method'] = method
        parsed_http['request_headers'] = http.request.line
        parsed_http['host'] = http.host
        parsed_http['authorization'] = http.authorization
        parsed_http['user_agent'] = http.user.agent
        parsed_http['request_uri'] = http.request.uri
        parsed_http['request_uri_full'] = http.request.full.uri
        parsed_http['version'] = http.request.version

        if method != 'GET':
            parsed_http['payload'] = http.file.data
    else:
        # Packet is an HTTP response
        uri = getattr(http, 'for')
        parsed_http['uri'] = uri.uri
        parsed_http['response_headers'] = http.response.line
        parsed_http['response_code'] = http.response.code
        parsed_http['version'] = http.response.version
        parsed_http['response_data'] = http.file.data

    return parsed_http


def get_statcode_string(statcode_id):
    # source for statcodes: https://opal-rt.atlassian.net/wiki/spaces/PRD/pages/144120734/OPC+UA+Status+Codes
    status_codes = {
        2147549184: "BadUnexpectedError",
        2147614720: "BadInternalError",
        2147680256: "BadOutOfMemory",
        2147745792: "BadResourceUnavailable",
        2147811328: "BadCommunicationError",
        2147876864: "BadEncodingError",
        2147942400: "BadDecodingError",
        2148007936: "BadEncodingLimitsExceeded",
        2159542272: "BadRequestTooLarge",
        2159607808: "BadResponseTooLarge",
        2148073472: "BadUnknownResponse",
        2148139008: "BadTimeout",
        2148204544: "BadServiceUnsupported",
        2148270080: "BadShutdown",
        2148335616: "BadServerNotConnected",
        2148401152: "BadServerHalted",
        2148466688: "BadNothingToDo",
        2148532224: "BadTooManyOperations",
        2148597760: "BadDataTypeIdUnknown",
        2148663296: "BadCertificateInvalid",
        2148728832: "BadSecurityChecksFailed",
        2148794368: "BadCertificateTimeInvalid",
        2148859904: "BadCertificateIssuerTimeInvalid",
        2148925440: "BadCertificateHostNameInvalid",
        2148990976: "BadCertificateUriInvalid",
        2149056512: "BadCertificateUseNotAllowed",
        2149122048: "BadCertificateIssuerUseNotAllowed",
        2149187584: "BadCertificateUntrusted",
        2149253120: "BadCertificateRevocationUnknown",
        2149318656: "BadCertificateIssuerRevocationUnknown",
        2149384192: "BadCertificateRevoked",
        2149449728: "BadCertificateIssuerRevoked",
        2149515264: "BadUserAccessDenied",
        2149580800: "BadIdentityTokenInvalid",
        2149646336: "BadIdentityTokenRejected",
        2149711872: "BadSecureChannelIdInvalid",
        2149777408: "BadInvalidTimestamp",
        2149842944: "BadNonceInvalid",
        2149908480: "BadSessionIdInvalid",
        2149974016: "BadSessionClosed",
        2150039552: "BadSessionNotActivated",
        2150105088: "BadSubscriptionIdInvalid",
        2150236160: "BadRequestHeaderInvalid",
        2150301696: "BadTimestampsToReturnInvalid",
        2150367232: "BadRequestCancelledByClient",
        2949120: "GoodSubscriptionTransferred",
        3014656: "GoodCompletesAsynchronously",
        3080192: "GoodOverload",
        3145728: "GoodClamped",
        2150694912: "BadNoCommunication",
        2150760448: "BadWaitingForInitialData",
        2150825984: "BadNodeIdInvalid",
        2150891520: "BadNodeIdUnknown",
        2150957056: "BadAttributeIdInvalid",
        2151022592: "BadIndexRangeInvalid",
        2151088128: "BadIndexRangeNoData",
        2151153664: "BadDataEncodingInvalid",
        2151219200: "BadDataEncodingUnsupported",
        2151284736: "BadNotReadable",
        2151350272: "BadNotWritable",
        2151415808: "BadOutOfRange",
        2151481344: "BadNotSupported",
        2151546880: "BadNotFound",
        2151612416: "BadObjectDeleted",
        2151677952: "BadNotImplemented",
        2151743488: "BadMonitoringModeInvalid",
        2151809024: "BadMonitoredItemIdInvalid",
        2151874560: "BadMonitoredItemFilterInvalid",
        2151940096: "BadMonitoredItemFilterUnsupported",
        2152005632: "BadFilterNotAllowed",
        2152071168: "BadStructureMissing",
        2152136704: "BadEventFilterInvalid",
        2152202240: "BadContentFilterInvalid",
        2160132096: "BadFilterOperatorInvalid",
        2160197632: "BadFilterOperatorUnsupported",
        2160263168: "BadFilterOperandCountMismatch",
        2152267776: "BadFilterOperandInvalid",
        2160328704: "BadFilterElementInvalid",
        2160394240: "BadFilterLiteralInvalid",
        2152333312: "BadContinuationPointInvalid",
        2152398848: "BadNoContinuationPoints",
        2152464384: "BadReferenceTypeIdInvalid",
        2152529920: "BadBrowseDirectionInvalid",
        2152595456: "BadNodeNotInView",
        2152660992: "BadServerUriInvalid",
        2152726528: "BadServerNameMissing",
        2152792064: "BadDiscoveryUrlMissing",
        2152857600: "BadSempahoreFileMissing",
        2152923136: "BadRequestTypeInvalid",
        2152988672: "BadSecurityModeRejected",
        2153054208: "BadSecurityPolicyRejected",
        2153119744: "BadTooManySessions",
        2153185280: "BadUserSignatureInvalid",
        2153250816: "BadApplicationSignatureInvalid",
        2153316352: "BadNoValidCertificates",
        2160459776: "BadIdentityChangeNotSupported",
        2153381888: "BadRequestCancelledByRequest",
        2153447424: "BadParentNodeIdInvalid",
        2153512960: "BadReferenceNotAllowed",
        2153578496: "BadNodeIdRejected",
        2153644032: "BadNodeIdExists",
        2153709568: "BadNodeClassInvalid",
        2153775104: "BadBrowseNameInvalid",
        2153840640: "BadBrowseNameDuplicated",
        2153906176: "BadNodeAttributesInvalid",
        2153971712: "BadTypeDefinitionInvalid",
        2154037248: "BadSourceNodeIdInvalid",
        2154102784: "BadTargetNodeIdInvalid",
        2154168320: "BadDuplicateReferenceNotAllowed",
        2154233856: "BadInvalidSelfReference",
        2154299392: "BadReferenceLocalOnly",
        2154364928: "BadNoDeleteRights",
        1086062592: "UncertainReferenceNotDeleted",
        2154430464: "BadServerIndexInvalid",
        2154496000: "BadViewIdUnknown",
        2160656384: "BadViewTimestampInvalid",
        2160721920: "BadViewParameterMismatch",
        2160787456: "BadViewVersionInvalid",
        1086324736: "UncertainNotAllNodesAvailable",
        12189696: "GoodResultsMayBeIncomplete",
        2160590848: "BadNotTypeDefinition",
        1080819712: "UncertainReferenceOutOfServer",
        2154627072: "BadTooManyMatches",
        2154692608: "BadQueryTooComplex",
        2154758144: "BadNoMatch",
        2154823680: "BadMaxAgeInvalid",
        2154889216: "BadHistoryOperationInvalid",
        2154954752: "BadHistoryOperationUnsupported",
        2159869952: "BadInvalidTimestampArgument",
        2155020288: "BadWriteNotSupported",
        2155085824: "BadTypeMismatch",
        2155151360: "BadMethodInvalid",
        2155216896: "BadArgumentsMissing",
        2155282432: "BadTooManySubscriptions",
        2155347968: "BadTooManyPublishRequests",
        2155413504: "BadNoSubscription",
        2155479040: "BadSequenceNumberUnknown",
        2155544576: "BadMessageNotAvailable",
        2155610112: "BadInsufficientClientProfile",
        2160001024: "BadStateNotActive",
        2155675648: "BadTcpServerTooBusy",
        2155741184: "BadTcpMessageTypeInvalid",
        2155806720: "BadTcpSecureChannelUnknown",
        2155872256: "BadTcpMessageTooLarge",
        2155937792: "BadTcpNotEnoughResources",
        2156003328: "BadTcpInternalError",
        2156068864: "BadTcpEndpointUrlInvalid",
        2156134400: "BadRequestInterrupted",
        2156199936: "BadRequestTimeout",
        2156265472: "BadSecureChannelClosed",
        2156331008: "BadSecureChannelTokenUnknown",
        2156396544: "BadSequenceNumberInvalid",
        2159935488: "BadProtocolVersionUnsupported",
        2156462080: "BadConfigurationError",
        2156527616: "BadNotConnected",
        2156593152: "BadDeviceFailure",
        2156658688: "BadSensorFailure",
        2156724224: "BadOutOfService",
        2156789760: "BadDeadbandFilterInvalid",
        1083113472: "UncertainNoCommunicationLastUsableValue",
        1083179008: "UncertainLastUsableValue",
        1083244544: "UncertainSubstituteValue",
        1083310080: "UncertainInitialValue",
        1083375616: "UncertainSensorNotAccurate",
        1083441152: "UncertainEngineeringUnitsExceeded",
        1083506688: "UncertainSubNormal",
        9830400: "GoodLocalOverride",
        2157379584: "BadRefreshInProgress",
        2157445120: "BadConditionAlreadyDisabled",
        2160852992: "BadConditionAlreadyEnabled",
        2157510656: "BadConditionDisabled",
        2157576192: "BadEventIdUnknown",
        2159738880: "BadEventNotAcknowledgeable",
        2160918528: "BadDialogNotActive",
        2160984064: "BadDialogResponseInvalid",
        2161049600: "BadConditionBranchAlreadyAcked",
        2161115136: "BadConditionBranchAlreadyConfirmed",
        2161180672: "BadConditionAlreadyShelved",
        2161246208: "BadConditionNotShelved",
        2161311744: "BadShelvingTimeOutOfRange",
        2157641728: "BadNoData",
        2157707264: "BadNoBound",
        2157772800: "BadDataLost",
        2157838336: "BadDataUnavailable",
        2157903872: "BadEntryExists",
        2157969408: "BadNoEntryExists",
        2158034944: "BadTimestampNotSupported",
        10616832: "GoodEntryInserted",
        10682368: "GoodEntryReplaced",
        1084489728: "UncertainDataSubNormal",
        10813440: "GoodNoData",
        10878976: "GoodMoreData",
        10944512: "GoodCommunicationEvent",
        11010048: "GoodShutdownEvent",
        11075584: "GoodCallAgain",
        11141120: "GoodNonCriticalTimeout",
        2158690304: "BadInvalidArgument",
        2158755840: "BadConnectionRejected",
        2158821376: "BadDisconnect",
        2158886912: "BadConnectionClosed",
        2158952448: "BadInvalidState",
        2159017984: "BadEndOfStream",
        2159083520: "BadNoDataAvailable",
        2159149056: "BadWaitingForResponse",
        2159214592: "BadOperationAbandoned",
        2159280128: "BadExpectedStreamToBlock",
        2159345664: "BadWouldBlock",
        2159411200: "BadSyntaxError",
        2159476736: "BadMaxConnectionsReached"
    }
    status_code = status_codes.get(statcode_id, "Unknown status code #")
    return status_code


def index_packets(cap):
    for packet in cap:
        action = {
            "_op_type": "index",
            "_index": INDEX_NAME,
            "_source": packet
        }
        yield action


def expand_multipacket(multipacket):
    opc = multipacket["opcua"]
    resp, req = False, False
    mtype = opc["message_type"]
    if mtype in ["ReadRequest", "WriteRequest"]:
        req = opc["request"]
        num_to_duplicate = len(req)
        handler = handle_read_request if mtype == 'ReadRequest' else handle_write_request
    elif opc["message_type"] in ["ReadResponse", "WriteResponse"]:
        resp = opc["response"]
        num_to_duplicate = len(resp)
        handler = handle_response
    else:
        raise ValueError(f"Unknown message type: {opc['message_type']}")

    packets = []
    orig_packet = multipacket
    for i in range(0, num_to_duplicate):
        temp_packet = orig_packet.copy()
        temp_opc = copy.deepcopy(temp_packet["opcua"])
        handler(temp_opc, req if req else resp, i)
        temp_packet["opcua"] = temp_opc
        packets.append(temp_packet)
    return packets


def handle_response(opc_layer, request, index):
    # Used by expand_multipacket() to handle construction of Read/WriteResposne packets
    opc_layer["response"] = {
        "value": request[index]
    }
    opc_layer["index"] = index


def handle_write_request(opc_layer, request, index):
    # Used by expand_multipacket() to handle construction of WriteRequest packets
    opc_layer["request"] = {
        "identifier": request[index]["identifier"],
        "value": request[index]["value"]
    }
    opc_layer["index"] = index


def handle_read_request(opc_layer, request, index):
    # Used by expand_multipacket() to handle construction of ReadRequest packets
    opc_layer["request"] = {
        "identifier": request[index]
    }
    opc_layer["index"] = index


def main(args):

    log.info(f"EShark started with arguments: {args}")

    # Command-line options
    capture_mode = args.mode
    log.info(f"Capture mode: {capture_mode}")
    if capture_mode == 'live':
        interface = args.interface
        pcapfile = ''
        log.info(f"Interface(s) to capture on: {interface}")
    elif capture_mode == 'file':
        pcapfile = args.file
        interface = ''
        log.info(f"PCAP file to read: {pcapfile}")
    else:
        print(f'[FATAL ERROR]: Unrecognized mode: {capture_mode}')
        log.fatal(f"Unrecognized operating mode: {capture_mode}. Valid modes are: live, file")
        return 0

    try:
        packet_count = args.packet_count
        log.info(f"Packet count set to: {packet_count}")
    except AttributeError:
        packet_count = 0

    try:
        bpf = args.bpf
        log.info(f"BPF set to: {bpf}")
    except AttributeError:
        bpf = ''
    # Connect to ElasticSearch
    print("Connecting to ElasticSearch...")
    try:
        es = Elasticsearch(ELASTIC_ENDPOINT, api_key=API_KEY)
        log.info(f"Connected to ElasticSearch: {es.info()}")
    except elasticsearch.AuthenticationException:
        print('ERROR: Unable to authenticate. Make sure API key is correct.')
        log.error('Unable to authenticate. Make sure API key is correct.')
        return 0
    except elasticsearch.AuthorizationException:
        print('ERROR: Unauthorized. Make sure API key has correct permissions.')
        log.error('Unauthorized. Make sure API key has correct permissions.')
        return 0
    except elastic_transport.ConnectionError:
        print('ERROR: Connection failed to establish. Make sure IP address/domain for ElasticSearch instance is valid.')
        log.error('ERROR: Connection failed to establish. Make sure IP address/domain for ElasticSearch instance is valid.')
        return 0
    except elastic_transport.ConnectionTimeout:
        print('ERROR: Connection timed out. Make sure IP address/domain and port for ElasticSearch are correct.')
        log.error('Connection timed out. Make sure IP address/domain and port for ElasticSearch are correct.')
        return 0

    if es:
        print('ElasticSearch connection successful.')
        print('Creating index...')
        # Connection to ElasticSearch succeeded. Create the index:
        create_index(es)
        # Index is now created (or already existed)
        # Start capture
        print('Starting capture...')
        log.info('Starting Capture...')
        while True:
            try:
                capture(es, capture_mode, interface, pcapfile, bpf, packet_count)
            except Exception as err:
                print(f"ERROR: Received error while attempting to index packets: {err}")
                print("Sleeping for 10s, then retrying")
                time.sleep(10)


if __name__ == '__main__':
    arguments = parse_arguments()
    main(arguments)
