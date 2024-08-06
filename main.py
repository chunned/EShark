import pyshark
from elasticsearch import Elasticsearch, helpers
import elasticsearch
import elastic_transport
from os import getenv
from dotenv import load_dotenv
import argparse


# Load environment variables for required global variables
load_dotenv()
INDEX_NAME = getenv("INDEX_NAME")
ELASTIC_ENDPOINT = getenv("ELASTICSEARCH_ENDPOINT")
API_KEY = getenv("API_KEY")


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
            "timestamp": {
                "type": "date"
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
                    },
                    "interface": {
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
                        "type": "string"
                    },
                    "stream": {
                        "type": "string"
                    },
                    "payload": {
                        "type": "text"
                    },
                    "flags": {
                        "type": "nested"
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
                    "opcua_timestamp": {
                        "type": "text"
                    },
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
                        "type": "text"
                    },
                    "nodes_response_list": {
                        "type": "nested"
                    },
                    "nodes_request_list": {
                        "type": "nested"
                    },
                    "write_req_details": {
                        "type": "nested"
                    },
                    "write_resp_status": {
                        "type": "nested"
                    }
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

    print(f'Creating index: {INDEX_NAME}')
    try:
        es.indices.create(index=INDEX_NAME, mappings=mappings)
    except elasticsearch.BadRequestError:
        print('Index already exists, moving on.')


def capture(es, mode, interface, file, bpf, packet_count):
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
            packets.append(parsed)
            helpers.bulk(client=es, actions=index_packets(cap=packets))
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
            packets.append(parsed)
            helpers.bulk(client=es, actions=index_packets(cap=packets))

    cap.close()


def parse_packet(pkt):
    # Takes a Packet object received from Tshark and parses the relevant fields
    # Each layer is parsed in its own function
    interface = pkt.frame_info.interface.name
    timestamp = pkt.sniff_timestamp
    frame = parse_frame(pkt.eth)

    parsed = {"timestamp": timestamp, "interface": interface, "eth": frame}
    if frame['type'] == 'ARP':
        arp = parse_arp(pkt.arp)
        parsed['arp'] = arp
    elif frame['type'] == 'IP':
        ip = parse_ip(pkt.ip)
        parsed['ip'] = ip

        if ip["protocol"] == 6:
            tcp = parse_tcp(pkt.tcp)
            parsed["tcp"] = tcp

        elif ip["protocol"] == 17:
            udp = parse_udp(pkt.udp)
            parsed["udp"] = udp

        applayer_protocol = pkt.highest_layer

        if applayer_protocol in ["TCP", "UDP"]:
            return parsed
        elif applayer_protocol == "OPCUA":
            opcua = parse_opcua(pkt.opcua)
            parsed["opcua"] = opcua
        elif applayer_protocol == "DNS":
            dns = parse_dns(pkt.dns)
            parsed["dns"] = dns
        elif applayer_protocol == "MODBUS":
            modbus = parse_modbus([pkt.mbtcp, pkt.modbus])
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
    if frametype == 2054:
        ftype = 'ARP'
    elif frametype == 2048:
        ftype = 'IP'
    parsed_frame = {
        "mac_src": frame.src.resolved,
        "mac_dst": frame.dst.resolved,
        "type": ftype,
    }
    return parsed_frame


def parse_arp(arp):
    parsed_arp = {
        "opcode": arp.opcode,
        "src_mac": arp.src.hw.mac,
        "src_ip": arp.src.proto.ipv4,
        "dst_mac": arp.dst.hw.mac,
        "dst_ip": arp.dst.proto.ipv4
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
    # get TCP flags
    flags = tcp.flags
    active_flags = []
    possible_flags = ["syn", "ack", "urg", "push", "fin", "reset"]
    for f in possible_flags:
        if getattr(flags, f):
            # If attribute is True, append flag to list of active flags for this packet
            active_flags.append(f)

    parsed_tcp = {
        "port_src": tcp.srcport,
        "port_dst": tcp.dstport,
        "stream": tcp.stream,
        "seq": tcp.seq.raw,
        "payload_raw": payload,
        "flags": active_flags
    }
#    print(type(payload))
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
    parsed_opcua = {
        "opcua_timestamp": opc.Timestamp,
        "secure_channel_id": opc.transport.scid,
        "security_request_id": opc.security.rqid,
        "security_sequence": opc.security.seq,
        "security_token_id": opc.security.tokenid,
    }
    msg_type = opc.servicenodeid_numeric
    try:
        status_code = get_statcode_string(opc.StatusCode)
    except AttributeError:
        status_code = None

    parsed_opcua["status_code"] = status_code

    if msg_type == 634:
        message_type = "ReadResponse"
        try:
            nodes_response_value = opc.Double
            if isinstance(nodes_response_value, float):
                nodes_list = {0: nodes_response_value}
            else:
                nodes_list = {i: nodes_response_value[i] for i in range(len(nodes_response_value))}
            parsed_opcua["nodes_response_list"] = nodes_list
        except AttributeError:
            parsed_opcua["nodes_response_list"] = {}

    elif msg_type == 631:
        message_type = "ReadRequest"
        nodes_to_read = opc.nodeid.string
        if isinstance(nodes_to_read, str):
            nodes_list = {0: nodes_to_read}
        else:
            nodes_list = {i: nodes_to_read[i] for i in range(len(nodes_to_read))}
        parsed_opcua["nodes_request_list"] = nodes_list

    elif msg_type == 673:
        message_type = "WriteRequest"
        nodes_values = opc.Double
        nodes_identifiers = opc.nodeid.string
        if isinstance(nodes_identifiers, str):
            # only 1 node being written to
            nodes_to_write = {0: {
                "identifier": nodes_identifiers,
                "value": nodes_values
            }}
        else:
            # multiple nodes being written to
            nodes_to_write = {j: {"identifier": identifier, "value": value}
                              for j, (identifier, value) in enumerate(zip(nodes_identifiers, nodes_values))}
        parsed_opcua["write_req_details"] = nodes_to_write

    elif msg_type == 676:
        message_type = "WriteResponse"
        results = opc.Results
        if isinstance(results, int):
            # Only 1 result returned
            write_result = {0: results}
        else:
            write_result = {n: results[n] for n in range(len(results))}
        parsed_opcua["write_resp_status"] = write_result
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
        records = dns.a    # TODO: support for other record types
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
        # try to parse query data
        register = modbus[1].regnum16
        register_val = modbus[1].regval.uint16

        if isinstance(register, str):
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


def main(args):
    # Command-line options
    capture_mode = args.mode
    if capture_mode == 'live':
        interface = args.interface
        pcapfile = ''
    elif capture_mode == 'file':
        pcapfile = args.file
        interface = ''
    else:
        print(f'[FATAL ERROR]: Unrecognized mode: {capture_mode}')
        return 0

    try:
        packet_count = args.packet_count
    except AttributeError:
        packet_count = 0

    try:
        bpf = args.bpf
    except AttributeError:
        bpf = ''
    # Connect to ElasticSearch
    try:
        es = Elasticsearch(ELASTIC_ENDPOINT, api_key=API_KEY)
        print(es.info())
    except elasticsearch.AuthenticationException:
        print('ERROR: Unable to authenticate. Make sure API key is correct.')
        return 0
    except elasticsearch.AuthorizationException:
        print('ERROR: Unauthorized. Make sure API key has correct permissions.')
        return 0
    except elastic_transport.ConnectionError:
        print('ERROR: Connection error. Make sure IP address/domain for ElasticSearch instance is valid.')
        return 0
    except elastic_transport.ConnectionTimeout:
        print('ERROR: Connection timed out. Make sure IP address/domain and port for ElasticSearch are correct.')
        return 0

    if es:
        # Connection to ElasticSearch succeeded. Create the index:
        create_index(es)
        # Index is now created (or already existed)
        # Start capture
        capture(es, capture_mode, interface, pcapfile, bpf, packet_count)


if __name__ == '__main__':
    arguments = parse_arguments()
    main(arguments)
