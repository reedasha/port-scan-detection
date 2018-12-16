import pyshark
import sys

fileToScan = sys.argv[1]
cap = pyshark.FileCapture(fileToScan) 

#############live capture##########################
# capture = pyshark.LiveCapture(interface='wlp1s0')
# def packet_captured(packet):
#     print ('Just arrived:', packet)
# capture.apply_on_packets(packet_captured)

print('Reading input file', fileToScan, '...')

udpCount = 0
icmpCount = set()
nullScanCount = 0
xmasScanCount = 0
# for pkt in cap:
#     print(pkt)
portsNull = set()
portsXmas = set()
portsUdp = set()

sourceIp = cap[0].ip.src
destIp = cap[0].ip.dst
detected_port_scan = 'Unknown'

def print_conversation_header(pkt):
    try:
        global detected_port_scan
        global udpCount
        global xmasScanCount
        global nullScanCount
        global icmpCount
        protocol =  pkt.transport_layer
        if hasattr(pkt, 'icmp'):
            if hasattr(pkt.icmp, 'ip_src'):
                src_addr = pkt.icmp.ip_src
                dst_addr = pkt.icmp.ip_dst
                icmpInfo = '%s --> %s' % (src_addr, dst_addr)
                icmpCount.add(icmpInfo)
            if hasattr(pkt.ip, 'src'):
                # print only requests
                if pkt.icmp.type == '8':
                    src_addr = pkt.ip.src
                    dst_addr = pkt.ip.dst
                    icmpInfo = '%s --> %s' % (src_addr, dst_addr)
                    icmpCount.add(icmpInfo)
        if protocol == 'TCP':
            src_addr = pkt.ip.src
            src_port = pkt[pkt.transport_layer].srcport
            dst_addr = pkt.ip.dst
            flags = pkt[pkt.transport_layer].flags
            dst_port = pkt[pkt.transport_layer].dstport
            # print ('%s  %s:%s --> %s:%s flags: %s' % (protocol, src_addr, src_port, dst_addr, dst_port, flags))
            
            # if src_addr == sourceIp:
            if int(flags, 16) == 0:
                portsNull.add(dst_port)
                nullScanCount += 1
            if int(flags, 16) == 41:
                portsXmas.add(dst_port)
                xmasScanCount += 1
        if protocol == 'UDP':
            udpCount += 1
            src_addr = pkt.ip.src
            src_port = pkt.udp.srcport
            dst_addr = pkt.ip.dst
            dst_port = pkt.udp.dstport
            portsUdp.add(dst_port)

    except AttributeError as e:
        print('Invalid packet data. Not a TCP/UDP or IPV4', dir(pkt.ip))   
        pass

def print_summary():
    print('\n\t\t*************DETECTION SUMMARY*************\n')
    if len(icmpCount) > 0:
        print('\n\t\t*************ICMP DETECTION: %s*************\n' % len(icmpCount))
        for each in icmpCount:
            print('Detected ICMP ECHO REQUEST SOURCE IP:', each)
    if (xmasScanCount >= nullScanCount) and (xmasScanCount >= udpCount):
        largest = xmasScanCount
    elif (nullScanCount >= xmasScanCount) and (nullScanCount >= udpCount):
        largest = nullScanCount
    else:
        largest = udpCount

    if largest == xmasScanCount:
        detected_port_scan = 'XMAS_SCAN'
        ports = portsXmas
    if largest == nullScanCount:
        detected_port_scan = 'NULL_SCAN'
        ports = portsNull
    if largest == udpCount:
        detected_port_scan = 'UDP_SCAN'
        ports = portsUdp
    if largest == 0:
        detected_port_scan = 'unknown'
        ports = []
    print('\n', detected_port_scan, 'detected with the following IP\n')
    print('Source IP', sourceIp, 'and Destination IP', destIp, '\n')
    print(len(ports), 'ports have been scanned. The following ports have been scanned')
    print(ports)

cap.apply_on_packets(print_conversation_header, timeout=100)
print_summary()
cap.close()
