import dpkt
import socket
import sys

def inet_to_str(inet):
    #First tries ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def tcp_flags(tcp):
    if (tcp.flags & dpkt.tcp.TH_SYN) and (int(tcp.flags & dpkt.tcp.TH_ACK) == 0):
        if ip.src not in syn_scans:
            syn_scans[srcIP] = {'SYN': 0, 'SYN+ACK': 0}
        syn_scans[srcIP]['SYN'] += 1
    if (tcp.flags & dpkt.tcp.TH_SYN) and (tcp.flags & dpkt.tcp.TH_ACK):
        if ip.dst not in syn_scans:
            syn_scans[dstIP] = {'SYN': 0, 'SYN+ACK': 0}
        syn_scans[dstIP]['SYN+ACK'] += 1

def test(pcap_filename):
    """Open up a pcap file and print out potential SYN Scan attacks"""
    with open(pcap_filename, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)

        syn_scans = dict()
        #print("scanning packets now!")
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except (dpkt.dpkt.UnpackError, IndexError):
                continue

            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data

            if ip.p != dpkt.ip.IP_PROTO_TCP:
                continue

            srcIP = inet_to_str(ip.src)
            dstIP = inet_to_str(ip.dst)

            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                if (tcp.flags & dpkt.tcp.TH_SYN) and (tcp.flags & dpkt.tcp.TH_ACK == 0):
                    if srcIP not in syn_scans:
                        syn_scans[srcIP] = {'SYN': 0, 'SYN+ACK': 0}
                    syn_scans[srcIP]['SYN'] += 1
                if (tcp.flags & dpkt.tcp.TH_SYN) and (tcp.flags & dpkt.tcp.TH_ACK):
                    if dstIP not in syn_scans:
                        syn_scans[dstIP] = {'SYN': 0, 'SYN+ACK': 0}
                    syn_scans[dstIP]['SYN+ACK'] += 1

        for s in syn_scans.keys():
            if syn_scans[s]['SYN'] > ((syn_scans[s]['SYN+ACK'])*3):
                print(s)

if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print( "Use format: python detector.py filename.pcap")
        sys.exit(-1)
    test(sys.argv[1])