#! /usr/bin/env python3
# https://thepacketgeek.com/scapy/building-network-tools/part-09/
from scapy.all import DNS, DNSQR, DNSRR, IP, send, sniff, sr1, UDP
#import asyncio
#import socket
IFACE = "Realtek PCIe GBE Family Controller #2"   # Or your default interface
DNS_SERVER_IP = "192.168.1.1"  # Your local IP

BPF_FILTER = f"udp port 53 and ip dst {DNS_SERVER_IP}"


def dns_responder(local_ip: str):

    def forward_dns(orig_pkt: IP):
        print(f"Forwarding: {orig_pkt[DNSQR].qname}")
        response = sr1(
            IP(dst='8.8.8.8')/
                UDP(sport=orig_pkt[UDP].sport)/
                DNS(rd=1, id=orig_pkt[DNS].id, qd=DNSQR(qname=orig_pkt[DNSQR].qname)),
            verbose=0,
        )
        resp_pkt = IP(dst=orig_pkt[IP].src, src=DNS_SERVER_IP)/UDP(dport=orig_pkt[UDP].sport)/DNS()
        resp_pkt[DNS] = response[DNS]
        response[IP]
        if "facebook.com" in str(orig_pkt["DNS Question Record"].qname):
            resp_pkt.show()
            response.show()

        send(resp_pkt, verbose=0)
        return f"Responding to {orig_pkt[IP].src}"

    def get_response(pkt: IP):
        if (
            DNS in pkt and
            pkt[DNS].opcode == 0 and
            pkt[DNS].ancount == 0
        ):
            if "facebok.com" in str(pkt["DNS Question Record"].qname):
                spf_resp = IP(dst=pkt[IP].src)/UDP(dport=pkt[UDP].sport, sport=53)/DNS(id=pkt[DNS].id,ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname, rdata=local_ip)/DNSRR(rrname="trailers.apple.com",rdata=local_ip))
                send(spf_resp, verbose=0, iface=IFACE)
                #return f"Spoofed DNS Response Sent: {pkt[IP].src}"
                #local_host = "127.0.0.1"
                #spf_resp = IP(dst=pkt[IP].src)/UDP(dport=pkt[UDP].sport, sport=53)/DNS(id=pkt[DNS].id,ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname, rdata=local_ip)/DNSRR(rrname="trailers.apple.com",rdata=local_ip))
                #spf_resp = IP(dst=local_host)/UDP(dport=pkt[UDP].sport, sport=53)/DNS(id=pkt[DNS].id,ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname, rdata=local_host))#/DNSRR(rrname="facebook.com",rdata=local_host))
                spf_resp.show()

                send(spf_resp, verbose=2, iface=IFACE)
                return f"Spoofed DNS Response Sent: {pkt[IP].src}"

            else:
                # make DNS query, capturing the answer and send the answer
                return forward_dns(pkt)

    return get_response

sniff(filter=BPF_FILTER, prn=dns_responder(DNS_SERVER_IP), iface=IFACE)

#from dnslib import *
#from dnslib import server
#
## Customize the port and address of your local server to suit your needs (e.g. localhost -> 0.0.0.0)
#local_addr = 'localhost'
#local_port = 53
#
## Customize the address and port of the external DNS server
#external_dns_server_addr = DNS_SERVER_IP#'192.168.20.1'
#external_dns_server_port = 53
#
#class SpecialResolver:
#    def resolve(self, request, handler):
#        d = request.reply()
#        q = request.get_q()
#        q_name = str(q.qname)
#
#        # Custom response for 'pfghmj.com' and 'carvezine.com'
#        if 'google.com' in q_name or 'carvezine.com' in q_name:
#            # Answers
#            d.add_answer(*RR.fromZone("pfghmj.com 136 A 239.136.254.248"))
#            d.add_answer(*RR.fromZone("pfghmj.com 136 A 98.45.51.8"))
#            d.add_answer(*RR.fromZone("pfghmj.com 136 A 70.58.60.21"))
#            d.add_answer(*RR.fromZone("pfghmj.com 136 A 165.203.213.15"))
#            d.add_answer(*RR.fromZone("pfghmj.com 136 A 210.53.31.233"))
#
#            # Authoritative Name Servers
#            d.add_auth(*RR.fromZone("pfghmj.com 128505 NS ns1.mecadasome.com"))
#            d.add_auth(*RR.fromZone("pfghmj.com 128505 NS ns2.mecadasome.com"))
#
#            # Additional Records
#            d.add_ar(*RR.fromZone("ns1.mecadasome.com 157982 A 45.116.79.94"))
#            d.add_ar(*RR.fromZone("ns2.mecadasome.com 157982 A 45.116.79.94"))
#
#        # Recursively query another DNS server for other domains
#        else:
#            a = DNSRecord.parse(DNSRecord.question(q_name).send(external_dns_server_addr, external_dns_server_port))
#            for rr in a.rr:
#                d.add_answer(rr)
#        return d
#
#r = SpecialResolver()
#s = server.DNSServer(r, port=local_port, address=local_addr)
#s.start_thread()
#
#while True:
#    pass

# Use scapy2.3.1+ from pip (secdev original) or for Python3 use the
# https://github.com/phaethon/scapy Scapy3K version.
#
# Example DNS server that resolves NAME.IPV4.example.com A record
# requests to an A:IPV4 response.
#
# $ dig test.12.34.56.78.example.com -p 1053 @127.0.0.1 +short
# 12.34.56.78

#from scapy.all import DNS, DNSQR, DNSRR, dnsqtypes
#from socket import AF_INET, SOCK_DGRAM, socket
#from traceback import print_exc
#
#sock = socket(AF_INET, SOCK_DGRAM)
#sock.bind(('0.0.0.0', 1053))
#
#while True:
#    request, addr = sock.recvfrom(4096)
#
#    try:
#        dns = DNS(request)
#        assert dns.opcode == 0, dns.opcode  # QUERY
#        assert dnsqtypes[dns[DNSQR].qtype] == 'A', dns[DNSQR].qtype
#        query = dns[DNSQR].qname.decode('ascii')  # test.1.2.3.4.example.com.
#        #head, domain, tld, tail = query.rsplit('.', 3)
#        print(query)
#        print(dns)
#        #assert domain == 'example' and tld == 'com' and tail == ''
#        #head = head.split('.', 1)[-1]  # drop leading "prefix." part
#        #print(head)
#        response = sr1(
#            IP(dst='8.8.8.8')/
#                UDP(sport=orig_pkt[UDP].sport)/
#                DNS(rd=1, id=orig_pkt[DNS].id, qd=DNSQR(qname=orig_pkt[DNSQR].qname)),
#            verbose=0,
#        )
#        #response = DNS(
#        #    id=dns.id, ancount=1, qr=1,
#        #    an=DNSRR(rrname=str(query), type='A', rdata=str('127.0.0.1'), ttl=1234))
#        print(repr(response))
#        #sock.sendto(bytes(dns),addr)
#        sock.sendto(bytes(response), addr)
#
#    except Exception as e:
#        print('')
#        print_exc()
#        print('garbage from {!r}? data {!r}'.format(addr, request))
