#! /usr/bin/env python3
# https://thepacketgeek.com/scapy/building-network-tools/part-09/
from scapy.all import DNS, DNSQR, DNSRR, IP, send, sniff, sr1, UDP, ls, Ether
#import asyncio
#import socket
IFACE = "Realtek PCIe GBE Family Controller #2"   # Or your default interface
DNS_SERVER_IP = "192.168.1.1"  # Your local IP

BPF_FILTER = f"udp port 53 and ip dst {DNS_SERVER_IP}"


#************************ WEBSITE FILTERING ***************************
website_list = []
try:
    if False: #comment out reading in websites
        with open('csv.txt', newline='') as csvfile:
            count =0
            #read in lines from file

            lines = csvfile.readlines()
            sites = [line.strip() for line in lines]
            print("in web filter")
            # remove header lines from array
            sites = sites[lines_in_header:]
            for site in sites:


                # Data process site to be an array of arrays of site info
                site = site.replace('"', '')
                site=site.split(",")

                #Format for site = [id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter]
                #example site =
                #['1068863', '2021-03-15 14:22:05', 'http://59.99.143.111:33869/bin.sh',
                #'offline', 'malware_download', '32-bit', 'elf', 'mips', 'https://urlhaus.abuse.ch/url/1068863/', 'geenensp']

                if site[3] == "online":
                    website_list.append(site[2])
except:
    print("[ ERROR ] Could not read in blocked websites. ")
    exit(-1)

# websites that we can visit to test
test_list = ["www.facebook.com","facebook.com",
      "dub119.mail.live.com","www.dub119.mail.live.com",
      "www.gmail.com","gmail.com"]

print("Sites to test this with: ")
for site in test_list:
    print(site)
    website_list.append(site)
#************************ END WEBSITE FILTERING ***************************
def dns_responder(local_ip: str):

    def forward_dns(orig_pkt: IP):
        # Get the response from the Google DNS server.
        # (If we use our default DNS server we get recursion)
        response = sr1(
            IP(dst='8.8.8.8')/
                UDP(sport=orig_pkt[UDP].sport)/
                DNS(rd=1, id=orig_pkt[DNS].id, qd=DNSQR(qname=orig_pkt[DNSQR].qname)),
            verbose=0,
        )

        # Make the response packet to send to the client.
        # Put in the IP of the default DNS server.
        resp_pkt = IP(dst=orig_pkt[IP].src, src=DNS_SERVER_IP)/UDP(dport=orig_pkt[UDP].sport)/DNS()
        resp_pkt[DNS] = response[DNS]

#        CODE USED FOR EXAMPLE OUTPUT
#        if "facebook.com" in str(orig_pkt["DNS Question Record"].qname):
#            print("****************** FACEBOOK PACKET BELOW ******************")
#            resp_pkt.show()

        send(resp_pkt, verbose = 0)
        return f"Forwarded: {orig_pkt[DNSQR].qname}\n"
    def get_response(pkt: IP):
        # First check if it is a
        #  DNS request packet
        if (
            DNS in pkt and
            pkt[DNS].opcode == 0 and
            pkt[DNS].ancount == 0
        ):
            # Init site in banned list
            # to be False.
            site_in_list = False

            # Find out if the site is
            # in the banned list.
            for site in website_list:
                if site in str(pkt["DNS Question Record"].qname):
                    site_in_list = True

            # If the site is in the banned list
            # spoof the packet.
            if site_in_list:

                # Create a spoofed packet
                spf_resp = IP(src = DNS_SERVER_IP, dst = pkt[IP].src)/UDP()/DNS(an = DNSRR(rrname = pkt[DNSQR].qname, ttl=299, rdata = '127.0.0.1') )

                # Print for demo purposes
                print("******************** SITE IN BANNED LIST *****************")
                print("****************** SPOOFED PACKET BELOW ******************")
                spf_resp.show()

                # Send spoofed packet
                send(spf_resp, verbose=2, iface=IFACE)

                return f"Spoofed DNS Response Sent: {pkt[IP].src}"

            else:
                # Send the real response packet
                return forward_dns(pkt)

    return get_response

sniff(filter=BPF_FILTER, prn=dns_responder(DNS_SERVER_IP), iface=IFACE)

