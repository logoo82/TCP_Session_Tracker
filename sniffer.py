from scapy.all import *

#패킷이 캡처될 때마다 실행되는 함수
#IP 계층에서 송·수신 주소와 프로토콜 번호(TCP: 6, UDP: 17)을 추출
def monitor_packet(pkt):
    if IP in pkt and TCP in pkt:    
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        flags = pkt[TCP].flags


    print(f"[TCP] {src_ip}:{src_port} -> {dst_ip}:{dst_port} / flags = {flags}")

def main(filter):
    #실제 패킷 캡처를 수행하는 함수
    #패킷을 캡처할 때 마다 monitor_packet함수 호출
    sniff(filter=filter, prn=monitor_packet, count=0)


#TCP 패킷만 수집하도록 필터링
filter = 'tcp'
print("Sniffing Start")
main(filter)