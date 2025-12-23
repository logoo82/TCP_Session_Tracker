from scapy.all import *

protocols = {1:'ICMP', 6:'TCP', 17:'UDP'}

#패킷이 캡처될 때마다 실행되는 함수
#IP 계층에서 송·수신 주소와 프로토콜 번호(TCP: 6, UDP: 17)을 추출
def monitor_packet(pkt):
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    proto = pkt[IP].proto
    
    if proto in protocols:
        print(f"protocols: [{protocols[proto]}] / {src_ip} -> {dst_ip}")

        if proto == 1:
            print(f"type:{pkt[ICMP].type}, code:{pkt[ICMP].code}")
        
        #패킷이 TCP 프로토콜일 경우 포트 번호(sport, dport)와 플래그 출력(SYN/ACK 등)
        if proto == 6 and TCP in pkt:
            print(f"[TCP] Port: {pkt[TCP].sport} -> {pkt[TCP].dport} | Flags: {pkt[TCP].flags}")

def main(filter):
    #실제 패킷 캡처를 수행하는 함수
    #패킷을 캡처할 때 마다 monitor_packet함수 호출
    sniff(filter=filter, prn=monitor_packet, count=0)


#IP 패킷만 수집하도록 필터링
print("Sniffing Start!!!")
filter = 'tcp'
main(filter)