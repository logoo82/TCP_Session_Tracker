from scapy.all import *

#세션을 담을 Dictonary
sessions = {}
#세션의 index 번호
flow_cnt = 1

#패킷이 캡처될 때마다 실행되는 함수
#IP 계층에서 송·수신 주소와 포트, flag들을 추출
def monitor_packet(pkt):
    global flow_cnt
    
    if IP in pkt and TCP in pkt:    
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        flags = pkt[TCP].flags
        
        session_key = tuple(sorted([ (src_ip, src_port), (dst_ip, dst_port)]))
        
        if session_key not in sessions:
            
            display_flow = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            
            sessions[session_key] = {
                'id': flow_cnt,
                'flow': display_flow,
                'status': 'Active',
                'packets': []
            }
            print(f"{flow_cnt}) {sessions[session_key]['flow']}")
            flow_cnt += 1
        
        sessions[session_key]['packets'].append(pkt)
        
        if 'F' in flags or 'R' in flags:
            sessions[session_key]['status'] = 'Closed'


def main(filter):
    #실제 패킷 캡처를 수행하는 함수
    #패킷을 캡처할 때 마다 monitor_packet함수 호출
    sniff(filter=filter, prn=monitor_packet, count=0)


#TCP 패킷만 수집하도록 필터링
filter = 'tcp'
print("Sniffing Start")
main(filter)