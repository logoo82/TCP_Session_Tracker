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
            
            display_flow = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} "
            
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
    #Ctrl+c를 눌렀을 때 연결된(연결되었던) 세션들 나열
    try:
        #실제 패킷 캡처를 수행하는 함수
        #패킷을 캡처할 때 마다 monitor_packet함수 호출
        sniff(filter=filter, prn=monitor_packet, count=0)    
    except KeyboardInterrupt:
        pass
    
    print("\nSession List")
    
    sorted_sessions = sorted(sessions.values(), key=lambda x: x['id'])
    
    for session in sorted_sessions: 
        print(f"{session['id']}) {session['flow']} ({session['status']})")
    
    #선택한 Flow의 스트림 나열
    while True:
        try:
            input_num = input("\nSelect Session ID(or 'exit' to quit): ")
            if input_num.lower() == 'exit':
                break
            
            input_num_id = int(input_num)
            search_session = None
            
            for s in sessions.values():
                if s['id'] == input_num_id:
                    search_session = s
                    break
                    
            if search_session:
                print(f"\nTCP stream for [{input_num_id}]")

                packets = search_session['packets']
                current_src = None
                direction_cnt = 0
                
                for pkt in packets:
                    if TCP not in pkt:
                        continue
                    
                    if pkt[IP].src != current_src:
                        direction_cnt += 1
                        current_src = pkt[IP].src
                        print(f"#{direction_cnt}")
                    
                    seq = pkt[TCP].seq
                    ack = pkt[TCP].ack
                    flags = pkt[TCP].flags
                    payload_len = len(pkt[TCP].payload)
                    
                    if 'S' in flags:
                        print(f"[SYN SEQ: {seq}:{seq+1}]")
                    elif 'F' in flags:
                        print(f"[FIN SEQ: {seq}:{seq+1}]")
                    elif payload_len > 0:
                        print(f"[SEQ: {seq}:{seq+payload_len}]")
                    elif 'A' in flags:
                        print(f"[ACK: {ack}]")
            else:
                print("Invalid Session ID")
        except ValueError:
            print("Enter a valid number")
        except Exception as e:
            print(f"Error: {e}")
                
            


#TCP 패킷만 수집하도록 필터링
filter = 'tcp'
print("Sniffing Start, Press Ctrl+c to view Session List")
main(filter)