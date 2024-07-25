## BOB 13기 - 이경문 멘토님 - 네트워크 과제

# 과제
송수신되는 packet을 capture하여 중요 정보를 출력하는 C/C++ 기반 프로그램을 작성하라.

1. Ethernet Header의 src mac / dst mac
2. IP Header의 src ip / dst ip
3. TCP Header의 src port / dst port
4. Payload(Data)의 hexadecimal value(최대 20바이트까지만)

# 실행
```
syntax: pcap-test <interface>
sample: pcap-test wlan0
```

# 상세
- TCP packet이 잡히는 경우 "ETH + IP + TCP + DATA" 로 구성이 된다. 이 경우(TCP packet이 잡혔다고 판단되는 경우만)에만 1~4의 정보를 출력하도록 한다(Data의 크기가 0여도 출력한다).
- 각각의 Header에 있는 특정 정보들(mac, ip, port)를 출력할 때, 노다가(packet의 시작위치로부터 일일이 바이트 세어 가며)로 출력해도 되는데 불편함.
- 이럴 때 각각의 Header 정보들이 structure로 잘 선언한 파일이 있으면 코드의 구성이 한결 간결해진다. 앞으로 가급적이면 네트워크 관련 코드를 작성할 할 때에는 libnet 혹은 자체적인 구조체를 선언하여 사용하도록 한다.
- http://packetfactory.openwall.net/projects/libnet > Latest Stable Version: 1.1.2.1 다운로드(libnet.tar.gz) > include/libnet/libnet-headers.h
- libnet-headers.h 안에 있는 본 과제와 직접적으로 관련된 구조체들 :
- -  struct libnet_ethernet_hdr (479 line)
- - struct libnet_ipv4_hdr (647 line)
- - struct libnet_tcp_hdr (1519 line)

- pcap-test 코드를 skeleton code으로 하여 과제를 수행해야 하며, pcap_findalldevs, pcap_compile, pcap_setfilter, pcap_lookupdev, pcap_loop API는 사용하지 않는다(인터넷에 돌아다니는 코드에 포함되어 있는 함수들이며, 본 함수들이 과제의 코드에 포함되는 경우 과제를 베낀 것으로 간주함).

- Dummy interface를 이용하여 디버깅을 쉽게할 수 있는 방법을 알면 과제 수행에 도움이 된다.

# 결과
```
98 bytes captured
Ethernet Header
    | - Soucre Information
       | - Source IP Address       : 142.251.42.206
       | - Source MAC Address      : 00:50:56:F8:9C:0D 
       | - Source Port             : 0
       | - Protocol                : 1
    |   
    | - Desination Information
       | - Destination IP Address  : 192.168.147.131
       | - Destination MAC Address : 00:0C:29:02:59:2C 
       | - Destination Port        : 40428
    |    
    | - Payload (first 20 bytes):
00 00 9d ec ab e1 00 02 8c 74 a2 66 00 00 00 00 bd 81 0b 00
```