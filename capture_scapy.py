from scapy.all import *


def get_url_from_payload(payload):
    http_header_regex = r"(?P<name>.*?): (?P<value>.*?)\r\n"
    start = payload.index(b"GET ") +4
    end = payload.index(b" HTTP/1.1")
    url_path = payload[start:end].decode("utf8")
    http_header_raw = payload[:payload.index(b"\r\n\r\n") + 2 ]
    http_header_parsed = dict(re.findall(http_header_regex, http_header_raw.decode("utf8")))
    url = http_header_parsed["Host"] + url_path + "\n"
    return url




def parse_pcap(pcap_path, urls_file):
    pcap_flow = rdpcap(pcap_path)
    sessions = pcap_flow.sessions()
    urls_output = open(urls_file, "wb")
    for session in sessions:
        for packet in sessions[session]:
            try:
                if packet[TCP].dport == 80:
                    payload = bytes(packet[TCP].payload)
                    url = get_url_from_payload(payload)
                    urls_output.write(url.encode())
            except Exception as e:
                pass
    urls_output.close()


scapy_cap = rdpcap('net.pcap', count=100)
for packet in scapy_cap:
    try:
        print(packet.getlayer(TCP).payload)
    except:
        print("Err")