import struct
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

pcap_file = "5.pcap"

def parse_pcap(filename):
    packets = []
    with open(filename, "rb") as f:
        f.read(24)  # global header
        while True:
            hdr = f.read(16)
            if not hdr:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", hdr)
            data = f.read(incl_len)
            packets.append(data)
    return packets

def parse_ipv4(pkt):
    if len(pkt) < 20:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    proto = pkt[9]
    src = ".".join(map(str, pkt[12:16]))
    dst = ".".join(map(str, pkt[16:20]))
    return proto, src, dst, pkt[ihl:]

def parse_icmp(payload):
    if len(payload) < 8:
        return None
    return payload[8:]  # skip ICMP header

packets = parse_pcap(pcap_file)

icmp_blob = b""

for pkt in packets:
    parsed = parse_ipv4(pkt)
    if not parsed:
        continue
    proto, src, dst, payload = parsed
    if proto == 1 and src == "192.168.1.100" and dst == "192.168.1.200":
        icmp_payload = parse_icmp(payload)
        if icmp_payload:
            icmp_blob += icmp_payload

key = b"R9t!Jm4La@BqXe2Po#Wc%UyNs7DkHvZf"
iv  = b"LkJhGfDsAzXcVbNm"

cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
decryptor = cipher.decryptor()
plaintext = decryptor.update(icmp_blob) + decryptor.finalize()

with open("recovered.png", "wb") as f:
    f.write(plaintext)

print("Recovered file written as recovered.png")
