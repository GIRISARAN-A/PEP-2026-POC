## 1) Open the PCAP in Wireshark

Open `5.pcap` in Wireshark.

<img width="1856" height="497" alt="Image" src="https://github.com/user-attachments/assets/9a57a574-0449-4194-8e8b-acbd05d179eb" />

First, do not try to read every packet.
Just look for:

* repeated IP pairs
* unusual protocols
* packets carrying readable text
* long packet sequences


## 2) Find the important conversation

You will notice one suspicious pair communicating a lot:

* `192.168.1.100`
* `192.168.1.200`

That is the flow you should focus on.

### What to write

> During initial inspection, the most suspicious communication was found between `192.168.1.100` and `192.168.1.200`, so that stream was selected for deeper analysis.


## 3) Check UDP traffic first

Apply this filter in Wireshark:

```wireshark
udp
```

<img width="902" height="308" alt="Image" src="https://github.com/user-attachments/assets/42bdabf3-c8cd-427d-a6aa-c96a5ec723c4" />


Now inspect the UDP packets between those two IPs.

You will see human-readable messages.
Among them, two packets contain Base64-looking strings.


<img width="1411" height="483" alt="Image" src="https://github.com/user-attachments/assets/a1633433-b85e-477c-bab8-8207b6474bcb" />


Important strings:

```text
Ujl0IUptNExhQEJxWGUyUG8jV2MlVXlOczdEa0h2WmY=
TGtKaEdmRHNBelhjVmJObQ==
```

### Why this matters

When you see text like this in a PCAP, it usually means:

* encoded data
* key material
* hidden clue

### What to write

> The UDP stream contained several readable messages. Two of them included Base64-encoded values, which suggested they could be cryptographic material.


## 4) Decode the Base64 values

Now decode both strings using CyberChef or Python.

### Python example

```python
import base64

s1 = "Ujl0IUptNExhQEJxWGUyUG8jV2MlVXlOczdEa0h2WmY="
s2 = "TGtKaEdmRHNBelhjVmJObQ=="

print(base64.b64decode(s1))
print(base64.b64decode(s2))
```

### Output

```text
b'R9t!Jm4La@BqXe2Po#Wc%UyNs7DkHvZf'
b'LkJhGfDsAzXcVbNm'
```

So you get:

* first value = **32 bytes** → AES key
* second value = **16 bytes** → IV

### Beginner understanding

* **Key** = main secret used for decryption
* **IV** = extra value used in CBC mode

### What to write

> Decoding the Base64 strings revealed a 32-byte AES key and a 16-byte IV, strongly indicating that the hidden content was encrypted with AES-CBC.


## 5) Now inspect ICMP traffic

Apply this filter:

```wireshark
icmp
```

Now check ICMP packets between:

* `192.168.1.100`
* `192.168.1.200`

You will see many ICMP echo packets carrying payload data.

These are not just normal pings.
They contain binary data.

### Important observation

There are a **large number of ICMP packets**, and each one carries part of the hidden data.

### What to write

> After recovering the key material from UDP, attention shifted to ICMP traffic. A large sequence of ICMP echo packets between the same hosts was found carrying non-empty binary payloads, suggesting that the encrypted data was fragmented across these packets.

## 6) Extract the ICMP payloads

Now the practical job is:

* take the payload from each relevant ICMP packet
* keep them in packet order
* join them together into one binary blob

### Beginner idea

Think of each ICMP packet like one piece of a broken file.
When all pieces are joined in order, the full encrypted file is rebuilt.


## 7) Decrypt the rebuilt data

Use:

* AES
* CBC mode
* recovered key
* recovered IV

### Python example

This is the practical script idea:

```python
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
```
<img width="248" height="25" alt="Image" src="https://github.com/user-attachments/assets/6f9bd8e5-3108-43b3-9935-02426f12c7d2" />

---

## 8) Open the recovered file

After decryption, the output starts with:

```text
89 50 4E 47
```

That means it is a **PNG file**.

Open it, and the flag is inside the image.

---

# Final flag


<img width="524" height="499" alt="Image" src="https://github.com/user-attachments/assets/e45d6871-c43f-4b8a-9650-da67bf21d6be" />

```text
flag{d34d_p4ck3ts_t3ll_n0_t4l3s_0x28934}
```

---

# What to write in your writeup

You can write this directly:

## Analysis

1. Opened the PCAP in Wireshark and inspected overall traffic.
2. Identified suspicious communication between `192.168.1.100` and `192.168.1.200`.
3. Inspected UDP packets and found two Base64-encoded strings in the payload.
4. Decoded them to recover a 32-byte AES key and a 16-byte IV.
5. Investigated ICMP traffic between the same hosts and found many packets carrying binary payloads.
6. Extracted and concatenated the ICMP payloads in packet order.
7. Decrypted the reconstructed blob using AES-CBC with the recovered key and IV.
8. The decrypted output was a PNG image containing the flag.

---

# Only necessary screenshots

Take these for the writeup:

## 1. Wireshark main packet view

Show the overall capture.

## 2. UDP packet with readable text + Base64

Show where the encoded string appears.

## 3. Base64 decode result

Show the key and IV recovery.

## 4. ICMP filtered view

Show many ICMP packets between the two hosts.

## 5. ICMP packet bytes pane

Show that ICMP contains binary payload.

## 6. Decryption script/output

Show the recovered PNG creation.

## 7. Final image with flag

This is the proof.

---

# Very simple explanation for beginner

This challenge works like this:

* **UDP** gives you the **decryption secret**
* **ICMP** carries the **encrypted hidden file**
* combine ICMP payloads
* decrypt using the UDP values
* get the image
