The flag is found!
   
 **Flag:** **JCOE_CTF{tcp_s3qu3nc3_st3g0}**  
   
 The hidden technique here is **TCP Sequence Number Steganography** — a clever way to hide data inside network packets. Here's your full beginner-friendly writeup guide:  
   
 **Finding the Flag in a PCAP**  
   
## Step 1 — Open and Explore the PCAP   
   
 The first thing you do with any PCAP challenge is figure out what's inside. Tools you'd normally use:  
- **Wireshark** (GUI) — drag and drop your .pcap file in  
- **tshark** (terminal) — tshark -r 4.pcap  
   
 When you open it, you'll notice **293 packets** total, and two types of payloads:  
- Packets labeled **Data000** , **Data001** ,  **Data002** **...** (from port 13337 → 8080)  
- Packets labeled **Noise0** , **Noise5**, **Noise10** **...** (random ports, random data)  
   
 The "Noise" packets are red herrings — ignore them. The "Data" packets are your focus.
 
 ## Step 2 — Isolate the Data Packets  
   
 In Wireshark, filter for the data stream:  
  ` 
 tcp.srcport == 13337  
   `
    
 <img width="932" height="375" alt="Image" src="https://github.com/user-attachments/assets/b08b9af3-ac46-4a47-a79c-7704e3a5920f" />

   
 This gives you **224 packets** all going from port 13337 to port 8080. These are all labeled DataXXX.  
## Step 3 — Look at the TCP Sequence Numbers (The Key Insight!)  
   
 Click on any Data packet and expand the **TCP layer** in Wireshark. Look at the   **Sequence Number** field.  
 
<img width="932" height="446" alt="Image" src="https://github.com/user-attachments/assets/e0e9bbb4-dbe2-442f-80fb-75a03ea02a94" />
   
 Next packet,  
 <img width="394" height="18" alt="Image" src="https://github.com/user-attachments/assets/323f4c39-0918-4aa8-8dbf-72d69352d4d0" />

   
 Next,  
<img width="394" height="18" alt="Image" src="https://github.com/user-attachments/assets/01e09dae-1625-46c2-b010-a86eec38914b" />

   
 Then,  
 <img width="394" height="18" alt="Image" src="https://github.com/user-attachments/assets/ba088b72-893e-4dab-8a6f-c1e72cf0793f" />
   
 Then,  
 <img width="394" height="18" alt="Image" src="https://github.com/user-attachments/assets/0361bc8c-d06c-439d-8436-62eead960242" />
   
 Same like ,  
   
 W.k.t  
`1byte = 8bits`  
   
You'll notice a pattern — the sequence numbers follow a formula of 5,000,000 + (packet_index * 1000) but some end in 000 and some end in 001:  
   

| Packet  | Sequence Number | Last 3 digits      |
|---------|-----------------|--------------------|
| Data000 | 5,000,000       | 000 → **bit = 0**  |
| Data001 | 5,001,001       | 001 → **bit = 1**  |
| Data002 | 5,002,000       | 000 → **bit = 0**  |
| Data003 | 5,003,000       | 000 → **bit = 0**  |
| Data004 | 5,004,001       | 001 → **bit = 1**  |
 
    
   
 This is **LSB (Least Significant Bit) steganography** — the +1 offset encodes a hidden 1 bit, and no offset encodes a 0 bit!  
   
 This will form 01001010  
   
## Step 4 — Extract the Hidden Bits  
   
 Go through all 224 Data packets in order and write down:  
- If seq % 1000 == 1 → bit is 1  
- If seq % 1000 == 0 → bit is 0  
   
 This gives you 224 bits total.
## Step 5 — Convert Bits to Characters  
   
 Group the 224 bits into groups of 8 (one byte each), then convert each group from binary to ASCII:  
```
 01001010 → 74 → 'J'  
   
  01000011 → 67 → 'C'  
   
  01001111 → 79 → 'O'  
   
  01000101 → 69 → 'E'  
   
  ...  

```
    
   
 The full decoded message spells out the flag!  
 **The Flag**  
  
 `JCOE_CTF{tcp_s3qu3nc3_st3g0}`  
  
    
   
 The flag name itself tells the story: **TCP sequence number steganography** (tcp_s3qu3nc3_st3g0).  
   
 
   
 The trick was recognizing that the sequence numbers were **slightly off** (+1) in some packets — that tiny difference was the hidden binary message.  
   
 Here's your interactive decoder! It already has your PCAP's bits loaded and decoded.  
   
 Here's the exact Python script version of the decoder:  
 ```python3
**============================================================**  
 #  Bits → ASCII Flag Decoder  
   
  #  Step 5 of the TCP Sequence Number Steganography writeup  
   
  # ============================================================  
   
    
   
  def decode_bits_to_ascii(raw_bits):  
   
      # Step 1: Strip everything that isn't 0 or 1  
   
      bits = ''.join(c for c in raw_bits if c in '01')  
   
    
   
      if len(bits) < 8:  
   
          print("ERROR: Need at least 8 bits to decode anything.")  
   
          return  
   
    
   
      # Step 2: Warn if bits don't divide evenly into 8  
   
      extra = len(bits) % 8  
   
      if extra != 0:  
   
          print(f"WARNING: {extra} leftover bit(s) at the end — they will be ignored.")  
   
       
   
      usable_bits = bits[:len(bits) - extra] if extra else bits  
   
      total_chars = len(usable_bits) // 8  
   
    
   
      print(f"\n{'='*55}")  
   
      print(f"  Total bits   : {len(bits)}")  
   
      print(f"  Characters   : {total_chars}")  
   
      print(f"{'='*55}")  
   
      print(f"  {'#':<4} {'8-bit group':<12} {'Decimal':<10} {'ASCII'}")  
   
      print(f"  {'-'*4} {'-'*12} {'-'*10} {'-'*5}")  
   
    
   
      result = ''  
   
    
   
      for i in range(0, len(usable_bits), 8):  
   
          group   = usable_bits[i:i+8]          # grab 8 bits  
   
          decimal = int(group, 2)                # binary → decimal  
   
          char    = chr(decimal) if 32 <= decimal <= 126 else '?'  
   
          result += char  
   
          char_num = i // 8 + 1  
   
          print(f"  {char_num:<4} {group:<12} {decimal:<10} {char}")  
   
    
   
      print(f"{'='*55}")  
   
      print(f"\n  FLAG: {result}")  
   
      print(f"{'='*55}\n")  
   
      return result  
   
    
   
    
   
  # -------------------------------------------------------  
   
  # Paste your bits below (spaces, commas, newlines are ok)  
   
  # -------------------------------------------------------  
   
  bits = """  
   
  01001010 01000011 01001111 01000101 01011111  
   
  01000011 01010100 01000110 01111011 01110100  
   
  01100011 01110000 01011111 01110011 00110011  
   
  01110001 01110101 00110011 01101110 01100011  
   
  00110011 01011111 01110011 01110100 00110011  
   
  01100111 00110000 01111101  
   
  """  
   
    
   
  decode_bits_to_ascii(bits)  
   
```
   
 **Output you'll see:**  
   
   <img width="570" height="834" alt="Image" src="https://github.com/user-attachments/assets/d6de38c4-ff5d-494d-8b5a-65556f2909dd" />

 **How to use it for any future CTF challenge:**  
 
1. Replace the bits = """ ... """ string with your new bits  
2. Run with python3 decoder.py  
3. Spaces, newlines, and commas in your bit string are all fine — the script strips them out automatically  
4. If you get ? characters, your bits might be in a different order (try reversing each 8-bit group — some challenges use LSB-first instead of MSB-first)
5. 
 **How to use it:**
   
6. The bits from your PCAP are pre-loaded — you can see the flag decoded instantly in the green box  
7. Paste any new bits from a different challenge and hit **Decode bits → ASCII**  
8. The table shows every step: the 8-bit group → decimal number → ASCII character  
9. Leftover bits (if total isn't divisible by 8) are automatically ignored
10. 
 **What the decoder does under the hood:**
   
- Strips out everything that isn't a 0 or 1 (spaces, commas, newlines are all fine to paste in)  
- Splits into groups of 8 bits  
- Converts each group from binary to a decimal number (e.g. 01001010 → 74)  
- Looks up that decimal in the ASCII table → character (74 → J)  
- Repeats until all bits are decoded → flag!  
   
 You can also click **Load PCAP sample** to reload your original bits at any time.  
