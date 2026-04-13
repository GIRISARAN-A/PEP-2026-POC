# Task 2-PCAP 

 *  Analyze the uploaded 2.pcap using Wireshark.  

**Tool Used**  

 *  Wireshark  

**Final Flag**  
```
   ctf{hidden_cname_masterpiece}  
```
   
* more fake **HTTP 200 OK responses**  
* hundreds of **decoy server logs**  
* random-looking **DNS numeric subdomains**  
* The real clue appears near the string:  
* target-challenge  
   
### Snap:  
<img width="1339" height="87" alt="Image" src="https://github.com/user-attachments/assets/30e2648f-cbfc-486e-9651-80e83fcdd762" />

The hidden payload appears as:  
```
637466377b68696464656e5f636e616d655f6d617374657270.696563657d.challenge.hidden  
```

This is **hex-encoded  data.**  

**Extracted Hex**  
```
6374667b68696464656e5f636e616d655f6d617374657270696563657d  
```

**Hex Decoded Output** 
```
ctf{hidden_cname_masterpiece}
```

### Step 1: Open the PCAP  
     
   Open the file in Wireshark:  

```
2.pcap  
```
<img width="1253" height="420" alt="Image" src="https://github.com/user-attachments/assets/1cbf860d-f4e5-42b4-8baa-9ed92ffee902" />


   
### Step 2: Check DNS Traffic
   
   Apply the display filter:  

`dns`  
   
<img width="1253" height="420" alt="Image" src="https://github.com/user-attachments/assets/93fad663-85c9-4829-8493-94c59c5c0aa4" />

These are **decoy DNS packets**

### Step 3: Search for Suspicious String  

Go to:  
`Edit → Find Packet → String ` 
   

<img width="1253" height="234" alt="Image" src="https://github.com/user-attachments/assets/05f4d5b8-39b6-4622-858d-d29e925329a3" />

Then,  
Search for:  

`target-challenge `

<img width="1341" height="531" alt="Image" src="https://github.com/user-attachments/assets/00d85284-0350-4b0e-bed4-0dfa0766cb4c" />


### Step 4: Inspect Packet Bytes

#### Open:  
~ Packet Details  
~ Packet Bytes  
~ You will notice a long hex string:  
 `6374667b... ` 

This is  hidden flag encoded in hex.  

<img width="1358" height="301" alt="Image" src="https://github.com/user-attachments/assets/c3da9825-dfbf-43b1-8baa-6ca50542b60a" />


**Step 5: Decode the Hex**  
Copy the hex string:  
```
6374667b68696464656e5f636e616d655f6d617374657270696563657d  
```

<img width="1079" height="398" alt="Image" src="https://github.com/user-attachments/assets/4f81028f-f2e6-483c-885e-e6fe150fafd4" />

#### Output:  

`ctf{hidden_cname_masterpiece}` 
   
