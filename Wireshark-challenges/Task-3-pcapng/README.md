## **Part 1 — Understand the Decoy Layer**  
### **Step 1: Open the file**  

* Open capture.pcap in Wireshark. 

At first glance, FTP traffic looks highly suspicious because it includes:  
* login credentials  
* file retrieval  
* readable text  
   
<img width="207" height="168" alt="Image" src="https://github.com/user-attachments/assets/797b3674-3bca-40be-bde7-27fb8343b3ae" />

   
### **Step 2: Filter FTP**  

#### Use display filter:  

`ftp ` 

   
<img width="1149" height="207" alt="Image" src="https://github.com/user-attachments/assets/c5d7cf5c-3359-499f-b21b-974088914bd0" />

Now locate the login session.  
#### Right click a packet:  

`Follow → TCP Stream`  
   
#### You will see:  
```
 220 Welcome to FTP server  
 USER admin  
 PASS supersecretpassword123  
 RETR confidential.txt  
```  
Then the downloaded content shows:  
Filter by `ftp-data`,  
You can see  
<img width="595" height="80" alt="Image" src="https://github.com/user-attachments/assets/dde1f1ee-2539-49af-ae50-ea668253f697" />
```bash
REDHERRING{th1s_1s_n0t_th3_fl4g}  
```
This is a fake evidence intentionally inserted to waste analyst time.  

## **Part 2 — Find the Real Covert Channel**  

### **Step 3: Switch to DNS**  

Apply:  
`dns`  
   
This reveals repeated DNS queries.  
**Why DNS is impotant**  
DNS is often abused for:  
malware beaconing, command & control, data exfiltration, covert tunneling because DNS is usually allowed through firewalls  

<img width="1321" height="419" alt="Image" src="https://github.com/user-attachments/assets/8bc4ebee-e408-4aac-92cf-77f1527fc486" />  



### **Step 4: Identify the malicious domain**  

Find the abnormal behaviour:  
`Click statics -> protocal hierarchy   `  

Do the above witthout any filters  
#### Snap:  
<img width="1180" height="411" alt="Image" src="https://github.com/user-attachments/assets/bffd8529-de1c-43b0-8f10-d7b41a8d88d5" />

Look for any abnormal protocols  
      * ICMP(ping request) will not send this much packets ,this is abnormal here and it may contain any content with in it.  
Filter by ICMP:  
Here,   
                     `id=0xc0de `  

* This is the manipulated content from the attacker,this may contain any ....  
* Look at each and every packet whose id is 0xc0de  
* Nothing is there  
Now,  
**Filter by dns**  
Look for repeated requests to:  
`data.evil-c2.net  `
   
This is the real attacker-controlled domain.  
<img width="1304" height="413" alt="Image" src="https://github.com/user-attachments/assets/b9339350-99c5-49ed-b9db-c36c22eafa0e" />

The suspicious packets are:  
```
 5c967e59f7c9.00.data.evil-c2.net  
 ae1c30048cac.01.data.evil-c2.net  
 2951d884d3d1.02.data.evil-c2.net  
 d5a428f4f901.03.data.evil-c2.net  
 d6f0edbdfaa1.04.data.evil-c2.net  
 99ff5b72a40e.05.data.evil-c2.net  
 138e0d565641.06.data.evil-c2.net  
```
**Data chunk**  
Example:  
`5c967e59f7c9 `  

   
This is the **actual payload fragment**.  
### Sequence index
#### Example:  

`00`  
   
This tells the receiver the **correct order**.  
**Attacker domain**  
`data.evil-c2.net`  
   
This is the **C2/exfiltration server domain**.  
   
### **Part 3 — Reconstruct the Hidden Payload**  
**Step 5: Extract only the first labels**   

Take only the payload chunks:  
```
 5c967e59f7c9  
 ae1c30048cac  
 2951d884d3d1  
 d5a428f4f901  
 d6f0edbdfaa1  
 99ff5b72a40e  
 138e0d565641  
```

**Step 6: Order using the index**  
Use the sequence IDs:
```  
00 → 06  
```
This ensures the reconstructed data is correct.  
**Step 7: Join the chunks**  
Final reconstructed payload:  
```
5c967e59f7c9ae1c30048cac2951d884d3d1d5a428f4f901d6f0edbdfaa199ff5b72a40e138e0d565641  
```
attacker splits data into small chunks  
places each chunk inside DNS labels  
Then,  
   
`Filter -> by -> icmp`  
   
**Filter it:**  
   
`click -> Edit -> Find packet -> string  `
   
Then,  
       
         Search for `c0de`   
   
Visit one by one  
Those packets will contains the string by splitting  
```   
S3cr3t_ICMP_K3y!  
```
Decode the values found its   

### final step crypt the foundvalues with the secret key

platform:

    <a href="https://www.dcode.fr/rc4-cipher">https://www.dcode.fr/rc4-cipher</a>

then,
   enter the key and decrypt it

snap:

<img width="795" height="413" alt="Image" src="https://github.com/user-attachments/assets/ba8bbc83-1cdc-4fed-8704-1335d109896d" />

the final flag,

```bash
DCxTCTF{ph4nt0m_dns_3xf1ltr4t10n_d3t3ct3d}
```
