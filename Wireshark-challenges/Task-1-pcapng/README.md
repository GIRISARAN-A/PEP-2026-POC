**Task 1 - PCAPNG**  
    Analyze the given .pcapng file using wireshark and recover the hidden flag.  
   
    
  **Tool Used**  
              #   Wireshark  
   
  **Final Flag**  
  
  ``` 
  $JG1{p4cket_c4ptured}  
   ```
   
  **Step 1: Open the PCAPNG File**  
   
          1 Open **Wireshark**   
   
          2 Click **File → Open**  
   
          3 Select the provided 1.pcapng  
  
<img width="1411" height="623" alt="Image" src="https://github.com/user-attachments/assets/4c636526-32c3-4d62-bd2d-d74b4cd1ff2a" />

  
**Step 2: Check Protocol Statistics**  
    
  Go to **Statistics → Protocol Hierarchy**  
   
  This helps find what protocols are there.  
  <img width="1159" height="493" alt="Image" src="https://github.com/user-attachments/assets/e6ff8b3a-bb02-4a14-ab27-69f40248737c" />
   
  This mainly contains:  
- TCP  
- HTTPS (443)  
- HTTP (80)  
    
  The important clue is **HTTP traffic**, because HTTP can expose credentials in plain text.  

**Step 3: Filter Only HTTP Traffic**  
   
  In the display filter bar, type:  
```
  http  
```
<img width="834" height="122" alt="Image" src="https://github.com/user-attachments/assets/6c1927f0-40af-4d8e-a301-551f84eaba36" />
  This removes unrelated encrypted traffic and shows only web requests.  
  You will notice requests to:  
  
<img width="1264" height="198" alt="Image" src="https://github.com/user-attachments/assets/0e4e9863-b475-43f8-a988-ba4aeda91d06" />

  **Step 4: Find POST Request**  
   
  Look for an HTTP packet with:   
   
  POST /secured/newuser.php HTTP/1.1  
 <img width="1264" height="198" alt="Image" src="https://github.com/user-attachments/assets/158fdfdd-ebeb-4bdd-a6b9-36d0175f8d2c" />
   
  This is usually a form submission request.  
   
  A POST request often contains:  
   
  username   
  password  
  email  
  hidden values  
  sometimes the flag  
   
  <img width="185" height="164" alt="Image" src="https://github.com/user-attachments/assets/0e2469e5-b4cf-4f39-b30e-6d99105206e6" />

   
  **Step 5: Follow HTTP Stream**  
   
  Right click the POST packet:  
  **Follow → HTTP Stream**  

   
<img width="1560" height="496" alt="Image" src="https://github.com/user-attachments/assets/845affb8-e3b1-49db-acd3-e076a2ba5bab" />
  
   
  This reconstructs the full web conversation in readable format.  
  Then it will show some thing like   
  <img width="1902" height="609" alt="Image" src="https://github.com/user-attachments/assets/6063587d-7e30-4371-894e-92e1ace1f96d" />

  **What you will see**   
   
  The body contains:  
    
```
  uuname=flag%7B%7D  
  upass=%24JG1%7Bp4cket_c4ptured%7D  
```  
    
   
  This is **URL-encoded data**.  
   
  **Step 6: Decode URL Encoding**   
   
  Decoded password value:  
   
  
  <img width="910" height="522" alt="Image" src="https://github.com/user-attachments/assets/ca364a83-d2f2-4791-80e8-fec882dfd714" />
   
  $JG1{p4cket_c4ptured}   
   
   This is the **flag**.  
   
 **The traffic used ** **HTTP** **, not HTTPS**  
   
 **HTTP sends form data in ** **plain text**  
   
 **Signup forms commonly use ** **POST requests**  
