# Codtech_01-25
** Company name ** : CODTECH IT SOLUTIONS 
** Name ** : Tulsi Bedarkar
** Intern ID ** : CT08GZV
** Domain **: Cybersecurity and Ethical Hacking
** Batch duration **: December 30,2024 to January 30,2025
** Mentor name **: NEELA SANTOSH KUMAR

# Task 1: File_integrity_checker 
# Tool to Monitor File Changes
Have you ever worried that someone might tamper with your important files, or that changes might happen without you knowing? Our tool is here to help! It's a simple Python script designed to watch over your files and alert you if anything changes.

Why This Tool is Important
Think of this tool as a digital watchdog. In today's world, data security is crucial. Files can be altered by hackers, corrupted by software glitches, or accidentally changed by human error. This tool keeps an eye on your files, ensuring their integrity. If someone changes even a single letter in a file, the tool will notice and alert you right away.

How It Works
The tool uses a method called hashing to monitor your files. A hash is a unique fingerprint for a file. If the content of a file changes, its fingerprint changes too. Here's a breakdown of how the tool functions:

Calculating Hashes: The tool scans your files and calculates their hash values using the SHA-256 algorithm. Imagine taking a snapshot of your files' contents – that's what hashing does.

Monitoring for Changes: It then continuously monitors these files, recalculating their hashes and comparing them to the initial values. If the hash value changes, it means the file has been altered. The tool then alerts you to the change.

Running the Tool: When you run the script, you specify the files you want to monitor. The tool starts by calculating and displaying the initial hashes of these files. It then keeps watching, and if it detects any changes, it prints a message indicating which file has changed and what the new hash value is.

User Experience
Using this tool is straightforward:

Set Up: Just list the file paths you want to monitor.

Run the Tool: Start the script, and it will begin monitoring the files.

Practical Uses
This tool can be used for various purposes:

# Security: 
Detect unauthorized changes to critical files.

# Data Integrity: 
Ensure that important documents and backups remain unchanged.

# Development: 
Track changes in project files during development.

# OUTPUT OF THE TASK: ![output](https://github.com/user-attachments/assets/b47a9b49-6d1e-46f0-92e2-1c34228b3f29)

Customization
The script is easy to customize. You can add more files to monitor, use different hashing algorithms, or even integrate it with other systems to send alerts through email or logging systems.

Conclusion
Our file integrity checker tool is a simple yet powerful way to ensure your files remain untouched. By using cryptographic hashing, it provides a reliable method to detect changes and safeguard your data. Whether for personal use, work, or security, this tool is a valuable asset to keep your files safe and sound.

# Task2 : web_application_vulnerability_scanner
# Tool to scan web application vulnerabilities 
The web_application_vulnerability_scanner is a Python-based tool designed to scan web applications for common vulnerabilities such as SQL Injection and Cross-Site Scripting (XSS). The tool leverages the requests and BeautifulSoup libraries to interact with web pages and analyze the forms present in them. It helps identify security weaknesses that could potentially be exploited by attackers.

Description
The script performs the following key functions:

Extract Forms:

The get_forms function retrieves all HTML forms from a given URL. It handles both file URLs (e.g., file://) and HTTP/HTTPS URLs.

For file URLs, it reads the HTML content from the local file system.

For HTTP/HTTPS URLs, it fetches the content using the requests library.

Form Details Extraction:

The get_form_details function extracts useful information from each form, such as the action URL, method (GET or POST), and input fields.

Submit Forms:

The submit_form function submits forms with a given payload. It handles both GET and POST methods, appending the payload to the relevant input fields.

# Check for SQL Injection:

The check_sql_injection function tests forms for SQL Injection vulnerabilities by submitting a set of SQL payloads.

If the response contains the payload, it indicates a potential SQL Injection vulnerability.

# Check for XSS:

The check_xss function tests forms for XSS vulnerabilities by submitting a set of XSS payloads.

If the response contains the payload, it indicates a potential XSS vulnerability.

# Check for Other Vulnerabilities:

The check_other_vulnerabilities function is a placeholder for additional vulnerability checks (e.g., CSRF, Open Redirects) that can be added as needed.

Main Function:

The main function orchestrates the scanning process. It prompts the user to enter the URL of the web application to scan and consolidates all vulnerabilities found.

Conclusion
The web_application_vulnerability_scanner is a powerful and flexible tool that aids in identifying security vulnerabilities in web applications. By leveraging common libraries like requests and BeautifulSoup, it is capable of extracting, analyzing, and testing forms for known weaknesses. The scanner provides insights into potential security risks and suggests mitigation strategies for each identified vulnerability.

Developers can further extend this tool by adding more sophisticated checks for additional vulnerabilities and improving payloads to cover a broader range of attack vectors. This scanner serves as a valuable resource for enhancing the security posture of web applications, ensuring they are more resilient against common threats. You can simply input any web app URL to scan for its vulnerabilities and receive detailed reports of any issues found, or confirmation that no vulnerabilities were detected. Happy scanning, and stay secure! 🌐🔐

#OUTPUT :
![web_app_vuln_scanner_r](https://github.com/user-attachments/assets/25ef10bd-b115-479e-a981-690b0d717c2d)
![web_vuln_scanner_result](https://github.com/user-attachments/assets/fb34437b-6e1a-45dd-9738-0aa8171ac1f2)

# Task 3 : Penetration testing toolkit
# Tool to perform various penetration testing tasks
Pentesting Tool Overview
Purpose: The tool is designed to scan a given URL for vulnerabilities by appending different payloads to it and analyzing the HTTP responses. Additionally, it can perform functions like brute force attacks, vulnerability scans, port scans, network sniffing, and listing network interfaces.

Key Features:

URL Scheme Check: Ensures the URL has the correct scheme (http:// or https://). If the scheme is missing, it defaults to http://.

URL Validation: Uses the validators library to check if the provided URL is valid.

Payload Encoding: Encodes payloads using urllib.parse.quote to ensure special characters in the payload do not break the URL.

Error Handling: Catches and handles exceptions that may occur during the request process, providing clear error messages.

Functionality:

Initial URL Check:

Prepends http:// if the URL does not start with http:// or https://.

Validates the URL.

# Payload Handling:

Encodes each payload to ensure it's safely appended to the URL.

Validates the full URL with the payload.

# HTTP Requests:

Sends HTTP GET requests to the full URL with the encoded payloads.

Prints the status code of the response for each request.

Catches and displays any request-related errors.

# Brute Force Attacks:

Attempts to guess passwords or keys by systematically checking all possible combinations until the correct one is found.

# Port Scanning:

Scans a target's network ports to identify open and closed ports, helping to understand the services running on the target.

# Network Sniffing:

Monitors and captures network traffic to analyze the data being transmitted over the network.

# Listing Network Interfaces:

Lists all available network interfaces on the machine, providing details about each interface.
write conclusion

Conclusion
The pentesting tool we've crafted is a powerful utility designed to automate various security testing tasks. By incorporating features like brute force attacks, vulnerability scanning, port scanning, network sniffing, and listing network interfaces, it offers a comprehensive solution for identifying and analyzing potential vulnerabilities in a target system. The tool also includes robust error handling, URL validation, and payload encoding to ensure that the testing process is both efficient and reliable.

Whether you're a cybersecurity professional or an enthusiast, this tool provides a streamlined approach to discovering and mitigating security threats, helping to enhance the overall security posture of your systems

# Output
![Screenshot 2025-01-10 104803](https://github.com/user-attachments/assets/787e711a-e698-421e-9990-c9900209dedb)
![Screenshot 2025-01-10 131912](https://github.com/user-attachments/assets/a4c12c3a-582a-4b31-b5ce-bc4403851036)

# Task 4 :ADVANCED ENCRYPTION TOOL
# Purpose: 
The primary purpose of this application is to provide a secure and efficient way for users to encrypt and decrypt files. By using strong encryption algorithms and a user-friendly interface, the tool ensures that sensitive data can be protected from unauthorized access.

# Description:
The "Advanced Encryption Tool" is a file encryption and decryption application built using Python and Tkinter. It utilizes the AES encryption algorithm and the scrypt key derivation function to ensure data security. The tool allows users to select files, encrypt them with a password, and decrypt previously encrypted files. It also maintains a history of operations and prominently displays the application name.

# Overview: 
This encryption application provides a user-friendly interface for file encryption and decryption. The main components of the application include:

GUI Components:

Labels for the application name.

Buttons for encrypting, decrypting files, and viewing the history of operations.

An entry widget to input the encryption/decryption key with an option to show/hide the key.

# File Encryption:

Allows users to select a file for encryption.

Prompts the user to enter a password for encryption.

Uses AES encryption algorithm in GCM mode to encrypt the file.

Saves the encrypted file with a ".enc" extension and opens it to demonstrate successful encryption.

# File Decryption:

Allows users to select an encrypted file for decryption.

Prompts the user to enter the password used for encryption.

Uses AES decryption algorithm in GCM mode to decrypt the file.

Saves the decrypted file without the ".enc" extension and opens it to demonstrate successful decryption.

 # User History:

Maintains a history of encryption and decryption operations.

Provides a button to view the history in a new window.

Conclusion: The "Advanced Encryption Tool" is a robust and visually appealing application for securely encrypting and decrypting files. It provides a straightforward way for users to protect their sensitive data using strong encryption algorithms. By incorporating a history feature, the tool also ensures users can keep track of their operations. Overall, it is a valuable utility for anyone looking to enhance their data security
# Output:
![Screenshot 2025-01-10 135224](https://github.com/user-attachments/assets/de660275-af03-4853-8830-a241431dc5b9)
![Screenshot 2025-01-10 141320](https://github.com/user-attachments/assets/28e48798-671e-4fbb-a9bd-d40f617a69b7)
![Screenshot 2025-01-10 140952](https://github.com/user-attachments/assets/4535feef-a7d6-4091-8233-9e52c819a4b3)
![Screenshot 2025-01-10 141057](https://github.com/user-attachments/assets/06a4867a-9a11-4085-b302-54e982d112a2)
