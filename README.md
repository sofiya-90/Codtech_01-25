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

Security: Detect unauthorized changes to critical files.

Data Integrity: Ensure that important documents and backups remain unchanged.

Development: Track changes in project files during development.

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

Check for SQL Injection:

The check_sql_injection function tests forms for SQL Injection vulnerabilities by submitting a set of SQL payloads.

If the response contains the payload, it indicates a potential SQL Injection vulnerability.

Check for XSS:

The check_xss function tests forms for XSS vulnerabilities by submitting a set of XSS payloads.

If the response contains the payload, it indicates a potential XSS vulnerability.

Check for Other Vulnerabilities:

The check_other_vulnerabilities function is a placeholder for additional vulnerability checks (e.g., CSRF, Open Redirects) that can be added as needed.

Main Function:

The main function orchestrates the scanning process. It prompts the user to enter the URL of the web application to scan and consolidates all vulnerabilities found.

Conclusion
The web_application_vulnerability_scanner is a powerful and flexible tool that aids in identifying security vulnerabilities in web applications. By leveraging common libraries like requests and BeautifulSoup, it is capable of extracting, analyzing, and testing forms for known weaknesses. The scanner provides insights into potential security risks and suggests mitigation strategies for each identified vulnerability.

Developers can further extend this tool by adding more sophisticated checks for additional vulnerabilities and improving payloads to cover a broader range of attack vectors. This scanner serves as a valuable resource for enhancing the security posture of web applications, ensuring they are more resilient against common threats. You can simply input any web app URL to scan for its vulnerabilities and receive detailed reports of any issues found, or confirmation that no vulnerabilities were detected. Happy scanning, and stay secure! 🌐🔐

