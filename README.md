# Codtech_01-25
# Task 1: File_integrity_checker 
** Company name ** : CODTECH IT SOLUTIONS 
** Name ** : Tulsi Bedarkar
** Intern ID ** : CT08GZV
** Domain **: Cybersecurity and Ethical Hacking
** Batch duration **: December 30,2024 to January 30,2025
** Mentor name **: NEELA SANTOSH KUMAR
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

Customization
The script is easy to customize. You can add more files to monitor, use different hashing algorithms, or even integrate it with other systems to send alerts through email or logging systems.

Conclusion
Our file integrity checker tool is a simple yet powerful way to ensure your files remain untouched. By using cryptographic hashing, it provides a reliable method to detect changes and safeguard your data. Whether for personal use, work, or security, this tool is a valuable asset to keep your files safe and sound.
