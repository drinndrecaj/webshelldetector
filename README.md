# PHP Webshell Detector in Python
This Python code detects the presence of webshells in PHP files. A webshell is a type of malware that allows an attacker to remotely execute code on a web server. The code uses a combination of signature-based and behavior-based checks to identify potential webshells.

# How it works
The program takes a file path as input and reads the content of the file. It then performs various checks on the content to determine if it contains a webshell. The first check is a blacklist of known webshell signatures that are commonly used by attackers. If any of these signatures are found in the file, the program will return a positive result.

Next, the program performs system call-based checks by running the file through a strace command and checking the output for suspicious system calls. It then performs behavior-based checks, including checks for variable obfuscation, function obfuscation, and encoding using hex or base64.

The program also checks for suspicious file names that may indicate the presence of a webshell. If any of these checks return a positive result, the program will return a positive result indicating that the file contains a webshell. It only scans files with the following extensions:

EXTENSIONS = ['.png','.jpg','.php', '.php2', '.php3', '.php4', '.php5', '.php6', '.php7', '.phps', '.pht', '.phtm', '.phtml', '.pgif', '.shtml', '.htaccess', '.phar', '.inc', '.hphp', '.ctp', '.module','.png.php','.jpg.php','.php.png','.php.jpg','.phtml.png','.phtml.jpg','.jpg.phtml','.png.phtml']


The MD5 checksum is blacklisted with known webshell signatures that are updated up to 2023.

# Usage
To use the program, first install the required packages by running:


pip3 install -r requirements.txt
To scan a single directory, run:


python3 webshelldetector.py /var/www/html
To scan multiple directories, run:


python3 webshelldetector.py /var/www/html /home/user/public_html

After the program finishes scanning, review the webshell_report.txt file for information on any detected webshells. Manual review is required to determine if the file is actually a webshell or a false positive.

# Contributions
Feel free to contribute to this code and help improve it. Pull requests are welcome!
