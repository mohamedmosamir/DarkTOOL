import os
import shutil
import subprocess

# --- Categorized Tools List ---
# Expanded and categorized list of tools.
# Note: Providing 950 *verified* real tools with accurate installation commands for each
# is a massive, ongoing task. This list offers an expanded, categorized example structure.
tools_categorized = {
    "Web Exploitation": [
        {"name": "sqlmap", "install": "sudo apt install -y sqlmap", "command": "sqlmap"},
        {"name": "nikto", "install": "sudo apt install -y nikto", "command": "nikto"},
        {"name": "dirb", "install": "sudo apt install -y dirb", "command": "dirb"},
        {"name": "gobuster", "install": "sudo apt install -y gobuster", "command": "gobuster"},
        {"name": "ffuf", "install": "sudo apt install -y ffuf", "command": "ffuf"},
        {"name": "whatweb", "install": "sudo apt install -y whatweb", "command": "whatweb"},
        {"name": "wpscan", "install": "sudo apt install -y wpscan", "command": "wpscan"},
        {"name": "joomscan", "install": "sudo apt install -y joomscan", "command": "joomscan"},
        {"name": "XSStrike", "install": "git clone https://github.com/s0md3v/XSStrike", "command": "python3 XSStrike/xsstrike.py"},
        {"name": "Commix", "install": "sudo apt install -y commix", "command": "commix"},
        {"name": "skipfish", "install": "sudo apt install -y skipfish", "command": "skipfish"},
        {"name": "davtest", "install": "sudo apt install -y davtest", "command": "davtest"},
        {"name": "theharvester", "install": "sudo apt install -y theharvester", "command": "theharvester"},
        {"name": "wafw00f", "install": "sudo apt install -y wafw00f", "command": "wafw00f"},
        {"name": "sublist3r", "install": "git clone https://github.com/aboul3la/Sublist3r && pip3 install -r Sublist3r/requirements.txt", "command": "python3 Sublist3r/sublist3r.py"},
        {"name": "shodan", "install": "sudo apt install -y shodan", "command": "shodan"},
        {"name": "photon", "install": "git clone https://github.com/s0md3v/Photon && pip3 install -r Photon/requirements.txt", "command": "python3 Photon/photon.py"},
        {"name": "arachni", "install": "gem install arachni", "command": "arachni"},
        {"name": "dotdotpwn", "install": "sudo apt install -y dotdotpwn", "command": "dotdotpwn"},
        {"name": "dirsearch", "install": "pip3 install dirsearch", "command": "dirsearch"},
        {"name": "arjun", "install": "pip3 install arjun", "command": "arjun"},
        {"name": "paramspider", "install": "git clone https://github.com/devanshbatham/ParamSpider && pip3 install -r ParamSpider/requirements.txt", "command": "python3 ParamSpider/paramspider.py"},
        {"name": "dalfox", "install": "go install github.com/hahwul/dalfox/v2@latest", "command": "dalfox"},
        {"name": "xssor", "install": "pip3 install xssor", "command": "xssor"},
        {"name": "reconftw", "install": "bash <(curl -sL https://raw.githubusercontent.com/six2dez/reconftw/main/install.sh)", "command": "reconftw"},
        {"name": "testssl.sh", "install": "git clone --depth 1 https://github.com/drwetter/testssl.sh.git", "command": "./testssl.sh/testssl.sh"},
        {"name": "sslscan", "install": "sudo apt install -y sslscan", "command": "sslscan"},
        {"name": "webshells", "install": "git clone https://github.com/tennc/webshell", "command": "ls webshell"},
        {"name": "cmsmap", "install": "pip3 install cmsmap", "command": "cmsmap"},
        {"name": "site-mapper", "install": "git clone https://github.com/s0md3v/Sitemap-Scraper.git", "command": "python3 Sitemap-Scraper/sitemap_scraper.py"},
        {"name": "corscanner", "install": "git clone https://github.com/s0md3v/Corsy.git", "command": "python3 Corsy/corsy.py"},
        {"name": "tplmap", "install": "pip install tplmap", "command": "tplmap"},
        {"name": "sqliv", "install": "pip install sqliv", "command": "sqliv"},
    ],
    "Network Scanning": [
        {"name": "nmap", "install": "sudo apt install -y nmap", "command": "nmap"},
        {"name": "masscan", "install": "sudo apt install -y masscan", "command": "masscan"},
        {"name": "rustscan", "install": "cargo install rustscan", "command": "rustscan"},
        {"name": "netcat", "install": "sudo apt install -y netcat", "command": "nc"},
        {"name": "hping3", "install": "sudo apt install -y hping3", "command": "hping3"},
        {"name": "dnsrecon", "install": "sudo apt install -y dnsrecon", "command": "dnsrecon"},
        {"name": "dmitry", "install": "sudo apt install -y dmitry", "command": "dmitry"},
        {"name": "enum4linux", "install": "sudo apt install -y enum4linux", "command": "enum4linux"},
        {"name": "snmp-check", "install": "sudo apt install -y snmp-check", "command": "snmp-check"},
        {"name": "fierce", "install": "sudo apt install -y fierce", "command": "fierce"},
        {"name": "dnsenum", "install": "sudo apt install -y dnsenum", "command": "dnsenum"},
        {"name": "amass", "install": "sudo apt install -y amass", "command": "amass"},
        {"name": "assetfinder", "install": "go install github.com/tomnomnom/assetfinder@latest", "command": "assetfinder"},
        {"name": "subfinder", "install": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "command": "subfinder"},
        {"name": "httpx", "install": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", "command": "httpx"},
        {"name": "nuclei", "install": "go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest", "command": "nuclei"},
        {"name": "naabu", "install": "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", "command": "naabu"},
        {"name": "gau", "install": "go install github.com/lc/gau@latest", "command": "gau"},
        {"name": "waybackurls", "install": "go install github.com/tomnomnom/waybackurls@latest", "command": "waybackurls"},
        {"name": "meg", "install": "go install github.com/tomnomnom/meg@latest", "command": "meg"},
        {"name": "interactsh-client", "install": "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest", "command": "interactsh-client"},
        {"name": "subdomainizer", "install": "git clone https://github.com/nsonaniya2003/Subdomainizer.git && pip3 install -r Subdomainizer/requirements.txt", "command": "python3 Subdomainizer/Subdomainizer.py"},
        {"name": "zmap", "install": "sudo apt install -y zmap", "command": "zmap"},
        {"name": "arping", "install": "sudo apt install -y iputils-arping", "command": "arping"},
        {"name": "fping", "install": "sudo apt install -y fping", "command": "fping"},
        {"name": "sslyze", "install": "pip install sslyze", "command": "sslyze"},
        {"name": "tlssled", "install": "git clone https://github.com/portcullislabs/tls-sled.git", "command": "python3 tls-sled/tlssled.py"},
    ],
    "Password Attacks": [
        {"name": "hashcat", "install": "sudo apt install -y hashcat", "command": "hashcat"},
        {"name": "john", "install": "sudo apt install -y john", "command": "john"},
        {"name": "hydra", "install": "sudo apt install -y hydra", "command": "hydra"},
        {"name": "medusa", "install": "sudo apt install -y medusa", "command": "medusa"},
        {"name": "patator", "install": "sudo apt install -y patator", "command": "patator"},
        {"name": "cewl", "install": "sudo apt install -y cewl", "command": "cewl"},
        {"name": "crunch", "install": "sudo apt install -y crunch", "command": "crunch"},
        {"name": "fcrackzip", "install": "sudo apt install -y fcrackzip", "command": "fcrackzip"},
        {"name": "rarcrack", "install": "sudo apt install -y rarcrack", "command": "rarcrack"},
        {"name": "hash-identifier", "install": "sudo apt install -y hash-identifier", "command": "hash-identifier"},
        {"name": "ophcrack", "install": "sudo apt install -y ophcrack", "command": "ophcrack"},
        {"name": "rainbowcrack", "install": "sudo apt install -y rainbowcrack", "command": "rcracki_mt"},
        {"name": "chntpw", "install": "sudo apt install -y chntpw", "command": "chntpw"},
        {"name": "samdump2", "install": "sudo apt install -y samdump2", "command": "samdump2"},
        {"name": "bkhive", "install": "sudo apt install -y bkhive", "command": "bkhive"},
        {"name": "creddump7", "install": "pip install creddump7", "command": "creddump7"},
        {"name": "lazagne", "install": "git clone https://github.com/AlessandroZ/LaZagne.git", "command": "python LaZagne/lazagne.py"},
        {"name": "mimikatz", "install": "echo 'Requires manual download/setup on Windows.'", "command": "mimikatz"},
        {"name": "pth-toolkit", "install": "sudo apt install -y pth-toolkit", "command": "pth-winexe"},
    ],
    "Wireless Attacks": [
        {"name": "aircrack-ng", "install": "sudo apt install -y aircrack-ng", "command": "aircrack-ng"},
        {"name": "bully", "install": "sudo apt install -y bully", "command": "bully"},
        {"name": "reaver", "install": "sudo apt install -y reaver", "command": "reaver"},
        {"name": "macchanger", "install": "sudo apt install -y macchanger", "command": "macchanger"},
        {"name": "bettercap", "install": "sudo apt install -y bettercap", "command": "bettercap"},
        {"name": "kismet", "install": "sudo apt install -y kismet", "command": "kismet"},
        {"name": "wigen", "install": "sudo apt install -y wigen", "command": "wigen"},
        {"name": "pixiewps", "install": "sudo apt install -y pixiewps", "command": "pixiewps"},
        {"name": "wifite", "install": "git clone https://github.com/derv82/wifite2.git", "command": "python2 wifite2/wifite.py"}, # Wifite2 supports Python3
        {"name": "mdk4", "install": "sudo apt install -y mdk4", "command": "mdk4"},
        {"name": "eaphammer", "install": "pip install eaphammer", "command": "eaphammer"},
    ],
    "Forensics & Reverse Engineering": [
        {"name": "volatility", "install": "sudo apt install -y volatility", "command": "volatility"},
        {"name": "autopsy", "install": "sudo apt install -y autopsy", "command": "autopsy"},
        {"name": "sleuthkit", "install": "sudo apt install -y sleuthkit", "command": "tsk_loaddb"},
        {"name": "binwalk", "install": "sudo apt install -y binwalk", "command": "binwalk"},
        {"name": "foremost", "install": "sudo apt install -y foremost", "command": "foremost"},
        {"name": "steghide", "install": "sudo apt install -y steghide", "command": "steghide"},
        {"name": "exiftool", "install": "sudo apt install -y libimage-exiftool-perl", "command": "exiftool"},
        {"name": "strings", "install": "sudo apt install -y binutils", "command": "strings"},
        {"name": "testdisk", "install": "sudo apt install -y testdisk", "command": "testdisk"},
        {"name": "photorec", "install": "sudo apt install -y testdisk", "command": "photorec"},
        {"name": "extundelete", "install": "sudo apt install -y extundelete", "command": "extundelete"},
        {"name": "ddrescue", "install": "sudo apt install -y gddrescue", "command": "ddrescue"},
        {"name": "radare2", "install": "sudo apt install -y radare2", "command": "radare2"},
        {"name": "ghidra", "install": "echo 'Requires manual download/setup.'", "command": "ghidra"},
        {"name": "gdb", "install": "sudo apt install -y gdb", "command": "gdb"},
        {"name": "strace", "install": "sudo apt install -y strace", "command": "strace"},
        {"name": "ltrace", "install": "sudo apt install -y ltrace", "command": "ltrace"},
        {"name": "valgrind", "install": "sudo apt install -y valgrind", "command": "valgrind"},
        {"name": "binutils", "install": "sudo apt install -y binutils", "command": "objdump"},
        {"name": "angr", "install": "pip install angr", "command": "python -c \"import angr\""},
        {"name": "ropgadget", "install": "pip install ropgadget", "command": "ROPgadget"},
        {"name": "one_gadget", "install": "gem install one_gadget", "command": "one_gadget"},
        {"name": "pwntools", "install": "pip install pwntools", "command": "python -c \"from pwn import *\""},
        {"name": "gef", "install": "git clone https://github.com/hugsy/gef.git ~/.gef && echo \"source ~/.gef/gef.py\" >> ~/.gdbinit", "command": "gdb"},
        {"name": "peda", "install": "git clone https://github.com/longld/peda.git ~/peda && echo \"source ~/peda/peda.py\" >> ~/.gdbinit", "command": "gdb"},
        {"name": "pwndbg", "install": "git clone https://github.com/pwndbg/pwndbg ~/pwndbg && cd ~/pwndbg && ./setup.sh", "command": "gdb"},
        {"name": "apktool", "install": "sudo apt install -y apktool", "command": "apktool"},
        {"name": "dex2jar", "install": "sudo apt install -y dex2jar", "command": "dex2jar"},
        {"name": "jd-gui", "install": "sudo apt install -y jd-gui", "command": "jd-gui"},
        {"name": "bytecode-viewer", "install": "echo 'Requires manual download.'", "command": "bytecode-viewer"},
        {"name": "x64dbg", "install": "echo 'Windows only, manual install.'", "command": "x64dbg"},
        {"name": "ollydbg", "install": "echo 'Windows only, manual install.'", "command": "ollydbg"},
    ],
    "Exploitation Frameworks & Post-Exploitation": [
        {"name": "metasploit-framework", "install": "sudo apt install -y metasploit-framework", "command": "msfconsole"},
        {"name": "msfvenom", "install": "sudo apt install -y metasploit-framework", "command": "msfvenom"},
        {"name": "setoolkit", "install": "sudo apt install -y setoolkit", "command": "setoolkit"},
        {"name": "beef-xss", "install": "sudo apt install -y beef-xss", "command": "beef"},
        {"name": "weevely3", "install": "sudo apt install -y weevely", "command": "weevely"},
        {"name": "powersploit", "install": "git clone https://github.com/PowerShellMafia/PowerSploit", "command": "ls PowerSploit"},
        {"name": "empire", "install": "git clone https://github.com/BC-SECURITY/Empire && cd Empire && ./setup/install.sh", "command": "empire"},
        {"name": "koadic", "install": "git clone https://github.com/zerosum0x0/koadic && cd koadic && pip install -r requirements.txt", "command": "python koadic/koadic.py"},
        {"name": "responder", "install": "sudo apt install -y responder", "command": "responder"},
        {"name": "impacket", "install": "pip install impacket", "command": "impacket-psexec"},
        {"name": "crackmapexec", "install": "pip install crackmapexec", "command": "crackmapexec"},
        {"name": "bloodhound", "install": "sudo apt install -y bloodhound", "command": "bloodhound"},
        {"name": "enumuser", "install": "sudo apt install -y enumuser", "command": "enumuser"},
        {"name": "kerbrute", "install": "go install github.com/ropnop/kerbrute@latest", "command": "kerbrute"},
        {"name": "adidnsdump", "install": "pip install adidnsdump", "command": "adidnsdump"},
        {"name": "dnschef", "install": "pip install dnschef", "command": "dnschef"},
        {"name": "evil-winrm", "install": "gem install evil-winrm", "command": "evil-winrm"},
        {"name": "sliver", "install": "curl https://sliver.sh/install | sudo bash", "command": "sliver"},
        {"name": "covenant", "install": "git clone --recurse-submodules https://github.com/cobbr/Covenant && dotnet build Covenant/Covenant.sln", "command": "dotnet run --project Covenant/Covenant"},
        {"name": "veil", "install": "git clone https://github.com/Veil-Framework/Veil && cd Veil && ./setup.sh", "command": "veil"},
        {"name": "shellter", "install": "sudo apt install -y shellter", "command": "shellter"}, # Check if still in apt
        {"name": "unicorn", "install": "git clone https://github.com/trustedsec/unicorn && cd unicorn && python unicorn.py", "command": "python unicorn/unicorn.py"},
        {"name": "greatsct", "install": "git clone https://github.com/GreatSCT/GreatSCT && cd GreatSCT && pip install -r requirements.txt", "command": "python GreatSCT/GreatSCT.py"},
        {"name": "donut", "install": "git clone https://github.com/TheWover/donut && cd donut && make", "command": "./donut"},
    ],
    "Sniffing & Spoofing": [
        {"name": "wireshark", "install": "sudo apt install -y wireshark", "command": "wireshark"},
        {"name": "tshark", "install": "sudo apt install -y tshark", "command": "tshark"},
        {"name": "tcpdump", "install": "sudo apt install -y tcpdump", "command": "tcpdump"},
        {"name": "ettercap", "install": "sudo apt install -y ettercap-graphical", "command": "ettercap"},
        {"name": "proxychains", "install": "sudo apt install -y proxychains", "command": "proxychains"},
        {"name": "mitmproxy", "install": "pip install mitmproxy", "command": "mitmproxy"},
        {"name": "scapy", "install": "pip install scapy", "command": "python -c \"from scapy.all import *\""},
        {"name": "tcpflow", "install": "sudo apt install -y tcpflow", "command": "tcpflow"},
        {"name": "ngrep", "install": "sudo apt install -y ngrep", "command": "ngrep"},
        {"name": "dumpcap", "install": "sudo apt install -y wireshark-common", "command": "dumpcap"},
        {"name": "mergecap", "install": "sudo apt install -y wireshark-common", "command": "mergecap"},
        {"name": "editcap", "install": "sudo apt install -y wireshark-common", "command": "editcap"},
        {"name": "capinfos", "install": "sudo apt install -y wireshark-common", "command": "capinfos"},
    ],
    "Vulnerability Analysis": [
        {"name": "burpsuite", "install": "sudo apt install -y burpsuite", "command": "burpsuite"},
        {"name": "owasp-zap", "install": "sudo apt install -y zaproxy", "command": "zap"},
        {"name": "lynis", "install": "sudo apt install -y lynis", "command": "lynis"},
        {"name": "openvas", "install": "sudo apt install -y openvas", "command": "openvas-start"},
        {"name": "nessus", "install": "echo 'Requires manual download/setup.'", "command": "nessus"},
        {"name": "greenbone-security-assistant", "install": "sudo apt install -y gsa", "command": "gsad"},
        {"name": "trivy", "install": "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo bash -s -- -b /usr/local/bin", "command": "trivy"},
        {"name": "nuclei", "install": "go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest", "command": "nuclei"},
        {"name": "kube-hunter", "install": "pip install kube-hunter", "command": "kube-hunter"},
        {"name": "kubeaudit", "install": "go install github.com/Shopify/kubeaudit@latest", "command": "kubeaudit"},
        {"name": "kube-linter", "install": "curl -sL https://raw.githubusercontent.com/stackrox/kube-linter/main/scripts/install_kube_linter.sh | bash", "command": "kube-linter"},
        {"name": "bandit", "install": "pip install bandit", "command": "bandit"},
        {"name": "safety", "install": "pip install safety", "command": "safety"},
        {"name": "clair", "install": "echo 'Requires manual setup, usually as a service.'", "command": "clairctl"},
        {"name": "anchore-cli", "install": "pip install anchorecli", "command": "anchore-cli"},
    ],
    "Tunneling & Pivoting": [
        {"name": "tor", "install": "sudo apt install -y tor", "command": "tor"},
        {"name": "cryptcat", "install": "sudo apt install -y cryptcat", "command": "cryptcat"},
        {"name": "stunnel4", "install": "sudo apt install -y stunnel4", "command": "stunnel"},
        {"name": "sshuttle", "install": "sudo apt install -y sshuttle", "command": "sshuttle"},
        {"name": "iodine", "install": "sudo apt install -y iodine", "command": "iodine"},
        {"name": "dnscat2", "install": "git clone https://github.com/lukebaggett/dnscat2.git", "command": "ruby dnscat2/server.rb"},
        {"name": "chisel", "install": "go install github.com/jpillora/chisel@latest", "command": "chisel"},
        {"name": "ligolo-ng", "install": "go install github.com/nicocha30/ligolo-ng@latest", "command": "ligolo-ng"},
        {"name": "frp", "install": "echo 'Requires manual download/setup.'", "command": "frps"},
        {"name": "ngrok", "install": "echo 'Requires manual download/setup and auth token.'", "command": "ngrok http 80"},
        {"name": "serveo", "install": "echo 'Public service, no installation needed.'", "command": "ssh -R 80:localhost:80 serveo.net"},
        {"name": "localtunnel", "install": "npm install -g localtunnel", "command": "lt --port 80"},
        {"name": "zrok", "install": "curl -s https://get.zrok.io | sudo bash", "command": "zrok"},
        {"name": "gost", "install": "go install github.com/go-gost/gost/cmd/gost@latest", "command": "gost"},
        {"name": "v2ray", "install": "echo 'Requires manual download/setup.'", "command": "v2ray"},
        {"name": "trojan", "install": "echo 'Requires manual download/setup.'", "command": "trojan"},
        {"name": "shadowsocks", "install": "pip install shadowsocks", "command": "sslocal"},
    ],
    "Information Gathering": [
        {"name": "whois", "install": "sudo apt install -y whois", "command": "whois"},
        {"name": "dig", "install": "sudo apt install -y dnsutils", "command": "dig"},
        {"name": "host", "install": "sudo apt install -y dnsutils", "command": "host"},
        {"name": "nslookup", "install": "sudo apt install -y dnsutils", "command": "nslookup"},
        {"name": "finger", "install": "sudo apt install -y finger", "command": "finger"},
        {"name": "maltego", "install": "sudo apt install -y maltego", "command": "maltego"},
        {"name": "recon-ng", "install": "sudo apt install -y recon-ng", "command": "recon-ng"},
        {"name": "osint-framework", "install": "echo 'Web-based framework, no installation.'", "command": "echo 'Visit osintframework.com'"},
        {"name": "sherlock", "install": "pip3 install sherlock", "command": "sherlock"},
        {"name": "ghunt", "install": "pip3 install ghunt", "command": "ghunt"},
        {"name": "holehe", "install": "pip3 install holehe", "command": "holehe"},
        {"name": "snscrape", "install": "pip3 install snscrape", "command": "snscrape"},
    ],
    "Operating System & Utilities": [
        {"name": "ls", "install": "sudo apt install -y coreutils", "command": "ls"},
        {"name": "cat", "install": "sudo apt install -y coreutils", "command": "cat"},
        {"name": "grep", "install": "sudo apt install -y grep", "command": "grep"},
        {"name": "find", "install": "sudo apt install -y findutils", "command": "find"},
        {"name": "ps", "install": "sudo apt install -y procps", "command": "ps"},
        {"name": "top", "install": "sudo apt install -y procps", "command": "top"},
        {"name": "htop", "install": "sudo apt install -y htop", "command": "htop"},
        {"name": "wget", "install": "sudo apt install -y wget", "command": "wget"},
        {"name": "curl", "install": "sudo apt install -y curl", "command": "curl"},
        {"name": "git", "install": "sudo apt install -y git", "command": "git"},
        {"name": "tmux", "install": "sudo apt install -y tmux", "command": "tmux"},
        {"name": "screen", "install": "sudo apt install -y screen", "command": "screen"},
        {"name": "vim", "install": "sudo apt install -y vim", "command": "vim"},
        {"name": "nano", "install": "sudo apt install -y nano", "command": "nano"},
        {"name": "ip", "install": "sudo apt install -y iproute2", "command": "ip"},
        {"name": "ifconfig", "install": "sudo apt install -y net-tools", "command": "ifconfig"},
        {"name": "netstat", "install": "sudo apt install -y net-tools", "command": "netstat"},
        {"name": "ss", "install": "sudo apt install -y iproute2", "command": "ss"},
        {"name": "lsof", "install": "sudo apt install -y lsof", "command": "lsof"},
        {"name": "df", "install": "sudo apt install -y coreutils", "command": "df"},
        {"name": "du", "install": "sudo apt install -y coreutils", "command": "du"},
        {"name": "uname", "install": "echo 'Built-in Linux binary.'", "command": "uname"},
        {"name": "whoami", "install": "echo 'Built-in Linux/Windows binary.'", "command": "whoami"},
        {"name": "id", "install": "echo 'Built-in Linux binary.'", "command": "id"},
        {"name": "hostname", "install": "echo 'Built-in Linux/Windows binary.'", "command": "hostname"},
        {"name": "traceroute", "install": "sudo apt install -y traceroute", "command": "traceroute"},
        {"name": "mtr", "install": "sudo apt install -y mtr", "command": "mtr"},
        {"name": "ping", "install": "sudo apt install -y iputils-ping", "command": "ping"},
        {"name": "rm", "install": "sudo apt install -y coreutils", "command": "rm"},
        {"name": "mv", "install": "sudo apt install -y coreutils", "command": "mv"},
        {"name": "cp", "install": "sudo apt install -y coreutils", "command": "cp"},
        {"name": "mkdir", "install": "sudo apt install -y coreutils", "command": "mkdir"},
        {"name": "rmdir", "install": "sudo apt install -y coreutils", "command": "rmdir"},
        {"name": "chmod", "install": "sudo apt install -y coreutils", "command": "chmod"},
        {"name": "chown", "install": "sudo apt install -y coreutils", "command": "chown"},
        {"name": "useradd", "install": "sudo apt install -y passwd", "command": "useradd"},
        {"name": "passwd", "install": "sudo apt install -y passwd", "command": "passwd"},
        {"name": "top", "install": "sudo apt install -y procps", "command": "top"},
    ],
    "Development & Programming Tools": [
        {"name": "python", "install": "sudo apt install -y python3", "command": "python3"},
        {"name": "pip", "install": "sudo apt install -y python3-pip", "command": "pip3"},
        {"name": "go", "install": "sudo apt install -y golang-go", "command": "go"},
        {"name": "rustc", "install": "sudo apt install -y rustc", "command": "rustc"},
        {"name": "gcc", "install": "sudo apt install -y build-essential", "command": "gcc"},
        {"name": "g++", "install": "sudo apt install -y build-essential", "command": "g++"},
        {"name": "java", "install": "sudo apt install -y default-jdk", "command": "java"},
        {"name": "ruby", "install": "sudo apt install -y ruby", "command": "ruby"},
        {"name": "php", "install": "sudo apt install -y php", "command": "php"},
        {"name": "node", "install": "sudo apt install -y nodejs", "command": "node"},
        {"name": "npm", "install": "sudo apt install -y npm", "command": "npm"},
        {"name": "composer", "install": "sudo apt install -y composer", "command": "composer"},
        {"name": "make", "install": "sudo apt install -y make", "command": "make"},
        {"name": "cargo", "install": "sudo apt install -y cargo", "command": "cargo"},
        {"name": "gem", "install": "sudo apt install -y ruby", "command": "gem"},
        {"name": "vscode", "install": "sudo snap install --classic code", "command": "code"},
        {"name": "jupyter", "install": "pip install jupyter", "command": "jupyter-notebook"},
        {"name": "sublime-text", "install": "echo 'Requires manual download/setup.'", "command": "subl"},
        {"name": "atom", "install": "echo 'Requires manual download/setup.'", "command": "atom"},
        {"name": "emacs", "install": "sudo apt install -y emacs", "command": "emacs"},
        {"name": "neovim", "install": "sudo apt install -y neovim", "command": "nvim"},
    ],
    "DevOps & Containerization": [
        {"name": "docker", "install": "sudo apt install -y docker.io", "command": "docker"},
        {"name": "docker-compose", "install": "sudo apt install -y docker-compose", "command": "docker-compose"},
        {"name": "kubernetes", "install": "sudo snap install kubectl --classic", "command": "kubectl"},
        {"name": "helm", "install": "sudo snap install helm --classic", "command": "helm"},
        {"name": "minikube", "install": "sudo snap install minikube --classic", "command": "minikube"},
        {"name": "kind", "install": "go install sigs.k8s.io/kind@latest", "command": "kind"},
        {"name": "ansible", "install": "sudo apt install -y ansible", "command": "ansible"},
        {"name": "terraform", "install": "sudo apt install -y terraform", "command": "terraform"},
        {"name": "awscli", "install": "pip install awscli", "command": "aws"},
        {"name": "azure-cli", "install": "curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash", "command": "az"},
        {"name": "gcloud", "install": "echo 'Requires manual download/setup.'", "command": "gcloud"},
        {"name": "vagrant", "install": "sudo apt install -y vagrant", "command": "vagrant"},
        {"name": "virtualbox", "install": "sudo apt install -y virtualbox", "command": "vboxmanage"},
        {"name": "qemu-kvm", "install": "sudo apt install -y qemu-kvm", "command": "qemu-system-x86_64"},
        {"name": "libvirt-daemon", "install": "sudo apt install -y libvirt-daemon", "command": "virsh"},
        {"name": "packer", "install": "sudo apt install -y packer", "command": "packer"},
        {"name": "nomad", "install": "sudo apt install -y nomad", "command": "nomad"},
        {"name": "consul", "install": "sudo apt install -y consul", "command": "consul"},
        {"name": "vault", "install": "sudo apt install -y vault", "command": "vault"},
    ],
    "CI/CD & Automation": [
        {"name": "gitlab-runner", "install": "curl -L \"https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.deb.sh\" | sudo bash && sudo apt install gitlab-runner", "command": "gitlab-runner"},
        {"name": "jenkins", "install": "echo 'Requires manual setup as a service.'", "command": "jenkins"},
        {"name": "travis-ci", "install": "gem install travis", "command": "travis"},
        {"name": "circleci-cli", "install": "curl -fLSs https://circle.ci/cli | sudo bash", "command": "circleci"},
        {"name": "gh", "install": "sudo apt install -y gh", "command": "gh"},
        {"name": "hub", "install": "sudo apt install -y hub", "command": "hub"},
        {"name": "pre-commit", "install": "pip install pre-commit", "command": "pre-commit"},
        {"name": "lefthook", "install": "go install github.com/Arkweid/lefthook@latest", "command": "lefthook"},
        {"name": "husky", "install": "npm install husky", "command": "husky"},
        {"name": "lint-staged", "install": "npm install lint-staged", "command": "lint-staged"},
        {"name": "commitlint", "install": "npm install @commitlint/cli @commitlint/config-conventional", "command": "commitlint"},
        {"name": "semantic-release", "install": "npm install semantic-release", "command": "semantic-release"},
        {"name": "conventional-changelog-cli", "install": "npm install -g conventional-changelog-cli", "command": "conventional-changelog"},
    ],
    "Code Analysis & SAST/DAST": [
        {"name": "sonarqube", "install": "echo 'Requires manual download/setup.'", "command": "sonar.sh"},
        {"name": "snyk", "install": "npm install -g snyk", "command": "snyk"},
        {"name": "checkov", "install": "pip install checkov", "command": "checkov"},
        {"name": "gitleaks", "install": "go install github.com/zricethezav/gitleaks@latest", "command": "gitleaks"},
        {"name": "trufflehog", "install": "pip install trufflehog", "command": "trufflehog"},
        {"name": "detect-secrets", "install": "pip install detect-secrets", "command": "detect-secrets"},
        {"name": "hadolint", "install": "wget -O hadolint https://github.com/hadolint/hadolint/releases/download/v2.10.0/hadolint-Linux-x86_64 && chmod +x hadolint && sudo mv hadolint /usr/local/bin/", "command": "hadolint"},
        {"name": "bandit", "install": "pip install bandit", "command": "bandit"},
        {"name": "safety", "install": "pip install safety", "command": "safety"},
        {"name": "npm-audit", "install": "echo 'Built into npm.'", "command": "npm audit"},
        {"name": "yarn-audit", "install": "echo 'Built into yarn.'", "command": "yarn audit"},
    ],
    "System Monitoring & Defense": [
        {"name": "ossec-hids", "install": "sudo apt install -y ossec-hids", "command": "/var/ossec/bin/ossec-control"},
        {"name": "snort", "install": "sudo apt install -y snort", "command": "snort"},
        {"name": "suricata", "install": "sudo apt install -y suricata", "command": "suricata"},
        {"name": "fail2ban", "install": "sudo apt install -y fail2ban", "command": "fail2ban-client"},
        {"name": "ufw", "install": "sudo apt install -y ufw", "command": "ufw"},
        {"name": "iptables", "install": "sudo apt install -y iptables", "command": "iptables"},
        {"name": "firewalld", "install": "sudo apt install -y firewalld", "command": "firewall-cmd"},
        {"name": "apparmor", "install": "sudo apt install -y apparmor", "command": "aa-status"},
        {"name": "selinux", "install": "sudo apt install -y selinux-utils", "command": "sestatus"},
        {"name": "auditd", "install": "sudo apt install -y auditd", "command": "auditctl"},
        {"name": "clamav", "install": "sudo apt install -y clamav", "command": "clamscan"},
        {"name": "rkhunter", "install": "sudo apt install -y rkhunter", "command": "rkhunter"},
        {"name": "chkrootkit", "install": "sudo apt install -y chkrootkit", "command": "chkrootkit"},
    ],
    "Databases": [
        {"name": "mysql-client", "install": "sudo apt install -y mysql-client", "command": "mysql"},
        {"name": "postgresql-client", "install": "sudo apt install -y postgresql-client", "command": "psql"},
        {"name": "sqlite3", "install": "sudo apt install -y sqlite3", "command": "sqlite3"},
        {"name": "mongodb-tools", "install": "sudo apt install -y mongodb-clients", "command": "mongo"},
        {"name": "redis-tools", "install": "sudo apt install -y redis-tools", "command": "redis-cli"},
        {"name": "mariadb-client", "install": "sudo apt install -y mariadb-client", "command": "mariadb"},
        {"name": "sqlcl", "install": "echo 'Oracle SQLcl, requires manual download.'", "command": "sqlcl"},
    ],
    "Virtualization": [
        {"name": "qemu-kvm", "install": "sudo apt install -y qemu-kvm", "command": "qemu-system-x86_64"},
        {"name": "libvirt-daemon", "install": "sudo apt install -y libvirt-daemon", "command": "virsh"},
        {"name": "virt-manager", "install": "sudo apt install -y virt-manager", "command": "virt-manager"},
        {"name": "vagrant", "install": "sudo apt install -y vagrant", "command": "vagrant"}, # Duplicate but relevant
        {"name": "virtualbox", "install": "sudo apt install -y virtualbox", "command": "vboxmanage"}, # Duplicate but relevant
    ],
    "Web Servers": [
        {"name": "apache2", "install": "sudo apt install -y apache2", "command": "apache2ctl"},
        {"name": "nginx", "install": "sudo apt install -y nginx", "command": "nginx"},
        {"name": "lighttpd", "install": "sudo apt install -y lighttpd", "command": "lighttpd"},
        {"name": "caddy", "install": "sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https && curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg && curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list && sudo apt update && sudo apt install caddy", "command": "caddy"},
    ],
    "Cloud Exploitation": [
        {"name": "pacu", "install": "git clone https://github.com/RhinoSecurityLabs/Pacu.git --recursive && pip3 install -r Pacu/requirements.txt", "command": "python3 Pacu/pacu.py"},
        {"name": "cloudgoat", "install": "git clone https://github.com/RhinoSecurityLabs/cloudgoat.git", "command": "cd cloudgoat && python3 cloudgoat.py"},
        {"name": "flaws-cloud", "install": "echo 'Requires manual setup, usually as a CTF.'", "command": "echo 'Refer to Flaws.cloud setup.'"},
        {"name": "cloud-nuke", "install": "go install github.com/gruntwork-io/cloud-nuke@latest", "command": "cloud-nuke"},
        {"name": "awscli", "install": "pip install awscli", "command": "aws"}, # Relevant to cloud exploitation
        {"name": "azure-cli", "install": "curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash", "command": "az"}, # Relevant to cloud exploitation
        {"name": "gcloud", "install": "echo 'Requires manual download/setup.'", "command": "gcloud"}, # Relevant to cloud exploitation
    ],
    "Container Exploitation": [
        {"name": "kube-bench", "install": "curl -L https://github.com/aquasecurity/kube-bench/releases/download/v0.6.9/kube-bench_0.6.9_linux_amd64.deb -o kube-bench.deb && sudo dpkg -i kube-bench.deb", "command": "kube-bench"},
        {"name": "kube-api-access", "install": "echo 'Not a single tool, refers to kubectl for API access.'", "command": "kubectl api-resources"},
        {"name": "docker-cli-exploit", "install": "echo 'Refers to common Docker misconfigurations.'", "command": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"},
        {"name": "kube-hunter", "install": "pip install kube-hunter", "command": "kube-hunter"}, # Duplicate but relevant
        {"name": "kubeaudit", "install": "go install github.com/Shopify/kubeaudit@latest", "command": "kubeaudit"}, # Duplicate but relevant
    ],
    "SCADA/ICS Tools": [
        {"name": "modscan", "install": "echo 'Proprietary Windows tool, no apt install.'", "command": "echo 'Search for Modscan.'"},
        {"name": "s7-plc-tool", "install": "echo 'Custom scripts or proprietary software.'", "command": "echo 'Search for S7 PLC tools.'"},
        {"name": "nmap-nse-scada", "install": "sudo apt install -y nmap", "command": "nmap --script=modbus-discover"},
        {"name": "plcscan", "install": "git clone https://github.com/scy-phy/plcscan.git", "command": "python3 plcscan/plcscan.py"},
    ],
    "Malware Analysis": [
        {"name": "cuckoo-sandbox", "install": "pip install cuckoo", "command": "cuckoo"},
        {"name": "virustotal-cli", "install": "pip install virustotal-api", "command": "virustotal"},
        {"name": "yara", "install": "sudo apt install -y yara", "command": "yara"},
        {"name": "clamav", "install": "sudo apt install -y clamav", "command": "clamscan"},
        {"name": "cutter", "install": "echo 'Requires manual download/setup (GUI for Radare2).' ", "command": "cutter"},
        {"name": "pefile", "install": "pip install pefile", "command": "python -c \"import pefile\""},
        {"name": "upx", "install": "sudo apt install -y upx-ucl", "command": "upx"},
    ],
    "Network Utilities": [
        {"name": "ping", "install": "sudo apt install -y iputils-ping", "command": "ping"},
        {"name": "traceroute", "install": "sudo apt install -y traceroute", "command": "traceroute"},
        {"name": "netstat", "install": "sudo apt install -y net-tools", "command": "netstat"},
        {"name": "ss", "install": "sudo apt install -y iproute2", "command": "ss"},
        {"name": "dig", "install": "sudo apt install -y dnsutils", "command": "dig"},
        {"name": "nc", "install": "sudo apt install -y netcat", "command": "nc"},
        {"name": "iproute2", "install": "sudo apt install -y iproute2", "command": "ip"},
        {"name": "whois", "install": "sudo apt install -y whois", "command": "whois"},
        {"name": "host", "install": "sudo apt install -y dnsutils", "command": "host"},
        {"name": "nslookup", "install": "sudo apt install -y dnsutils", "command": "nslookup"},
    ],
    "Web Development Utilities": [
        {"name": "nginx", "install": "sudo apt install -y nginx", "command": "nginx"},
        {"name": "apache2", "install": "sudo apt install -y apache2", "command": "apache2"},
        {"name": "php-fpm", "install": "sudo apt install -y php-fpm", "command": "php-fpm"},
        {"name": "nodejs", "install": "sudo apt install -y nodejs", "command": "node"},
        {"name": "npm", "install": "sudo apt install -y npm", "command": "npm"},
        {"name": "yarn", "install": "sudo apt install -y yarn", "command": "yarn"},
        {"name": "webpack", "install": "npm install -g webpack", "command": "webpack"},
        {"name": "gulp", "install": "npm install -g gulp-cli", "command": "gulp"},
        {"name": "grunt", "install": "npm install -g grunt-cli", "command": "grunt"},
    ],
    "Miscellaneous": [
        {"name": "cowsay", "install": "sudo apt install -y cowsay", "command": "cowsay"},
        {"name": "sl", "install": "sudo apt install -y sl", "command": "sl"},
        {"name": "figlet", "install": "sudo apt install -y figlet", "command": "figlet"},
        {"name": "toilet", "install": "sudo apt install -y toilet", "command": "toilet"},
        {"name": "neofetch", "install": "sudo apt install -y neofetch", "command": "neofetch"},
        {"name": "htop", "install": "sudo apt install -y htop", "command": "htop"},
        {"name": "tmux", "install": "sudo apt install -y tmux", "command": "tmux"},
        {"name": "screen", "install": "sudo apt install -y screen", "command": "screen"},
    ]
}


def clear():
    """Clears the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def show_header():
    """Displays the custom ASCII art header."""
    print("\033[91m") # Set text color to red
    print("████████▄     ▄████████    ▄████████    ▄█   ▄█▄          ███      ▄██████▄   ▄██████▄   ▄█       ")
    print("███   ▀███   ███    ███   ███    ███   ███ ▄███▀      ▀█████████▄ ███    ███ ███    ███ ███       ")
    print("███    ███   ███    ███   ███    ███   ███▐██▀           ▀███▀▀██ ███    ███ ███    ███ ███       ")
    print("███    ███   ███    ███  ▄███▄▄▄▄██▀  ▄█████▀             ███   ▀ ███    ███ ███    ███ ███       ")
    print("███    ███ ▀███████████ ▀▀███▀▀▀▀▀   ▀▀█████▄             ███     ███    ███ ███    ███ ███       ")
    print("███    ███   ███    ███ ▀███████████   ███▐██▄            ███     ███    ███ ███    ███ ███       ")
    print("███   ▄███   ███    ███   ███    ███   ███ ▀███▄          ███     ███    ███ ███    ███ ███▌    ▄ ")
    print("████████▀    ███    █▀    ███    ███   ███   ▀█▀         ▄████▀    ▀██████▀   ▀██████▀  █████▄▄██ ")
    print("                          ███    ███   ▀                                                ▀         ")
    print("\033[0m") # Reset text color
    print("Version: 1.0 | Author: medo | Tool: DARK TOOL")
    print("-" * 60)

def show_categories(categories_dict):
    """Displays the list of available categories."""
    print("\n[+] Available Categories:")
    category_names = list(categories_dict.keys())
    for idx, category in enumerate(category_names, 1):
        print(f"[{idx:02}] {category}")
    print("-" * 60)
    return category_names

def is_installed(cmd):
    """Checks if a command-line tool is installed."""
    return shutil.which(cmd) is not None

def install_tool(tool):
    """Installs a specified tool."""
    print(f"[!] Tool '{tool['name']}' not found.")
    print(f"[+] Installing {tool['name']}...")
    # It's generally safer to run install commands with sudo.
    # We prepend 'sudo' to the install command if it's not already there.
    install_cmd = tool['install']
    if not install_cmd.strip().lower().startswith('sudo'):
        install_cmd = 'sudo ' + install_cmd
    os.system(install_cmd)
    print("[✔] Installed successfully.")

def launch_tool(tool):
    """Launches a specified tool."""
    print(f"[+] Launching {tool['name']}...")
    try:
        subprocess.call(tool['command'], shell=True)
    except Exception as e:
        print(f"[!] Failed to launch: {e}")

def display_tools_in_category_paginated(category_name, tools_dict, tools_per_page=25):
    """Displays tools within a selected category with pagination."""
    tools_list = tools_dict.get(category_name, [])
    total_tools = len(tools_list)
    total_pages = (total_tools + tools_per_page - 1) // tools_per_page
    
    current_page = 1

    while True:
        clear()
        show_header()
        print(f"[*] Category: {category_name} (Page {current_page}/{total_pages})")
        print("-" * 60)

        start_idx = (current_page - 1) * tools_per_page
        end_idx = start_idx + tools_per_page
        
        # Adjust end_idx if it exceeds the list length
        if end_idx > total_tools:
            end_idx = total_tools

        displayed_tools = tools_list[start_idx:end_idx]

        if not displayed_tools:
            print("[!] No tools found in this category.")
            input("Press Enter to return to categories menu...")
            return

        for idx, tool in enumerate(displayed_tools, start_idx + 1):
            print(f"[{idx:03}] {tool['name']:<25}", end="")
            if (idx - (start_idx + 1) + 1) % 3 == 0: # 3 tools per line for better formatting
                print()
        if (len(displayed_tools)) % 3 != 0: # Ensure final newline if last line isn't full
            print()
        
        print("-" * 60)
        print("Options: (N)ext Page, (P)revious Page, (M)ain Menu, (V)ersion, (H)elp")
        tool_choice = input(f"Enter tool number ({start_idx}-{end_idx}), option, or (M)ain menu: ").strip().lower()

        if tool_choice == 'n':
            if current_page < total_pages:
                current_page += 1
            else:
                print("[!] You are already on the last page.")
                input("Press Enter to continue...")
        elif tool_choice == 'p':
            if current_page > 1:
                current_page -= 1
            else:
                print("[!] You are already on the first page.")
                input("Press Enter to continue...")
        elif tool_choice == 'm':
            return # Exit category display, go back to main menu
        elif tool_choice == 'v':
            print("[+] Version: DARK TOOL_V1")
            input("Press Enter to continue...")
        elif tool_choice == 'h':
            print("[+] Usage Instructions:")
            print("    - From the main menu, select the tool category you wish to browse by entering its number.")
            print("    - Within the category, you can navigate between pages using 'n' for next page and 'p' for previous page.")
            print("    - Enter the corresponding number of the tool you wish to use.")
            print("    - The script will check if the tool is installed. If not, it will attempt to install it.")
            print("    - After installation (if necessary), the tool will be launched.")
            print("    - Press 'Enter' after the tool finishes to return to the category menu.")
            print("    - Type 'm' to return to the main menu (category list).")
            print("    - Type 'v' to view the tool version.")
            print("    - Type 'h' to view these usage instructions.")
            print("    - Press Ctrl+C at any time to exit the script.")
            input("Press Enter to continue...")
        else:
            try:
                selected_tool_number = int(tool_choice)
                if start_idx <= selected_tool_number <= end_idx:
                    tool = tools_list[selected_tool_number - 1]
                    if is_installed(tool['command'].split()[0]):
                        print(f"[✔] Tool '{tool['name']}' is already installed.")
                        launch_tool(tool)
                    else:
                        install_tool(tool)
                        launch_tool(tool)
                    input("Press Enter to return to category menu...") # After tool finishes
                else:
                    print("[!] Invalid tool number for the current page. Please enter a number from the displayed list.")
                    input("Press Enter to continue...")
            except ValueError:
                print("[!] Invalid input. Please enter a tool number, 'n', 'p', 'm', 'v', or 'h'.")
                input("Press Enter to continue...")
            except KeyboardInterrupt:
                print("\n[!] Exiting. Goodbye...")
                break # Exit current loop, main loop will also handle exit


def main():
    """Main function to run the DarkTool application with categories."""
    while True:
        clear()
        show_header()
        
        category_names = show_categories(tools_categorized)
        
        try:
            choice = input("\nEnter category number, 'v' for version, 'h' for help, or Ctrl+C to exit: ").strip().lower()

            if choice == 'v':
                print("[+] Version: DARK TOOL_V1")
                input("Press Enter to continue...")
                continue
            elif choice == 'h':
                print("[+] Usage Instructions:")
                print("    - From the main menu, select the tool category you wish to browse by entering its number.")
                print("    - Within the category, you can navigate between pages using 'n' for next page and 'p' for previous page.")
                print("    - Enter the corresponding number of the tool you wish to use.")
                print("    - The script will check if the tool is installed. If not, it will attempt to install it.")
                print("    - After installation (if necessary), the tool will be launched.")
                print("    - Press 'Enter' after the tool finishes to return to the category menu.")
                print("    - Type 'm' to return to the main menu (category list).")
                print("    - Type 'v' to view the tool version.")
                print("    - Type 'h' to view these usage instructions.")
                print("    - Press Ctrl+C at any time to exit the script.")
                input("Press Enter to continue...")
                continue
            
            category_choice_idx = int(choice)
            if 1 <= category_choice_idx <= len(category_names):
                selected_category_name = category_names[category_choice_idx - 1]
                display_tools_in_category_paginated(selected_category_name, tools_categorized)
            else:
                print("[!] Invalid category number.")
                input("Press Enter to continue...")
        except ValueError:
            print("[!] Please enter a valid number, 'v', or 'h'.")
            input("Press Enter to continue...")
        except KeyboardInterrupt:
            print("\n[!] Exiting. Goodbye...")
            break

if __name__ == "__main__":
    main()