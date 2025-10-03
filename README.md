# BLUE TEAM

## SOBRE O ROADMAP

Repositório criado para documentar minha jornada de aprendizado em Blue Team, Defensive Security e SOC.

-----

## FASE 1: FUNDAMENTOS DE IT E SEGURANÇA

### Fundamentos de TI

#### Hardware e Troubleshooting

- [ ] **Componentes de Hardware**
  - [ ] CPU, RAM, Storage (HDD/SSD), Motherboard
  - [ ] Periféricos e interfaces
  - [ ] Power supplies e cooling
- [ ] **Troubleshooting Básico**
  - [ ] Diagnóstico de problemas de hardware
  - [ ] Boot process e BIOS/UEFI
  - [ ] Device drivers

#### Sistemas Operacionais - Linux

- [ ] **Distribuições**
  - [ ] Ubuntu/Debian (user-friendly)
  - [ ] CentOS/RHEL (enterprise)
  - [ ] Security-focused (Kali para análise)
- [ ] **Comandos Essenciais**
  - [ ] Navegação: ls, cd, pwd, find
  - [ ] Arquivos: cat, grep, less, tail, head
  - [ ] Processos: ps, top, htop, kill
  - [ ] Network: netstat, ss, ip, ifconfig
- [ ] **Gerenciamento de Sistema**
  - [ ] systemctl, service
  - [ ] Package management (apt, yum, dnf)
  - [ ] User/group management
  - [ ] Permissions (chmod, chown)
- [ ] **Log Analysis**
  - [ ] journalctl (systemd logs)
  - [ ] /var/log/ (syslog, auth.log, kern.log)
  - [ ] Log rotation

#### Sistemas Operacionais - Windows

- [ ] **Versões e Diferenças**
  - [ ] Windows 10/11 (workstation)
  - [ ] Windows Server 2019/2022
- [ ] **Comandos CMD e PowerShell**
  - [ ] Basic: dir, cd, ipconfig, netstat
  - [ ] PowerShell: Get-Command, Get-Process, Get-EventLog
- [ ] **Event Viewer**
  - [ ] Windows Logs (Application, Security, System)
  - [ ] Event IDs importantes
  - [ ] Filtering e queries
- [ ] **Registry Basics**
  - [ ] Hives (HKLM, HKCU, HKU)
  - [ ] Autorun locations
  - [ ] Common attack vectors

#### Redes - Fundamentos

- [ ] **Modelo OSI (7 camadas)**
  - [ ] Layer 1: Physical
  - [ ] Layer 2: Data Link (switches, MAC)
  - [ ] Layer 3: Network (routers, IP)
  - [ ] Layer 4: Transport (TCP/UDP)
  - [ ] Layer 5: Session
  - [ ] Layer 6: Presentation
  - [ ] Layer 7: Application
- [ ] **Modelo TCP/IP (4 camadas)**
- [ ] **Protocolos Comuns**
  - [ ] HTTP/HTTPS (80/443)
  - [ ] DNS (53)
  - [ ] SMTP/POP3/IMAP (25/110/143)
  - [ ] FTP/SFTP (21/22)
  - [ ] SSH (22)
  - [ ] SMB/CIFS (445)
  - [ ] LDAP (389/636)
  - [ ] RDP (3389)
- [ ] **IP Addressing**
  - [ ] IPv4 vs IPv6
  - [ ] Public vs Private IPs
  - [ ] Subnetting e CIDR
  - [ ] localhost/loopback (127.0.0.1)
  - [ ] Default gateway, subnet mask
- [ ] **Network Devices**
  - [ ] Switches vs Routers
  - [ ] Firewalls
  - [ ] Load Balancers
  - [ ] Proxies
- [ ] **Network Topologies**
  - [ ] LAN, WAN, MAN, WLAN
  - [ ] Star, Ring, Mesh, Bus
- [ ] **Network Services**
  - [ ] DHCP (Dynamic IP assignment)
  - [ ] DNS (Name resolution)
  - [ ] NTP (Time synchronization)
  - [ ] IPAM (IP Address Management)

#### Virtualização

- [ ] **Conceitos Básicos**
  - [ ] Hypervisor Type 1 vs Type 2
  - [ ] VM vs Container
  - [ ] Guest OS vs Host OS
- [ ] **Tecnologias**
  - [ ] VMware (Workstation, ESXi)
  - [ ] VirtualBox
  - [ ] Proxmox
  - [ ] Hyper-V
- [ ] **Network Modes**
  - [ ] NAT
  - [ ] Bridged
  - [ ] Host-only

### Fundamentos de Segurança

#### Conceitos Core

- [ ] **CIA Triad**
  - [ ] Confidentiality (Confidencialidade)
  - [ ] Integrity (Integridade)
  - [ ] Availability (Disponibilidade)
- [ ] **AAA Framework**
  - [ ] Authentication (Autenticação)
  - [ ] Authorization (Autorização)
  - [ ] Accounting (Auditoria)
- [ ] **Defense in Depth**
  - [ ] Layered security approach
  - [ ] Multiple controls
- [ ] **Zero Trust**
  - [ ] “Never trust, always verify”
  - [ ] Least privilege
  - [ ] Micro-segmentation

#### Protocolos Seguros vs Inseguros

- [ ] **Inseguros (evitar)**
  - [ ] FTP (usar SFTP/FTPS)
  - [ ] Telnet (usar SSH)
  - [ ] HTTP (usar HTTPS)
  - [ ] SNMP v1/v2 (usar v3)
  - [ ] LDAP (usar LDAPS)
- [ ] **Seguros**
  - [ ] HTTPS (SSL/TLS)
  - [ ] SSH
  - [ ] SFTP/FTPS
  - [ ] IPSec
  - [ ] DNSSEC
  - [ ] LDAPS
  - [ ] SRTP (Secure RTP)
  - [ ] S/MIME (Secure email)

#### Criptografia Básica

- [ ] **Symmetric Encryption**
  - [ ] AES, DES, 3DES
  - [ ] Same key para encrypt/decrypt
- [ ] **Asymmetric Encryption**
  - [ ] RSA, ECC
  - [ ] Public/Private key pair
- [ ] **Hashing**
  - [ ] MD5 (quebrado, não usar)
  - [ ] SHA-1 (fraco)
  - [ ] SHA-256, SHA-512 (recomendados)
  - [ ] One-way function
- [ ] **Salting**
  - [ ] Random data adicionada a passwords
  - [ ] Previne rainbow tables
- [ ] **Key Exchange**
  - [ ] Diffie-Hellman
  - [ ] ECDH
- [ ] **PKI (Public Key Infrastructure)**
  - [ ] Certificate Authorities (CA)
  - [ ] Digital certificates
  - [ ] Certificate chains
- [ ] **SSL/TLS**
  - [ ] Handshake process
  - [ ] Certificate validation

#### Autenticação

- [ ] **Métodos de Autenticação**
  - [ ] Local authentication
  - [ ] LDAP/Active Directory
  - [ ] RADIUS
  - [ ] TACACS+
  - [ ] Kerberos
  - [ ] SSO (Single Sign-On)
  - [ ] SAML
  - [ ] OAuth/OIDC
- [ ] **Multi-Factor Authentication (MFA)**
  - [ ] Something you know (password)
  - [ ] Something you have (token, phone)
  - [ ] Something you are (biometrics)
- [ ] **Biometrics**
  - [ ] Fingerprint
  - [ ] Facial recognition
  - [ ] Iris scan
  - [ ] False positive/negative rates

#### Wireless Security

- [ ] **WiFi Standards**
  - [ ] 802.11 a/b/g/n/ac/ax
- [ ] **Encryption**
  - [ ] WEP (inseguro, quebrado)
  - [ ] WPA (deprecated)
  - [ ] WPA2 (current standard)
  - [ ] WPA3 (latest, mais seguro)
- [ ] **Authentication**
  - [ ] EAP (Extensible Authentication Protocol)
  - [ ] PEAP (Protected EAP)
  - [ ] EAP-TLS
  - [ ] WPS (inseguro, desabilitar)
- [ ] **Other Wireless**
  - [ ] Bluetooth security
  - [ ] NFC (Near Field Communication)
  - [ ] Infrared

### Prática Inicial

- [ ] **TryHackMe**
  - [ ] Introduction to Cybersecurity
  - [ ] Pre Security Path
  - [ ] SOC Level 1 Path (início)
- [ ] **Blue Team Labs Online**
  - [ ] Free challenges para começar
- [ ] **Configurar Lab Básico**
  - [ ] VM com Windows 10
  - [ ] VM com Linux (Ubuntu)
  - [ ] Praticar logs e event viewer

-----

## FASE 2: AMEAÇAS E ATAQUES

### Tipos de Ameaças

#### Malware

- [ ] **Vírus**
  - [ ] Infecta arquivos legítimos
  - [ ] Requer execução
- [ ] **Worms**
  - [ ] Auto-replicante
  - [ ] Não precisa de host file
- [ ] **Trojans**
  - [ ] Disfarçado como software legítimo
  - [ ] Backdoor access
- [ ] **Ransomware**
  - [ ] Encrypta dados
  - [ ] Exige pagamento
  - [ ] Exemplos: WannaCry, Ryuk
- [ ] **Spyware**
  - [ ] Coleta informações
  - [ ] Keyloggers
- [ ] **Adware**
  - [ ] Anúncios indesejados
- [ ] **Rootkits**
  - [ ] Acesso privilegiado
  - [ ] Difícil detecção
- [ ] **Botnet**
  - [ ] Rede de máquinas comprometidas
  - [ ] C2 (Command & Control)
- [ ] **Fileless Malware**
  - [ ] Executa em memória
  - [ ] Não deixa arquivos no disco

#### Social Engineering

- [ ] **Phishing**
  - [ ] Email fraudulento
  - [ ] Credential harvesting
- [ ] **Spear Phishing**
  - [ ] Targeted phishing
  - [ ] Personalized
- [ ] **Whaling**
  - [ ] Phishing contra executives
- [ ] **Vishing**
  - [ ] Voice phishing
  - [ ] Telefone
- [ ] **Smishing**
  - [ ] SMS phishing
- [ ] **Spam vs Spim**
  - [ ] Spam: email não solicitado
  - [ ] Spim: instant messaging spam
- [ ] **Pretexting**
  - [ ] Criar cenário falso
- [ ] **Baiting**
  - [ ] Oferecer algo atrativo (USB, download)
- [ ] **Tailgating/Piggybacking**
  - [ ] Seguir pessoa autorizada
- [ ] **Shoulder Surfing**
  - [ ] Observar informações sensíveis
- [ ] **Dumpster Diving**
  - [ ] Buscar informações no lixo
- [ ] **Impersonation**
  - [ ] Fingir ser outra pessoa
- [ ] **Watering Hole Attack**
  - [ ] Comprometer site legítimo visitado por alvos

#### Network Attacks

- [ ] **DoS (Denial of Service)**
  - [ ] Flood de tráfego
  - [ ] Exaurir recursos
- [ ] **DDoS (Distributed DoS)**
  - [ ] Botnet-based
  - [ ] Múltiplas fontes
- [ ] **MITM (Man-in-the-Middle)**
  - [ ] Interceptar comunicação
  - [ ] ARP spoofing
  - [ ] Session hijacking
- [ ] **DNS Poisoning/Spoofing**
  - [ ] Manipular DNS cache
  - [ ] Redirecionar tráfego
- [ ] **ARP Poisoning**
  - [ ] Manipular ARP table
  - [ ] MITM em LAN
- [ ] **IP/MAC Spoofing**
  - [ ] Falsificar endereço origem
- [ ] **Evil Twin**
  - [ ] Fake WiFi access point
- [ ] **Deauthentication Attack**
  - [ ] Desconectar clientes WiFi
- [ ] **Rogue Access Point**
  - [ ] AP não autorizado
- [ ] **VLAN Hopping**
  - [ ] Bypass VLAN segmentation
- [ ] **War-driving/War-dialing**
  - [ ] Buscar redes WiFi vulneráveis

#### Application Attacks

- [ ] **SQL Injection**
  - [ ] Manipular queries SQL
  - [ ] Bypass authentication
  - [ ] Data exfiltration
- [ ] **XSS (Cross-Site Scripting)**
  - [ ] Inject malicious scripts
  - [ ] Steal cookies/sessions
- [ ] **CSRF (Cross-Site Request Forgery)**
  - [ ] Forçar ações não intencionadas
- [ ] **Buffer Overflow**
  - [ ] Exceder buffer memory
  - [ ] Code execution
- [ ] **Memory Leak**
  - [ ] Fail to release memory
  - [ ] DoS eventual
- [ ] **Directory Traversal**
  - [ ] Access unauthorized files
  - [ ] ../ attacks
- [ ] **Pass-the-Hash**
  - [ ] Use hashed credentials
- [ ] **Replay Attack**
  - [ ] Re-send captured packets
- [ ] **Privilege Escalation**
  - [ ] Gain higher privileges
  - [ ] Horizontal vs Vertical

### Threat Intelligence e OSINT

- [ ] **OSINT (Open Source Intelligence)**
  - [ ] Informação pública
  - [ ] Google Dorking
  - [ ] Shodan, Censys
  - [ ] theHarvester
- [ ] **Threat Intelligence Feeds**
  - [ ] IOCs (Indicators of Compromise)
  - [ ] IP reputation lists
  - [ ] Malware signatures
  - [ ] STIX/TAXII
- [ ] **Threat Intelligence Platforms**
  - [ ] MISP
  - [ ] OpenCTI
  - [ ] ThreatConnect
- [ ] **False Positives vs False Negatives**
  - [ ] False Positive: Alert on benign activity
  - [ ] False Negative: Miss actual threat
  - [ ] True Positive: Correct alert
  - [ ] True Negative: Correct no-alert

### Attack Frameworks

- [ ] **MITRE ATT&CK Framework**
  - [ ] TTPs (Tactics, Techniques, Procedures)
  - [ ] 14 Tactics (Reconnaissance to Impact)
  - [ ] ATT&CK Navigator
  - [ ] Mapping detections
- [ ] **Cyber Kill Chain** (Lockheed Martin)
  - [ ] Reconnaissance
  - [ ] Weaponization
  - [ ] Delivery
  - [ ] Exploitation
  - [ ] Installation
  - [ ] Command & Control
  - [ ] Actions on Objectives
- [ ] **Diamond Model**
  - [ ] Adversary
  - [ ] Capability
  - [ ] Infrastructure
  - [ ] Victim

### Prática

- [ ] **TryHackMe**
  - [ ] Cyber Defense Path
  - [ ] Cyber Threat Intelligence
- [ ] **Blue Team Labs Online**
  - [ ] Malware analysis challenges
- [ ] **Estudar IOCs de ataques reais**
  - [ ] VirusTotal analysis
  - [ ] ANY.RUN sandbox

-----

## FASE 3: DETECÇÃO E MONITORAMENTO

**Período**: 6 a 10 meses  
**Status**: Planejado

### Log Management

#### Linux Logs

- [ ] **/var/log/syslog** - System logs
- [ ] **/var/log/auth.log** - Authentication
- [ ] **/var/log/kern.log** - Kernel
- [ ] **/var/log/apache2/** - Web server
- [ ] **journalctl** - systemd logs
  - [ ] journalctl -u service
  - [ ] journalctl -f (follow)
  - [ ] journalctl –since/–until

#### Windows Logs

- [ ] **Event Viewer**
  - [ ] Application logs
  - [ ] Security logs (audit)
  - [ ] System logs
  - [ ] Setup logs
- [ ] **Important Event IDs**
  - [ ] 4624: Successful logon
  - [ ] 4625: Failed logon
  - [ ] 4672: Admin logon
  - [ ] 4768/4769: Kerberos (TGT/TGS)
  - [ ] 4776: NTLM authentication
  - [ ] 4720: User account created
  - [ ] 4732: User added to group
  - [ ] 4688: Process creation
  - [ ] 4697: Service installed
  - [ ] 5140/5145: Network share access
  - [ ] 7045: Service installed (System log)
- [ ] **PowerShell Logging**
  - [ ] Module logging
  - [ ] Script block logging
  - [ ] Transcription
  - [ ] Event IDs: 4103, 4104

#### Network Logs

- [ ] **Firewall Logs**
  - [ ] Allowed/blocked connections
  - [ ] Source/destination IPs
  - [ ] Ports and protocols
- [ ] **Proxy Logs**
  - [ ] Web traffic
  - [ ] User activity
  - [ ] Blocked URLs
- [ ] **VPN Logs**
  - [ ] Connection attempts
  - [ ] Authentication
  - [ ] Session duration
- [ ] **DNS Logs**
  - [ ] Queries
  - [ ] Potential C2 communication
  - [ ] Data exfiltration
- [ ] **NetFlow/sFlow**
  - [ ] Network traffic metadata
  - [ ] Flow analysis
- [ ] **Packet Captures (PCAP)**
  - [ ] Full packet data
  - [ ] Wireshark analysis
  - [ ] tcpdump

### SIEM (Security Information and Event Management)

#### Conceitos SIEM

- [ ] **Log Aggregation**
  - [ ] Centralizar logs de múltiplas fontes
- [ ] **Correlation**
  - [ ] Relacionar eventos
  - [ ] Detect patterns
- [ ] **Normalization**
  - [ ] Padronizar formato
- [ ] **Alerting**
  - [ ] Rule-based
  - [ ] Threshold-based
  - [ ] Anomaly-based
- [ ] **Dashboards e Reporting**

#### SIEM Platforms

- [ ] **Splunk**
  - [ ] SPL (Search Processing Language)
  - [ ] Apps e Add-ons
  - [ ] Searches, Alerts, Dashboards
  - [ ] Free tier (500MB/day)
- [ ] **Elastic Stack (ELK)**
  - [ ] Elasticsearch (storage/search)
  - [ ] Logstash (ingest)
  - [ ] Kibana (visualization)
  - [ ] Beats (shippers)
  - [ ] Open-source
- [ ] **Wazuh**
  - [ ] Open-source SIEM
  - [ ] EDR capabilities
  - [ ] File integrity monitoring
  - [ ] Log analysis
- [ ] **ArcSight** (Micro Focus)
  - [ ] Enterprise SIEM
- [ ] **QRadar** (IBM)
  - [ ] Enterprise SIEM
- [ ] **Azure Sentinel**
  - [ ] Cloud-native SIEM
  - [ ] KQL (Kusto Query Language)

#### SIEM Use Cases

- [ ] **Failed Login Attempts**
  - [ ] Brute force detection
  - [ ] Threshold alerts
- [ ] **Privilege Escalation**
  - [ ] Unusual admin actions
  - [ ] Event ID 4672
- [ ] **Malware Execution**
  - [ ] Process creation
  - [ ] Known malicious hashes
- [ ] **Data Exfiltration**
  - [ ] Large data transfers
  - [ ] Unusual destinations
- [ ] **Lateral Movement**
  - [ ] Unusual network connections
  - [ ] Pass-the-hash indicators

### IDS/IPS (Intrusion Detection/Prevention Systems)

#### Tipos

- [ ] **NIDS (Network-based IDS)**
  - [ ] Monitora tráfego de rede
  - [ ] Snort, Suricata
- [ ] **NIPS (Network-based IPS)**
  - [ ] NIDS + block capability
- [ ] **HIDS (Host-based IDS)**
  - [ ] Monitora host individual
  - [ ] OSSEC, Wazuh
- [ ] **HIPS (Host-based IPS)**

#### Detection Methods

- [ ] **Signature-based**
  - [ ] Known patterns
  - [ ] Low false positives
  - [ ] Miss new threats
- [ ] **Anomaly-based**
  - [ ] Baseline behavior
  - [ ] Detect unknowns
  - [ ] Higher false positives
- [ ] **Behavior-based**
  - [ ] Heuristics
  - [ ] Malicious behavior patterns

#### Popular Tools

- [ ] **Snort**
  - [ ] Open-source NIDS
  - [ ] Rule-based
  - [ ] Community rules
- [ ] **Suricata**
  - [ ] Modern NIDS/IPS
  - [ ] Multi-threading
  - [ ] Protocol awareness
- [ ] **Zeek (Bro)**
  - [ ] Network analysis framework
  - [ ] Log generation
  - [ ] Scripting language

### EDR (Endpoint Detection and Response)

- [ ] **Conceito EDR**
  - [ ] Next-gen antivirus
  - [ ] Behavioral analysis
  - [ ] Threat hunting
  - [ ] Response capabilities
- [ ] **Recursos EDR**
  - [ ] Process monitoring
  - [ ] File integrity monitoring
  - [ ] Network connections
  - [ ] Registry changes
  - [ ] Memory analysis
  - [ ] Automated response
- [ ] **EDR Solutions**
  - [ ] Microsoft Defender for Endpoint
  - [ ] CrowdStrike Falcon
  - [ ] SentinelOne
  - [ ] Carbon Black
  - [ ] Cortex XDR (Palo Alto)

### Network Monitoring

- [ ] **Packet Analysis**
  - [ ] Wireshark (GUI)
  - [ ] tshark (CLI)
  - [ ] tcpdump
  - [ ] Display filters
  - [ ] Capture filters
- [ ] **Protocol Analysis**
  - [ ] HTTP/HTTPS
  - [ ] DNS
  - [ ] SMB
  - [ ] Kerberos
  - [ ] TLS handshakes
- [ ] **Network Baseline**
  - [ ] Normal traffic patterns
  - [ ] Bandwidth usage
  - [ ] Common connections
- [ ] **Anomaly Detection**
  - [ ] Unusual ports
  - [ ] Large data transfers
  - [ ] Beaconing (C2)
  - [ ] DNS tunneling

### Prática

- [ ] **Splunk**
  - [ ] Splunk Fundamentals 1 (free training)
  - [ ] Boss of the SOC (CTF)
- [ ] **TryHackMe**
  - [ ] Splunk 101, 201
  - [ ] Investigating with ELK 101
  - [ ] Wireshark 101
- [ ] **Security Blue Team**
  - [ ] BTL1 course material
- [ ] **Criar lab SIEM**
  - [ ] Wazuh ou ELK Stack
  - [ ] Ingerir logs Windows/Linux
  - [ ] Criar dashboards

-----

## FASE 4: INCIDENT RESPONSE

### Incident Response Process (NIST)

- [ ] **1. Preparation**
  - [ ] IR plan documented
  - [ ] Tools ready
  - [ ] Team trained
  - [ ] Communication plan
- [ ] **2. Detection and Analysis (Identification)**
  - [ ] Monitor alerts
  - [ ] Triage incidents
  - [ ] Determine scope
  - [ ] Classify severity
- [ ] **3. Containment**
  - [ ] **Short-term**: Isolate affected systems
  - [ ] **Long-term**: Temporary fixes
  - [ ] Preserve evidence
- [ ] **4. Eradication**
  - [ ] Remove malware
  - [ ] Close vulnerabilities
  - [ ] Patch systems
- [ ] **5. Recovery**
  - [ ] Restore systems
  - [ ] Validate functionality
  - [ ] Monitor for reinfection
- [ ] **6. Post-Incident/Lessons Learned**
  - [ ] Document incident
  - [ ] Root cause analysis
  - [ ] Improve processes
  - [ ] Update defenses

### Incident Classification

- [ ] **Severity Levels**
  - [ ] P1/Critical: Business-stopping
  - [ ] P2/High: Significant impact
  - [ ] P3/Medium: Limited impact
  - [ ] P4/Low: Minimal impact
- [ ] **Incident Types**
  - [ ] Malware infection
  - [ ] Phishing/Social engineering
  - [ ] Data breach
  - [ ] DDoS attack
  - [ ] Insider threat
  - [ ] Account compromise
  - [ ] Unauthorized access

### Digital Forensics Basics

- [ ] **Evidence Collection**
  - [ ] Chain of custody
  - [ ] Order of volatility
  - [ ] Legal considerations
- [ ] **Memory Forensics**
  - [ ] RAM acquisition
  - [ ] Volatility framework
  - [ ] Process analysis
  - [ ] Network connections
- [ ] **Disk Forensics**
  - [ ] Disk imaging
  - [ ] FTK Imager
  - [ ] Autopsy
  - [ ] File carving
  - [ ] Timeline analysis
- [ ] **Network Forensics**
  - [ ] PCAP analysis
  - [ ] Flow data
  - [ ] IDS/IPS logs
- [ ] **Artifacts Analysis**
  - [ ] Windows:
    - [ ] Prefetch
    - [ ] Registry
    - [ ] Event logs
    - [ ] Browser history
    - [ ] Shimcache, Amcache
    - [ ] USN Journal
  - [ ] Linux:
    - [ ] Bash history
    - [ ] Auth logs
    - [ ] Cron jobs

### Malware Analysis

#### Static Analysis

- [ ] **File Properties**
  - [ ] File type, size
  - [ ] Hash (MD5, SHA256)
  - [ ] PE headers (Windows)
  - [ ] Strings
  - [ ] Imports/Exports
- [ ] **Tools**
  - [ ] PEStudio, PE-bear
  - [ ] strings, file
  - [ ] VirusTotal
  - [ ] Hybrid-Analysis

#### Dynamic Analysis

- [ ] **Sandbox Analysis**
  - [ ] ANY.RUN
  - [ ] Joe Sandbox
  - [ ] Cuckoo Sandbox
  - [ ] Hybrid-Analysis
- [ ] **Behavior Monitoring**
  - [ ] Process Monitor (ProcMon)
  - [ ] Process Explorer
  - [ ] Regshot (registry changes)
  - [ ] Wireshark (network)
- [ ] **Indicators**
  - [ ] File creation/modification
  - [ ] Registry changes
  - [ ] Network connections (C2)
  - [ ] Process injection
  - [ ] Persistence mechanisms

### Threat Hunting

- [ ] **Conceito**
  - [ ] Proactive search for threats
  - [ ] Hypothesis-driven
  - [ ] Assume compromise
- [ ] **Metodologias**
  - [ ] Intelligence-driven
  - [ ] Situational awareness
  - [ ] Domain knowledge
- [ ] **Hunt Process**
  - [ ] Formulate hypothesis
  - [ ] Investigate via tools/data
  - [ ] Pattern/TTP discovery
  - [ ] Automate via analytics
- [ ] **Hunt Techniques**
  - [ ] Living off the Land detection
  - [ ] Lateral movement indicators
  - [ ] C2 beaconing
  - [ ] Unusual processes
  - [ ] Abnormal user behavior
- [ ] **Tools**
  - [ ] SIEM queries
  - [ ] EDR telemetry
  - [ ] PowerShell (Get-WinEvent)
  - [ ] OSQuery
  - [ ] Velociraptor

### Runbooks e Playbooks

- [ ] **Runbook**
  - [ ] Step-by-step procedures
  - [ ] Operational tasks
  - [ ] “How to do X”
- [ ] **Playbook**
  - [ ] Incident-specific response
  - [ ] Decision trees
  - [ ] “What to do when X happens”
- [ ] **Playbook Examples**
  - [ ] Phishing response
  - [ ] Ransomware response
  - [ ] Data breach response
  - [ ] DDoS response
  - [ ] Insider threat response

### Tools IR/Forensics

- [ ] **Volatility** - Memory analysis
- [ ] **Autopsy** - Disk forensics (GUI)
- [ ] **FTK Imager** - Disk imaging
- [ ] **Wireshark** - Network analysis
- [ ] **Sysinternals Suite** - Windows utilities
- [ ] **KAPE** - Kroll Artifact Parser and Extractor
- [ ] **Velociraptor** - Endpoint visibility
- [ ] **TheHive** - Incident response platform
- [ ] **MISP** - Threat intelligence platform

### Prática

- [ ] **TryHackMe**
  - [ ] Incident Response paths
  - [ ] DFIR modules
- [ ] **Blue Team Labs Online**
  - [ ] Incident Response challenges
- [ ] **CyberDefenders**
  - [ ] Digital forensics CTFs
- [ ] **Criar Playbooks**
  - [ ] Ransomware response
  - [ ] Phishing response
  - [ ] Account compromise

-----
## FASE 5: HARDENING E SECURE CONFIGURATION (CONTINUAÇÃO)

#### Windows Hardening (continuação)

- [ ] **Windows Firewall** (continuação)
  - [ ] Default deny inbound
  - [ ] Logging enabled
- [ ] **UAC (User Account Control)**
  - [ ] Enabled e configurado corretamente
- [ ] **Remote Desktop**
  - [ ] Network Level Authentication (NLA)
  - [ ] Limited users
  - [ ] Strong passwords

#### Linux Hardening

- [ ] **User Management**
  - [ ] Disable root login via SSH
  - [ ] Sudo configuration
  - [ ] Remove unnecessary users
- [ ] **SSH Hardening**
  - [ ] Key-based authentication only
  - [ ] Disable password auth
  - [ ] Change default port (opcional)
  - [ ] Fail2ban implementation
- [ ] **Firewall**
  - [ ] iptables/nftables
  - [ ] UFW (Uncomplicated Firewall)
  - [ ] Default deny policy
- [ ] **SELinux/AppArmor**
  - [ ] Mandatory Access Control
  - [ ] Policy configuration
- [ ] **File Permissions**
  - [ ] Least privilege
  - [ ] SUID/SGID audit
  - [ ] Remove world-writable files
- [ ] **Services**
  - [ ] Disable unnecessary services
  - [ ] systemctl list-units
- [ ] **Updates e Patching**
  - [ ] Automated security updates
  - [ ] unattended-upgrades (Debian/Ubuntu)

#### Active Directory Hardening

- [ ] **Account Policies**
  - [ ] Complex passwords
  - [ ] Account lockout policies
  - [ ] Kerberos policies
- [ ] **Group Policy**
  - [ ] Least privilege
  - [ ] Restricted groups
  - [ ] Software restriction policies
- [ ] **Admin Accounts**
  - [ ] Separate admin accounts
  - [ ] PAW (Privileged Access Workstations)
  - [ ] Tiered administration model
- [ ] **LAPS (Local Administrator Password Solution)**
  - [ ] Randomize local admin passwords
  - [ ] Centralized management
- [ ] **Kerberos**
  - [ ] Enable AES encryption
  - [ ] Disable DES, RC4
  - [ ] Monitor for delegation issues
- [ ] **LDAP**
  - [ ] LDAP signing
  - [ ] LDAP channel binding
- [ ] **SMB**
  - [ ] SMB signing enabled
  - [ ] Disable SMBv1
- [ ] **Attack Surface Reduction**
  - [ ] Disable LLMNR/NBT-NS
  - [ ] Disable WPAD
  - [ ] Protected Users group
  - [ ] Credential Guard

### Network Hardening

- [ ] **Network Segmentation**
  - [ ] VLANs
  - [ ] DMZ (Demilitarized Zone)
  - [ ] Perimeter defense
  - [ ] Zero Trust Network Access
- [ ] **Access Control**
  - [ ] ACLs (Access Control Lists)
  - [ ] MAC-based port security
  - [ ] 802.1X (NAC - Network Access Control)
- [ ] **Switch Security**
  - [ ] Port security
  - [ ] DHCP snooping
  - [ ] Dynamic ARP Inspection
  - [ ] Disable unused ports
- [ ] **Wireless Security**
  - [ ] WPA3 (ou WPA2-Enterprise)
  - [ ] Disable WPS
  - [ ] Hidden SSID (security by obscurity - limited)
  - [ ] MAC filtering (complementar)
  - [ ] Guest network isolation
- [ ] **VPN Security**
  - [ ] Strong encryption
  - [ ] MFA
  - [ ] Split tunneling policy

### Application Hardening

- [ ] **Web Servers**
  - [ ] Disable unnecessary modules
  - [ ] HTTPS only (TLS 1.2+)
  - [ ] Security headers (CSP, HSTS, X-Frame-Options)
  - [ ] Remove server banners
- [ ] **Databases**
  - [ ] Least privilege users
  - [ ] Encrypted connections
  - [ ] Disable remote root
  - [ ] Regular backups
- [ ] **Containers**
  - [ ] Run as non-root
  - [ ] Read-only filesystems
  - [ ] Resource limits
  - [ ] Image scanning (Trivy, Clair)

### Patch Management

- [ ] **Vulnerability Assessment**
  - [ ] Regular scans
  - [ ] Nessus, OpenVAS, Qualys
- [ ] **Patch Prioritization**
  - [ ] Critical patches first
  - [ ] CVSS scoring
  - [ ] Exploit availability
- [ ] **Testing**
  - [ ] Test environment
  - [ ] Rollback plan
- [ ] **Deployment**
  - [ ] Automated tools (WSUS, SCCM)
  - [ ] Maintenance windows

### Backup e Recovery

- [ ] **Backup Strategy**
  - [ ] 3-2-1 rule
    - 3 copies
    - 2 different media
    - 1 offsite
  - [ ] Full, incremental, differential
- [ ] **Testing Restores**
  - [ ] Regular restore tests
  - [ ] RTO (Recovery Time Objective)
  - [ ] RPO (Recovery Point Objective)
- [ ] **Ransomware Protection**
  - [ ] Immutable backups
  - [ ] Air-gapped backups
  - [ ] Backup encryption

### Prática

- [ ] **CIS Benchmarks**
  - [ ] Download benchmarks
  - [ ] Apply to lab systems
  - [ ] CIS-CAT tool
- [ ] **STIGs (Security Technical Implementation Guides)**
  - [ ] DISA STIGs
  - [ ] Apply guidelines
- [ ] **Criar Hardening Checklist**
  - [ ] Windows Server
  - [ ] Linux Server
  - [ ] Network devices

-----

## FASE 6: VULNERABILITY MANAGEMENT

**Período**: 17 a 20 meses  
**Status**: Planejado

### Vulnerability Assessment

#### Conceitos

- [ ] **Vulnerability**
  - [ ] Weakness que pode ser explorada
  - [ ] CVE (Common Vulnerabilities and Exposures)
- [ ] **Exposure**
  - [ ] Misconfiguration
  - [ ] Não é bug de software
- [ ] **Risk**
  - [ ] Likelihood x Impact
- [ ] **CVSS (Common Vulnerability Scoring System)**
  - [ ] Base score (0-10)
  - [ ] Temporal score
  - [ ] Environmental score
  - [ ] v2 vs v3 vs v4
- [ ] **Vulnerability Lifecycle**
  - [ ] Discovery
  - [ ] Disclosure
  - [ ] Patch availability
  - [ ] Patch deployment
  - [ ] Verification

#### Vulnerability Scanners

- [ ] **Nessus**
  - [ ] Tenable’s scanner
  - [ ] Professional vs Essentials
  - [ ] Policy creation
  - [ ] Authenticated vs unauthenticated scans
- [ ] **OpenVAS**
  - [ ] Open-source
  - [ ] Greenbone Security Manager
- [ ] **Qualys**
  - [ ] Cloud-based
  - [ ] VMDR (Vulnerability Management, Detection, Response)
- [ ] **Rapid7 Nexpose/InsightVM**
- [ ] **Configuration Assessment**
  - [ ] CIS-CAT
  - [ ] Microsoft Security Compliance Toolkit

#### Scan Types

- [ ] **Network Scans**
  - [ ] External perimeter
  - [ ] Internal network
- [ ] **Authenticated Scans**
  - [ ] Credentialed
  - [ ] Deeper visibility
- [ ] **Web Application Scans**
  - [ ] OWASP ZAP
  - [ ] Burp Suite Scanner
  - [ ] Nikto, Acunetix
- [ ] **Container Scans**
  - [ ] Trivy
  - [ ] Clair
  - [ ] Anchore
- [ ] **Cloud Scans**
  - [ ] ScoutSuite
  - [ ] Prowler (AWS)
  - [ ] Native tools (AWS Inspector, Azure Defender)

### Vulnerability Management Process

- [ ] **1. Discovery/Identification**
  - [ ] Asset inventory
  - [ ] Scanning
- [ ] **2. Prioritization**
  - [ ] CVSS score
  - [ ] Exploit availability
  - [ ] Asset criticality
  - [ ] Compensating controls
- [ ] **3. Remediation**
  - [ ] Patching
  - [ ] Configuration changes
  - [ ] Workarounds
- [ ] **4. Verification**
  - [ ] Rescan
  - [ ] Validate fix
- [ ] **5. Reporting**
  - [ ] Executive summaries
  - [ ] Technical details
  - [ ] Trend analysis

### Asset Management

- [ ] **Inventory**
  - [ ] Hardware inventory
  - [ ] Software inventory
  - [ ] Cloud resources
  - [ ] CMDB (Configuration Management Database)
- [ ] **Asset Classification**
  - [ ] Critical, High, Medium, Low
  - [ ] Data sensitivity
- [ ] **Lifecycle Management**
  - [ ] Procurement
  - [ ] Deployment
  - [ ] Maintenance
  - [ ] Decommission

### Compliance Scanning

- [ ] **Compliance Frameworks**
  - [ ] PCI DSS
  - [ ] HIPAA
  - [ ] SOX
  - [ ] GDPR/LGPD
  - [ ] ISO 27001
- [ ] **Compliance Tools**
  - [ ] Nessus compliance modules
  - [ ] OpenSCAP
  - [ ] Cloud compliance tools

### Prática

- [ ] **Instalar Nessus Essentials**
  - [ ] Scan de lab environment
  - [ ] Análise de resultados
- [ ] **OpenVAS**
  - [ ] Setup e scanning
- [ ] **Trivy**
  - [ ] Container image scanning
- [ ] **Criar Vulnerability Management Program**
  - [ ] Policies e procedures
  - [ ] SLA para remediation
  - [ ] Reporting templates

-----

## FASE 7: SECURITY OPERATIONS CENTER (SOC)

**Período**: 20 a 22 meses  
**Status**: Avançado

### SOC Fundamentals

#### SOC Tiers

- [ ] **Tier 1: Analyst (Triage)**
  - [ ] Alert monitoring
  - [ ] Initial triage
  - [ ] Ticket creation
  - [ ] Escalation
- [ ] **Tier 2: Incident Responder**
  - [ ] Deep investigation
  - [ ] Incident handling
  - [ ] Threat hunting
- [ ] **Tier 3: Subject Matter Expert**
  - [ ] Advanced threats
  - [ ] Malware analysis
  - [ ] Tool tuning
- [ ] **SOC Manager**
  - [ ] Team leadership
  - [ ] Metrics and reporting
  - [ ] Process improvement

#### SOC Metrics e KPIs

- [ ] **Detection Metrics**
  - [ ] MTTD (Mean Time To Detect)
  - [ ] Alert volume
  - [ ] True positive rate
  - [ ] False positive rate
- [ ] **Response Metrics**
  - [ ] MTTR (Mean Time To Respond)
  - [ ] MTTC (Mean Time To Contain)
  - [ ] Incident resolution time
- [ ] **Operational Metrics**
  - [ ] Ticket volume
  - [ ] SLA compliance
  - [ ] Escalation rate

### SOC Tools Stack

- [ ] **SIEM** (já coberto em Fase 3)
- [ ] **SOAR** (Security Orchestration, Automation, Response)
  - [ ] Automated workflows
  - [ ] Playbook execution
  - [ ] Integration hub
  - [ ] Platforms: Splunk SOAR, Cortex XSOAR, TheHive
- [ ] **Ticketing/Case Management**
  - [ ] JIRA
  - [ ] ServiceNow
  - [ ] TheHive
- [ ] **Threat Intelligence Platforms**
  - [ ] MISP
  - [ ] ThreatConnect
  - [ ] Anomali
- [ ] **Sandbox**
  - [ ] ANY.RUN
  - [ ] Joe Sandbox
  - [ ] Cuckoo
- [ ] **EDR** (já coberto)
- [ ] **NDR (Network Detection and Response)**
  - [ ] Darktrace
  - [ ] Vectra
  - [ ] ExtraHop
- [ ] **Email Security**
  - [ ] Proofpoint
  - [ ] Mimecast
  - [ ] Microsoft Defender for Office 365
- [ ] **UEBA (User and Entity Behavior Analytics)**
  - [ ] Exabeam
  - [ ] Splunk UBA
  - [ ] Microsoft Sentinel UEBA

### Alert Triage

- [ ] **Triage Process**

1. Alert received
1. Initial assessment
1. Context gathering
1. Determine true/false positive
1. Escalate or close

- [ ] **Context Gathering**
  - [ ] User information
  - [ ] Asset information
  - [ ] Historical activity
  - [ ] Threat intelligence
  - [ ] Related alerts
- [ ] **Common Alert Types**
  - [ ] Malware detection
  - [ ] Suspicious authentication
  - [ ] Data exfiltration
  - [ ] Policy violation
  - [ ] Network anomaly

### Threat Intelligence

- [ ] **Intelligence Types**
  - [ ] Strategic (high-level trends)
  - [ ] Tactical (TTPs)
  - [ ] Operational (campaigns)
  - [ ] Technical (IOCs)
- [ ] **IOCs (Indicators of Compromise)**
  - [ ] IP addresses
  - [ ] Domain names
  - [ ] File hashes
  - [ ] URLs
  - [ ] Email addresses
  - [ ] Registry keys
- [ ] **Threat Feeds**
  - [ ] Commercial feeds
  - [ ] Open-source (AlienVault OTX, [Abuse.ch](http://Abuse.ch))
  - [ ] ISACs/ISAOs
  - [ ] Government (CISA)
- [ ] **Threat Intelligence Platforms**
  - [ ] MISP (Malware Information Sharing Platform)
  - [ ] OpenCTI
  - [ ] ThreatConnect

### SOC Automation (SOAR)

- [ ] **Use Cases**
  - [ ] Phishing triage
  - [ ] Malware analysis
  - [ ] Enrichment automation
  - [ ] Ticket creation
  - [ ] Containment actions
- [ ] **Playbooks**
  - [ ] Automated workflows
  - [ ] Decision trees
  - [ ] Human approval gates
- [ ] **Integration**
  - [ ] SIEM
  - [ ] EDR
  - [ ] Firewall
  - [ ] Active Directory
  - [ ] Ticketing

### Communication

- [ ] **Stakeholder Communication**
  - [ ] Management
  - [ ] IT teams
  - [ ] Legal
  - [ ] PR/Communications
- [ ] **Reporting**
  - [ ] Daily briefings
  - [ ] Weekly reports
  - [ ] Monthly metrics
  - [ ] Executive summaries
- [ ] **Incident Notification**
  - [ ] Escalation procedures
  - [ ] Contact lists
  - [ ] Communication templates

### Prática

- [ ] **Boss of the SOC (BOTS)**
  - [ ] Splunk CTF dataset
- [ ] **CyberDefenders**
  - [ ] SOC challenges
- [ ] **TryHackMe**
  - [ ] SOC Level 1 Path (completo)
  - [ ] SOC Level 2 Path
- [ ] **Security Blue Team**
  - [ ] BTL1 certification prep
- [ ] **Simular Shift SOC**
  - [ ] Monitor lab SIEM
  - [ ] Criar e resolver tickets

-----

## FASE 8: GOVERNANCE, RISK & COMPLIANCE (GRC)

**Período**: 22 a 24 meses  
**Status**: Especialização

### Governance

- [ ] **Security Policies**
  - [ ] Acceptable Use Policy (AUP)
  - [ ] Password policy
  - [ ] Data classification policy
  - [ ] Incident response policy
  - [ ] Change management policy
- [ ] **Security Standards**
  - [ ] Technical standards
  - [ ] Configuration baselines
  - [ ] Naming conventions
- [ ] **Procedures**
  - [ ] Step-by-step instructions
  - [ ] Runbooks
- [ ] **Guidelines**
  - [ ] Recommendations
  - [ ] Best practices

### Risk Management

- [ ] **Risk Assessment Process**

1. Asset identification
1. Threat identification
1. Vulnerability identification
1. Risk analysis
1. Risk evaluation
1. Risk treatment

- [ ] **Risk Analysis Methods**
  - [ ] Qualitative (Low/Med/High)
  - [ ] Quantitative (financial)
  - [ ] Semi-quantitative
- [ ] **Risk Treatment Options**
  - [ ] Accept
  - [ ] Mitigate
  - [ ] Transfer (insurance)
  - [ ] Avoid
- [ ] **Risk Metrics**
  - [ ] ALE (Annual Loss Expectancy)
  - [ ] SLE (Single Loss Expectancy)
  - [ ] ARO (Annual Rate of Occurrence)
  - [ ] ALE = SLE x ARO
- [ ] **Risk Register**
  - [ ] Document identified risks
  - [ ] Risk owners
  - [ ] Mitigation status

### Compliance Frameworks

#### ISO 27001/27002

- [ ] **ISO 27001**
  - [ ] ISMS (Information Security Management System)
  - [ ] Certification process
  - [ ] Annex A controls (114 controls)
- [ ] **Control Categories**
  - [ ] Organizational controls
  - [ ] People controls
  - [ ] Physical controls
  - [ ] Technological controls

#### NIST Frameworks

- [ ] **NIST Cybersecurity Framework (CSF)**
  - [ ] Identify
  - [ ] Protect
  - [ ] Detect
  - [ ] Respond
  - [ ] Recover
- [ ] **NIST 800-53**
  - [ ] Security controls for federal systems
  - [ ] Control families (AC, AU, CA, CM, etc)
- [ ] **NIST 800-171**
  - [ ] Protecting CUI (Controlled Unclassified Information)

#### CIS Controls

- [ ] **CIS Critical Security Controls**
  - [ ] 18 controls
  - [ ] Implementation Groups (IG1, IG2, IG3)
  - [ ] Prioritized approach
- [ ] **Key Controls**
  - [ ] Inventory and control of assets
  - [ ] Continuous vulnerability management
  - [ ] Controlled use of administrative privileges
  - [ ] Secure configuration
  - [ ] Account monitoring and control

#### Industry-Specific

- [ ] **PCI DSS** (Payment Card Industry)
  - [ ] 12 requirements
  - [ ] Protect cardholder data
  - [ ] Quarterly scans (ASV)
- [ ] **HIPAA** (Healthcare)
  - [ ] PHI (Protected Health Information)
  - [ ] Privacy Rule
  - [ ] Security Rule
  - [ ] Breach Notification Rule
- [ ] **SOX** (Sarbanes-Oxley)
  - [ ] Financial reporting
  - [ ] IT controls
- [ ] **GDPR** (General Data Protection Regulation - Europe)
  - [ ] Personal data protection
  - [ ] Right to be forgotten
  - [ ] Breach notification (72 hours)
- [ ] **LGPD** (Lei Geral de Proteção de Dados - Brasil)
  - [ ] Similar to GDPR
  - [ ] ANPD (Autoridade Nacional)

### Audit e Assessment

- [ ] **Internal Audit**
  - [ ] Self-assessment
  - [ ] Control testing
  - [ ] Findings and recommendations
- [ ] **External Audit**
  - [ ] Third-party auditors
  - [ ] Certification audits
  - [ ] Compliance verification
- [ ] **Penetration Testing**
  - [ ] Authorized testing
  - [ ] White/Gray/Black box
  - [ ] Rules of engagement
- [ ] **Vulnerability Assessment** (já coberto)

### Business Continuity & Disaster Recovery

- [ ] **BCP (Business Continuity Plan)**
  - [ ] Ensure business operations continue
  - [ ] Alternative work locations
  - [ ] Communication plans
- [ ] **DRP (Disaster Recovery Plan)**
  - [ ] IT system recovery
  - [ ] Backup and restore
  - [ ] Failover procedures
- [ ] **Testing**
  - [ ] Tabletop exercises
  - [ ] Simulations
  - [ ] Full failover tests
- [ ] **Metrics**
  - [ ] RTO (Recovery Time Objective)
  - [ ] RPO (Recovery Point Objective)
  - [ ] MTBF (Mean Time Between Failures)

### Third-Party Risk Management

- [ ] **Vendor Assessment**
  - [ ] Security questionnaires
  - [ ] SOC 2 reports
  - [ ] Onsite assessments
- [ ] **Contracts**
  - [ ] Security requirements
  - [ ] SLAs
  - [ ] Right to audit
- [ ] **Ongoing Monitoring**
  - [ ] Annual reassessment
  - [ ] Incident notification requirements

### Prática

- [ ] **Study ISO 27001**
  - [ ] Read standard (ISO/IEC 27001:2022)
  - [ ] Review Annex A
- [ ] **NIST CSF**
  - [ ] Framework documentation
  - [ ] Apply to lab/project
- [ ] **CIS Controls**
  - [ ] Implementation guide
  - [ ] CIS-CAT assessment
- [ ] **Create GRC Documentation**
  - [ ] Sample security policy
  - [ ] Risk assessment template
  - [ ] Compliance checklist

-----

## CERTIFICAÇÕES (CAMINHO RECOMENDADO)

### Entry Level (0-6 meses)

- [ ] **CompTIA A+**
  - Custo: ~$250 por exam (2 exams)
  - Foco: IT fundamentals, hardware, OS
- [ ] **CompTIA Network+**
  - Custo: ~$350
  - Foco: Networking fundamentals
- [ ] **CompTIA Security+**
  - Custo: ~$400
  - Foco: Security fundamentals
  - **RECOMENDADA** - Entry point para InfoSec

### Intermediate (6-18 meses)

- [ ] **CompTIA CySA+** (Cybersecurity Analyst)
  - Custo: ~$400
  - Foco: Threat detection, SOC operations
- [ ] **Security Blue Team Level 1 (BTL1)**
  - Custo: ~$400
  - Foco: Hands-on Blue Team skills
- [ ] **CompTIA CASP+** (Advanced Security Practitioner)
  - Custo: ~$500
  - Foco: Enterprise security architect

### Advanced (18-24 meses)

- [ ] **GCIH** (GIAC Certified Incident Handler)
  - Custo: ~$2500 (exam only) ou ~$8000 (com curso SANS)
  - Foco: Incident response
- [ ] **GCFA** (GIAC Certified Forensic Analyst)
  - Custo: ~$2500
  - Foco: Digital forensics
- [ ] **GCIA** (GIAC Certified Intrusion Analyst)
  - Custo: ~$2500
  - Foco: Network traffic analysis, IDS
- [ ] **GSEC** (GIAC Security Essentials)
  - Custo: ~$2000
  - Foco: Security fundamentals (mais avançado que Sec+)

### Management/GRC (18+ meses)

- [ ] **CISSP** (Certified Information Systems Security Professional)
  - Custo: ~$750
  - Requisito: 5 anos experiência (waiver possível)
  - Foco: Broad security knowledge, management
- [ ] **CISM** (Certified Information Security Manager)
  - Custo: ~$750
  - Foco: Security management, governance
- [ ] **CISA** (Certified Information Systems Auditor)
  - Custo: ~$760
  - Foco: IT audit, compliance
- [ ] **CRISC** (Certified in Risk and Information Systems Control)
  - Custo: ~$760
  - Foco: Risk management

### Specialized

- [ ] **CCNA Cyber Ops**
  - Custo: ~$300
  - Foco: Cisco SOC operations
- [ ] **Azure Security Engineer Associate**
  - Custo: ~$165
  - Foco: Azure security
- [ ] **AWS Certified Security - Specialty**
  - Custo: ~$300
  - Foco: AWS security

-----

## PLATAFORMAS DE PRÁTICA

### Iniciante (0-6 meses)

- [ ] **TryHackMe**
  - Pre Security Path
  - Introduction to Cybersecurity
  - SOC Level 1 Path
  - Custo: ~$10/mês Premium
- [ ] **Blue Team Labs Online**
  - Free challenges
  - Investigations
  - Custo: Free tier ou ~$15/mês
- [ ] **CyberDefenders**
  - Blue Team CTFs
  - DFIR challenges
  - Free
- [ ] **LetsDefend**
  - SOC Analyst training
  - Hands-on incidents
  - Custo: Free tier ou ~$20/mês

### Intermediário (6-18 meses)

- [ ] **Security Blue Team**
  - BTL1 course content
  - Hands-on labs
  - Custo: ~$400 com certificação
- [ ] **SANS Cyber Ranges**
  - NetWars
  - CyberCity
  - Custo: Varia (geralmente em eventos)
- [ ] **RangeForce**
  - Enterprise training platform
  - Custo: Geralmente corporativo

### Avançado (18+ meses)

- [ ] **HackTheBox**
  - Sherlock (DFIR challenges)
  - Forensics challenges
  - Custo: ~$20/mês VIP
- [ ] **CyberDefenders**
  - Advanced challenges
  - Malware analysis
- [ ] **Boss of the SOC (BOTS)**
  - Splunk CTF datasets
  - Free

-----

## FERRAMENTAS ESSENCIAIS POR CATEGORIA

### SIEM

- [ ] Splunk (commercial)
- [ ] Elastic Stack (open-source)
- [ ] Wazuh (open-source)
- [ ] Azure Sentinel (cloud)
- [ ] IBM QRadar (enterprise)

### Log Analysis

- [ ] Splunk
- [ ] ELK (Elasticsearch, Logstash, Kibana)
- [ ] Graylog
- [ ] Grep, awk, sed (CLI)

### Network Monitoring

- [ ] Wireshark
- [ ] tshark / tcpdump
- [ ] Zeek (Bro)
- [ ] Suricata
- [ ] NetworkMiner

### Endpoint

- [ ] Microsoft Defender for Endpoint
- [ ] CrowdStrike Falcon
- [ ] SentinelOne
- [ ] Carbon Black
- [ ] Wazuh (open-source)

### IDS/IPS

- [ ] Snort
- [ ] Suricata
- [ ] Zeek

### Vulnerability Scanning

- [ ] Nessus
- [ ] OpenVAS
- [ ] Qualys
- [ ] Rapid7 Nexpose

### Forensics

- [ ] Volatility (memory)
- [ ] Autopsy (disk)
- [ ] FTK Imager
- [ ] KAPE
- [ ] Velociraptor

### Malware Analysis

- [ ] ANY.RUN (sandbox)
- [ ] Joe Sandbox
- [ ] Cuckoo Sandbox
- [ ] VirusTotal
- [ ] Hybrid-Analysis

### Incident Response

- [ ] TheHive
- [ ] Velociraptor
- [ ] GRR Rapid Response
- [ ] OSQuery

### Threat Intelligence

- [ ] MISP
- [ ] OpenCTI
- [ ] ThreatConnect
- [ ] AlienVault OTX

### SOAR

- [ ] Splunk SOAR (Phantom)
- [ ] Cortex XSOAR (Palo Alto)
- [ ] TheHive + Cortex
- [ ] Shuffle (open-source)

### Hardening/Config

- [ ] CIS-CAT
- [ ] Microsoft Security Compliance Toolkit
- [ ] Lynis (Linux auditing)

### Windows

- [ ] Sysinternals Suite
- [ ] Event Viewer
- [ ] PowerShell
- [ ] Windows Admin Center

### Linux

- [ ] journalctl
- [ ] auditd
- [ ] osquery
- [ ] fail2ban

-----

## TIMELINE REALISTA

**Total**: 24 meses de estudo dedicado

|Fase  |Período  |Duração|Foco Principal                           |
|------|---------|-------|-----------------------------------------|
|Fase 1|Mês 1-3  |3 meses|Fundamentos IT e Segurança               |
|Fase 2|Mês 3-6  |3 meses|Ameaças e Ataques                        |
|Fase 3|Mês 6-10 |4 meses|Detecção e Monitoramento (SIEM, IDS, EDR)|
|Fase 4|Mês 10-14|4 meses|Incident Response e Forensics            |
|Fase 5|Mês 14-17|3 meses|Hardening e Secure Configuration         |
|Fase 6|Mês 17-20|3 meses|Vulnerability Management                 |
|Fase 7|Mês 20-22|2 meses|SOC Operations                           |
|Fase 8|Mês 22-24|2 meses|GRC (Governance, Risk, Compliance)       |

### Dedicação Sugerida

**Dias úteis**: 2-3 horas/dia

- 1h teoria
- 1-2h prática (labs)

**Fins de semana**: 4-6 horas/dia

- Challenges
- Lab setup
- Documentação

**Total semanal**: ~20 horas

-----

## MÉTRICAS DE PROGRESSO

### Metas Mensais

- [ ] Completar módulos/paths planejados
- [ ] Resolver 5-10 challenges (BTL, CyberDefenders)
- [ ] Documentar aprendizados
- [ ] Atualizar lab environment

### Metas Trimestrais

- [ ] Completar certificação ou curso
- [ ] Projeto prático (lab completo, análise de incidente)
- [ ] Cheat sheets atualizados

### Metas Anuais

- [ ] **Ano 1**: CompTIA Security+ + CySA+ + Lab SIEM funcional + Incident response playbooks
- [ ] **Ano 2**: BTL1/GCIH + Advanced SIEM skills + Portfolio completo + Pronto para SOC Analyst role

-----

## PRÓXIMOS PASSOS IMEDIATOS

### Esta Semana

- [ ] Completar TryHackMe: Introduction to Cybersecurity
- [ ] Configurar VM Windows + Linux
- [ ] Estudar: OSI Model
- [ ] Praticar: Event Viewer (Windows)

### Este Mês

- [ ] TryHackMe: Pre Security Path
- [ ] Estudar CIA Triad, AAA
- [ ] Configurar lab básico (Kali + targets)
- [ ] Começar CompTIA Security+ study

### Este Trimestre

- [ ] Completar Fase 1
- [ ] Iniciar Fase 2
- 
