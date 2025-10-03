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

