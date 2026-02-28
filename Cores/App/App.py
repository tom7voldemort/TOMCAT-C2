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

import threading
import os
from Cores.Systems.System import StrObject
from Config.Color import TMColor
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from time import time


class TOMCATC2GUI:
    def __init__(self):
        import os

        BaseDir = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        TemplateDir = os.path.join(BaseDir, "Config", "templates")
        StaticDir = os.path.join(BaseDir, "Config", "static")
        if not os.path.exists(TemplateDir):
            TemplateDir = os.path.join(BaseDir, "config", "templates")
            StaticDir = os.path.join(BaseDir, "config", "static")
        self.App = Flask(
            __name__,
            template_folder=TemplateDir,
            static_folder=StaticDir,
        )
        self.App.config["SECRET_KEY"] = "VE9NQ0FULUMyLUZyYW1ld29ya3MtVjIK"
        self.Server = None
        self.ServerStartTime = None
        self.Logs = []
        self.MaxLogs = 1000
        self.SetupRoutes()

    def SetupRoutes(self):
        @self.App.route("/")
        def Index():
            return render_template("index.html")

        @self.App.route("/api/server/status")
        def ServerStatus():
            if self.Server and self.Server.Running:
                Uptime = self.GetUptime()
                if hasattr(self.Server, "GetSessionStats"):
                    Stats = self.Server.GetSessionStats()
                    AgentCount = Stats["Total"]
                    SessionBreakdown = {
                        "TOMCAT": Stats.get("TOMCAT", 0),
                        "Meterpreter": Stats.get("Meterpreter", 0),
                        "ReverseShell": Stats.get("ReverseShell", 0),
                    }
                else:
                    AgentCount = len(self.Server.Agents)
                    SessionBreakdown = None
                UseMeterpreterMode = (
                    os.environ.get("TOMCAT_METERPRETER_MODE", "0") == "1"
                )
                response = {
                    "Status": "Online",
                    "Host": self.Server.Host,
                    "Port": self.Server.Port,
                    "Uptime": Uptime,
                    "Agents": AgentCount,
                    "Timestamp": time(),
                    "MeterpreterMode": UseMeterpreterMode,
                }
                if not UseMeterpreterMode:
                    response["Key"] = self.Server.Crypto.GetKey().decode()
                else:
                    response["Key"] = "Multi-Protocol (Mixed Encryption)"
                if SessionBreakdown:
                    response["SessionStats"] = SessionBreakdown
                return jsonify(response)
            return jsonify({"Status": "Offline", "Agents": 0})

        @self.App.route("/api/agents")
        def GetAgents():
            if self.Server and self.Server.Running:
                Agents = []
                if hasattr(self.Server, "GetSessions"):
                    Sessions = self.Server.GetSessions()
                    for Session in Sessions:
                        Agents.append(
                            {
                                "ID": Session["ID"],
                                "Address": f"{Session['Address'][0]}:{Session['Address'][1]}",
                                "OS": Session["OS"],
                                "Hostname": Session["Hostname"],
                                "User": Session["User"],
                                "Arch": Session["Arch"],
                                "AgentIP": Session.get("AgentIP", "N/A"),
                                "AgentName": Session.get(
                                    "AgentName", f"AGENT-{Session['ID']}"
                                ),
                                "JoinedAt": Session["JoinedAt"],
                                "Type": Session.get("Type", "TOMCAT"),
                                "ShellMode": Session.get("ShellMode", "Standard"),
                            }
                        )
                else:
                    for Agent in self.Server.GetAgents():
                        Agents.append(
                            {
                                "ID": Agent["ID"],
                                "Address": f"{Agent['Address'][0]}:{Agent['Address'][1]}",
                                "OS": Agent["OS"],
                                "Hostname": Agent["Hostname"],
                                "User": Agent["User"],
                                "Arch": Agent["Arch"],
                                "AgentIP": Agent.get("AgentIP", "N/A"),
                                "AgentName": Agent.get(
                                    "AgentName", f"AGENT-{Agent['ID']}"
                                ),
                                "JoinedAt": Agent["JoinedAt"],
                                "Type": "TOMCAT",
                                "ShellMode": "Standard",
                            }
                        )
                return jsonify({"Agents": Agents})
            return jsonify({"Agents": []})

        @self.App.route("/api/logs")
        def GetLogs():
            return jsonify({"Logs": self.Logs})

        @self.App.route("/api/logs/clear", methods=["POST"])
        def ClearLogs():
            self.Logs = []
            return jsonify({"Success": True})

        @self.App.route("/api/server/start", methods=["POST"])
        def StartServer():
            Data = request.get_json()
            Host = Data.get("Host", "0.0.0.0")
            Port = int(Data.get("Port", 4444))
            UseMTLS = os.environ.get("TOMCAT_USE_MTLS", "0") == "1"
            UseMeterpreterMode = os.environ.get("TOMCAT_METERPRETER_MODE", "0") == "1"
            if self.Server and self.Server.Running:
                return jsonify({"Success": False, "Message": "Server Already Running"})
            if UseMeterpreterMode:
                from Cores.Systems.MultiProtocolServer import MultiProtocolServer

                self.Server = MultiProtocolServer(
                    Host, Port, UseMTLS=UseMTLS, MeterpreterMode=True
                )
            else:
                from Cores.Systems.Server import TOMCATC2SERVER

                self.Server = TOMCATC2SERVER(Host, Port, UseMTLS=UseMTLS)
            self.Server.AddEventListener(self.ServerEventHandler)
            Success, Message = self.Server.StartServer()
            if Success:
                self.ServerStartTime = time()
                StrObject.Animation(
                    f"{TMColor.green}[{TMColor.cyan}DEBUG{TMColor.green}] {TMColor.green}] Server Started At Timestamp: {self.ServerStartTime}", delay=0.001
                )
                StrObject.Animation(
                    f"{TMColor.green}[{TMColor.cyan}DEBUG{TMColor.green}] {TMColor.green}] Current Time: {time()}", delay=0.001
                )
                self.AddLog(f"[+] {Message}")
                if UseMeterpreterMode:
                    self.AddLog("[+] Mode: Multi-Protocol")
                    self.AddLog(
                        "[+] Accepts: TOMCAT Agents, Meterpreter Sessions, Reverse Shells"
                    )
                else:
                    self.AddLog(
                        f"[+] Session Key: {self.Server.Crypto.GetKey().decode()}"
                    )
                if UseMTLS:
                    self.AddLog("[+] Security: MTLS Enabled")
                AcceptThread = threading.Thread(
                    target=self.Server.AcceptConnections, daemon=True
                )
                AcceptThread.start()
                response = {
                    "Success": True,
                    "Message": Message,
                    "Host": Host,
                    "Port": Port,
                    "MTLSEnabled": UseMTLS,
                    "MeterpreterMode": UseMeterpreterMode,
                }
                if not UseMeterpreterMode:
                    response["Key"] = self.Server.Crypto.GetKey().decode()
                else:
                    response["Key"] = "Multi-Protocol Mode"
                return jsonify(response)
            else:
                self.AddLog(f"[!] {Message}")
                return jsonify({"Success": False, "Message": Message})

        @self.App.route("/api/server/stop", methods=["POST"])
        def StopServer():
            if self.Server and self.Server.Running:
                self.Server.StopServer()
                self.ServerStartTime = None
                self.AddLog("[!] Server Stopped")
                return jsonify({"Success": True, "Message": "Server Stopped"})
            else:
                return jsonify({"Success": False, "Message": "Server Not Running"})

        @self.App.route("/api/command/execute", methods=["POST"])
        def ExecuteCommand():
            Data = request.get_json()
            AgentId = Data.get("AgentId")
            Command = Data.get("Command")
            if not self.Server or not self.Server.Running:
                return jsonify({"Success": False, "Output": "Server Not Running"})
            if not AgentId or not Command:
                return jsonify(
                    {"Success": False, "Output": "Missing Agent ID Or Command"}
                )
            self.AddLog(f"[+] Agent {AgentId} | Executing: {Command}")
            Success, Output = self.Server.ExecuteCommand(int(AgentId), Command)
            if Success:
                self.AddLog(f"[+] Output:\n{Output}")
            else:
                self.AddLog(f"[!] Error: {Output}")
            return jsonify({"Success": Success, "Output": Output, "Command": Command})

    def ServerEventHandler(self, EventType, Data):
        if EventType == "AgentConnected":
            SessionType = Data.get("Type", "TOMCAT")
            TypeBadge = f"[{SessionType}]"
            LogMessage = f"[+] New Session Connected {TypeBadge}\n    ID: {Data['ID']}\n    Hostname: {Data['Hostname']}\n    Connection: {Data['Address'][0]}:{Data['Address'][1]}\n    Agent IP: {Data.get('AgentIP', 'Unknown')}\n    OS: {Data['OS']}\n    User: {Data['User']}\n    Arch: {Data['Arch']}\n"
            if SessionType == "TOMCAT":
                if Data.get("MTLSEnabled"):
                    LogMessage += f"    Certificate: {Data.get('CertCN', 'N/A')}\n"
                    LogMessage += "    Security: MTLS Verified\n"
                LogMessage += "    Encryption: Fernet\n"
                if Data.get("ShellMode"):
                    LogMessage += f"    Shell Mode: {Data['ShellMode']}\n"
            elif SessionType == "METERPRETER":
                LogMessage += "    Protocol: Meterpreter TLV\n"
                LogMessage += "    Security: RAW (No encryption)\n"
            elif SessionType == "REVERSE_SHELL":
                LogMessage += "    Protocol: Raw Shell\n"
                LogMessage += "    Security: RAW (No encryption)\n"
            self.AddLog(LogMessage)
        elif EventType == "AgentDisconnected":
            self.AddLog(
                f"[!] Session Disconnected\n    ID: {Data['ID']}\n    Reason: {Data.get('Reason', 'Unknown')}\n"
            )
        elif EventType == "ServerStarted":
            pass
        elif EventType == "Error":
            self.AddLog(f"[!] {Data.get('Message', 'Unknown Error')}")

    def AddLog(self, Message):
        Timestamp = datetime.now().strftime("%H:%M:%S")
        LogEntry = f"[{Timestamp}] {Message}"
        self.Logs.append(LogEntry)
        if len(self.Logs) > self.MaxLogs:
            self.Logs = self.Logs[-self.MaxLogs :]

    def GetUptime(self):
        if not self.ServerStartTime:
            return "00:00:00"
        Elapsed = int(time() - self.ServerStartTime)
        Hours = Elapsed // 3600
        Minutes = (Elapsed % 3600) // 60
        Seconds = Elapsed % 60
        return f"{Hours:02d}:{Minutes:02d}:{Seconds:02d}"

    def Run(self, Host="0.0.0.0", Port=5000, Debug=False):
        StrObject.Messages(f"Starting Web Panel On http://{Host}:{Port}")
        StrObject.Messages(f"Press Ctrl+C To Stop")
        self.App.run(host=Host, port=Port, debug=Debug, threaded=True)
