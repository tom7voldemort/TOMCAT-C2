#!/usr/bin/python3
# TOMCAT C2 Frameworks V2
# Author: TOM7
# GitHub: tom7voldemort

"""
[+] NOTE:
    -- Copying without owner permission is illegal.
    -- If you want to expand this project, ask owner for collaboration instead.

    Thanks for understanding.
    ~TOM7
"""

import random
import socket
from datetime import datetime

from Config.Color import TMColor
from Cores.Systems.System import StrObject

Hostname = socket.gethostname()
Now = datetime.now()


class AUTHBanner:
    def Logo():
        Banner = f"""
            {TMColor.red}[{TMColor.white}+{TMColor.red}]  {TMColor.red}Author       :   {TMColor.white}TOM7
            {TMColor.red}[{TMColor.white}+{TMColor.red}]  {TMColor.red}Github       :   {TMColor.white}tom7voldemort
            {TMColor.red}[{TMColor.white}+{TMColor.red}]  {TMColor.red}Version      :   {TMColor.white}2.0
            {TMColor.red}[{TMColor.white}+{TMColor.red}]  {TMColor.red}Time         :   {TMColor.white}{Now.strftime("%H:%M:%S")}
            {TMColor.red}[{TMColor.white}+{TMColor.red}]  {TMColor.red}Date         :   {TMColor.white}{Now.strftime("%Y-%m-%d")}
        {TMColor.reset}
        """
        StrObject.Animation(Banner, delay=0.001)


class TBanner:
    def Logo():
        quote = [
            "                             ♠️ Access Denied? Watch Me ♠️                      ",
            "                      ♠️ Encrypt Your Fear, Decrypt Your Power ♠️               ",
            "                           ♠️ Peace Was Never An Options ♠️                     ",
            "                                ♠️ TRICK OR TRAPPED ♠️                          ",
            "                     ♠️ Boys Life In Peace, But Man Want A War! ♠️              ",
            "                            ♠️ Break - Breach - Dominate ♠️                     ",
            "                              ♠️ Ghost In Your Machine ♠️                       ",
            "                               ♠️ Hunt. Hack. Conquer ♠️                        ",
        ]
        msg = random.choice(quote)
        Banner = f"""
        {TMColor.bold}
		{TMColor.red}
        ___________________      _____  _________     ________________ _________  ________
        \\__    ___/\\_____  \\    /     \\ \\_   ___ \\   /  _  \\__    ___/ \\_   ___ \\ \\_____  \\
          |    |    /   |   \\  /  \\ /  \\/    \\  \\/  /  /_\\  \\|    |    /    \\  \\/  /  ____/
          |    |   /    |    \\/    Y    \\     \\____/    |    \\    |    \\     \\____/       \\
          |____|   \\_______  /\\____|__  /\\______  /\\____|__  /____|     \\______  /\\_______ \\
                           \\/         \\/        \\/         \\/                  \\/         \\/
                                            Framework V2.0
        {TMColor.white}{msg}{TMColor.reset}
        """
        StrObject.Animation(Banner, delay=0.001)


class CLIBanner:
    def Logo():
        Banner = f"""
        {TMColor.white}Server Command:{TMColor.reset}
            {TMColor.red}sessions{TMColor.reset}             - List all active sessions
            {TMColor.red}use <id>{TMColor.reset}             - Interact with session
            {TMColor.red}exec <id> <cmd>{TMColor.reset}      - Execute command on session
            {TMColor.red}logs{TMColor.reset}                 - Show recent logs
            {TMColor.red}status{TMColor.reset}               - Server status
            {TMColor.red}stats{TMColor.reset}                - Session statistics
            {TMColor.red}kill <id>{TMColor.reset}            - Kill session
            {TMColor.red}clear{TMColor.reset}                - Clear screen
            {TMColor.red}help{TMColor.reset}                 - Show this help
            {TMColor.red}exit{TMColor.reset}                 - Stop server and exit

        {TMColor.white}Agent Command:{TMColor.reset}
            {TMColor.red}back{TMColor.reset}                 - Exit interactive session
            {TMColor.red}<command>{TMColor.reset}            - Execute on current session
            {TMColor.red}SYSINFO{TMColor.reset}              - Show complete victim info
            {TMColor.red}SCREENSHOT{TMColor.reset}           - Take screenshot from victim
            {TMColor.red}ELEVATE{TMColor.reset}              - Elevating Check
            {TMColor.red}UPLOAD{TMColor.reset}               - Upload any files to victim machine
            {TMColor.red}DOWNLOAD{TMColor.reset}             - Download any files from victim machine

        """
        print(Banner)


class EndBanner:
    def EndLogo():
        GoodBye = f"""
    {TMColor.red}
          ________                  .______.
         /  _____/  ____   ____   __| _/\\_ |__ ___.__. ____
        /   \\  ___ /  _ \\ /  _ \\ / __ |  | __ <   |  |/ __ \\
        \\    \\_\\  (  <_> |  <_> ) /_/ |  | \\_\\ \\___  \\  ___/
         \\______  /\\____/ \\____/\\____ |  |___  / ____|\\___  >
                \\/                   \\/      \\/\\/         \\/

    {TMColor.reset}
    """

        StrObject.Animation(GoodBye, delay=0.0001)
