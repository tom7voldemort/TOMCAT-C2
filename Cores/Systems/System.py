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
from itertools import cycle
from Config.Color import TMColor
from sys import stdout
from time import sleep


class StrObject:
    def Clear():
        os.system("cls" if os.name == "nt" else "clear")

    def Animation(text, delay):
        for chars in text:
            stdout.write(chars)
            stdout.flush()
            sleep(delay)
        print()

    def Messages(msg, delay=0.001):
        text = f"{TMColor.green}[{TMColor.white}INFO{TMColor.green}]:{TMColor.green} {msg}{TMColor.reset}"
        for chars in text:
            stdout.write(chars)
            stdout.flush()
            sleep(delay)
        print()

    def Warnings(msg, delay=0.001):
        text = f"{TMColor.red}[{TMColor.yellow}WARNING{TMColor.red}]:{TMColor.yellow} {msg}{TMColor.reset}"
        for chars in text:
            stdout.write(chars)
            stdout.flush()
            sleep(delay)
        print()

    def Error(msg, delay=0.001):
        text = f"{TMColor.red}[{TMColor.white}ERROR{TMColor.red}]:{TMColor.red} {msg}{TMColor.reset}"
        for chars in text:
            stdout.write(chars)
            stdout.flush()
            sleep(delay)
        print()


class Processing:
    def Loading():
        spinner = cycle(["/", "-", "\\", "|"])
        for i in range(1, 50):
            sleep(0.0001)
            stdout.write(f"\r{next(spinner)}")
            stdout.flush()

    def Modules():
        StrObject.Messages("Checking For Modules Availability")
        try:
            import socket
            import tkinter
            import cryptography
            import flask
        except Exception:
            os.system(
                "pip install pysocks cryptography tkinter flask"
                if os.name == "nt"
                else "pip install pysocks cryptography tkinter flask --break-system-packages"
            )
