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

from cryptography.fernet import Fernet
import base64


class Cryptography:
    def __init__(self):
        self.Key = None
        self.Cipher = None

    def GenerateKey(self):
        self.Key = Fernet.generate_key()
        self.Cipher = Fernet(self.Key)
        return self.Key

    def SetKey(self, Key):
        if isinstance(Key, str):
            Key = Key.encode("utf-8")
        self.Key = Key
        self.Cipher = Fernet(self.Key)

    def GetKey(self):
        return self.Key

    def Encrypt(self, Data):
        if self.Cipher is None:
            raise ValueError("No encryption key set")
        if isinstance(Data, str):
            Data = Data.encode("utf-8")
        return self.Cipher.encrypt(Data)

    def Decrypt(self, EncryptedData):
        if self.Cipher is None:
            raise ValueError("No encryption key set")
        if isinstance(EncryptedData, str):
            EncryptedData = EncryptedData.encode("utf-8")
        Decrypted = self.Cipher.decrypt(EncryptedData)
        return Decrypted.decode("utf-8")

    def EncryptMessage(self, Message):
        Encrypted = self.Encrypt(Message)
        return base64.b64encode(Encrypted).decode("utf-8")

    def DecryptMessage(self, EncryptedMessage):
        Encrypted = base64.b64decode(EncryptedMessage.encode("utf-8"))
        return self.Decrypt(Encrypted)
