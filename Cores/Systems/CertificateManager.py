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
import json
from Config.Color import TMColor
from Cores.Systems.System import StrObject
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta


"""
Certificate Manager for mTLS Communication
- Generates CA (Certificate Authority)
- Issues Server Certificates
- Issues Client Certificates for Agents
- Validates Certificates
"""


class CertificateManager:
    def __init__(self, CertsDir="Certs"):
        self.CertsDir = CertsDir
        self.CAKey = None
        self.CACert = None
        self.ServerKey = None
        self.ServerCert = None
        os.makedirs(self.CertsDir, exist_ok=True)
        self.CAKeyPath = os.path.join(self.CertsDir, "ca-key.pem")
        self.CACertPath = os.path.join(self.CertsDir, "ca-cert.pem")
        self.ServerKeyPath = os.path.join(self.CertsDir, "server-key.pem")
        self.ServerCertPath = os.path.join(self.CertsDir, "server-cert.pem")
        self.ClientsDir = os.path.join(self.CertsDir, "AgentTCF")
        self.MetadataPath = os.path.join(self.CertsDir, "Metadata.json")
        os.makedirs(self.ClientsDir, exist_ok=True)
        self.Metadata = self.LoadMetadata()

    def LoadMetadata(self):
        if os.path.exists(self.MetadataPath):
            with open(self.MetadataPath, "r") as f:
                return json.load(f)
        return {"CACreated": None, "ServerCreated": None, "AgentTCF": {}}

    def SaveMetadata(self):
        with open(self.MetadataPath, "w") as f:
            json.dump(self.Metadata, f, indent=4)

    def GeneratePrivateKey(self, KeySize=4096):
        return rsa.generate_private_key(
            public_exponent=65537, key_size=KeySize, backend=default_backend()
        )

    def SavePrivateKey(self, Key, Path, Password=None):
        encryption = serialization.NoEncryption()
        if Password:
            encryption = serialization.BestAvailableEncryption(Password.encode())
        with open(Path, "wb") as f:
            f.write(
                Key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=encryption,
                )
            )

    def LoadPrivateKey(self, Path, Password=None):
        with open(Path, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=Password.encode() if Password else None,
                backend=default_backend(),
            )

    def SaveCertificate(self, Cert, Path):
        with open(Path, "wb") as f:
            f.write(Cert.public_bytes(serialization.Encoding.PEM))

    def LoadCertificate(self, Path):
        with open(Path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())

    def CreateCA(self, Force=False):
        if (
            os.path.exists(self.CAKeyPath)
            and os.path.exists(self.CACertPath)
            and not Force
        ):
            StrObject.Messages(f"Loading Existing CA")
            self.CAKey = self.LoadPrivateKey(self.CAKeyPath)
            self.CACert = self.LoadCertificate(self.CACertPath)
            return True
        StrObject.Messages(f"Generating Certificate Authority")
        self.CAKey = self.GeneratePrivateKey(4096)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Cybertron"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Dark Net"),
                x509.NameAttribute(
                    NameOID.ORGANIZATION_NAME, "TOMCAT C2 Frameworks V2"
                ),
                x509.NameAttribute(
                    NameOID.ORGANIZATIONAL_UNIT_NAME, "Man In The Matrix"
                ),
                x509.NameAttribute(NameOID.COMMON_NAME, "TOMCAT C2 Root CA"),
            ]
        )
        self.CACert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.CAKey.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.CAKey.public_key()),
                critical=False,
            )
            .sign(self.CAKey, hashes.SHA256(), default_backend())
        )
        self.SavePrivateKey(self.CAKey, self.CAKeyPath)
        self.SaveCertificate(self.CACert, self.CACertPath)
        self.Metadata["CACreated"] = datetime.utcnow().isoformat()
        self.SaveMetadata()
        StrObject.Messages(f"CA Created Successfully!")
        StrObject.Messages(f"{TMColor.brightGreen} CA Key: {self.CAKeyPath}")
        StrObject.Messages(f"{TMColor.brightGreen} CA Cert: {self.CACertPath}")
        return True

    def CreateServerCertificate(self, ServerHost="0.0.0.0", Force=False):
        if (
            os.path.exists(self.ServerKeyPath)
            and os.path.exists(self.ServerCertPath)
            and not Force
        ):
            StrObject.Messages(f"Loading Existing Server Certificate")
            self.ServerKey = self.LoadPrivateKey(self.ServerKeyPath)
            self.ServerCert = self.LoadCertificate(self.ServerCertPath)
            return True
        if not self.CAKey or not self.CACert:
            StrObject.Warnings(f"CA Not Found. Creating CA First")
            self.CreateCA()
        StrObject.Messages(f"Generating Server Certificate")
        self.ServerKey = self.GeneratePrivateKey(2048)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Cybertron"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Dark Net"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TOMCAT C2 Frameworks"),
                x509.NameAttribute(
                    NameOID.ORGANIZATIONAL_UNIT_NAME, "Man In The Matrix"
                ),
                x509.NameAttribute(NameOID.COMMON_NAME, "TOMCAT C2 Server"),
            ]
        )
        san_list = [
            x509.DNSName("localhost"),
            x509.DNSName("*.tomcat.local"),
            x509.IPAddress(__import__("ipaddress").IPv4Address("127.0.0.1")),
        ]
        try:
            import ipaddress

            ip = ipaddress.IPv4Address(ServerHost)
            san_list.append(x509.IPAddress(ip))
        except Exception:
            if ServerHost not in ["0.0.0.0", "localhost"]:
                san_list.append(x509.DNSName(ServerHost))
        self.ServerCert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.CACert.subject)
            .public_key(self.ServerKey.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.SERVER_AUTH,
                    ]
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.ServerKey.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.CAKey.public_key()
                ),
                critical=False,
            )
            .sign(self.CAKey, hashes.SHA256(), default_backend())
        )
        self.SavePrivateKey(self.ServerKey, self.ServerKeyPath)
        self.SaveCertificate(self.ServerCert, self.ServerCertPath)
        self.Metadata["ServerCreated"] = datetime.utcnow().isoformat()
        self.SaveMetadata()
        StrObject.Messages(f"Server Certificate Created Successfully!")
        StrObject.Messages(f"{TMColor.brightGreen} Server Key: {self.ServerKeyPath}")
        StrObject.Messages(f"{TMColor.brightGreen} Server Cert: {self.ServerCertPath}")
        return True

    def CreateClientCertificate(self, ClientID, ValidDays=365, UseRawName=False):
        if not self.CAKey or not self.CACert:
            StrObject.Warnings(f"CA Not Found. Creating CA First")
            self.CreateCA()
        if UseRawName:
            ClientName = ClientID
        else:
            ClientName = f"Agent-{ClientID}"
        ClientKeyPath = os.path.join(self.ClientsDir, f"{ClientName}-key.pem")
        ClientCertPath = os.path.join(self.ClientsDir, f"{ClientName}-cert.pem")
        if os.path.exists(ClientKeyPath) and os.path.exists(ClientCertPath):
            StrObject.Messages(f"Client Certificate Already Exists: {ClientName} ")
            return ClientKeyPath, ClientCertPath, self.CACertPath
        StrObject.Messages(f"Generating Client Certificate: {ClientName}")
        ClientKey = self.GeneratePrivateKey(2048)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Cybertron"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Dark Net"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TOMCAT C2 Frameworks"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "C2 Agents"),
                x509.NameAttribute(NameOID.COMMON_NAME, ClientName),
            ]
        )
        ClientCert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.CACert.subject)
            .public_key(ClientKey.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=ValidDays))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.CLIENT_AUTH,
                    ]
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(ClientKey.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.CAKey.public_key()
                ),
                critical=False,
            )
            .sign(self.CAKey, hashes.SHA256(), default_backend())
        )
        self.SavePrivateKey(ClientKey, ClientKeyPath)
        self.SaveCertificate(ClientCert, ClientCertPath)
        self.Metadata["AgentTCF"][ClientName] = {
            "Created": datetime.utcnow().isoformat(),
            "ValidDays": ValidDays,
            "KeyPath": ClientKeyPath,
            "CertPath": ClientCertPath,
        }
        self.SaveMetadata()
        StrObject.Messages(f"Client Certificate Created Successfully!")
        StrObject.Messages(f"{TMColor.brightGreen} Client ID: {ClientName}")
        StrObject.Messages(f"{TMColor.brightGreen} Client Key: {ClientKeyPath}")
        StrObject.Messages(f"{TMColor.brightGreen} Client Cert: {ClientCertPath}")
        return ClientKeyPath, ClientCertPath, self.CACertPath

    def Initialize(self, ServerHost="0.0.0.0"):
        StrObject.Messages(f"TOMCAT C2 - MTLS Certificate Manager")
        self.CreateCA()
        self.CreateServerCertificate(ServerHost)
        StrObject.Messages(f"Certificate Infrastructure Ready!")
        return True

    def GetServerFiles(self):
        return {
            "key": self.ServerKeyPath,
            "cert": self.ServerCertPath,
            "ca": self.CACertPath,
        }

    def ListClients(self):
        return self.Metadata.get("AgentTCF", {})

    def RevokeClient(self, ClientName):
        ClientKeyPath = os.path.join(self.ClientsDir, f"{ClientName}-key.pem")
        ClientCertPath = os.path.join(self.ClientsDir, f"{ClientName}-cert.pem")
        if os.path.exists(ClientKeyPath):
            os.remove(ClientKeyPath)
        if os.path.exists(ClientCertPath):
            os.remove(ClientCertPath)
        if ClientName in self.Metadata["AgentTCF"]:
            del self.Metadata["AgentTCF"][ClientName]
            self.SaveMetadata()
        StrObject.Messages(f"Client Certificate Revoked: {ClientName}")


if __name__ == "__main__":
    import sys

    CertManager = CertificateManager()
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        if command == "init":
            ServerHost = sys.argv[2] if len(sys.argv) > 2 else "0.0.0.0"
            CertManager.Initialize(ServerHost)
        elif command == "client":
            ClientID = sys.argv[2] if len(sys.argv) > 2 else "default"
            CertManager.CreateCA()
            CertManager.CreateClientCertificate(ClientID)
        elif command == "list":
            clients = CertManager.ListClients()
            StrObject.Messages(f"\nTotal Clients: {len(clients)}")
            for name, info in clients.items():
                StrObject.Messages(f"   - {name}: Created {info['Created']}")
        elif command == "revoke":
            if len(sys.argv) > 2:
                CertManager.RevokeClient(sys.argv[2])
            else:
                StrObject.Messages(
                    "[!] Usage: python CertificateManager.py revoke <client-name>",
                )
        else:
            StrObject.Messages(f"Usage:")
            StrObject.Messages(f"    python3 CertificateManager.py init [server-host]")
            StrObject.Messages(f"    python3 CertificateManager.py client <client-id>")
            StrObject.Messages(f"    python3 CertificateManager.py list")
            StrObject.Messages(
                f"    python3 CertificateManager.py revoke <client-name>"
            )
    else:
        CertManager.Initialize()
