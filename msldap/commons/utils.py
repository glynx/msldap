import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Union


def timestamp2datetime(dt: Union[bytes, int]) -> datetime.datetime:
    """
    Converting Windows timestamps to datetime.datetime format
    :param dt: Windows timestamp as array of bytes or integer
    :type dt: bytearray | int
    :return: datetime.datetime
    """

    if isinstance(dt, bytes):
        dt = int.from_bytes(dt, "little")

    return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=dt / 10)


def datetime2timestamp(dt) -> int:
    delta = dt - datetime.datetime(1601, 1, 1)
    ns = int((delta / datetime.timedelta(microseconds=1)) * 10)
    return ns.to_bytes(8, "little", signed=False)


def bytes2ipv4(data: bytes) -> str:
    return str(IPv4Address(data))


def bytes2ipv6(data: bytes) -> str:
    return str(IPv6Address(data))


def wrap(s, w) -> str:
    return [s[i : i + w] for i in range(0, len(s), w)]


def print_cert(cert, offset=0) -> str:
    cert = cert["tbs_certificate"]
    blanks = " " * offset
    msg = [
        "Cert Subject: %s" % cert["subject"]["common_name"],
        "Cert Serial: %s" % cert["serial_number"],
        "Cert Start: %s" % cert["validity"]["not_before"],
        "Cert End: %s" % cert["validity"]["not_after"],
        "Cert Issuer: %s" % cert["issuer"]["common_name"],
    ]
    return "{}{}".format(blanks, "\n{}".format(blanks).join(msg))


def win_timestamp_to_unix(seconds):
    """
    Convert Windows timestamp (100 ns since 1 Jan 1601) to
    unix timestamp.
    """
    seconds = int(seconds)
    if seconds == 0:
        return 0
    return int((seconds - 116444736000000000) / 10000000)


def bh_dt_convert(dt: datetime.datetime):
    if dt is None or dt == 0 or dt == "0" or dt == "":
        return -1
    ts = max(0, int(dt.timestamp()))
    return ts


FUNCTIONAL_LEVELS = {
    0: "2000 Mixed/Native",
    1: "2003 Interim",
    2: "2003",
    3: "2008",
    4: "2008 R2",
    5: "2012",
    6: "2012 R2",
    7: "2016",
}

KNOWN_SIDS = {
    "S-1-0": "Null Authority",
    "S-1-0-0": "Nobody",
    "S-1-1": "World Authority",
    "S-1-1-0": "Everyone",
    "S-1-2": "Local Authority",
    "S-1-2-0": "Local",
    "S-1-3": "Creator Authority",
    "S-1-3-0": "Creator Owner",
    "S-1-3-1": "Creator Group",
    "S-1-3-4": "Owner Rights",
    "S-1-4": "Non-unique Authority",
    "S-1-5": "NT Authority",
    "S-1-5-1": "Dialup",
    "S-1-5-2": "Network",
    "S-1-5-3": "Batch",
    "S-1-5-4": "Interactive",
    "S-1-5-5-X-Y": "Logon Session",
    "S-1-5-6": "Service",
    "S-1-5-7": "Anonymous",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Principal Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-12": "Restricted Code",
    "S-1-5-13": "Terminal Server Users",
    "S-1-5-14": "Remote Interactive Logon",
    "S-1-5-17": "IUSR",
    "S-1-5-18": "Local System",
    "S-1-5-19": "NT Authority Local Service",
    "S-1-5-20": "NT Authority Network Service",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-32-547": "Power Users",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-552": "Replicators",
    "S-1-5-32-554": "Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555": "Remote Desktop Users",
    "S-1-5-32-556": "Network Configuration Operators",
    "S-1-5-32-557": "Incoming Forest Trust Builders",
    "S-1-5-32-558": "Performance Monitor Users",
    "S-1-5-32-559": "Performance Log Users",
    "S-1-5-32-560": "Windows Authorization Access Group",
    "S-1-5-32-561": "Terminal Server License Servers",
    "S-1-5-32-562": "Distributed COM Users",
    "S-1-5-32-568": "IIS_IUSRS",
    "S-1-5-32-569": "Cryptographic Operators",
    "S-1-5-32-573": "Event Log Readers",
    "S-1-5-32-574": "Certificate Service DCOM Access",
    "S-1-5-32-575": "RDS Remote Access Servers",
    "S-1-5-32-576": "RDS Endpoint Servers",
    "S-1-5-32-577": "RDS Management Servers",
    "S-1-5-32-578": "Hyper-V Administrators",
    "S-1-5-32-579": "Access Control Assistance Operators",
    "S-1-5-32-580": "Remote Management Users",
    "S-1-5-32-582": "Storage Replica Administrators",
    "S-1-5-64-10": "NTLM Authentication",
    "S-1-5-64-14": "SChannel Authentication",
    "S-1-5-64-21": "Digest Authentication",
    "S-1-5-80": "NT Service",
}

# Well-known domain-relative RIDs, used when a SID of a foreign domain cannot be looked up directly
# https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
KNOWN_DOMAIN_RIDS = {
    498: "Enterprise Read-only Domain Controllers",
    500: "Administrator",
    501: "Guest",
    502: "krbtgt",
    512: "Domain Admins",
    513: "Domain Users",
    514: "Domain Guests",
    515: "Domain Computers",
    516: "Domain Controllers",
    517: "Cert Publishers",
    518: "Schema Admins",
    519: "Enterprise Admins",
    520: "Group Policy Creator Owners",
    521: "Read-only Domain Controllers",
    522: "Cloneable Domain Controllers",
    525: "Protected Users",
    526: "Key Admins",
    527: "Enterprise Key Admins",
    553: "RAS and IAS Servers",
    571: "Allowed RODC Password Replication Group",
    572: "Denied RODC Password Replication Group",
}
