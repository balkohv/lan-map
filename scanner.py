"""Découverte des appareils du réseau local (ARP + DNS inverse + ports courants)."""
from __future__ import annotations

import ipaddress
import os
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict

try:
    from scapy.all import ARP, Ether, srp, conf  # type: ignore
    SCAPY = True
except Exception:  # pragma: no cover
    SCAPY = False

COMMON_PORTS = {
    22: "ssh", 53: "dns", 80: "http", 443: "https", 445: "smb",
    554: "rtsp", 1883: "mqtt", 3389: "rdp", 5000: "upnp/nas",
    8006: "proxmox", 8080: "http-alt", 8123: "home-assistant",
    9100: "imprimante", 32400: "plex",
}

VENDOR_HINTS = [
    (("apple", "samsung", "xiaomi", "oneplus", "huawei", "oppo", "google"), "mobile"),
    (("tp-link", "netgear", "ubiquiti", "cisco", "mikrotik", "sagemcom", "zyxel", "d-link", "freebox", "arcadyan", "technicolor"), "reseau"),
    (("hewlett", "epson", "canon", "brother", "lexmark", "xerox"), "imprimante"),
    (("raspberry",), "raspberry"),
    (("espressif", "tuya", "shelly", "sonoff", "philips lighting", "signify", "nest"), "iot"),
    (("sony", "nintendo", "microsoft"), "console"),
    (("lg electronics", "roku", "amazon", "vizio", "tcl"), "tv"),
    (("synology", "qnap", "western digital"), "nas"),
    (("intel", "dell", "lenovo", "asus", "micro-star", "gigabyte", "asrock", "realtek"), "ordinateur"),
]


@dataclass
class Device:
    ip: str
    mac: str
    hostname: str = ""
    vendor: str = ""
    type: str = "inconnu"
    ports: list[int] = field(default_factory=list)
    is_gateway: bool = False
    is_self: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------- réseau local
def detect_network() -> tuple[str, str | None, str | None]:
    """Retourne (cidr, ip_passerelle, ip_locale). NETWORK_CIDR force le réseau."""
    override = os.getenv("NETWORK_CIDR")
    gateway = local_ip = None

    if SCAPY:
        try:
            iface, local_ip, gateway = conf.route.route("0.0.0.0")
            for net, msk, gw, r_iface, addr, *_ in conf.route.routes:
                if r_iface == iface and addr == local_ip and msk not in (0, 0xFFFFFFFF) and gw == "0.0.0.0":
                    cidr = ipaddress.IPv4Network(
                        (ipaddress.IPv4Address(net), bin(msk).count("1")), strict=False
                    )
                    return override or str(cidr), gateway, local_ip
        except Exception:
            pass

    if not local_ip:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("10.255.255.255", 1))
            local_ip = s.getsockname()[0]
        finally:
            s.close()
    cidr = override or str(ipaddress.IPv4Network(f"{local_ip}/24", strict=False))
    return cidr, gateway, local_ip


# ---------------------------------------------------------------- découverte
def arp_scan(cidr: str, timeout: float = 2.0) -> dict[str, str]:
    """Scan ARP actif (nécessite root / CAP_NET_RAW). Retourne {ip: mac}."""
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
                 timeout=timeout, retry=1, verbose=False)
    return {r.psrc: r.hwsrc.lower() for _, r in ans}


def ping_sweep_scan(cidr: str) -> dict[str, str]:
    """Repli sans privilèges : ping de toutes les IP puis lecture de la table ARP."""
    hosts = [str(h) for h in ipaddress.IPv4Network(cidr).hosts()][:1024]
    count_flag = "-n" if platform.system() == "Windows" else "-c"

    def ping(ip: str) -> None:
        subprocess.run(["ping", count_flag, "1", "-W", "1", ip],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    with ThreadPoolExecutor(max_workers=128) as ex:
        list(ex.map(ping, hosts))
    return read_arp_table()


def read_arp_table() -> dict[str, str]:
    result: dict[str, str] = {}
    mac_re = r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})"
    try:
        out = subprocess.run(["ip", "neigh"], capture_output=True, text=True).stdout
        for line in out.splitlines():
            m = re.match(rf"(\d+\.\d+\.\d+\.\d+) .* lladdr {mac_re}", line)
            if m and "FAILED" not in line:
                result[m.group(1)] = m.group(2).lower()
    except FileNotFoundError:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True).stdout
        for line in out.splitlines():
            m = re.search(rf"(\d+\.\d+\.\d+\.\d+).*?{mac_re}", line)
            if m:
                result[m.group(1)] = m.group(2).lower().replace("-", ":")
    return result


# ---------------------------------------------------------------- enrichissement
_mac_lookup = None


def vendor_of(mac: str) -> str:
    global _mac_lookup
    try:
        if _mac_lookup is None:
            from mac_vendor_lookup import MacLookup  # type: ignore
            _mac_lookup = MacLookup()
        return _mac_lookup.lookup(mac)
    except Exception:
        pass
    if SCAPY:
        try:
            name = conf.manufdb._get_manuf(mac)
            if name and name != mac:
                return name
        except Exception:
            pass
    # bit "localement administré" = MAC aléatoire (iPhone/Android récents)
    if int(mac.split(":")[0], 16) & 0x02:
        return "MAC privée (aléatoire)"
    return ""


def hostname_of(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def open_ports(ip: str, timeout: float = 0.4) -> list[int]:
    found = []
    for port in COMMON_PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                found.append(port)
    return found


def guess_type(dev: Device) -> str:
    if dev.is_gateway:
        return "routeur"
    v, h = dev.vendor.lower(), dev.hostname.lower()
    if dev.is_self:
        return "serveur"
    if 9100 in dev.ports:
        return "imprimante"
    if 8123 in dev.ports:
        return "iot"
    if 8006 in dev.ports or 32400 in dev.ports:
        return "serveur"
    for keys, kind in VENDOR_HINTS:
        if any(k in v or k in h for k in keys):
            return kind
    if any(k in h for k in ("iphone", "android", "galaxy", "pixel")):
        return "mobile"
    if "privée" in v:
        return "mobile"
    if 3389 in dev.ports or 445 in dev.ports:
        return "ordinateur"
    if 22 in dev.ports:
        return "serveur"
    return "inconnu"


# ---------------------------------------------------------------- point d'entrée
def scan(cidr: str | None = None, port_scan: bool = True) -> dict:
    net, gateway, local_ip = detect_network()
    cidr = cidr or net

    method = "arp"
    try:
        if not SCAPY:
            raise PermissionError
        table = arp_scan(cidr)
    except (PermissionError, OSError):
        method = "ping+arp-table"
        table = ping_sweep_scan(cidr)

    network = ipaddress.IPv4Network(cidr, strict=False)
    table = {ip: mac for ip, mac in table.items()
             if ipaddress.IPv4Address(ip) in network and mac != "00:00:00:00:00:00"}

    if local_ip and local_ip not in table:
        try:
            from scapy.all import get_if_hwaddr  # type: ignore
            table[local_ip] = get_if_hwaddr(conf.route.route("0.0.0.0")[0]).lower()
        except Exception:
            mac = f"{__import__('uuid').getnode():012x}"
            table[local_ip] = ":".join(mac[i:i + 2] for i in range(0, 12, 2))

    def enrich(item: tuple[str, str]) -> Device:
        ip, mac = item
        d = Device(ip=ip, mac=mac, is_gateway=(ip == gateway), is_self=(ip == local_ip))
        d.hostname = hostname_of(ip)
        d.vendor = vendor_of(mac)
        if port_scan:
            d.ports = open_ports(ip)
        d.type = guess_type(d)
        return d

    with ThreadPoolExecutor(max_workers=32) as ex:
        devices = list(ex.map(enrich, table.items()))

    devices.sort(key=lambda d: ipaddress.IPv4Address(d.ip))
    return {
        "network": cidr, "gateway": gateway, "local_ip": local_ip,
        "method": method, "devices": [d.to_dict() for d in devices],
    }


if __name__ == "__main__":
    import json
    print(json.dumps(scan(), indent=2, ensure_ascii=False))
