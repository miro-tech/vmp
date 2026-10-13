
#!/usr/bin/env python3
# VMP VPN -> URI extractor
# Python 3.x / Termux
# Регистрация, парсинг, DNS, GeoIP и названия конфигов.
# Без Gist, закреплённого конфига и локального сохранения.

import argparse
import base64
import json
import re
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

VERSION = "1.1-vmp-python"
UA = "okhttp/4.12.0"
APP_ID = "com.vpnmasterpro.android"
APP_VERSION = "4.24"
PHONE_MODEL = "Pixel 7"

API_HOSTS = [
    "vmpaccount.com",
    "apiv2.avianbpo.com",
    "apiv2.sherashera.com",
    "apiv2.themebeaver.com",
    "my.vpnmasterpro.com",
]

URI_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)
DIRECT_RE = re.compile(
    r"""[a-z][a-z0-9+.-]*://[^\s"'<>\\]+""", re.I
)
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
DNS_CACHE = {}


def http_request(method, url, headers=None, body=None,
                 timeout=25, insecure=False):
    headers = dict(headers or {})
    headers.setdefault("User-Agent", UA)
    headers.setdefault("Accept", "*/*")

    data = None
    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode()
            headers.setdefault("Content-Type", "application/json")
        elif isinstance(body, str):
            data = body.encode()

    req = urllib.request.Request(
        url, data=data, headers=headers, method=method
    )
    context = ssl._create_unverified_context() if insecure else None

    try:
        with urllib.request.urlopen(
            req, timeout=timeout, context=context
        ) as response:
            return (
                response.status, response.headers,
                response.read().decode("utf-8", "replace"), ""
            )
    except urllib.error.HTTPError as exc:
        return (
            exc.code, exc.headers,
            exc.read().decode("utf-8", "replace"), str(exc)
        )
    except Exception as exc:
        return 0, {}, "", str(exc)


def http_json(method, url, headers=None, body=None,
              timeout=25, insecure=False):
    code, hdrs, raw, err = http_request(
        method, url, headers, body, timeout, insecure
    )
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        data = None
    return code, hdrs, data, raw, err


def resolve_host(host, timeout=3):
    if not host:
        return None

    if IPV4_RE.fullmatch(host):
        try:
            if all(0 <= int(p) <= 255 for p in host.split(".")):
                return host
        except ValueError:
            pass
        return None

    if host in DNS_CACHE:
        return DNS_CACHE[host]

    ip = None

    try:
        result = subprocess.run(
            ["dig", "+short", "+time=2", "+tries=1", host, "A"],
            capture_output=True, text=True, timeout=timeout
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if IPV4_RE.fullmatch(line):
                ip = line
                break
    except (OSError, subprocess.TimeoutExpired):
        pass

    if not ip:
        try:
            candidate = socket.gethostbyname(host)
            if IPV4_RE.fullmatch(candidate):
                ip = candidate
        except OSError:
            pass

    DNS_CACHE[host] = ip
    return ip


def replace_host_in_uri(uri):
    match = re.match(
        r"^([a-z][a-z0-9+.-]*://)([^/?#]+)(.*)$",
        uri, re.I | re.S
    )
    if not match:
        return uri

    scheme, authority, rest = match.groups()
    at = authority.rfind("@")
    prefix = authority[:at + 1] if at >= 0 else ""
    hostport = authority[at + 1:] if at >= 0 else authority

    if hostport.startswith("["):
        return uri

    if ":" in hostport:
        host, port = hostport.rsplit(":", 1)
        suffix = ":" + port
    else:
        host, suffix = hostport, ""

    if not host or IPV4_RE.fullmatch(host):
        return uri

    ip = resolve_host(host)
    if not ip:
        return uri

    new_uri = scheme + prefix + ip + suffix + rest
    before_fragment, sep, fragment = new_uri.partition("#")

    query_pos = before_fragment.find("?")
    if query_pos < 0:
        before_fragment += "?sni=" + urllib.parse.quote(host, safe=".-")
    else:
        query = before_fragment[query_pos + 1:]
        keys = {
            part.split("=", 1)[0].lower()
            for part in query.split("&") if part
        }
        if "sni" not in keys and "host" not in keys:
            before_fragment += (
                "&sni=" + urllib.parse.quote(host, safe=".-")
            )

    return before_fragment + (sep + fragment if sep else "")


def parse_surge_line(line):
    if "=" not in line:
        return None

    _, rhs = line.split("=", 1)
    parts = [p.strip() for p in rhs.split(",")]

    if len(parts) < 3:
        return None

    protocol, host, port = parts[:3]
    protocol = protocol.lower()

    if not protocol or protocol in ("direct", "reject"):
        return None
    if not port.isdigit():
        return None

    kv = {}
    for part in parts[3:]:
        if "=" in part:
            key, value = part.split("=", 1)
            kv[key.strip().lower()] = value.strip()
        else:
            kv[part.lower()] = True

    return {"type": protocol, "host": host, "port": port, "kv": kv}


def kv_get(kv, keys, default=""):
    for key in keys:
        value = kv.get(key)
        if value is not None and value is not True and value != "":
            return str(value)
    return default


def surge_to_uri(proxy):
    protocol = proxy["type"]
    host = proxy["host"]
    port = proxy["port"]
    kv = proxy["kv"]

    password = kv_get(kv, ["password"])
    uid = kv_get(kv, ["username", "uuid", "id"])
    ws = str(kv.get("ws", "")).lower() == "true"
    path = kv_get(kv, ["ws-path", "path"])
    network = "ws" if ws else "tcp"
    sni = kv_get(kv, ["sni", "tls-name", "servername"], host)

    query = (
        "security=tls&sni=" + sni
        + "&type=" + network + "&headerType=none"
    )
    if path:
        query += "&path=" + path

    # Временное имя заменится на страну в GeoIP-этапе.
    fragment = "#VMP"

    if protocol == "trojan":
        return f"trojan://{password}@{host}:{port}?{query}{fragment}"

    if protocol == "vless":
        return (
            f"vless://{uid}@{host}:{port}?"
            f"encryption=none&{query}{fragment}"
        )

    if protocol == "vmess":
        config = {
            "v": "2", "ps": "VMP", "add": host, "port": port,
            "id": uid, "aid": kv_get(kv, ["alterid"], "0"),
            "net": network, "type": "none", "host": "",
            "path": path, "tls": "tls", "sni": sni,
        }
        encoded = base64.b64encode(
            json.dumps(config, separators=(",", ":")).encode()
        ).decode()
        return "vmess://" + encoded

    if protocol in ("ss", "shadowsocks"):
        method = kv_get(
            kv, ["encrypt-method", "method", "cipher"], "aes-256-gcm"
        )
        auth = base64.b64encode(
            (method + ":" + password).encode()
        ).decode()
        return f"ss://{auth}@{host}:{port}{fragment}"

    if protocol == "tuic":
        user = uid or kv_get(kv, ["token"])
        return (
            f"tuic://{user}:{password}@{host}:{port}"
            f"?sni={sni}&congestion_control=bbr&alpn=h3{fragment}"
        )

    if protocol in ("hysteria", "hysteria2"):
        auth = password or kv_get(kv, ["auth", "auth-str"])
        return (
            f"{protocol}://{auth}@{host}:{port}"
            f"?sni={sni}&insecure=0{fragment}"
        )

    auth = uid or password
    if auth:
        auth += "@"

    return f"{protocol}://{auth}{host}:{port}?{query}{fragment}"


def parse_vmpguard(text):
    uris = []
    in_proxy = False

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("["):
            in_proxy = line.lower() == "[proxy]"
            continue
        if in_proxy:
            proxy = parse_surge_line(line)
            if proxy:
                uris.append(surge_to_uri(proxy))

    return uris


def parse_ini_text(text):
    result = {}
    for line in text.splitlines():
        line = line.strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().lower()
        if key and key not in result:
            result[key] = value.strip()
    return result


def parse_wireguard(value):
    if isinstance(value, dict):
        chunks = []
        for section in ("interface", "peer"):
            item = value.get(section, "")
            if isinstance(item, dict):
                chunks.append(f"[{section.title()}]")
                chunks.extend(f"{k} = {v}" for k, v in item.items())
            elif isinstance(item, str):
                chunks.append(item)
        text = "\n".join(chunks)
    elif isinstance(value, str):
        text = value
    else:
        return None

    if not text.strip():
        return None

    ini = parse_ini_text(text)
    private = ini.get("privatekey", "")
    public = ini.get("publickey", "")
    psk = ini.get("presharedkey", "")
    address = ini.get("address", "")
    mtu = ini.get("mtu", "")
    endpoint = ini.get("endpoint", "")

    if not private or not endpoint:
        return None

    if endpoint.startswith("[") and "]:" in endpoint:
        host, port = endpoint[1:].split("]:", 1)
    elif ":" in endpoint:
        host, port = endpoint.rsplit(":", 1)
    else:
        host, port = endpoint, "443"

    params = [("publickey", public)]
    if psk:
        params.append(("presharedkey", psk))
    if address:
        params.append(("address", address))
    if mtu:
        params.append(("mtu", mtu))

    return (
        "wireguard://" + urllib.parse.quote(private, safe="")
        + "@" + host + ":" + port
        + "?" + urllib.parse.urlencode(params) + "#VMP-WG"
    )


def scan_direct_uris(text):
    result = []
    for uri in DIRECT_RE.findall(text or ""):
        uri = uri.rstrip('",);]')
        if URI_RE.match(uri):
            result.append(uri)
    return result


def parse_server_config(server, raw_body):
    uris = []

    if isinstance(server, dict):
        if isinstance(server.get("vmpguardConfig"), str):
            uris.extend(parse_vmpguard(server["vmpguardConfig"]))

        if "wireguardConfig" in server:
            wg = parse_wireguard(server["wireguardConfig"])
            if wg:
                uris.append(wg)

        for value in server.values():
            if isinstance(value, str):
                uris.extend(scan_direct_uris(value))
            elif isinstance(value, (dict, list)):
                uris.extend(
                    scan_direct_uris(json.dumps(value, ensure_ascii=False))
                )

    uris.extend(scan_direct_uris(raw_body))
    return uris


def cc_to_flag(cc):
    if not cc or len(cc) != 2 or not cc.isalpha():
        return ""
    return "".join(
        chr(0x1F1E6 + ord(c.upper()) - ord("A"))
        for c in cc
    )


def batch_geoip(ips):
    result = {}

    for start in range(0, len(ips), 100):
        batch = ips[start:start + 100]
        url = (
            "http://ip-api.com/batch"
            "?fields=status,countryCode,country,query"
        )

        code, _, data, _, err = http_json(
            "POST", url,
            headers={"Content-Type": "application/json"},
            body=batch,
            timeout=20,
        )

        if code != 200 or not isinstance(data, list):
            print(f"[!] GeoIP: ошибка запроса: {err or code}")
            continue

        for item in data:
            if item.get("status") == "success":
                ip = item.get("query")
                if ip:
                    result[ip] = {
                        "cc": item.get("countryCode", ""),
                        "country": item.get("country", ""),
                    }

    return result


def extract_ip_from_uri(uri):
    match = re.match(
        r"^[a-z][a-z0-9+.-]*://(?:[^@/]*@)?"
        r"(\d{1,3}(?:\.\d{1,3}){3})(?=[:/?#]|$)",
        uri, re.I
    )
    return match.group(1) if match else None


def set_country_fragment(uri, geo):
    if geo:
        flag = cc_to_flag(geo.get("cc", ""))
        country = geo.get("country") or "Unknown"
        name = f"{flag} {country} • VMP".strip()
    else:
        name = "Unknown • VMP"

    return uri.split("#", 1)[0] + "#" + name


class VMP:
    def __init__(self, insecure=False, timeout=25):
        self.insecure = insecure
        self.timeout = timeout
        self.base = None
        self.device_id = str(uuid.uuid4())

    def headers(self):
        return {"deviceUserId": self.device_id}

    def pick_host(self):
        for host in API_HOSTS:
            base = f"https://{host}/api"
            code, _, _, _, _ = http_json(
                "GET", base + "/servers", self.headers(),
                timeout=12, insecure=self.insecure
            )
            if 0 < code < 500:
                self.base = base
                print(f"[+] API-хост: {base} (HTTP {code})")
                return
        raise RuntimeError("Не удалось подключиться к API-хостам VMP")

    def register(self):
        if not self.base:
            self.pick_host()

        payload = {
            "deviceUserId": self.device_id,
            "appId": APP_ID,
            "appVersion": APP_VERSION,
            "phoneModel": PHONE_MODEL,
            "platform": "android",
        }

        code, _, data, raw, _ = http_json(
            "POST", self.base + "/device/register",
            body=payload, timeout=self.timeout,
            insecure=self.insecure
        )

        if not 200 <= code < 300:
            raise RuntimeError(
                f"device/register HTTP {code}: {raw[:200]}"
            )

        user_id = "?"
        if isinstance(data, dict):
            user = data.get("user")
            if isinstance(user, dict):
                user_id = user.get("id", "?")

        print(f"[+] Устройство зарегистрировано: userId={user_id}")

    def list_servers(self):
        code, _, data, raw, _ = http_json(
            "GET", self.base + "/servers", self.headers(),
            timeout=60, insecure=self.insecure
        )

        if code != 200 or not isinstance(data, (dict, list)):
            raise RuntimeError(f"servers HTTP {code}: {raw[:200]}")

        if isinstance(data, dict):
            for key in ("servers", "data", "items"):
                if isinstance(data.get(key), list):
                    return data[key]
        return data

    def best_in_batch(self, batch):
        url = (
            self.base + "/servers/v2/best-in-batch"
            "?retryCount=0&batchId="
            + urllib.parse.quote(str(batch), safe="")
        )

        code, _, data, raw, _ = http_json(
            "GET", url, self.headers(),
            timeout=30, insecure=self.insecure
        )

        if code != 200:
            print(f"  [!] batch {batch}: HTTP {code}")
            return None, ""

        server = data.get("server") if isinstance(data, dict) else None
        return server, raw


def main():
    parser = argparse.ArgumentParser(
        description="VMP VPN: извлечение URI, DNS и GeoIP"
    )
    parser.add_argument("--no-resolve", action="store_true",
                        help="не заменять домены на IPv4")
    parser.add_argument("--no-geoip", action="store_true",
                        help="не определять страны")
    parser.add_argument("--insecure", action="store_true",
                        help="отключить проверку TLS-сертификатов")
    parser.add_argument("--timeout", type=int, default=25)
    args = parser.parse_args()

    vmp = VMP(args.insecure, args.timeout)
    vmp.register()
    servers = vmp.list_servers()

    batches = []
    seen_batches = set()

    for server in servers:
        if not isinstance(server, dict):
            continue
        batch = server.get("batchId")
        if not server.get("active") or not batch:
            continue
        if batch not in seen_batches:
            seen_batches.add(batch)
            batches.append(batch)

    print(
        f"[+] Серверов: {len(servers)}, "
        f"активных батчей: {len(batches)}"
    )

    uris = []
    seen = set()
    ok = fail = 0

    for batch in batches:
        server, raw = vmp.best_in_batch(batch)

        if server is None and not raw:
            fail += 1
            continue

        ok += 1
        for uri in parse_server_config(server, raw):
            if uri not in seen:
                seen.add(uri)
                uris.append(uri)
        time.sleep(0.2)

    print(
        f"[+] Батчи: ok={ok}, fail={fail}; "
        f"собрано URI: {len(uris)}"
    )

    if not uris:
        raise RuntimeError("Конфиги не найдены")

    if not args.no_resolve:
        changed = 0
        resolved = []
        for uri in uris:
            new_uri = replace_host_in_uri(uri)
            if new_uri != uri:
                changed += 1
            resolved.append(new_uri)
        uris = resolved
        print(f"[+] DNS: изменено URI: {changed}")

    if not args.no_geoip:
        ipset = sorted({
            ip for uri in uris
            if (ip := extract_ip_from_uri(uri))
        })

        print(f"[+] GeoIP: определение стран для {len(ipset)} IP...")
        geo = batch_geoip(ipset)
        print(f"[+] GeoIP: получено {len(geo)}/{len(ipset)}")

        uris = [
            set_country_fragment(uri, geo.get(extract_ip_from_uri(uri)))
            for uri in uris
        ]

    # При отключённом GeoIP оставляем исходные фрагменты.
    unique = list(dict.fromkeys(uris))

    print(f"\n[+] Итого конфигов: {len(unique)}")
    print("\n----- SUBSCRIPTION -----")
    print("\n".join(unique))



if __name__ == "__main__":
    import contextlib
    import sys

    try:
        with contextlib.redirect_stdout(sys.stderr):
            main()
    except KeyboardInterrupt:
        print("[!] Остановлено пользователем", file=sys.stderr)
    except Exception as exc:
        print(f"[-] Ошибка: {exc}", file=sys.stderr)
        sys.exit(1)
