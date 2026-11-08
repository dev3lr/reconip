#!/usr/bin/env python3
"""
ipcheck - IP lookup + reputation + "is this a VPN or a real person's connection?"

Usage:
    python ipcheck.py                 # check your own public IP
    python ipcheck.py 8.8.8.8 1.2.3.4 # check one or more IPs
    python ipcheck.py --json 8.8.8.8  # raw JSON output

Free sources used (no key needed):
    ip-api.com           geo, ISP, ASN, proxy/hosting/mobile flags
    Shodan InternetDB    open ports, tags (vpn/proxy/tor/cloud), known CVEs
    GreyNoise Community  is this IP scanning/attacking the internet?
    Tor Project          official Tor exit-node list
    DNS blocklists       Spamhaus ZEN, SpamCop, DroneBL

Optional (much better abuse history + usage type):
    Set ABUSEIPDB_API_KEY env var (free key at https://www.abuseipdb.com/register)

Python 3.8+, standard library only.
"""

import argparse
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

def load_env_file(path=os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")):
    """Read KEY=value lines from a local .env file. Real environment variables win; empty values are ignored."""
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key, val = key.strip(), val.strip().strip('"').strip("'")
                if val and not os.environ.get(key):
                    os.environ[key] = val
    except FileNotFoundError:
        pass

load_env_file()

UA = "recon-ip/1.0 (+python-urllib)"
TIMEOUT = 10

# ---------------------------------------------------------------- helpers

def http_json(url, headers=None, timeout=TIMEOUT, data=None):
    hdrs = {"User-Agent": UA, **(headers or {})}
    if data is not None:
        data = json.dumps(data).encode()
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, headers=hdrs, data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        # Several APIs (GreyNoise, InternetDB) return JSON bodies on 404
        try:
            body = json.loads(e.read().decode("utf-8", "replace"))
            body["_http_status"] = e.code
            return body
        except Exception:
            return {"_error": f"HTTP {e.code}"}
    except Exception as e:
        return {"_error": str(e)}


def http_text(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return r.read().decode("utf-8", "replace")

# ---------------------------------------------------------------- sources

def src_ipapi(ip):
    fields = ("status,message,query,country,countryCode,regionName,city,"
              "isp,org,as,asname,reverse,mobile,proxy,hosting")
    # free tier is HTTP-only
    return http_json(f"http://ip-api.com/json/{urllib.parse.quote(ip)}?fields={fields}")


def src_internetdb(ip):
    d = http_json(f"https://internetdb.shodan.io/{ip}")
    if d.get("_http_status") == 404:
        return {"ports": [], "tags": [], "vulns": [], "hostnames": [], "_not_indexed": True}
    return d


def src_greynoise(ip):
    return http_json(f"https://api.greynoise.io/v3/community/{ip}")


_tor_cache, _tor_time = None, 0.0
_tor_lock = threading.Lock()
def src_tor(ip):
    global _tor_cache, _tor_time
    with _tor_lock:  # refresh hourly; matters when running as a long-lived web server
        if _tor_cache is None or time.time() - _tor_time > 3600:
            try:
                txt = http_text("https://check.torproject.org/torbulkexitlist")
                _tor_cache = {l.strip() for l in txt.splitlines() if l.strip() and not l.startswith("#")}
                _tor_time = time.time()
            except Exception as e:
                if _tor_cache is None:
                    return {"_error": str(e)}
    return {"is_exit": ip in _tor_cache, "list_size": len(_tor_cache)}


def src_abuseipdb(ip):
    key = os.environ.get("ABUSEIPDB_API_KEY")
    if not key:
        return {"_skipped": "set ABUSEIPDB_API_KEY for abuse report history"}
    q = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 365})
    d = http_json(f"https://api.abuseipdb.com/api/v2/check?{q}",
                  headers={"Key": key, "Accept": "application/json"})
    return d.get("data", d)


DNSBLS = {
    "zen.spamhaus.org": "Spamhaus ZEN",
    "bl.spamcop.net": "SpamCop",
    "dnsbl.dronebl.org": "DroneBL",
}

def src_dnsbl(ip):
    addr = ipaddress.ip_address(ip)
    if addr.version != 4:
        return {"_skipped": "IPv4 only"}
    rev = ".".join(reversed(ip.split(".")))
    out = {}
    for zone, name in DNSBLS.items():
        try:
            answers = sorted(set(socket.gethostbyname_ex(f"{rev}.{zone}")[2]))  # zones can return several codes
            if any(a.startswith("127.255.255.") for a in answers):
                out[name] = "query refused (public DNS resolver)"
            elif zone == "zen.spamhaus.org":
                pbl = [a for a in answers if a in ("127.0.0.10", "127.0.0.11")]
                bad = sorted({{"127.0.0.2": "SBL spam source", "127.0.0.3": "SBL CSS spam",
                               "127.0.0.9": "DROP hijacked/criminal netblock"}.get(a, "XBL exploited/botnet host")
                              for a in answers if a not in pbl})
                if bad:
                    out[name] = f"LISTED ({', '.join(bad)})" + (" + PBL end-user range" if pbl else "")
                else:
                    out[name] = "PBL (end-user / dynamic IP range, not a threat)"
            else:
                out[name] = f"LISTED ({', '.join(answers)})"
        except socket.gaierror:
            out[name] = "clean"
        except Exception as e:
            out[name] = f"error: {e}"
    return out

RIPESTAT = "https://stat.ripe.net/data/{}/data.json?sourceapp=ipcheck&"

def _ts(s):
    from datetime import datetime, timezone
    return datetime.fromisoformat(s.replace("Z", "")).replace(tzinfo=timezone.utc).timestamp()


def src_routing(ip):
    """BGP routing history from RIPEstat: who has announced this block, and since when."""
    ov = http_json(RIPESTAT.format("prefix-overview") + f"resource={ip}", timeout=20).get("data") or {}
    if not ov.get("announced"):
        return {"announced": False, "_error": None if ov else "RIPEstat unavailable"}
    prefix = ov.get("resource")
    with ThreadPoolExecutor(2) as ex:
        f_hist = ex.submit(http_json, RIPESTAT.format("routing-history") + f"resource={prefix}&min_peers=10", None, 25)
        f_rir = ex.submit(http_json, RIPESTAT.format("rir") + f"resource={ip}&lod=2", None, 20)
        hist, rir = (f_hist.result().get("data") or {}), (f_rir.result().get("data") or {})

    addr, ann_len = ipaddress.ip_address(ip), int(prefix.split("/")[1])
    now = time.time()
    end = _ts(hist["query_endtime"]) if hist.get("query_endtime") else now
    origins, anomalies = [], 0
    for o in hist.get("by_origin", []):
        spans, prefixes = [], set()
        for p in o.get("prefixes", []):
            net = ipaddress.ip_network(p["prefix"], strict=False)
            if addr not in net:                          # history of a big block includes unrelated sub-ranges
                continue
            if net.prefixlen < min(16 if addr.version == 4 else 32, ann_len):
                anomalies += 1                           # huge covering ranges: leaks/test routes, not ownership
                anomalies += 1
                continue
            prefixes.add(p["prefix"])
            spans += [(_ts(t["starttime"]), _ts(t["endtime"])) for t in p.get("timelines", [])]
        if not spans:
            continue
        days = sum(b - a for a, b in spans) / 86400
        if days < 14:                                    # brief announcement: possible leak / hijack
            anomalies += 1
            continue
        first, last = min(a for a, _ in spans), max(b for _, b in spans)
        prefixes = sorted(prefixes, key=lambda x: -int(x.split("/")[1]))
        origins.append({"asn": int(o["origin"]), "first_seen": int(first), "last_seen": int(last),
                        "days_visible": round(days), "active": end - last < 30 * 86400,
                        "most_specific": int(prefixes[0].split("/")[1]), "prefixes": prefixes})
    origins.sort(key=lambda x: x["first_seen"])

    # Look up the holder name for each origin AS
    holders = {a["asn"]: a.get("holder") for a in ov.get("asns", [])}
    missing = [o["asn"] for o in origins if o["asn"] not in holders][:8]
    with ThreadPoolExecutor(max(1, len(missing))) as ex:
        for asn, res in zip(missing, ex.map(
                lambda a: http_json(RIPESTAT.format("as-overview") + f"resource=AS{a}", timeout=15), missing)):
            holders[asn] = (res.get("data") or {}).get("holder")
    for o in origins:
        o["holder"] = holders.get(o["asn"]) or f"AS{o['asn']}"

    # Traffic follows the most specific route, so the current owner is whoever announces
    # the longest active prefix; shorter active ones are upstream aggregates.
    active = [o for o in origins if o["active"]]
    best = max((o["most_specific"] for o in active), default=None)
    for o in origins:
        o["current"] = o["active"] and o["most_specific"] == best
        o["role"] = "owner" if o["current"] else ("upstream aggregate" if o["active"] else "previous")
    current = [o for o in origins if o["current"]]
    since = min((o["first_seen"] for o in current), default=None)
    reg = next(iter(rir.get("rirs") or []), {})
    return {
        "announced": True, "prefix": prefix, "origins": origins,
        "current_since": since, "current_age_days": int((now - since) / 86400) if since else None,
        "first_routed": origins[0]["first_seen"] if origins else None,
        "owner_count": len(origins), "anomalies": anomalies,
        "rir": {"name": reg.get("rir"), "registered": reg.get("registration"), "status": reg.get("status"),
                "block": reg.get("resource"), "country": reg.get("country")},
    }

# ---------------------------------------------------------------- analysis

VPN_BRANDS = re.compile(
    r"nord|express ?vpn|surfshark|mullvad|proton|private internet access|\bpia\b|"
    r"cyberghost|ipvanish|windscribe|hide\.?me|purevpn|torguard|ivpn|airvpn|"
    r"vyprvpn|hotspot shield|tunnelbear|astrill|perfect privacy|ovpn|"
    r"cloudflare warp|\bvpn\b|proxy", re.I)

# Hosters that commercial VPN providers (Nord, Mullvad, Surfshark, Proton...) rent most of
# their servers from. A home user is basically never on these networks.
VPN_HOSTERS = re.compile(
    r"m247|datacamp|datapacket|cdn77|packethub|tzulo|zenlayer|clouvider|xtom|"
    r"31173|hostroyale|creanova|performive|globalaxs|quadranet|leaseweb|"
    r"privatelayer|flokinet|hydra communications|tefincom|incognet", re.I)

# Generic hosting / cloud
HOSTERS = re.compile(
    r"m247|datacamp|datapacket|cdn77|leaseweb|ovh|hetzner|digitalocean|linode|akamai|vultr|"
    r"choopa|the constant company|amazon|aws|google cloud|google llc|microsoft|azure|"
    r"oracle|alibaba|tencent|contabo|scaleway|online s\.a\.s|hostinger|godaddy|"
    r"hostwinds|quadranet|psychz|colocrossing|zenlayer|packethub|tzulo|"
    r"servers\.com|serverion|clouvider|xtom|frantech|buyvm|g-core|gcore|"
    r"hosting|datacenter|data center|colo|server|cloud", re.I)

RESIDENTIAL_ISP = re.compile(
    r"telecom|telekom|broadband|cable|comcast|charter|spectrum|verizon|at&t|"
    r"t-mobile|vodafone|orange|airtel|jio|reliance|bsnl|act fibernet|hathway|"
    r"bt |sky |virgin|telstra|optus|rogers|bell canada|shaw|telus|cox|frontier|"
    r"centurylink|lumen|deutsche|telefonica|movistar|claro|vivo|tim |"
    r"fiber|fibre|dsl|wireless|mobile|cellular|communications", re.I)

RESIDENTIAL_RDNS = re.compile(
    r"dsl|dyn|dynamic|pool|dhcp|cable|ftth|fttx|fios|res|cust|client|"
    r"broadband|ppp|home|user|static\.?\d|\d+-\d+-\d+-\d+", re.I)

VPN_PORTS = {1194: "OpenVPN", 51820: "WireGuard", 500: "IPsec/IKE",
             4500: "IPsec NAT-T", 1701: "L2TP", 1723: "PPTP", 443: None}
PROXY_PORTS = {1080: "SOCKS", 3128: "Squid proxy", 8080: "HTTP proxy", 8888: "HTTP proxy"}


def analyze(ip, s):
    geo, idb, gn, tor, ab, bl = (s["ipapi"], s["internetdb"], s["greynoise"],
                                 s["tor"], s["abuseipdb"], s["dnsbl"])
    names = " ".join(str(geo.get(k, "")) for k in ("isp", "org", "as", "asname"))
    if not ab.get("_skipped"):
        names += " " + str(ab.get("isp", "")) + " " + str(ab.get("domain", ""))
    rdns = geo.get("reverse", "") or " ".join(idb.get("hostnames", []) or [])
    tags = [t.lower() for t in (idb.get("tags") or [])]
    ports = idb.get("ports") or []
    usage = str(ab.get("usageType", "")) if not ab.get("_skipped") else ""

    anon, resid = 0, 0     # evidence scores
    strong_vpn = False     # VPN-specific evidence, not just "it's a server"
    why_anon, why_resid = [], []

    def a(pts, msg):
        nonlocal anon; anon += pts; why_anon.append(msg)
    def r(pts, msg):
        nonlocal resid; resid += pts; why_resid.append(msg)

    is_tor = tor.get("is_exit") or ab.get("isTor") or "tor" in tags
    if is_tor:                     a(10, "Listed as a Tor exit node")
    if geo.get("proxy"):           a(2, "ip-api flags it as proxy/VPN/Tor (noisy signal)")
    if geo.get("hosting"):         a(3, "ip-api flags it as hosting/datacenter")
    if "vpn" in tags:              a(5, "Shodan tags it 'vpn'"); strong_vpn = True
    if "proxy" in tags:            a(4, "Shodan tags it 'proxy'"); strong_vpn = True
    if "cloud" in tags:            a(2, "Shodan tags it 'cloud'")
    if VPN_BRANDS.search(names):   a(5, "Provider name looks like a VPN/proxy brand"); strong_vpn = True
    elif VPN_HOSTERS.search(names + " " + (rdns or "")):
        a(4, "Hosted on a network commercial VPN providers heavily rent from"); strong_vpn = True
    elif HOSTERS.search(names):    a(3, "ISP/ASN is a hosting / cloud company")
    if re.search(r"data center|hosting|transit|content delivery", usage, re.I):
        a(3, f"AbuseIPDB usage type: {usage}")
    vp = [VPN_PORTS[p] for p in ports if VPN_PORTS.get(p)]
    if vp:                         a(3, f"VPN server ports open: {', '.join(vp)}"); strong_vpn = True
    pp = [PROXY_PORTS[p] for p in ports if p in PROXY_PORTS]
    if pp:                         a(2, f"Proxy ports open: {', '.join(sorted(set(pp)))}")
    if re.search(r"vpn|proxy|exit|relay", rdns or "", re.I):
        a(3, f"Reverse DNS mentions vpn/proxy ({rdns})"); strong_vpn = True
    if gn.get("riot"):             a(2, f"GreyNoise: known business service ({gn.get('name')})")

    if geo.get("mobile"):          r(4, "ip-api flags it as a mobile/cellular network")
    if re.search(r"fixed line isp|mobile isp|cable/dsl", usage, re.I):
        r(4, f"AbuseIPDB usage type: {usage}")
    if RESIDENTIAL_ISP.search(names) and not HOSTERS.search(names):
        r(3, "ISP name looks like a consumer telecom/broadband provider")
    if (rdns and RESIDENTIAL_RDNS.search(rdns) and not HOSTERS.search(rdns)
            and not VPN_HOSTERS.search(rdns) and not HOSTERS.search(names)):
        r(2, f"Reverse DNS looks residential ({rdns})")
    if not geo.get("hosting") and not geo.get("proxy") and not geo.get("_error"):
        r(1, "Not flagged as hosting or proxy")
    if str(bl.get("Spamhaus ZEN", "")).startswith("PBL"):
        r(3, "Spamhaus PBL: ISP marks this as an end-user (home/mobile) range")
    if idb.get("_not_indexed") or not ports:
        r(1, "No public services exposed (typical of home connections behind NAT)")

    if is_tor:
        net = "TOR EXIT NODE"
    elif strong_vpn and anon >= 5 and anon > resid:
        net = "LIKELY VPN / PROXY"
    elif anon >= 3 and anon > resid:
        net = "DATACENTER / HOSTING (could be a VPN, bot, or server)"
    elif geo.get("mobile") and resid > anon:
        net = "LIKELY MOBILE CARRIER (real user, shared CGNAT IP)"
    elif resid >= 3 and resid > anon:
        net = "LIKELY RESIDENTIAL / REAL ISP"
    else:
        net = "UNCLEAR"

    # ---- threat / attack history
    threat, why_threat = 0, []
    def t(pts, msg):
        nonlocal threat; threat += pts; why_threat.append(msg)

    if not ab.get("_skipped") and not ab.get("_error") and "abuseConfidenceScore" in ab:
        sc, n = ab.get("abuseConfidenceScore", 0), ab.get("totalReports", 0)
        if sc >= 75:   t(6, f"AbuseIPDB confidence {sc}% ({n} reports)")
        elif sc >= 25: t(3, f"AbuseIPDB confidence {sc}% ({n} reports)")
        # 0% with reports = AbuseIPDB itself discounts them (e.g. whitelisted DNS/CDNs reported by mistake)
        elif n and sc > 0 and not ab.get("isWhitelisted"):
            t(1, f"AbuseIPDB: {n} reports, low confidence ({sc}%)")
    cls = gn.get("classification")
    if cls == "malicious":   t(5, "GreyNoise: classified MALICIOUS (seen attacking/scanning)")
    elif gn.get("noise"):    t(2, f"GreyNoise: mass-scanning the internet ({cls or 'unknown'})")
    listed = [k for k, v in bl.items() if isinstance(v, str) and v.startswith("LISTED")]
    if listed:               t(2 * len(listed), f"On blocklists: {', '.join(listed)}")
    if is_tor:               t(2, "Tor exit (traffic from many anonymous users)")
    if any(x in tags for x in ("compromised", "malware", "c2", "scanner")):
        t(3, f"Shodan tags: {', '.join(tags)}")
    vulns = idb.get("vulns") or []
    if vulns:                t(1, f"Host itself exposes {len(vulns)} known CVEs (may be compromised)")

    rt = s.get("routing") or {}
    age = rt.get("current_age_days")
    if age is not None and age < 30:
        t(3, f"Network only started routing {age} days ago (fresh infrastructure is common in attack campaigns)")
    elif age is not None and age < 180:
        t(1, f"Current owner has announced this block for only {age} days")
    if rt.get("owner_count", 0) >= 4:
        t(1, f"Block has passed through {rt['owner_count']} different networks (frequently re-leased space)")

    level = ("HIGH" if threat >= 6 else "MEDIUM" if threat >= 3
             else "LOW" if threat >= 1 else "NONE KNOWN")

    return {
        "network_type": net, "anon_score": anon, "residential_score": resid,
        "anon_reasons": why_anon, "residential_reasons": why_resid,
        "threat_level": level, "threat_score": threat, "threat_reasons": why_threat,
    }

# ---------------------------------------------------------------- output

USE_COLOR = sys.stdout.isatty()
def c(txt, code):
    return f"\033[{code}m{txt}\033[0m" if USE_COLOR else txt

def show(ip, s, v):
    geo, idb, gn, ab, bl = s["ipapi"], s["internetdb"], s["greynoise"], s["abuseipdb"], s["dnsbl"]
    line = "─" * 64
    print(c(line, "90"))
    print(c(f" {ip}", "1;97"))
    print(c(line, "90"))

    def row(k, val):
        if val not in (None, "", [], {}):
            print(f"  {c(k.ljust(14), '90')}{val}")

    loc = ", ".join(x for x in (geo.get("city"), geo.get("regionName"), geo.get("country")) if x)
    row("Location", loc)
    row("ISP", geo.get("isp"))
    row("Org", geo.get("org") if geo.get("org") != geo.get("isp") else None)
    row("ASN", geo.get("as"))
    row("Reverse DNS", geo.get("reverse"))
    if not ab.get("_skipped"):
        row("Usage type", ab.get("usageType"))
        row("Domain", ab.get("domain"))
    row("Open ports", ", ".join(map(str, idb.get("ports") or [])))
    row("Shodan tags", ", ".join(idb.get("tags") or []))
    if idb.get("vulns"):
        vs = idb["vulns"]
        row("Known CVEs", ", ".join(vs[:6]) + (f" (+{len(vs)-6} more)" if len(vs) > 6 else ""))
    if gn.get("_http_status") == 404 or gn.get("message", "").startswith("IP not observed"):
        row("GreyNoise", "not observed scanning the internet")
    elif gn.get("classification") or gn.get("riot"):
        row("GreyNoise", f"{gn.get('classification', '?')}  noise={gn.get('noise')}  "
                         f"riot={gn.get('riot')}  {gn.get('name') or ''}  last seen {gn.get('last_seen') or '-'}")
    elif gn.get("_error") or gn.get("message"):
        row("GreyNoise", gn.get("_error") or gn.get("message"))
    if ab.get("_skipped"):
        row("AbuseIPDB", c(ab["_skipped"], "90"))
    elif "abuseConfidenceScore" in ab:
        row("AbuseIPDB", f"{ab['abuseConfidenceScore']}% confidence, {ab.get('totalReports', 0)} reports "
                         f"from {ab.get('numDistinctUsers', 0)} users, last {ab.get('lastReportedAt') or '-'}")
    elif ab.get("_error") or ab.get("errors"):
        row("AbuseIPDB", ab.get("_error") or ab.get("errors"))
    rt = s.get("routing") or {}
    if rt.get("current_since"):
        from datetime import datetime, timezone
        d = lambda x: datetime.fromtimestamp(x, timezone.utc).strftime("%Y-%m-%d")
        cur = ", ".join(o["holder"] for o in rt["origins"] if o["current"])
        row("Routing", f"{rt['prefix']} announced by {cur} since {d(rt['current_since'])}"
                       f" ({rt['owner_count']} owner(s) in history)")
    if not bl.get("_skipped"):
        row("Blocklists", "  ".join(f"{k}: {v}" for k, v in bl.items()))

    print()
    ncol = {"TOR": "1;95", "LIKELY VPN": "1;93", "DATACENTER": "1;33",
            "LIKELY RES": "1;92", "LIKELY MOB": "1;92"}.get(v["network_type"][:10], "1;37")
    scores = f"(anon {v['anon_score']} vs residential {v['residential_score']})"
    print(f"  {c('NETWORK', '1')}       {c(v['network_type'], ncol)}   {c(scores, '90')}")
    for x in v["anon_reasons"]:
        print(f"      {c('+ anon ', '33')} {x}")
    for x in v["residential_reasons"]:
        print(f"      {c('+ real ', '32')} {x}")

    tcol = {"HIGH": "1;91", "MEDIUM": "1;93", "LOW": "1;33", "NONE KNOWN": "1;92"}[v["threat_level"]]
    print(f"  {c('THREAT', '1')}        {c(v['threat_level'], tcol)}")
    for x in v["threat_reasons"]:
        print(f"      {c('! ', '91')}{x}")
    if not v["threat_reasons"]:
        print(f"      {c('no malicious activity found in the sources checked', '90')}")
    print()

# ---------------------------------------------------------------- main

SOURCES = {"ipapi": src_ipapi, "internetdb": src_internetdb, "greynoise": src_greynoise,
           "tor": src_tor, "abuseipdb": src_abuseipdb, "dnsbl": src_dnsbl, "routing": src_routing}

def check(ip):
    with ThreadPoolExecutor(len(SOURCES)) as ex:
        futs = {k: ex.submit(fn, ip) for k, fn in SOURCES.items()}
        results = {}
        for k, f in futs.items():
            try:
                results[k] = f.result()
            except Exception as e:
                results[k] = {"_error": str(e)}
    return results


def resolve(target):
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        return socket.gethostbyname(target)   # allow hostnames too


def main():
    global USE_COLOR
    p = argparse.ArgumentParser(description="IP lookup, reputation and VPN/residential check")
    p.add_argument("targets", nargs="*", help="IPs or hostnames (default: your own public IP)")
    p.add_argument("--json", action="store_true", help="print raw JSON")
    p.add_argument("--no-color", action="store_true")
    args = p.parse_args()
    if args.no_color or args.json:
        USE_COLOR = False
    if os.name == "nt":
        os.system("")  # enable ANSI colors in Windows console
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    targets = args.targets
    if not targets:
        me = http_json("http://ip-api.com/json/?fields=query")
        if "query" not in me:
            sys.exit("Could not determine your public IP; pass one explicitly.")
        targets = [me["query"]]

    all_out = []
    for t in targets:
        try:
            ip = resolve(t)
        except Exception as e:
            print(f"{t}: cannot resolve ({e})", file=sys.stderr)
            continue
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_reserved:
            print(f"{ip}: private/reserved address, nothing to look up", file=sys.stderr)
            continue
        s = check(ip)
        v = analyze(ip, s)
        if args.json:
            all_out.append({"ip": ip, "verdict": v, "sources": s})
        else:
            if t != ip:
                print(c(f"\n {t} → {ip}", "90"))
            show(ip, s, v)
    if args.json:
        print(json.dumps(all_out if len(all_out) != 1 else all_out[0], indent=2, default=str))


if __name__ == "__main__":
    main()
