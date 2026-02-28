import argparse
import json
import sys
from pathlib import Path
import requests
import collections
import ipaddress

APP_DIR = Path.home() / ".config" / "iplookup"
CONFIG_PATH = APP_DIR / "config.json"
BASE_URL = "https://api.ipinfo.io/lite/"

def ensure_config_exists() -> None:
    if CONFIG_PATH.exists():
        return

    APP_DIR.mkdir(parents=True, exist_ok=True)
    template = {
        "token": "",
        "timeout": 10
    }
    CONFIG_PATH.write_text(json.dumps(template, indent=4) + "\n", encoding="utf-8")

    print(f"Created config file at: {CONFIG_PATH}")
    print("Set your IPinfo Lite token with:")
    print("  iplookup config set-token YOUR_TOKEN_HERE")
    print("If you dont have one go to https://ipinfo.io to get it")
    raise SystemExit(1)


def load_config() -> dict:
    ensure_config_exists()
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print(f"Config file is not valid JSON: {CONFIG_PATH}")
        raise SystemExit(1)


def save_config(cfg: dict) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=4) + "\n", encoding="utf-8")

def check_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def cmd_lookup(target: str, file: str | None, token_override: str | None, count: bool, alert_codes: list[str] | None) -> None:
    cfg = load_config()

    token = token_override or cfg.get("token", "")
    if not token:
        print(f"No token set. Edit {CONFIG_PATH} or run:")
        print("  iplookup config set-token YOUR_TOKEN_HERE")
        raise SystemExit(1)

    timeout = cfg.get("timeout", 10)
    headers = {"Authorization": f"Bearer {token}"}

    if file: 
        country_names = []
        country_codes = []
        alert_codes = [c.upper() for c in (alert_codes or [])]
        hits = {code: [] for code in alert_codes}

        with open(file, encoding="utf-8") as f:
            for line in f:
                ip = line.strip()
                if check_ip(ip):
                    r = requests.get(f"{BASE_URL}{ip}", headers=headers, timeout=timeout)
                    data = r.json()
                    if isinstance(data, dict) and "error" in data:
                        print(f"API error: {data['error']}")
                        continue

                    country_names.append(data['country'])
                    country_code = data['country_code']
                    country_codes.append(country_code)

                    if country_code in alert_codes:
                        hits[country_code].append(ip)

        if not count and not alert_codes:
            unique_codes = sorted(set(country_codes))
            print(json.dumps(unique_codes, indent=4))
        
        elif count:
            geo_data = collections.Counter(country_names)
            for country, n in geo_data.most_common():
                print(f"{country}: {n}")
        
        else:
            for code in alert_codes:
                ips = hits.get(code, [])
                if not ips:
                    continue
                
                print(f"{code} ({len(ips)})")
                for ip in ips:
                    print(f"  {ip}")

                print()
        return
    
    if target == "me" or check_ip(target):
        r = requests.get(f"{BASE_URL}{target}", headers=headers, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        if isinstance(data, dict) and "error" in data:
            print(f"API error: {data['error']}")
            raise SystemExit(2)

        print(json.dumps(data, indent=4))
    else:
        print("Target must be me or a valid IPv4/IPv6 address.")
        raise SystemExit(2)


def cmd_config_set_token(token: str) -> None:
    cfg = load_config()
    cfg["token"] = token.strip()
    save_config(cfg)
    print(f"Token saved to {CONFIG_PATH}")


def cmd_config_path() -> None:
    print(CONFIG_PATH)


def main() -> None:
    parser = argparse.ArgumentParser(prog="iplookup")
    sub = parser.add_subparsers(dest="command", required=True)

    lookup_parser = sub.add_parser("lookup", help="Lookup info for an IP (or 'me')")
    lookup_parser.add_argument("target", nargs="?", default="me", help="IP address or 'me'")
    lookup_parser.add_argument("--token", help="Override token (does not save)")
    lookup_parser.add_argument("--file", help="Read Ips from a .txt file returns a unique set of country codes")
    lookup_parser.add_argument("--count", action="store_true", help="With --file: print counts with country name instead of unique codes")
    lookup_parser.add_argument("--alert", nargs="+", help="Print IPs grouped by country code for the given codes (e.g. --alert CN RU)")

    cfg_parser = sub.add_parser("config", help="Manage config")
    cfg_sub = cfg_parser.add_subparsers(dest="cfg_command", required=True)

    set_token_parser = cfg_sub.add_parser("set-token", help="Save API token to config")
    set_token_parser.add_argument("token")

    cfg_sub.add_parser("path", help="Print config path")

    if len(sys.argv) == 1:
        sys.argv.insert(1, "lookup")
    else:
        first = sys.argv[1]
        if first not in ("lookup", "config", "-h", "--help"):
            sys.argv.insert(1, "lookup")

    args = parser.parse_args() 

    if args.command == "config":
        if args.cfg_command == "set-token":
            cmd_config_set_token(args.token)
        elif args.cfg_command == "path":
            cmd_config_path()
        return
    
    if args.count and not args.file:
        parser.error("--count can only be used with --file")
    
    if args.alert and args.count:
        parser.error("--alert cannot be used together with --count")

    if args.alert and not args.file:
        parser.error("--alert can only be used with --file")

    cmd_lookup(args.target, args.file, args.token, args.count, args.alert)

if __name__ == "__main__":
    main()