import argparse
import json
import sys
from pathlib import Path
import requests

APP_DIR = Path.home() / ".config" / "iplookup"
CONFIG_PATH = APP_DIR / "config.json"

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
    print("Set your token with:")
    print("  iplookup config set-token YOUR_TOKEN_HERE")
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


def cmd_lookup(target: str, token_override: str | None) -> None:
    cfg = load_config()

    token = token_override or cfg.get("token", "")
    if not token:
        print(f"No token set. Edit {CONFIG_PATH} or run:")
        print("  iplookup config set-token YOUR_TOKEN_HERE")
        raise SystemExit(1)

    timeout = cfg.get("timeout", 10)
    url = f"https://api.ipinfo.io/lite/{target}"

    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(url, headers=headers, timeout=timeout)
    r.raise_for_status()

    data = r.json()
    if isinstance(data, dict) and "error" in data:
        print(f"API error: {data['error']}")
        raise SystemExit(2)

    print(json.dumps(data, indent=4))


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

    cmd_lookup(args.target, args.token)


if __name__ == "__main__":
    main()