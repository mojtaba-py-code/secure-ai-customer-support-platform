"""Print an access token for a seeded demo account - for the dynamic security scans in CI.

    aegis seed                                            # writes var/seed-credentials.json
    python scripts/dast_token.py --role customer          # prints the token on stdout

Signs in as the first demo account with the given role, through the real login endpoint. Only
for the fictional demo data of a disposable instance: staff accounts that must use two-factor
authentication get a second-step challenge instead of a token, and the script stops there.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import httpx2

ROLES = ("customer", "support_agent", "support_manager", "admin")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--role", choices=ROLES, required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--credentials", default="var/seed-credentials.json")
    args = parser.parse_args()

    accounts = json.loads(Path(args.credentials).read_text(encoding="utf-8"))["accounts"]
    email, account = next(
        (email, account) for email, account in accounts.items() if account["role"] == args.role
    )
    response = httpx2.post(
        f"{args.base_url}/api/v1/auth/login",
        json={"email": email, "password": account["password"]},
        timeout=30.0,
    )
    response.raise_for_status()
    token = response.json().get("access_token")
    if not token:
        print(
            f"no access token for {args.role}: a second sign-in step is required", file=sys.stderr
        )
        return 1
    print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
