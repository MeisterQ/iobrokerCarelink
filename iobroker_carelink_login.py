import base64
import hashlib
import json
import secrets
import string
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

import requests
from seleniumwire import webdriver  # seleniumwire!
from selenium.webdriver.firefox.options import Options as FirefoxOptions


DISCOVERY_URL = "https://clcloud.minimed.eu/connect/carepartner/v13/discover/android/3.6"
REGION = "EU"
OUTFILE = "logindata.json"
TIMEOUT = 30


def b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def random_state(n: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def pkce_pair():
    alphabet = string.ascii_letters + string.digits + "-._~"
    verifier = "".join(secrets.choice(alphabet) for _ in range(80))
    challenge = b64url_no_pad(hashlib.sha256(verifier.encode("utf-8")).digest())
    return verifier, challenge


@dataclass
class Auth0Config:
    auth_base: str
    authorize_url: str
    token_url: str
    client_id: str
    client_secret: str | None
    redirect_uri: str
    scope: str
    audience: str | None


def load_auth0_config(region: str) -> Auth0Config:
    region = region.upper().strip()
    disc = requests.get(DISCOVERY_URL, timeout=TIMEOUT).json()
    cp = disc.get("CP", [])
    picked = next((c for c in cp if str(c.get("region", "")).upper() == region), None)
    if not picked:
        raise RuntimeError(f"Region {region} not found")

    use_key = picked.get("UseSSOConfiguration", "SSOConfiguration")
    sso_url = picked.get(use_key) or picked.get("SSOConfiguration")
    if not sso_url:
        raise RuntimeError("No SSO URL found")

    sso = requests.get(sso_url, timeout=TIMEOUT).json()

    server = sso.get("server", {})
    hostname = server.get("hostname")
    port = server.get("port")
    prefix = server.get("prefix", "") or ""
    if not hostname or not port:
        raise RuntimeError("SSO server missing hostname/port")

    auth_base = f"https://{hostname}:{port}{prefix}"

    client = sso.get("client", {})
    endpoints = sso.get("system_endpoints", {})

    client_id = client.get("client_id")
    redirect_uri = client.get("redirect_uri")
    scope = client.get("scope") or "openid profile offline_access"
    audience = client.get("audience")
    client_secret = client.get("client_secret") or None

    auth_path = endpoints.get("authorization_endpoint_path")
    token_path = endpoints.get("token_endpoint_path")
    if not client_id or not redirect_uri or not auth_path or not token_path:
        raise RuntimeError("SSO config incomplete (client_id/redirect_uri/auth/token)")

    return Auth0Config(
        auth_base=auth_base,
        authorize_url=auth_base + auth_path,
        token_url=auth_base + token_path,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        scope=scope,
        audience=audience,
    )


def build_authorize_url(cfg: Auth0Config, state: str, code_challenge: str) -> str:
    params = {
        "response_type": "code",
        "client_id": cfg.client_id,
        "redirect_uri": cfg.redirect_uri,
        "scope": cfg.scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if cfg.audience:
        params["audience"] = cfg.audience
    return cfg.authorize_url + "?" + urllib.parse.urlencode(params)


def extract_code_from_location(location: str) -> tuple[str | None, str | None]:
    # location: com.medtronic.carepartner:/sso?code=...&state=...
    try:
        u = urllib.parse.urlparse(location)
        qs = urllib.parse.parse_qs(u.query)
        code = qs.get("code", [None])[0]
        state = qs.get("state", [None])[0]
        return code, state
    except Exception:
        return None, None


def exchange_code(cfg: Auth0Config, code: str, code_verifier: str) -> dict:
    data = {
        "grant_type": "authorization_code",
        "client_id": cfg.client_id,
        "code": code,
        "redirect_uri": cfg.redirect_uri,
        "code_verifier": code_verifier,
    }
    # secret nur mitsenden, wenn wirklich vorhanden/benötigt
    if cfg.client_secret:
        data["client_secret"] = cfg.client_secret
    if cfg.audience:
        data["audience"] = cfg.audience

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0",
    }
    r = requests.post(cfg.token_url, data=data, headers=headers, timeout=TIMEOUT)
    if r.status_code != 200:
        raise RuntimeError(f"Token exchange failed HTTP {r.status_code}: {r.text[:500]}")
    return r.json()


def main():
    cfg = load_auth0_config(REGION)
    code_verifier, code_challenge = pkce_pair()
    state = random_state()
    auth_url = build_authorize_url(cfg, state, code_challenge)

    print("[auth] opening browser via SeleniumWire...")
    print("[auth] URL:", auth_url)

    # Firefox (am stabilsten). Für Chrome geht analog.
    opts = FirefoxOptions()
    # opts.add_argument("-headless")  # kannst du aktivieren, aber fürs Captcha/Login oft besser OHNE headless

    driver = webdriver.Firefox(options=opts)
    driver.scopes = [".*"]  # alles mitschneiden

    try:
        driver.get(auth_url)

        print("\nBitte im Browser-Fenster einloggen.")
        print("Ich warte auf den Redirect (302 Location) mit com.medtronic.carepartner:/sso?code=...\n")

        deadline = time.time() + 180  # 3 Minuten
        found_location = None

        while time.time() < deadline:
            # seleniumwire sammelt driver.requests laufend
            for req in driver.requests:
                resp = req.response
                if not resp:
                    continue
                # Auth0 redirectet oft mit 302/303
                if resp.status_code in (301, 302, 303, 307, 308):
                    headers = resp.headers
                    loc = headers.get("Location") or headers.get("location")
                    if loc and "com.medtronic.carepartner:/sso" in loc and "code=" in loc:
                        found_location = loc
                        break
            if found_location:
                break
            time.sleep(0.2)

        if not found_location:
            raise RuntimeError("Kein Redirect mit code= gefunden. (Evtl. Block/Fehler/anderer Flow)")

        code, returned_state = extract_code_from_location(found_location)
        print("[auth] captured Location:", found_location)
        if not code:
            raise RuntimeError("Location gefunden, aber kein code extrahierbar.")
        if returned_state and returned_state != state:
            raise RuntimeError("State mismatch (CSRF Schutz). Bitte erneut.")

        print("\n[token] exchanging code for tokens...")
        token_data = exchange_code(cfg, code, code_verifier)

        out = {
            "access_token": token_data.get("access_token"),
            "refresh_token": token_data.get("refresh_token"),
            "scope": token_data.get("scope") or cfg.scope,
            "client_id": cfg.client_id,
            "client_secret": cfg.client_secret or "",
            "audience": cfg.audience or "",
            "token_url": cfg.token_url,
        }

        outpath = Path(__file__).resolve().parent / OUTFILE
        outpath.write_text(json.dumps(out, indent=2), encoding="utf-8")
        print("[ok] wrote", outpath)
        print("[ok] access_token:", "<present>" if out["access_token"] else "<missing>")
        print("[ok] refresh_token:", "<present>" if out["refresh_token"] else "<missing>")

    finally:
        try:
            driver.quit()
        except Exception:
            pass


if __name__ == "__main__":
    main()
