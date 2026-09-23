"""Minimal GitHub REST client: stdlib only, with retry and rate-limit handling."""

import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

API_VERSION = "2022-11-28"
USER_AGENT = "org-license-check"


class GitHubError(Exception):
    pass


class Client:
    def __init__(self, token, api_base=None, log=None, max_retries=5):
        self.token = token
        self.api_base = (api_base or os.environ.get("GITHUB_API_URL")
                         or "https://api.github.com").rstrip("/")
        self.log = log or (lambda msg: print(msg, file=sys.stderr))
        self.max_retries = max_retries

    def request(self, path, method="GET", body=None, accept="application/vnd.github+json"):
        """Returns (status, parsed_json_or_None). 404 is returned, not raised."""
        url = path if path.startswith("http") else self.api_base + path
        data = json.dumps(body).encode("utf-8") if body is not None else None

        for attempt in range(self.max_retries):
            req = urllib.request.Request(url, data=data, method=method)
            req.add_header("Accept", accept)
            req.add_header("Authorization", "Bearer " + self.token)
            req.add_header("X-GitHub-Api-Version", API_VERSION)
            req.add_header("User-Agent", USER_AGENT)
            if data is not None:
                req.add_header("Content-Type", "application/json")

            try:
                with urllib.request.urlopen(req, timeout=60) as response:
                    payload = response.read().decode("utf-8")
                    parsed = json.loads(payload) if payload.strip() else None
                    return response.status, parsed
            except urllib.error.HTTPError as err:
                status = err.code
                if status == 404:
                    return 404, None
                detail = err.read().decode("utf-8", "replace")[:400]

                wait = self._retry_delay(status, err.headers, attempt)
                if wait is None:
                    raise GitHubError("HTTP %s %s: %s" % (status, url, detail))
                self.log("  rate limited/transient (HTTP %s); retrying in %ds" % (status, wait))
                time.sleep(wait)
            except urllib.error.URLError as err:
                if attempt == self.max_retries - 1:
                    raise GitHubError("network error for %s: %s" % (url, err))
                time.sleep(2 ** attempt)

        raise GitHubError("giving up on %s after %d attempts" % (url, self.max_retries))

    def _retry_delay(self, status, headers, attempt):
        """Seconds to wait before retrying, or None if the error is fatal."""
        if status in (403, 429):
            reset = headers.get("x-ratelimit-reset")
            remaining = headers.get("x-ratelimit-remaining")
            if remaining == "0" and reset:
                return max(1, min(int(reset) - int(time.time()) + 2, 900))
            retry_after = headers.get("retry-after")
            if retry_after:
                return max(1, int(retry_after))
            if status == 403:
                # A genuine permission error, not throttling.
                return None
            return 2 ** attempt
        if status >= 500:
            return 2 ** attempt
        return None

    def paginate(self, path, key=None, per_page=100):
        """Yield items across all pages. `key` unwraps object-style responses."""
        page = 1
        while True:
            joiner = "&" if "?" in path else "?"
            url = "%s%sper_page=%d&page=%d" % (path, joiner, per_page, page)
            status, data = self.request(url)
            if status == 404 or data is None:
                return
            items = data.get(key, []) if key else data
            if not items:
                return
            for item in items:
                yield item
            if len(items) < per_page:
                return
            page += 1

    # ------------------------------------------------------------------ repos

    def list_repos(self, org):
        """Repos visible to this token.

        Installation tokens see /installation/repositories; a PAT does not, so
        fall back to the org listing.
        """
        try:
            status, _ = self.request("/installation/repositories?per_page=1")
        except GitHubError:
            # A PAT gets 403 here -- the endpoint only accepts installation
            # tokens. That is not an error, it just means we take the org
            # listing below. A genuine auth problem resurfaces there.
            status = None

        if status == 200:
            self.log("Listing repositories via the App installation")
            for repo in self.paginate("/installation/repositories", key="repositories"):
                owner = (repo.get("owner") or {}).get("login") or ""
                if not org or owner.lower() == org.lower():
                    yield repo
            return

        if not org:
            raise GitHubError(
                "This token cannot list installation repositories, so an "
                "organization name is required (--org or ORG_NAME)."
            )
        self.log("Listing repositories via /orgs/%s/repos" % org)
        for repo in self.paginate("/orgs/%s/repos?type=all" % org):
            yield repo

    def sbom(self, full_name):
        status, data = self.request("/repos/%s/dependency-graph/sbom" % full_name)
        if status == 404 or not data:
            return None
        return data.get("sbom") or data


# ------------------------------------------------------------------ App auth

def installation_token(app_id, private_key_pem, org):
    """Mint an installation access token from App credentials.

    RS256 signing is done with the openssl binary so the script stays
    dependency-free.
    """
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"iat": now - 60, "exp": now + 540, "iss": str(app_id)}
    signing_input = b".".join(
        [_b64url(json.dumps(part, separators=(",", ":")).encode()) for part in (header, payload)]
    )
    jwt = signing_input + b"." + _b64url(_sign_rs256(signing_input, private_key_pem))

    client = Client(jwt.decode("ascii"))
    status, data = client.request("/orgs/%s/installation" % org)
    if status != 200 or not data:
        raise GitHubError(
            "App %s does not appear to be installed on organization %r" % (app_id, org)
        )

    status, token_data = client.request(
        "/app/installations/%s/access_tokens" % data["id"], method="POST"
    )
    if not token_data or "token" not in token_data:
        raise GitHubError("Could not create an installation access token")
    return token_data["token"]


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def _sign_rs256(data, private_key_pem):
    if isinstance(private_key_pem, str):
        private_key_pem = private_key_pem.encode()

    # openssl needs the key as a file and the payload on stdin. The key is
    # written 0600 into a temp file that is removed before this returns.
    handle, key_path = tempfile.mkstemp(prefix="gh-app-key-", suffix=".pem")
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, "wb") as key_file:
            key_file.write(private_key_pem)
        try:
            result = subprocess.run(
                ["openssl", "dgst", "-sha256", "-sign", key_path, "-binary"],
                input=data,
                capture_output=True,
                check=False,
            )
        except FileNotFoundError:
            raise GitHubError(
                "openssl is required to sign the GitHub App JWT. Either install it "
                "or pass a ready-made token via GITHUB_TOKEN."
            )
    finally:
        try:
            os.unlink(key_path)
        except OSError:
            pass

    if result.returncode != 0:
        raise GitHubError("openssl could not sign with the provided key: %s"
                          % result.stderr.decode("utf-8", "replace")[:300])
    return result.stdout
