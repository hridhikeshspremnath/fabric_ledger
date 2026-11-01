"""HTTPS fetching with a host allowlist and size caps. Download only."""
import json
import urllib.error
import urllib.request
from typing import Any, Protocol
from urllib.parse import urlsplit

from attesta.scoring.errors import FetchError

USER_AGENT = "attesta-scorer/0.1 (+download-only)"
DEFAULT_HOSTS = frozenset({"pypi.org", "files.pythonhosted.org", "registry.npmjs.org"})


class Fetcher(Protocol):
    def get_json(self, url: str) -> Any: ...

    def get_bytes(self, url: str, max_bytes: int) -> bytes: ...


class _AllowlistRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, hosts: frozenset[str]) -> None:
        self._hosts = hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        check_url(newurl, self._hosts)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def check_url(url: str, hosts: frozenset[str]) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https" or (parts.hostname or "") not in hosts:
        raise FetchError(f"URL not allowed: {parts.scheme}://{parts.hostname}")


class UrllibFetcher:
    def __init__(self, hosts: frozenset[str] = DEFAULT_HOSTS, timeout: float = 30.0) -> None:
        self._hosts = hosts
        self._timeout = timeout
        self._opener = urllib.request.build_opener(_AllowlistRedirect(hosts))

    def _open(self, url: str):  # type: ignore[no-untyped-def]
        check_url(url, self._hosts)
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            return self._opener.open(request, timeout=self._timeout)
        except urllib.error.HTTPError as exc:
            raise FetchError(f"HTTP {exc.code} for {url}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise FetchError(f"could not fetch {url}: {exc}") from exc

    def get_json(self, url: str) -> Any:
        with self._open(url) as response:
            raw = response.read(5 * 1024 * 1024 + 1)
        if len(raw) > 5 * 1024 * 1024:
            raise FetchError("metadata response too large")
        try:
            return json.loads(raw)
        except ValueError as exc:
            raise FetchError("registry returned invalid JSON") from exc

    def get_bytes(self, url: str, max_bytes: int) -> bytes:
        chunks: list[bytes] = []
        size = 0
        with self._open(url) as response:
            while True:
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise FetchError(f"download exceeds {max_bytes} bytes")
                chunks.append(chunk)
        return b"".join(chunks)
