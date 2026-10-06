"""Discovery-only bridge for official FLOP pages linking to flop-labs GitHub.

The Radar already fetches trusted FLOP-hosted HTML pages.  This module only
preserves selected href values that are already present in those fetched pages;
it never follows, fetches, clones, executes, or otherwise dereferences a GitHub
target.  Source fetch/redirect allowlists remain unchanged.
"""
from __future__ import annotations

from html.parser import HTMLParser
from types import ModuleType
from urllib.parse import unquote, urljoin, urlparse

_FLOP_PAGE_HOSTS = frozenset({"flop.finance", "www.flop.finance"})
_GITHUB_HOST = "github.com"
_GITHUB_OWNER_PREFIX = "/flop-labs/"


class _FlopLabsGithubLinks(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        href = next((value for key, value in attrs if key.lower() == "href"), None)
        if not href:
            return
        absolute = urljoin(self.base_url, href)
        try:
            parsed = urlparse(absolute)
            port = parsed.port
        except ValueError:
            return
        if (
            parsed.scheme != "https"
            or parsed.hostname != _GITHUB_HOST
            or parsed.username is not None
            or parsed.password is not None
            or port not in {None, 443}
            or not parsed.path.startswith(_GITHUB_OWNER_PREFIX)
        ):
            return

        # Require a real repository segment and reject traversal/backslash forms
        # before preserving the href as evidence. The Radar still never follows it.
        decoded_path = unquote(parsed.path)
        segments = decoded_path.split("/")
        if (
            len(segments) < 3
            or segments[1] != "flop-labs"
            or not segments[2]
            or "\\" in decoded_path
            or any(segment in {".", ".."} for segment in segments)
        ):
            return
        self.links.add(parsed._replace(query="", fragment="").geturl())


def install(radar_core: ModuleType) -> None:
    """Extend Radar link evidence exactly once without widening fetch authority."""
    if getattr(radar_core, "_FLOP_LABS_GITHUB_LINK_DISCOVERY_INSTALLED", False):
        return

    original = radar_core._official_interest_links

    def official_interest_links(html: str, source: object) -> list[str]:
        links = set(original(html, source))
        if getattr(source, "kind", None) != "html":
            return sorted(links)
        try:
            source_url = urlparse(str(getattr(source, "url", "")))
            source_port = source_url.port
        except ValueError:
            return sorted(links)
        allowed_hosts = frozenset(
            str(host).lower()
            for host in getattr(source, "allowed_hosts", ())
            if isinstance(host, str)
        )
        if (
            source_url.scheme != "https"
            or source_url.hostname not in _FLOP_PAGE_HOSTS
            or source_url.username is not None
            or source_url.password is not None
            or source_port not in {None, 443}
            or not allowed_hosts
            or not allowed_hosts.issubset(_FLOP_PAGE_HOSTS)
        ):
            return sorted(links)

        parser = _FlopLabsGithubLinks(str(getattr(source, "url")))
        parser.feed(html)
        parser.close()
        links.update(parser.links)
        return sorted(links)

    radar_core._official_interest_links = official_interest_links
    radar_core._FLOP_LABS_GITHUB_LINK_DISCOVERY_INSTALLED = True
