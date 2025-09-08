#!/usr/bin/env python3
"""
SUSE Documentation MCP Server - Streamlined Version

A streamlined Model Context Protocol server focused on two core functions:
1) Efficient web search-based discovery of SUSE documentation
2) Reliable content fetching (PDF-first where possible)

Key ideas:
- Domain allowlist for SUSE (SUSE, Rancher, openSUSE)
- PDF-first strategy: if a docs page is HTML, try to discover its PDF link
- Minimal toolset to keep API usage small and predictable
"""

import re
from typing import Any, List, Dict
from urllib.parse import urlparse

import httpx
import urllib3
from mcp.server.fastmcp import FastMCP

# Disable SSL warnings for lab environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize FastMCP
mcp = FastMCP("suse-docs-streamlined")

# === Official domains (SUSE + Rancher + openSUSE) ===
OFFICIAL_SUSE_DOMAINS = {
    # SUSE
    "suse.com",
    "documentation.suse.com",
    "download.suse.com",
    "registry.suse.com",
    "scc.suse.com",              # SUSE Customer Center (auth likely required)
    "releases.suse.com",
    "www.suse.com",

    # Rancher (SUSE)
    "rancher.com",
    "docs.rancher.com",
    "www.rancher.com",

    # openSUSE
    "opensuse.org",
    "en.opensuse.org",
    "doc.opensuse.org",
    "build.opensuse.org",
    "software.opensuse.org",
    "www.opensuse.org",
}

# Subdomain patterns (catch-all convenience)
SUSE_DOMAIN_PATTERNS = [
    r".*\.suse\.com$",
    r".*\.rancher\.com$",
    r".*\.opensuse\.org$",
]

# HTTP defaults
default_headers = {
    "User-Agent": "SUSE Documentation MCP Server/1.0",
    "Accept": "application/json, text/html, application/pdf, */*",
}
timeout = httpx.Timeout(30.0)


def is_official_suse_domain(url: str) -> bool:
    """Return True if URL belongs to an approved SUSE (or related) domain."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]

        if domain in OFFICIAL_SUSE_DOMAINS:
            return True

        for pat in SUSE_DOMAIN_PATTERNS:
            if re.match(pat, domain):
                return True
        return False
    except Exception:
        return False


async def make_request(url: str, method: str = "GET", **kwargs) -> httpx.Response | str:
    """HTTP request helper with clear error strings (never raises)."""
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False, headers=default_headers) as client:
            resp = await client.request(method, url, **kwargs)
        if resp.status_code == 200:
            return resp
        return f"HTTP {resp.status_code}: {resp.text[:200]}"
    except httpx.TimeoutException:
        return "Request timeout"
    except httpx.RequestError as e:
        return f"Request error: {e}"
    except Exception as e:
        return f"Unexpected error: {e}"


def find_pdf_links_in_html(html_text: str, base_url: str) -> List[str]:
    """
    Very lightweight PDF discovery:
    - looks for href="...pdf"
    - returns absolute or relative links as-is (consumer can resolve if needed)
    """
    # naive but effective for docs.suse.com which links direct PDFs
    links = re.findall(r'href=["\']([^"\']+\.pdf)["\']', html_text, flags=re.IGNORECASE)
    # Dedup while preserving order
    seen = set()
    result = []
    for href in links:
        if href not in seen:
            seen.add(href)
            result.append(href)
    return result


@mcp.tool()
async def search_suse_content(
    query: str,
    content_types: List[str] | None = None,
    limit: int = 10
) -> Dict[str, Any]:
    """
    Produce focused search queries for SUSE docs discovery.
    (Use with your WebSearch MCP or a browsing tool.)

    Args:
        query: e.g., "SLES 15 SP6 cockpit enablement", "Rancher 2.8 RKE2 install"
        content_types: ["docs", "support", "community", "all"] (default "all")
        limit: how many search results *per* category to aim for

    Returns:
        A JSON payload with suggested queries + workflow steps.
    """
    if content_types is None:
        content_types = ["all"]

    out: Dict[str, Any] = {
        "query": query,
        "documentation_queries": [],
        "support_queries": [],
        "community_queries": [],
        "instructions": "",
        "workflow": [],
        "total_queries": 0,
        "limit": limit,
    }

    # SUSE official docs (primary)
    if "docs" in content_types or "all" in content_types:
        docs_q = [
            f'{query} site:documentation.suse.com',
            f'{query} filetype:pdf site:documentation.suse.com',
            f'{query} site:doc.opensuse.org',
            f'{query} site:docs.rancher.com',
        ]
        for i, q in enumerate(docs_q[:3]):
            out["documentation_queries"].append({
                "query": q,
                "purpose": f"Find official SUSE/Rancher docs for: {query}",
                "expected_domains": ["documentation.suse.com", "doc.opensuse.org", "docs.rancher.com"],
                "content_type": "documentation",
                "priority": i + 1,
            })

    # SUSE “support” / knowledge base: (SCC or product pages often need auth; leave out deep SCC)
    if "support" in content_types or "all" in content_types:
        support_q = [
            f'{query} site:suse.com',
            f'{query} troubleshooting site:suse.com',
            f'{query} error site:suse.com',
        ]
        for i, q in enumerate(support_q[:2]):
            out["support_queries"].append({
                "query": q,
                "purpose": f"Find SUSE product/support pages for: {query}",
                "expected_domains": ["suse.com"],
                "content_type": "support",
                "priority": i + 1,
            })

    # Community/openSUSE (often helpful for edge cases)
    if "community" in content_types or "all" in content_types:
        comm_q = [
            f'{query} site:en.opensuse.org',
            f'{query} site:doc.opensuse.org',
        ]
        for i, q in enumerate(comm_q[:2]):
            out["community_queries"].append({
                "query": q,
                "purpose": f"Find openSUSE community docs related to: {query}",
                "expected_domains": ["en.opensuse.org", "doc.opensuse.org"],
                "content_type": "community",
                "priority": i + 1,
            })

    total = len(out["documentation_queries"]) + len(out["support_queries"]) + len(out["community_queries"])
    out["total_queries"] = total

    out["instructions"] = """
Use these queries with your web search MCP:
1) Execute each query and collect top results (respect 'limit').
2) Keep only official SUSE/Rancher/openSUSE domains.
3) Prefer documentation.suse.com and doc.opensuse.org for authoritative docs.
4) Pass chosen URLs to fetch_suse_content() to retrieve content (PDF-first).
"""

    out["workflow"] = [
        f"1) Run {total} searches from the lists above.",
        "2) Filter to official SUSE/Rancher/openSUSE domains.",
        "3) Categorize results (docs/support/community).",
        "4) For each relevant doc URL, call fetch_suse_content(url).",
        "5) If HTML returns a login wall or JS-only shell, discover PDF link and re-fetch.",
    ]
    return out


@mcp.tool()
async def fetch_suse_content(url: str, format_preference: str = "auto") -> str:
    """
    Fetch SUSE documentation content.

    Strategy:
      - Validate domain.
      - If PDF requested or auto: try direct .pdf; if HTML, discover .pdf links in-page.
      - If still HTML: return preview + headers and advise to use the PDF when available.

    Args:
        url: target URL on SUSE/Rancher/openSUSE domains
        format_preference: "pdf", "html", or "auto" (default)

    Returns:
        A short status string with content preview / metadata.
    """
    if not is_official_suse_domain(url):
        return f"Error: URL must be an official SUSE/Rancher/openSUSE domain. Got: {url}"

    # 1) If the caller passes a PDF directly
    if url.lower().endswith(".pdf") and format_preference in ("auto", "pdf"):
        resp = await make_request(url)
        if isinstance(resp, str):
            return f"ERROR: {resp}"
        ctype = resp.headers.get("content-type", "").lower()
        if "pdf" in ctype:
            return (
                "SUCCESS: PDF fetched\n"
                f"URL: {url}\n"
                f"Content-Type: {ctype}\n"
                f"Size: {len(resp.content):,} bytes\n"
                "Note: parse with a PDF library downstream."
            )
        # Fallback if server mislabeled content
        return f"INFO: Non-PDF content-type for .pdf URL ({ctype}). Size={len(resp.content):,} bytes"

    # 2) Fetch HTML (either requested or as part of auto)
    if format_preference in ("auto", "html"):
        resp = await make_request(url)
        if isinstance(resp, str):
            return f"ERROR: {resp}"

        ctype = resp.headers.get("content-type", "").lower()
        text = resp.text if "html" in ctype or "xml" in ctype or ctype == "" else ""

        # Try to discover a PDF link in the HTML page (common on documentation.suse.com)
        pdf_links = find_pdf_links_in_html(text, url) if text else []

        if format_preference == "auto" and pdf_links:
            # Pick the first discovered PDF
            pdf_url = pdf_links[0]
            # Resolve relative links naively if needed
            if pdf_url.startswith("/"):
                parsed = urlparse(url)
                pdf_url = f"{parsed.scheme}://{parsed.netloc}{pdf_url}"

            pdf_resp = await make_request(pdf_url)
            if isinstance(pdf_resp, str):
                # Couldn’t fetch PDF; return HTML preview at least
                preview = text[:2000] if text else ""
                return (
                    "INFO: HTML fetched; PDF link discovered but fetch failed\n"
                    f"URL: {url}\n"
                    f"PDF URL attempted: {pdf_links[0]}\n"
                    f"HTML Content-Type: {ctype}\n"
                    f"HTML length: {len(text):,}\n"
                    f"Preview:\n{preview}{'...[truncated]' if len(text) > 2000 else ''}"
                )
            pdf_ctype = pdf_resp.headers.get("content-type", "").lower()
            if "pdf" in pdf_ctype:
                return (
                    "SUCCESS: PDF discovered & fetched\n"
                    f"Source HTML: {url}\n"
                    f"PDF URL: {pdf_url}\n"
                    f"PDF Content-Type: {pdf_ctype}\n"
                    f"PDF Size: {len(pdf_resp.content):,} bytes\n"
                    "Note: parse with a PDF library downstream."
                )

        # If no PDF found or user insisted on HTML
        preview = text[:2000] if text else ""
        return (
            f"{'SUCCESS' if text else 'INFO'}: HTML fetched\n"
            f"URL: {url}\n"
            f"Content-Type: {ctype}\n"
            f"Length: {len(text):,}\n"
            f"{'Preview:\\n' + preview + ('...[truncated]' if len(text) > 2000 else '') if text else ''}"
        )

    return "Error: Unable to access content in requested format"


if __name__ == "__main__":
    mcp.run()
