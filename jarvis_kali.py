Fetched content from: https://raw.githubusercontent.com/praisebenard/Jarvis/master/jarvis.py
Size: 454145 bytes

Content:
---

from html import unescape
from html.parser import HTMLParser
from types import SimpleNamespace
from urllib.parse import quote, quote_from_bytes, unquote, urljoin, urlparse, urlsplit, urlunsplit
import hashlib
import ipaddress
import os
import secrets
import time
import requests

session = requests.Session()
session.headers.update({
    "User-Agent": "JARVIS-Lab-Assistant/1.0"
})
from pathlib import Path
import re
import json
from datetime import datetime, timezone


PROJECT_DIR = Path(__file__).resolve().parent
SCOPE_FILE = PROJECT_DIR / "scope.txt"
REPORTS_DIR = Path("reports")
DEFAULT_AUDIT_REQUEST_BUDGET = 25
MAX_AUDIT_REQUEST_BUDGET = 100
DEFAULT_AUDIT_REQUEST_INTERVAL_SECONDS = 0.25
MAX_REDIRECT_HOPS = 5
_ACTIVE_AUDIT_REQUEST_BUDGET = None
_REPORT_DISPLAY_ALIASES = {}
_HTTP_SESSIONS = {}


def load_scope():
    if not SCOPE_FILE.exists():
        return []

    try:
        lines = SCOPE_FILE.read_text().splitlines()
    except OSError:
        return []

    rules = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2 or parts[0] not in {"ALLOW", "EXCLUDE"}:
            return []
        rule = _parse_scope_url(parts[1], require_explicit_port=True, for_rule=True)
        if rule is None:
            return []
        rule["effect"] = parts[0]
        rules.append(rule)
    return rules


def _parse_scope_url(value, require_explicit_port=False, for_rule=False):
    """Parse and canonicalize a URL for strict scope-policy matching."""
    if not isinstance(value, str) or not value or any(char.isspace() or ord(char) < 32 for char in value):
        return None
    if "\\" in value or re.search(r"%(?![0-9a-fA-F]{2})", value):
        return None
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or not parsed.netloc:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        if for_rule and ("?" in value or "#" in value):
            return None
        if for_rule and not parsed.path:
            return None
        hostname = parsed.hostname
        if not hostname or "%" in hostname:
            return None
        if ":" in hostname:
            hostname = ipaddress.IPv6Address(hostname).compressed
        else:
            hostname = hostname.rstrip(".").encode("idna").decode("ascii").lower()
            if not hostname or len(hostname) > 253:
                return None
            if any(
                not label
                or len(label) > 63
                or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
                for label in hostname.split(".")
            ):
                return None

        explicit_port = "]:" in parsed.netloc if ":" in hostname else ":" in parsed.netloc
        port = parsed.port
        if explicit_port:
            port_text = parsed.netloc.rsplit(":", 1)[1]
            if not port_text.isdigit():
                return None
        if require_explicit_port and (not explicit_port or port is None):
            return None
        if port is None:
            port = 443 if scheme == "https" else 80
        if not 1 <= port <= 65535:
            return None

        raw_path = parsed.path or "/"
        wildcard = False
        if for_rule:
            wildcard = raw_path.endswith("/*")
            if "*" in raw_path and not wildcard:
                return None
        elif "*" in raw_path:
            return None
        if re.search(r"%(?![0-9a-fA-F]{2})", raw_path):
            return None
        path = unquote(raw_path)
        if re.search(r"%(?:2f|5c|2e)", path, re.I) or "\\" in path:
            return None
        if not path.startswith("/") or any(part in {".", ".."} for part in path.split("/")):
            return None
        if any(ord(char) < 32 for char in path):
            return None
        if "//" in path:
            return None

        # Inspect nested encodings for path-boundary characters without using
        # recursively decoded text for scope matching or request construction.
        validation_path = path
        for _ in range(8):
            if re.search(r"%(?:2f|5c|2e)", validation_path, re.I):
                return None
            decoded_validation_path = unquote(validation_path)
            if decoded_validation_path == validation_path:
                break
            validation_path = decoded_validation_path
        else:
            return None

        if wildcard:
            path = path[:-1]
        return {
            "scheme": scheme,
            "host": hostname,
            "port": port,
            "path": path,
            "prefix": wildcard,
        }
    except (ValueError, UnicodeError, ipaddress.AddressValueError):
        return None


def _scope_path_matches(rule, path):
    if not rule["prefix"]:
        return path == rule["path"]
    prefix = rule["path"].rstrip("/")
    return not prefix or path == prefix or path.startswith(prefix + "/")


def check_scope(target, announce=True):
    target = str(target)
    malformed_input = target != target.strip()
    if not malformed_input:
        target = target.strip()
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", target):
        scheme_end = target.find(":")
        target = target[:scheme_end].lower() + target[scheme_end:]
    else:
        target = get_url(target)
    parsed_target = None if malformed_input else _parse_scope_url(target)
    rules = load_scope()
    matching = []
    if parsed_target:
        matching = [
            rule for rule in rules
            if rule["scheme"] == parsed_target["scheme"]
            and rule["host"] == parsed_target["host"]
            and rule["port"] == parsed_target["port"]
        ]
    excluded = any(
        rule["effect"] == "EXCLUDE" and _scope_path_matches(rule, parsed_target["path"])
        for rule in matching
    ) if parsed_target else False
    allowed = not excluded and any(
        rule["effect"] == "ALLOW" and _scope_path_matches(rule, parsed_target["path"])
        for rule in matching
    ) if parsed_target else False

    if allowed:
        if announce:
            print(f"JARVIS: {_render_report_target(target)} is in the authorized scope.")
        return True

    if announce:
        print(f"JARVIS: {_render_report_target(target)} is NOT in the authorized scope.")
        print("JARVIS: I will not test this target.")
    return False


def _authorized_scope_context(url):
    """Return normalized origin and the most-specific matching authorized path root."""
    parsed_url = _parse_scope_url(url)
    if parsed_url is None or not check_scope(url, announce=False):
        raise requests.RequestException("Cannot select an authorized scope for this URL")

    matching_allow_rules = [
        rule for rule in load_scope()
        if rule["effect"] == "ALLOW"
        and rule["scheme"] == parsed_url["scheme"]
        and rule["host"] == parsed_url["host"]
        and rule["port"] == parsed_url["port"]
        and _scope_path_matches(rule, parsed_url["path"])
    ]
    if not matching_allow_rules:
        raise requests.RequestException("Cannot select an authorized scope for this URL")
    target_rule = max(matching_allow_rules, key=lambda rule: len(rule["path"]))
    return (
        parsed_url["scheme"], parsed_url["host"], parsed_url["port"],
        target_rule["path"], target_rule["prefix"],
    )


def _session_for_url(url):
    """Return a session isolated by normalized origin and authorized path root."""
    if not isinstance(session, requests.Session):
        # Keep injected test/client sessions intact; production uses requests.Session.
        return session

    origin = _authorized_scope_context(url)
    if origin in _HTTP_SESSIONS:
        return _HTTP_SESSIONS[origin]

    local_origin = ("http", "127.0.0.1", 80)
    # The process-wide session carries the manually configured bWAPP cookie.
    # Keep it bound to that path root; other loopback applications get their
    # own cookie jars even though they share the same network origin.
    if origin[:3] == local_origin and origin[3].rstrip("/") == "/bWAPP":
        selected = session
    else:
        selected = requests.Session()
        selected.headers.update({"User-Agent": "JARVIS-Lab-Assistant/1.0"})
    _HTTP_SESSIONS[origin] = selected
    return selected


def _hackerone_handle_for_url(url):
    """Return the optional program handle only for an explicitly configured scoped asset."""
    handle = os.environ.get("JARVIS_HACKERONE_HANDLE", "").strip()
    assets_text = os.environ.get("JARVIS_HACKERONE_ASSETS", "")
    if (
        not handle
        or len(handle) > 128
        or any(ord(char) < 33 or ord(char) > 126 for char in handle)
        or not assets_text.strip()
        or not check_scope(url, announce=False)
    ):
        return None

    parsed_target = _parse_scope_url(url)
    if parsed_target is None:
        return None

    asset_rules = []
    for asset_text in assets_text.split(","):
        asset_text = asset_text.strip()
        if not asset_text:
            continue
        rule = _parse_scope_url(
            asset_text,
            require_explicit_port=True,
            for_rule=True,
        )
        if rule is None:
            # Ambiguous opt-in configuration must never cause header forwarding.
            return None
        asset_rules.append(rule)

    if not asset_rules:
        return None
    if any(
        rule["scheme"] == parsed_target["scheme"]
        and rule["host"] == parsed_target["host"]
        and rule["port"] == parsed_target["port"]
        and _scope_path_matches(rule, parsed_target["path"])
        for rule in asset_rules
    ):
        return handle
    return None


def _remove_hackerone_header(headers):
    """Remove session-default copies so only scoped per-request policy adds it."""
    if headers is None:
        return
    try:
        names = list(headers.keys())
        for name in names:
            if isinstance(name, str) and name.casefold() == "x-hackerone-handle":
                del headers[name]
    except (AttributeError, KeyError, TypeError) as exc:
        raise requests.RequestException(
            "Cannot safely sanitize request session headers"
        ) from exc


def _keep_safe_redirect_headers(headers):
    """Keep only explicitly safe caller headers across a scope boundary."""
    if headers is None:
        return
    safe_names = {
        "accept", "accept-encoding", "accept-language", "cache-control",
        "if-match", "if-modified-since", "if-none-match",
        "if-unmodified-since", "user-agent", "x-test-trace",
    }
    try:
        names = list(headers.keys())
        for name in names:
            if not isinstance(name, str) or name.casefold() not in safe_names:
                del headers[name]
    except (AttributeError, KeyError, TypeError) as exc:
        raise requests.RequestException(
            "Cannot safely filter request headers at redirect boundary"
        ) from exc


def _snapshot_http_response_metadata(response):
    """Copy only non-body response metadata needed for local diagnostics."""
    headers = getattr(response, "headers", None)
    header_get = getattr(headers, "get", None)
    try:
        content_type = header_get("Content-Type") if callable(header_get) else None
        location = header_get("Location") if callable(header_get) else None
    except (AttributeError, KeyError, TypeError, ValueError):
        content_type = None
        location = None
    return SimpleNamespace(
        status_code=getattr(response, "status_code", None),
        content_type=content_type,
        location=location,
    )


def _attach_http_response_metadata(response, metadata):
    """Attach detached scalar snapshots without retaining response bodies."""
    response._jarvis_response_metadata = tuple(
        SimpleNamespace(
            status_code=item.status_code,
            content_type=item.content_type,
            location=item.location,
        )
        for item in metadata
    )
    return response


def scoped_get(url, **kwargs):
    if not check_scope(url, announce=False):
        raise requests.RequestException(
            "Request blocked outside authorized scope: "
            f"{_render_report_endpoint(url)}"
        )

    kwargs["allow_redirects"] = False
    caller_headers = dict(kwargs.get("headers") or {})
    caller_headers = {
        name: value for name, value in caller_headers.items()
        if not isinstance(name, str) or name.casefold() != "x-hackerone-handle"
    }
    redirects = 0
    scope_context = _authorized_scope_context(url)
    request_session = _session_for_url(url)
    max_redirects = min(
        getattr(request_session, "max_redirects", MAX_REDIRECT_HOPS),
        MAX_REDIRECT_HOPS,
    )
    response_metadata = []

    while True:
        budget = _ACTIVE_AUDIT_REQUEST_BUDGET
        if budget is not None:
            if budget["used"] >= budget["limit"]:
                budget["exhausted"] = True
                raise requests.RequestException("Audit request budget exhausted")
            minimum_interval = budget.get("minimum_interval", 0)
            previous_request_at = budget.get("last_request_at")
            if minimum_interval > 0 and previous_request_at is not None:
                delay = minimum_interval - (time.monotonic() - previous_request_at)
                if delay > 0:
                    time.sleep(delay)
            budget["used"] += 1
            if minimum_interval > 0:
                budget["last_request_at"] = time.monotonic()
        request_kwargs = dict(kwargs)
        request_headers = dict(caller_headers)
        # Requests merges Session.headers into each PreparedRequest. Suppress
        # any caller-installed default before adding an authorized per-request
        # value, and repeat this after every redirect/session selection.
        _remove_hackerone_header(getattr(request_session, "headers", None))
        hackerone_handle = _hackerone_handle_for_url(url)
        if hackerone_handle:
            request_headers["X-HackerOne-Handle"] = hackerone_handle
        if request_headers or "headers" in kwargs:
            request_kwargs["headers"] = request_headers
        response = request_session.get(url, **request_kwargs)
        response_metadata.append(_snapshot_http_response_metadata(response))
        # Keep the current hop's detached snapshot even if policy later blocks
        # this redirect and closes the live response.
        _attach_http_response_metadata(response, response_metadata)

        if not response.is_redirect:
            return response

        location = response_metadata[-1].location
        if not location:
            return response

        try:
            redirect_url = urljoin(response.url or url, location)
        except (TypeError, ValueError):
            response.close()
            raise requests.RequestException("Malformed redirect destination")
        if not check_scope(redirect_url, announce=False):
            response.close()
            raise requests.RequestException(
                "Redirect blocked outside authorized scope: "
                f"{_render_report_endpoint(redirect_url)}"
            )

        try:
            redirect_scope_context = _authorized_scope_context(redirect_url)
        except requests.RequestException:
            response.close()
            raise

        if redirect_scope_context != scope_context:
            # Active scope does not mean arbitrary caller headers are safe to
            # reuse at a different origin or independently authorized path root.
            try:
                _keep_safe_redirect_headers(caller_headers)
                _keep_safe_redirect_headers(getattr(request_session, "headers", None))
            except requests.RequestException:
                response.close()
                raise
            kwargs.pop("cookies", None)
            kwargs.pop("auth", None)

        if redirects >= max_redirects:
            response.close()
            raise requests.TooManyRedirects(
                f"Exceeded {max_redirects} redirects", response=response
            )

        response.close()
        url = redirect_url
        scope_context = redirect_scope_context
        request_session = _session_for_url(url)
        redirects += 1


def _get_audit_page_data(url, response_cache):
    """Return a per-audit response snapshot keyed by the exact requested URL."""
    if not check_scope(url, announce=False):
        raise requests.RequestException(
            "Request blocked outside authorized scope: "
            f"{_render_report_endpoint(url)}"
        )

    if url in response_cache:
        return response_cache[url]

    response = scoped_get(
        url,
        timeout=10,
        headers={"User-Agent": "JARVIS-Lab-Assistant/1.0"},
    )
    try:
        response_headers = getattr(response, "headers", None)
        headers_available = (
            response_headers is not None
            and callable(getattr(response_headers, "get", None))
            and callable(getattr(response_headers, "__contains__", None))
        )
        try:
            copied_headers = (
                requests.structures.CaseInsensitiveDict(response_headers)
                if headers_available else None
            )
        except (AttributeError, TypeError, ValueError):
            copied_headers = None
        response_metadata = getattr(response, "_jarvis_response_metadata", None)
        if response_metadata is None:
            response_metadata = (_snapshot_http_response_metadata(response),)
        response_metadata = tuple(
            SimpleNamespace(
                status_code=item.status_code,
                content_type=item.content_type,
                location=item.location,
            )
            for item in response_metadata
        )
        page_data = SimpleNamespace(
            requested_url=url,
            final_url=response.url,
            url=response.url,
            status_code=response.status_code,
            response_metadata=response_metadata,
            headers=copied_headers,
            text=response.text,
        )
    finally:
        response.close()

    response_cache[url] = page_data
    return page_data


def show_scope():
    rules = load_scope()

    print("JARVIS: Authorized targets:")

    if not rules:
        print("  (none)")
        return

    for rule in rules:
        host = f"[{rule['host']}]" if ":" in rule["host"] else rule["host"]
        path = rule["path"] + ("*" if rule["prefix"] else "")
        print(f"  - {rule['effect']} {rule['scheme']}://{host}:{rule['port']}{path}")


def get_url(target):
    if re.match(r"^https?://", target, re.I):
        return target

    if target.lower().startswith(("127.0.0.1/", "localhost/")):
        return "http://" + target

    if target.lower() in ("127.0.0.1", "localhost"):
        return "http://" + target

    return "https://" + target


def _classify_reflection_context(response_text, marker):
    """Return best-effort HTML contexts containing a marker, without snippets."""
    if not isinstance(response_text, str):
        return None

    event_handler_attributes = {
        "onabort", "onauxclick", "onbeforeinput", "onbeforetoggle",
        "onbeforeunload", "onblur",
        "oncancel", "oncanplay", "oncanplaythrough", "onchange", "onclick",
        "onclose", "oncontextmenu", "oncopy", "oncuechange", "oncut",
        "ondblclick", "ondrag", "ondragend", "ondragenter", "ondragleave",
        "ondragover", "ondragstart", "ondrop", "ondurationchange", "onemptied",
        "onended", "onerror", "onfocus", "onformdata", "oninput", "oninvalid",
        "onkeydown", "onkeypress", "onkeyup", "onload", "onloadeddata",
        "onloadedmetadata", "onloadstart", "onmessage", "onmousedown",
        "onmouseenter", "onmouseleave", "onmousemove", "onmouseout", "onmouseover",
        "onmouseup", "onpaste", "onpause", "onplay", "onplaying", "onprogress",
        "onratechange", "onreset", "onresize", "onscroll", "onseeked", "onseeking",
        "onselect", "onstalled", "onsubmit", "onsuspend", "ontimeupdate", "ontoggle",
        "onvolumechange", "onwaiting", "onwheel", "onpointercancel", "onpointerdown",
        "onpointerenter", "onpointerleave", "onpointermove", "onpointerout",
        "onpointerover", "onpointerup", "ontouchstart", "ontouchmove", "ontouchend",
        "ontouchcancel", "onanimationcancel", "onanimationend", "onanimationiteration",
        "onanimationstart", "ontransitioncancel", "ontransitionend", "ontransitionrun",
        "ontransitionstart",
    }

    malformed_check_text = response_text if marker in response_text else unescape(response_text)
    if re.search(
        r"<[A-Za-z][^>]*" + re.escape(marker) + r"[^>]*$",
        malformed_check_text,
        re.S,
    ):
        return "HTML context ambiguous"

    contexts = set()

    class MarkerContextParser(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.raw_text_tag = None

        def handle_starttag(self, tag, attrs):
            tag = tag.lower()
            for name, value in attrs:
                if value is not None and marker in value:
                    if name and name.lower() in event_handler_attributes:
                        contexts.add("event-handler attribute")
                    else:
                        contexts.add("HTML attribute")
            if tag in {"script", "style"}:
                self.raw_text_tag = tag

        def handle_startendtag(self, tag, attrs):
            self.handle_starttag(tag, attrs)
            if tag.lower() in {"script", "style"}:
                self.raw_text_tag = None

        def handle_endtag(self, tag):
            if tag.lower() == self.raw_text_tag:
                self.raw_text_tag = None

        def handle_data(self, data):
            if marker not in data:
                return
            if self.raw_text_tag == "script":
                contexts.add("script element")
            elif self.raw_text_tag == "style":
                contexts.add("style element")
            else:
                contexts.add("HTML text")

        def handle_comment(self, data):
            if marker in data:
                contexts.add("HTML comment")

    parse_failed = False
    try:
        parser = MarkerContextParser()
        parser.feed(response_text)
        parser.close()
    except Exception:
        parse_failed = True

    if not contexts and marker in response_text:
        contexts.add("HTML context ambiguous" if parse_failed else "unclassified HTML")
    if not contexts:
        return None

    if marker not in response_text:
        contexts = {f"{context} (HTML character references decoded)" for context in contexts}
    if parse_failed:
        contexts.add("HTML context ambiguous")
    return "; ".join(sorted(contexts))


def check_reflection(url, parameter, enabled=False):
    if not enabled:
        print("  [SKIPPED] Active reflection checks require explicit opt-in.")
        return False

    marker = "JARVIS_TEST_12345"

    parsed_url = urlsplit(url)
    query_items = parsed_url.query.split("&") if parsed_url.query else []
    replaced = False
    updated_items = []
    for item in query_items:
        name, separator, value = item.partition("=")
        if name == parameter:
            updated_items.append(f"{name}={marker}")
            replaced = True
        else:
            updated_items.append(item)
    if not replaced:
        updated_items.append(f"{parameter}={marker}")
    request_url = urlunsplit((
        parsed_url.scheme,
        parsed_url.netloc,
        parsed_url.path,
        "&".join(updated_items),
        parsed_url.fragment,
    ))

    try:
        response = scoped_get(
            request_url,
            timeout=10,
            headers={"User-Agent": "JARVIS-Lab-Assistant/1.0"}
        )
        try:
            reflection_context = _classify_reflection_context(response.text, marker)
            if reflection_context:
                safe_parameter = _safe_report_parameter_name(parameter)
                print(
                    f"  [POTENTIAL] Parameter '{safe_parameter}' is reflected "
                    f"in {reflection_context}."
                )

                record_candidate(
                    url,
                    "Reflected Input",
                    "Potential",
                    f"Parameter '{parameter}' reflected the harmless JARVIS test marker.",
                    f"Marker: {marker}\nTest URL: {_render_report_endpoint(response.url)}\n"
                    f"HTTP status: {response.status_code}\n"
                    f"Reflection context: {reflection_context}\n"
                    "Context classification is best-effort HTML parsing; malformed markup or browser parsing may differ. "
                    "Browser execution was not assessed.",
                    observation_confidence="Confirmed observation: test marker appeared in response text",
                    testing_context=(
                        f"GET parameter: {parameter}; harmless marker only; "
                        "no exploit payload sent; HTML context classification is evidence only."
                    ),
                    observed_evidence=(
                        "The harmless JARVIS marker appeared in the HTTP response text.\n"
                        f"HTTP status: {response.status_code}\n"
                        f"Best-effort HTML context: {reflection_context}"
                    ),
                    evidence_source="JARVIS active GET reflection check",
                    evidence_endpoint=response.url,
                    scanner_interpretation=(
                        f"Reflection in {reflection_context} is a potential output-handling review signal; "
                        "it does not establish script execution or a vulnerability."
                    ),
                    validation_limitations=(
                        "The response body was not saved. Browser execution, exploitability, and impact were not tested."
                    ),
                    structured_test_result={
                        "schema_version": 1,
                        "method": "scoped_get",
                        "test_type": "harmless_reflection_marker",
                        "observation": "marker_reflected",
                        "requested_endpoint": request_url,
                        "final_response_endpoint": response.url,
                        "response_origin": "fresh",
                        "evidence_completeness": "complete",
                        "not_established": ["browser_execution", "exploitability", "impact"],
                    },
                )

                return True

            print(f"  [OK] Parameter '{_safe_report_parameter_name(parameter)}' was not reflected.")
            return False
        finally:
            response.close()
    except requests.RequestException as e:
        budget = _ACTIVE_AUDIT_REQUEST_BUDGET
        if budget is not None and budget["exhausted"]:
            raise
        print(
            f"  [ERROR] Could not test parameter "
            f"'{_safe_report_parameter_name(parameter)}' at "
            f"{_render_report_endpoint(url)} ({type(e).__name__})."
        )
        return False





# ---------------------------------------------------------------------------
# SSRF probing (active)
# ---------------------------------------------------------------------------

_SSRF_PAYLOADS = [
    ("AWS metadata",    "http://169.254.169.254/latest/meta-data/"),
    ("localhost HTTP",  "http://127.0.0.1/"),
    ("localhost HTTPS", "https://127.0.0.1/"),
    ("internal DNS",    "http://internal.invalid/"),
]

_SSRF_RESPONSE_SIGNALS = [
    "ami-id", "instance-id", "local-ipv4",
    "root:x:0:0",
    "localhost",
    "127.0.0.1",
    "169.254.",
    "<title>",
]

_SSRF_REDIRECT_PARAM_NAMES = {
    "url", "uri", "redirect", "redirect_url", "redirect_uri",
    "next", "return", "returnto", "return_to", "goto", "target",
    "dest", "destination", "redir", "continue", "forward",
    "callback", "fetch", "load", "src", "source", "endpoint",
    "proxy", "request", "path",
}


def check_ssrf(url, parameter, enabled=False):
    """
    Probe `parameter` for SSRF by injecting internal/metadata URLs.
    Only runs when enabled=True (--active opt-in required).
    Returns True if any signal was observed.
    """
    if not enabled:
        return False

    if parameter.lower() not in _SSRF_REDIRECT_PARAM_NAMES:
        return False

    safe_parameter = _safe_report_parameter_name(parameter)
    found = False

    for label, payload in _SSRF_PAYLOADS:
        parsed_url = urlsplit(url)
        query_items = parsed_url.query.split("&") if parsed_url.query else []
        replaced = False
        updated_items = []

        for item in query_items:
            name, separator, value = item.partition("=")
            if name == parameter:
                updated_items.append(f"{name}={quote(payload, safe='')}")
                replaced = True
            else:
                updated_items.append(item)

        if not replaced:
            updated_items.append(f"{parameter}={quote(payload, safe='')}")

        request_url = urlunsplit((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            "&".join(updated_items),
            "",
        ))

        try:
            response = scoped_get(
                request_url,
                timeout=10,
                allow_redirects=False,
                headers={"User-Agent": "JARVIS-Lab-Assistant/1.0"},
            )

            try:
                location = response.headers.get("Location", "")
                body_lower = response.text[:4096].lower()

                redirect_hit = (
                    response.status_code in (301, 302, 303, 307, 308)
                    and any(
                        s in location
                        for s in ("169.254.", "127.0.0.1", "internal.")
                    )
                )
                body_hit = any(s in body_lower for s in _SSRF_RESPONSE_SIGNALS)

                if redirect_hit or body_hit:
                    signal = (
                        f"redirect to {location}"
                        if redirect_hit
                        else "response body matched internal content signal"
                    )
                    print(
                        f"  [POTENTIAL SSRF] Parameter '{safe_parameter}' "
                        f"({label}): {signal}"
                    )
                    record_candidate(
                        url,
                        "SSRF",
                        "High",
                        (
                            f"Parameter '{parameter}' may have caused the server "
                            f"to fetch an internal resource ({label})."
                        ),
                        (
                            f"Payload: {payload}\n"
                            f"Test URL: {_render_report_endpoint(request_url)}\n"
                            f"HTTP status: {response.status_code}\n"
                            f"Signal: {signal}\n"
                            "This is a heuristic observation. "
                            "Confirm by checking whether the server actually "
                            "fetched the payload URL."
                        ),
                        observation_confidence=(
                            "Heuristic candidate: redirect or body signal observed"
                        ),
                        testing_context=(
                            f"GET parameter: {parameter}; "
                            f"SSRF payload injected: {payload}; "
                            "allow_redirects=False."
                        ),
                        observed_evidence=(
                            f"HTTP status: {response.status_code}\n"
                            f"Location header: {location or 'none'}\n"
                            f"Body signal: {'yes' if body_hit else 'no'}"
                        ),
                        evidence_source="JARVIS active SSRF probe",
                        evidence_endpoint=response.url,
                        scanner_interpretation=(
                            "A redirect to or body content matching an internal "
                            "address was observed. This does not confirm the "
                            "server made an outbound request; manual verification "
                            "is required."
                        ),
                        validation_limitations=(
                            "No out-of-band callback was used. "
                            "Impact and exploitability were not assessed."
                        ),
                        structured_test_result={
                            "schema_version": 1,
                            "method": "scoped_get",
                            "test_type": "ssrf_internal_payload",
                            "observation": "redirect_or_body_signal",
                            "payload": payload,
                            "requested_endpoint": request_url,
                            "final_response_endpoint": response.url,
                            "response_origin": "fresh",
                            "evidence_completeness": "partial",
                            "not_established": [
                                "server_side_fetch_confirmed",
                                "data_exfiltration",
                                "impact",
                            ],
                        },
                    )
                    found = True
                else:
                    print(
                        f"  [OK] '{safe_parameter}' â€” "
                        f"no SSRF signal for {label} "
                        f"(status {response.status_code})"
                    )
            finally:
                response.close()

        except requests.RequestException as e:
            budget = _ACTIVE_AUDIT_REQUEST_BUDGET
            if budget is not None and budget["exhausted"]:
                raise
            print(
                f"  [ERROR] SSRF probe failed for '{safe_parameter}' "
                f"({label}): {type(e).__name__}"
            )

    return found


# ---------------------------------------------------------------------------
# Open redirect confirmation (active)
# ---------------------------------------------------------------------------

_OPEN_REDIRECT_CANARY = "https://redirect-canary.jarvis.invalid/"

_OPEN_REDIRECT_PARAM_NAMES = {
    "url", "uri", "redirect", "redirect_url", "redirect_uri",
    "next", "return", "returnto", "return_to", "goto", "target",
    "dest", "destination", "redir", "location", "continue",
    "forward", "callback",
}


def check_open_redirect(url, parameter, enabled=False):
    """
    Confirm whether `parameter` causes an open redirect to an external URL.
    Only runs when enabled=True (--active opt-in required).
    Returns True if a redirect to the canary was observed.
    """
    if not enabled:
        return False

    if parameter.lower() not in _OPEN_REDIRECT_PARAM_NAMES:
        return False

    safe_parameter = _safe_report_parameter_name(parameter)

    parsed_url = urlsplit(url)
    query_items = parsed_url.query.split("&") if parsed_url.query else []
    replaced = False
    updated_items = []

    for item in query_items:
        name, separator, value = item.partition("=")
        if name == parameter:
            updated_items.append(
                f"{name}={quote(_OPEN_REDIRECT_CANARY, safe='')}"
            )
            replaced = True
        else:
            updated_items.append(item)

    if not replaced:
        updated_items.append(
            f"{parameter}={quote(_OPEN_REDIRECT_CANARY, safe='')}"
        )

    request_url = urlunsplit((
        parsed_url.scheme,
        parsed_url.netloc,
        parsed_url.path,
        "&".join(updated_items),
        "",
    ))

    try:
        response = scoped_get(
            request_url,
            timeout=10,
            allow_redirects=False,
            headers={"User-Agent": "JARVIS-Lab-Assistant/1.0"},
        )

        try:
            location = response.headers.get("Location", "")
            is_redirect = response.status_code in (301, 302, 303, 307, 308)
            canary_hit  = _OPEN_REDIRECT_CANARY.rstrip("/") in location

            if is_redirect and canary_hit:
                print(
                    f"  [OPEN REDIRECT] Parameter '{safe_parameter}' "
                    f"redirected to canary: {location}"
                )
                record_candidate(
                    url,
                    "Open Redirect",
                    "Medium",
                    (
                        f"Parameter '{parameter}' caused the server to redirect "
                        "to an attacker-controlled URL."
                    ),
                    (
                        f"Canary payload: {_OPEN_REDIRECT_CANARY}\n"
                        f"Test URL: {_render_report_endpoint(request_url)}\n"
                        f"HTTP status: {response.status_code}\n"
                        f"Location header: {location}\n"
                        "The server issued a redirect to the injected external URL."
                    ),
                    observation_confidence=(
                        "Confirmed observation: redirect to canary URL observed"
                    ),
                    testing_context=(
                        f"GET parameter: {parameter}; "
                        f"canary URL injected: {_OPEN_REDIRECT_CANARY}; "
                        "allow_redirects=False."
                    ),
                    observed_evidence=(
                        f"HTTP status: {response.status_code}\n"
                        f"Location header: {location}"
                    ),
                    evidence_source="JARVIS active open-redirect probe",
                    evidence_endpoint=response.url,
                    scanner_interpretation=(
                        "The server redirected to the injected canary URL. "
                        "This is a strong signal of an open redirect. "
                        "Verify the program considers open redirects in scope."
                    ),
                    validation_limitations=(
                        "The canary domain does not resolve. "
                        "Phishing or token-theft impact was not demonstrated."
                    ),
                    structured_test_result={
                        "schema_version": 1,
                        "method": "scoped_get",
                        "test_type": "open_redirect_canary",
                        "observation": "redirect_to_canary",
                        "canary": _OPEN_REDIRECT_CANARY,
                        "requested_endpoint": request_url,
                        "final_response_endpoint": response.url,
                        "response_origin": "fresh",
                        "evidence_completeness": "complete",
                        "not_established": ["phishing_impact", "token_theft"],
                    },
                )
                return True

            print(
                f"  [OK] '{safe_parameter}' â€” no redirect to canary "
                f"(status {response.status_code})"
            )
            return False

        finally:
            response.close()

    except requests.RequestException as e:
        budget = _ACTIVE_AUDIT_REQUEST_BUDGET
        if budget is not None and budget["exhausted"]:
            raise
        print(
            f"  [ERROR] Open redirect probe failed for "
            f"'{safe_parameter}': {type(e).__name__}"
        )
        return False


# ---------------------------------------------------------------------------
# Cookie security checks (passive)
# ---------------------------------------------------------------------------

def check_cookies(response):
    """
    Inspect Set-Cookie headers for missing security flags.
    Passive â€” no requests sent.
    Returns list of result dicts; calls record_candidate for each issue found.

    Missing HttpOnly  -> JS can read the cookie (session hijacking risk)
    Missing Secure    -> cookie sent over plain HTTP
    Missing SameSite  -> CSRF risk
    SameSite=None     -> cross-site requests allowed (check Secure is set too)
    """
    results = []
    cookie_headers = [
        v for k, v in response.headers.items()
        if k.lower() == "set-cookie"
    ]

    if not cookie_headers:
        return results

    target_url = response.url

    for raw in cookie_headers:
        parts  = [p.strip() for p in raw.split(";")]
        name   = parts[0].split("=")[0].strip() if parts else "unknown"
        flags  = [p.lower() for p in parts[1:]]
        issues = []

        if not any(f == "httponly" for f in flags):
            issues.append("Missing HttpOnly flag (JavaScript can read this cookie)")

        if not any(f == "secure" for f in flags):
            issues.append("Missing Secure flag (cookie transmitted over HTTP)")

        samesite = next((f for f in flags if f.startswith("samesite")), None)
        if not samesite:
            issues.append("Missing SameSite attribute (CSRF risk)")
        elif samesite == "samesite=none":
            issues.append(
                "SameSite=None (cross-site requests carry this cookie â€” "
                "verify Secure flag is also set)"
            )

        results.append({
            "name":   name,
            "raw":    raw[:200],
            "issues": issues,
            "clean":  len(issues) == 0,
        })

        for issue in issues:
            safe_name = _safe_report_parameter_name(name)
            print(f"  [-] Cookie '{safe_name}': {issue}")
            record_candidate(
                target_url,
                "Insecure Cookie Configuration",
                "Low",
                f"Cookie '{name}': {issue}",
                (
                    f"Cookie name: {name}\n"
                    f"Issue: {issue}\n"
                    f"Raw Set-Cookie (truncated): {raw[:200]}\n"
                    "Missing cookie security flags are accepted findings "
                    "on many HackerOne programs."
                ),
                observation_confidence=(
                    "Confirmed observation: flag absent from Set-Cookie header"
                ),
                testing_context=(
                    "Passive inspection of Set-Cookie response header; "
                    "no requests sent."
                ),
                observed_evidence=(
                    f"Set-Cookie header observed:\n{raw[:200]}"
                ),
                evidence_source="JARVIS passive cookie flag check",
                evidence_endpoint=target_url,
                scanner_interpretation=(
                    f"{issue}. Confirmed from response header, not a heuristic."
                ),
                validation_limitations=(
                    "Exploitability depends on application context and "
                    "program scope. Impact was not demonstrated."
                ),
                structured_test_result={
                    "schema_version": 1,
                    "method": "passive_header_inspection",
                    "test_type": "cookie_flag_check",
                    "observation": "missing_flag",
                    "cookie_name": name,
                    "issue": issue,
                    "evidence_completeness": "complete",
                    "not_established": ["exploitability", "impact"],
                },
            )

    return results


def crawl_local_pages(
    start_url, max_pages=50, response_cache=None, initial_response=None,
    coverage_issues=None,
):
    if response_cache is None:
        response_cache = {}
    if coverage_issues is None:
        coverage_issues = []
    visited = set()
    queue = [start_url]
    pages = []

    def coverage_url(url):
        """Keep useful page identity while dropping credentials and query data."""
        try:
            parsed_url = urlsplit(url)
            hostname = parsed_url.hostname or ""
            if ":" in hostname:
                hostname = f"[{hostname}]"
            if parsed_url.port is not None:
                hostname = f"{hostname}:{parsed_url.port}"
            return urlunsplit((
                parsed_url.scheme,
                hostname,
                parsed_url.path,
                "",
                "",
            ))
        except (TypeError, ValueError):
            return "<unparseable discovered URL>"

    start_parsed = urlparse(start_url)
    allowed_host = start_parsed.hostname
    allowed_path = "/bWAPP/"

    while queue and len(visited) < max_pages:
        current_url = queue.pop(0)

        if current_url in visited:
            continue

        parsed = urlparse(current_url)

        if parsed.hostname != allowed_host:
            continue

        if not parsed.path.startswith(allowed_path):
            continue

        try:
            if initial_response is not None and current_url == start_url:
                if not check_scope(current_url, announce=False):
                    raise requests.RequestException(
                        f"Request blocked outside authorized scope: {current_url}"
                    )
                response = initial_response
                requested_url = response.requested_url
                initial_response = None
            else:
                response = _get_audit_page_data(current_url, response_cache)
                requested_url = current_url
        except requests.RequestException as error:
            budget = _ACTIVE_AUDIT_REQUEST_BUDGET
            if budget is not None and budget["exhausted"]:
                raise

            failed_url = coverage_url(current_url)

            error_text = str(error)
            if error_text.startswith((
                "Request blocked outside authorized scope:",
                "Redirect blocked outside authorized scope:",
            )):
                reason = "scope policy blocked the request or redirect"
            else:
                reason = "request failed; page was not analyzed"
            coverage_issues.append({"url": failed_url, "reason": reason})
            continue

        visited.add(current_url)
        pages.append({
            "requested_url": requested_url,
            "display_url": current_url,
        })

        print(f"  [LOCAL PAGE] {_render_report_endpoint(current_url)}")

        for link_type, full_url, original in discover_links(response):
            if link_type != "LOCAL":
                continue

            link_parsed = urlparse(full_url)

            if (
                link_parsed.hostname == allowed_host
                and link_parsed.path.startswith(allowed_path)
                and full_url not in visited
                and full_url not in queue
            ):
                queue.append(full_url)

    if queue and len(visited) >= max_pages:
        for skipped_url in queue:
            coverage_issues.append({
                "url": coverage_url(skipped_url),
                "reason": "page limit reached; page was not analyzed",
            })

    print(f"JARVIS: Local pages discovered: {len(visited)}")
    return pages


def audit_local_pages(pages, response_cache=None):
    if response_cache is None:
        response_cache = {}
    print()
    print("Local Page Audit:")

    for page in pages:
        requested_url = page["requested_url"]
        display_url = page["display_url"]
        try:
            response = _get_audit_page_data(requested_url, response_cache)

            print(f"  [PAGE] {_render_report_endpoint(display_url)}")
            print(f"    Requested URL: {_render_report_endpoint(requested_url)}")
            print(f"    Status: {response.status_code}")
            print(f"    Final URL: {_render_report_endpoint(response.url)}")
            print(f"    Title: {_escape_report_user_field(get_page_title(response))}")

            parsed = urlparse(response.url)

            if parsed.query:
                print("    GET parameters:")

                for item in parsed.query.split("&"):
                    if "=" in item:
                        name, _value = item.split("=", 1)
                        safe_name = _safe_report_parameter_name(name)
                        print(f"      - {safe_name} = [value omitted]")
                    else:
                        print(f"      - {_safe_report_parameter_name(item)}")
            else:
                print("    GET parameters: None")

        except requests.RequestException as e:
            print(f"  [ERROR] {_render_report_endpoint(display_url)} ({type(e).__name__}).")


def inventory_local_forms(pages, response_cache=None):
    if response_cache is None:
        response_cache = {}
    form_parameters = []

    print()

    for page in pages:
        requested_url = page["requested_url"]
        display_url = page["display_url"]
        try:
            response = _get_audit_page_data(requested_url, response_cache)
        except requests.RequestException as e:
            print(f"  [ERROR] {_render_report_endpoint(display_url)} ({type(e).__name__}).")
            continue

        forms = discover_forms(response)

        if not forms:
            print(f"  [NONE] {_render_report_endpoint(display_url)}")
            continue

        print(f"  [PAGE] {_render_report_endpoint(display_url)}")

        for number, form in enumerate(forms, 1):
            opening = re.search(r"<form\b([^>]*)>", form, re.I | re.S)
            attributes = _html_attributes(opening.group(1)) if opening else {}
            method = _form_method(attributes)

            print(f"    Form {number}: method={_safe_report_parameter_name(method)}")

            for control in _form_control_inventory(form):
                name = control["name"]
                if not name or control["disabled"]:
                    continue
                print(f"      - {_safe_report_parameter_name(name)}")
                form_parameters.append((method, name))
    return form_parameters



def _parse_audit_options(option_text):
    active_checks = False
    request_budget = DEFAULT_AUDIT_REQUEST_BUDGET
    seen_budget = False
    tokens = option_text.split()
    index = 0

    while index < len(tokens):
        token = tokens[index]
        if token == "--active" and not active_checks:
            active_checks = True
            index += 1
        elif token == "--request-budget" and not seen_budget:
            if index + 1 >= len(tokens) or not re.fullmatch(r"[0-9]+", tokens[index + 1]):
                raise ValueError("--request-budget requires a positive integer")
            request_budget = int(tokens[index + 1])
            seen_budget = True
            index += 2
            if not 1 <= request_budget <= MAX_AUDIT_REQUEST_BUDGET:
                raise ValueError(
                    f"request budget must be between 1 and {MAX_AUDIT_REQUEST_BUDGET}"
                )
        else:
            raise ValueError(f"unsupported or duplicate audit option: {token}")

    return active_checks, request_budget


def audit_target(target, active_checks=False, request_budget=DEFAULT_AUDIT_REQUEST_BUDGET):
    if (
        not isinstance(active_checks, bool)
        or isinstance(request_budget, bool)
        or not isinstance(request_budget, int)
        or not 1 <= request_budget <= MAX_AUDIT_REQUEST_BUDGET
    ):
        print(
            "JARVIS: Invalid audit controls. Request budget must be an integer "
            f"between 1 and {MAX_AUDIT_REQUEST_BUDGET}."
        )
        return

    if not check_scope(target):
        return

    url = get_url(target)
    report = []
    report.append(f"Target: {_render_report_endpoint(url)}")

    print()
    print("JARVIS SECURITY AUDIT")
    print("=====================")
    print(f"Target: {_render_report_endpoint(url)}")
    print()

    global _ACTIVE_AUDIT_REQUEST_BUDGET
    previous_budget = _ACTIVE_AUDIT_REQUEST_BUDGET
    budget_state = {
        "limit": request_budget,
        "used": 0,
        "exhausted": False,
        "minimum_interval": DEFAULT_AUDIT_REQUEST_INTERVAL_SECONDS,
        "last_request_at": None,
    }
    _ACTIVE_AUDIT_REQUEST_BUDGET = budget_state
    try:
        response_cache = {}
        response = _get_audit_page_data(url, response_cache)

        print(f"HTTP Status : {response.status_code}")
        print(f"Final URL  : {_render_report_endpoint(response.url)}")
        page_title = _escape_report_user_field(get_page_title(response))
        print(f"Page Title : {page_title}")

        report.append(f"HTTP Status: {response.status_code}")
        report.append(f"Final URL: {_render_report_endpoint(response.url)}")
        report.append(f"Page Title: {page_title}")

        print()
        print("Local Page Discovery:")
        crawl_issues = []
        local_pages = crawl_local_pages(
            response.url,
            response_cache=response_cache,
            initial_response=response,
            coverage_issues=crawl_issues,
        )

        report.append("Local Pages:")
        for page in local_pages:
            report.append(f"  {_render_report_endpoint(page['display_url'])}")

        if crawl_issues:
            report.append("Crawl Coverage: INCOMPLETE")
            for issue in crawl_issues:
                safe_issue_url = _render_report_endpoint(issue["url"])
                safe_reason = _escape_report_header_value(issue["reason"])
                report.append(f"  Not analyzed: {safe_issue_url} â€” {safe_reason}")

        audit_local_pages(local_pages, response_cache)
        form_parameters = inventory_local_forms(local_pages, response_cache)

        print()
        print("Link Discovery:")
        links = discover_links(response)
        print()

        report.append("Links:")
        if links:
            for link_type, full_url, original in links:
                report.append(
                    f"  [{link_type}] {_render_report_endpoint(full_url)}"
                )
        else:
            report.append("  None")

        print("Form Discovery:")
        forms = discover_forms(response)
        print()

        report.append("Forms:")
        if forms:
            for number, form in enumerate(forms, 1):
                for line in _summarize_form(form, response.url):
                    report.append(f"  Form {number}: {line}" if line.startswith("Form:") else f"    {line}")
        else:
            report.append("  None")

        parameters = discover_parameters(response)
        seen_get_parameters = {
            (item["url"].split("#", 1)[0], item["name"])
            for item in parameters
            if item["method"] == "GET" and item.get("url")
        }
        for page in local_pages:
            requested_page_url = page["requested_url"]
            if requested_page_url == response.requested_url:
                continue
            page_response = _get_audit_page_data(requested_page_url, response_cache)
            for item in discover_parameters(page_response):
                if item["method"] != "GET":
                    continue
                key = (item["url"].split("#", 1)[0], item["name"])
                if key not in seen_get_parameters:
                    parameters.append(item)
                    seen_get_parameters.add(key)
        parameter_pairs = [
            (item["method"], item["name"])
            for item in parameters
        ]
        print()

        report_endpoint_variants = {}
        report.append("Parameters:")
        if parameter_pairs:
            for item in parameters:
                method = item["method"]
                name = item["name"]
                if method == "GET" and item.get("url"):
                    report.append(
                        _render_discovered_get_parameter(item, report_endpoint_variants)
                    )
                else:
                    report.append(f"  {method}: {_safe_report_parameter_name(name)}")
        else:
            report.append("  None")
        high_risk_parameters = identify_high_risk_parameters(parameter_pairs)

        print("High-Risk Parameter Checks:")
        if high_risk_parameters:
            for item in high_risk_parameters:
                print(f"  [POTENTIAL HIGH RISK] {_safe_report_parameter_name(item)}")
                record_candidate(
                    url,
                    "High-Risk Input",
                    "",
                    f"JARVIS identified an input that may require deeper security review: {item}",
                    f"Target URL: {url}\nParameter: {item}\n"
                    "Evidence basis: parameter name classification only.",
                    observation_confidence="Heuristic candidate: parameter-name match",
                    testing_context="Observed during authorized-scope page/form inventory; no exploit payload sent.",
                    observed_evidence=(
                        f"The parameter name was present in JARVIS's authorized-scope input inventory: {item}."
                    ),
                    evidence_source="JARVIS page and form inventory",
                    scanner_interpretation=(
                        "A name-based heuristic selected this input for manual review; its behavior was not tested."
                    ),
                    validation_limitations=(
                        "No payload was sent, and no vulnerable behavior or impact was demonstrated."
                    ),
                )
        else:
            print("  None")


        sql_review_parameters = []

        sql_names = {
            "id", "user_id", "uid", "item_id",
            "search", "query", "q", "name",
            "category", "product", "sort", "order"
        }

        for item in parameters:
            method = item["method"]
            name = item["name"]
            if name.lower() in sql_names:
                sql_review_parameters.append((method, name, item.get("url")))

        for method, name in form_parameters:
            if name.lower() in sql_names:
                sql_review_parameters.append((method, name, None))

        sql_review_parameters = list(dict.fromkeys(sql_review_parameters))

        print("SQL Injection Review:")

        report.append("SQL Injection Heuristic Signals:")
        if sql_review_parameters:
            for method, name, endpoint_url in sql_review_parameters:
                print(
                    f"  [HEURISTIC REVIEW] {_safe_report_parameter_name(method)} parameter "
                    f"'{_safe_report_parameter_name(name)}' "
                    "matched a name-based review signal; query handling was not observed."
                )

                endpoint_evidence = (
                    f"Discovered GET endpoint (variant {report_endpoint_variants.get(endpoint_url, 'unknown')}): "
                    f"{_render_report_endpoint(endpoint_url)}\n"
                    if method == "GET" and endpoint_url
                    else "Source: local form inventory; endpoint provenance was not retained.\n"
                )
                report.append(
                    f"  Detected review signal: {_safe_report_parameter_name(method)} parameter "
                    f"'{_safe_report_parameter_name(name)}'\n"
                    f"{endpoint_evidence.rstrip()}\n"
                    "  Basis: parameter-name heuristic only; query handling and source-to-query flow were not observed.\n"
                    "  State: detected for review only; no SQL injection candidate or vulnerability was established."
                )
        else:
            print("  None")
            report.append("  None")
        # --- Cookie security checks (passive) ---
        print("Cookie Security:")
        report.append("Cookie Security:")
        _cookie_results = check_cookies(response)
        if not _cookie_results:
            print("  No Set-Cookie headers observed.")
            report.append("  No Set-Cookie headers observed.")
        else:
            for _c in _cookie_results:
                if _c["clean"]:
                    print(f"  [+] Cookie '{_safe_report_parameter_name(_c['name'])}': all flags present")
                    report.append(f"  [+] Cookie '{_safe_report_parameter_name(_c['name'])}': all flags present")
                else:
                    for _issue in _c["issues"]:
                        report.append(f"  [-] Cookie '{_safe_report_parameter_name(_c['name'])}': {_issue}")
        print()
        report.append("")
        # --- end cookie security checks ---
        if active_checks:
            print(f"Active Reflection Checks (request budget: {request_budget}):")
            report.append(
                f"Active Reflection Checks: opted in; request budget {request_budget}."
            )
            for item in parameters:
                if item["method"] == "GET":
                    check_reflection(item["url"], item["name"], enabled=True)
            # --- SSRF probing ---
            print("Active SSRF Checks:")
            report.append("Active SSRF Checks:")
            for _ssrf_item in parameters:
                if _ssrf_item["method"] == "GET":
                    check_ssrf(_ssrf_item["url"], _ssrf_item["name"], enabled=True)
            # --- Open redirect probing ---
            print("Active Open Redirect Checks:")
            report.append("Active Open Redirect Checks:")
            for _redir_item in parameters:
                if _redir_item["method"] == "GET":
                    check_open_redirect(_redir_item["url"], _redir_item["name"], enabled=True)
        else:
            print("Active Reflection Checks: skipped (explicit --active opt-in required).")
            report.append(
                "Active Reflection Checks: skipped; explicit --active opt-in required."
            )

        print()
        
        review_areas = identify_review_areas(parameter_pairs)

        print("Review Areas:")
        if review_areas:
            for area in review_areas:
                safe_area = _escape_report_user_field(area)
                print(f"  - {safe_area}")
        else:
            print("  None")

        report.append("Review Areas:")
        if review_areas:
            report.append("  Inventory-based review prompts only; these are not vulnerability findings.")
            for area in review_areas:
                report.append(f"  - {_escape_report_user_field(area)}")
        else:
            report.append("  None")

        print("Security Header Observations:")

        headers = check_security_headers(response)

        for item in headers:
            print(f"{item['header']}: {item['status']}")
            if item.get("value") is not None:
                print(f"  Observed value: {item['value']}")

        print()
        report.append("Security Header Observations:")
        for item in headers:
            report.append(f"  {item['header']}: {item['status']}")
            if item.get("value") is not None:
                report.append(f"    Observed value: {item['value']}")

        report.append("")
        report.append("Note: These are observations only. No vulnerability is automatically confirmed.")

        print("JARVIS: These are observations only.")
        print("JARVIS: No vulnerability is automatically confirmed.")

        if budget_state["exhausted"]:
            raise requests.RequestException("Audit request budget exhausted")

        save_report(target, report)

    except requests.RequestException as e:
        if budget_state["exhausted"]:
            print(
                "JARVIS: Audit stopped because the request budget was exhausted "
                f"({budget_state['used']} of {budget_state['limit']} requests used). "
                "Remaining checks were not run; the audit report was not saved."
            )
        else:
            print(f"JARVIS: Unable to connect to {_render_report_endpoint(url)}.")
            print(f"JARVIS: Request failed ({type(e).__name__}).")
    finally:
        _ACTIVE_AUDIT_REQUEST_BUDGET = previous_budget

    print()

def discover_links(response):
    text = response.text
    links = []
    seen_request_urls = set()
    lower_text = text.lower()
    position = 0

    base_url = response.url
    base_host = urlparse(base_url).hostname

    while True:
        start = lower_text.find("<a ", position)

        if start == -1:
            break

        end = lower_text.find(">", start)

        if end == -1:
            break

        href_start = lower_text.find("href=", start, end)

        if href_start != -1:
            quote = text[href_start + 5]

            if quote in ("'", '"'):
                value_start = href_start + 6
                value_end = text.find(quote, value_start)

                if value_end != -1:
                    href = unescape(text[value_start:value_end])
                    full_url = urljoin(base_url, href)
                    link_host = urlparse(full_url).hostname

                    request_url = full_url.split("#", 1)[0]
                    if request_url not in seen_request_urls:
                        seen_request_urls.add(request_url)
                        if link_host == base_host:
                            links.append(("LOCAL", full_url, href))
                        else:
                            links.append(("EXTERNAL - NOT TESTED", full_url, href))

        position = end + 1

    print(f"Links found: {len(links)}")

    for link_type, full_url, original in links:
        print(f"  - [{link_type}] {_render_report_endpoint(full_url)}")

    return links

def discover_parameters(response):
    parameters = []
    seen_get_parameters = set()
    print("Parameter Discovery:")

    url = response.url
    parsed = urlparse(url)

    if parsed.query:
        print("GET parameters:")
        for item in parsed.query.split("&"):
            name, separator, _value = item.partition("=")
            if not name:
                continue
            key = (url.split("#", 1)[0], name)
            if key not in seen_get_parameters:
                parameters.append({"method": "GET", "name": name, "url": url})
                seen_get_parameters.add(key)
            safe_name = _safe_report_parameter_name(name)
            print(
                f"  - {safe_name} = [value omitted]"
                if separator else f"  - {safe_name}"
            )
    else:
        print("GET parameters: None")

    # Also inspect local links for GET parameters.
    for link_type, full_url, original in discover_links(response):
        if link_type != "LOCAL":
            continue

        link_parsed = urlparse(full_url)

        if link_parsed.query:
            for item in link_parsed.query.split("&"):
                name, separator, _value = item.partition("=")
                if not name:
                    continue
                key = (full_url.split("#", 1)[0], name)
                if key not in seen_get_parameters:
                    parameters.append({"method": "GET", "name": name, "url": full_url})
                    seen_get_parameters.add(key)
                    safe_name = _safe_report_parameter_name(name)
                    print(
                        f"  - Link GET parameter: {safe_name} = [value omitted]"
                        if separator else f"  - Link GET parameter: {safe_name}"
                    )

    forms = _extract_html_forms(response.text)

    if forms:
        print("Form parameters:")

        for number, form in enumerate(forms, 1):
            form_opening = re.search(r"<form\b([^>]*)>", form, re.I | re.S)
            form_attributes = _html_attributes(form_opening.group(1)) if form_opening else {}
            form_method = _form_method(form_attributes)
            try:
                form_url = urljoin(
                    response.url,
                    unescape(form_attributes.get("action", "")),
                )
            except (TypeError, ValueError, UnicodeError):
                form_url = None
            for control in _form_control_inventory(form):
                name = control["name"]
                if not name or control["disabled"]:
                    continue
                if form_method == "GET":
                    key = (
                        form_url.split("#", 1)[0] if form_url else form_url,
                        name,
                    )
                    if key in seen_get_parameters:
                        continue
                    seen_get_parameters.add(key)
                parameters.append({
                    "method": form_method,
                    "name": name,
                    "url": form_url if form_method == "GET" else None,
                    "form_action": form_url,
                })
                print(f"  - Form {number}: {_safe_report_parameter_name(name)}")
    else:
        print("Form parameters: None")

    print()
    return parameters


def _extract_html_forms(text):
    """Extract form blocks while ignoring HTML comments."""
    cleaned = re.sub(
        r"<!--.*?-->",
        lambda match: re.sub(r"[^\r\n]", " ", match.group(0)),
        text,
        flags=re.S,
    )

    forms = []
    lower_text = cleaned.lower()
    position = 0

    while True:
        match = re.search(r"<form\b", lower_text[position:])
        if match is None:
            break

        start = position + match.start()
        end_match = re.search(r"</form\s*>", lower_text[start:])
        if end_match is None:
            break

        end = start + end_match.end()
        forms.append(cleaned[start:end])
        position = end

    return forms


def discover_forms(response):
    forms = _extract_html_forms(response.text)

    print(f"Forms found: {len(forms)}")

    for number, form in enumerate(forms, 1):
        print(f"\nForm {number}:")
        for line in _summarize_form(form, response.url):
            print("  " + line)

    return forms



def _html_attributes(markup):
    attributes = {}
    pattern = re.compile(
        r"([^\s=/>]+)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))",
        re.S,
    )
    for match in pattern.finditer(markup):
        attributes[match.group(1).lower()] = next(
            (value for value in match.groups()[1:] if value is not None), ""
        )
    return attributes


def _form_method(attributes):
    """Return the effective HTML form method, defaulting invalid values to GET."""
    method = attributes.get("method", "").lower()
    if method not in {"get", "post", "dialog"}:
        method = "get"
    return method.upper()


def _form_control_inventory(form):
    """Extract control structure without retaining submitted values."""
    controls = []
    pattern = re.compile(
        r"<input\b([^>]*)>|<textarea\b([^>]*)>(.*?)</textarea\s*>|"
        r"<select\b([^>]*)>(.*?)</select\s*>",
        re.I | re.S,
    )
    for match in pattern.finditer(form):
        if match.group(1) is not None:
            kind, attribute_text, body = "Input", match.group(1), ""
        elif match.group(2) is not None:
            kind, attribute_text, body = "Textarea", match.group(2), match.group(3)
        else:
            kind, attribute_text, body = "Select", match.group(4), match.group(5)

        attributes = _html_attributes(attribute_text)
        disabled = bool(
            re.search(r"(?:^|\s)disabled(?:\s|=|/|$)", attribute_text, re.I)
        )
        control_type = attributes.get("type", "text").strip().lower()
        control_name = attributes.get("name", "").strip()
        sensitive_name = bool(re.search(
            r"(?:pass(?:word|wd)?|csrf|xsrf|token|session|auth|secret|"
            r"credential|api[_-]?key)",
            control_name,
            re.I,
        ))
        action_type = control_type in {
            "hidden", "submit", "button", "reset", "image"
        }
        if control_type == "password" or sensitive_name:
            risk = "sensitive"
        elif action_type:
            risk = "action-related"
        else:
            risk = "review-only"

        controls.append({
            "kind": kind,
            "type": attributes.get("type", "text"),
            "name": attributes.get("name", ""),
            "disabled": disabled,
            "option_count": len(re.findall(r"<option\b", body, re.I)),
            "multiple": kind == "Select" and bool(
                re.search(r"(?:^|\s)multiple(?:\s|=|/|$)", attribute_text, re.I)
            ),
            "risk": risk,
        })
    return controls


def _summarize_form(form, base_url=None):
    """Describe form structure without serializing field values or raw markup."""
    opening = re.search(r"<form\b([^>]*)>", form, re.I | re.S)
    form_attributes = _html_attributes(opening.group(1)) if opening else {}
    method = _safe_report_parameter_name(_form_method(form_attributes))
    action = unescape(form_attributes.get("action", ""))
    if action:
        try:
            rendered_action = _render_report_endpoint(urljoin(base_url or "", action))
        except (TypeError, ValueError, UnicodeError):
            rendered_action = "<unavailable endpoint>"
    elif base_url:
        rendered_action = _render_report_endpoint(base_url)
    else:
        rendered_action = "(default)"
    lines = [f"Form: method={method} | action={rendered_action}"]
    for control in _form_control_inventory(form):
        field_name = _safe_report_parameter_name(control["name"] or "(unnamed)")
        if control["kind"] == "Input":
            description = (
                f"Input: type={_safe_report_parameter_name(control['type'])} "
                f"| name={field_name} | value omitted"
            )
        elif control["kind"] == "Textarea":
            description = f"Textarea: name={field_name} | value omitted"
        else:
            description = (
                f"Select: name={field_name} | options={control['option_count']}"
            )
            if control["multiple"]:
                description += " | multiple"
            description += " | value omitted"
        if control["disabled"]:
            description += " | disabled"
        description += f" | risk={control.get('risk', 'review-only')}"
        lines.append(description)
    return lines

def identify_review_areas(parameters):
    areas = []

    for method, name in parameters:
        name_lower = name.lower()

        if name_lower in ("login", "username", "user", "email"):
            areas.append(f"{method} parameter '{_safe_report_parameter_name(name)}': authentication/input handling")

        elif name_lower in ("password", "pass", "passwd"):
            areas.append(f"{method} parameter '{_safe_report_parameter_name(name)}': credential handling")

        else:
            areas.append(f"{method} parameter '{_safe_report_parameter_name(name)}': input handling")



    return areas


def identify_high_risk_parameters(parameters):
    high_risk = []

    risky_names = {
        "file", "filename", "path", "filepath",
        "url", "uri", "redirect", "return",
        "cmd", "command", "exec", "execute",
        "query", "search", "template", "include"
    }

    for method, name in parameters:
        if name.lower() in risky_names:
            high_risk.append(
                f"{method} parameter '{_safe_report_parameter_name(name)}' requires high-risk input review"
            )

    return high_risk


def _escape_report_header_value(value):
    escaped = []
    special = {"\r": r"\r", "\n": r"\n", "\x85": r"\x85", "\u2028": r"\u2028", "\u2029": r"\u2029"}
    for char in str(value):
        codepoint = ord(char)
        if char in special:
            escaped.append(special[char])
        elif codepoint < 32 or 0x7F <= codepoint <= 0x9F:
            escaped.append(f"\\x{codepoint:02x}")
        else:
            escaped.append(char)
    return "".join(escaped)


def _safe_report_parameter_name(value):
    """Keep parameter labels on one line and safe for plain-text reports."""
    raw = str(value).encode("utf-8", "surrogatepass")
    return quote_from_bytes(raw, safe="-._~[]$!()*+,;:@")


def _render_report_endpoint(value):
    """Render endpoint identity without credentials or raw query values."""
    try:
        parsed = urlsplit(str(value))
        hostname = parsed.hostname
        if not parsed.scheme or not parsed.netloc or not hostname:
            return "<unavailable endpoint>"
        port = parsed.port
        if ":" in hostname:
            safe_host = f"[{quote(hostname, safe=':')}]"
        else:
            safe_host = hostname.encode("idna").decode("ascii")
            safe_host = quote(safe_host, safe=".-")
        if port is not None:
            safe_host = f"{safe_host}:{port}"
        safe_path = quote(
            parsed.path,
            safe="/%:@!$&'()*+,;=-._~%",
        )
        safe_query = "&".join(
            f"{quote(field.partition('=')[0], safe='-._~%')}=%5BREDACTED%5D"
            for field in parsed.query.split("&")
        ) if parsed.query else ""
        return urlunsplit((
            quote(parsed.scheme.lower(), safe=""),
            safe_host,
            safe_path,
            safe_query,
            "",
        ))
    except (UnicodeError, TypeError, ValueError):
        return "<unavailable endpoint>"


def _render_report_target(value):
    """Render a target for display without exposing URL credentials or values."""
    raw = str(value)
    try:
        parsed = urlsplit(raw)
    except (TypeError, ValueError):
        return _safe_report_parameter_name(raw)
    if not parsed.scheme and not any(char in raw for char in "/?#"):
        return _safe_report_parameter_name(raw)
    candidate = raw if parsed.scheme else "https://" + raw
    rendered = _render_report_endpoint(candidate)
    return rendered if rendered != "<unavailable endpoint>" else _safe_report_parameter_name(raw)


def _report_target_filename_component(target):
    """Build a safe, collision-resistant filename component for a target."""
    raw = str(target)
    try:
        parsed = urlsplit(raw)
    except (TypeError, ValueError):
        parsed = urlsplit("")
    candidate = raw if parsed.scheme else ("https://" + raw if raw else "")
    rendered = _render_report_endpoint(candidate) if candidate else ""
    if rendered == "<unavailable endpoint>":
        rendered = _safe_report_parameter_name(raw)
    if not parsed.scheme and not any(char in raw for char in "/?#@"):
        rendered = _safe_report_parameter_name(raw)
    component = rendered.replace("/", "_").replace(":", "_")
    redacted_or_ambiguous = bool(
        parsed.query or parsed.fragment or parsed.username is not None
        or parsed.password is not None or (parsed.scheme and rendered != raw)
        or (not parsed.scheme and any(char in raw for char in "/?#@"))
    )
    if redacted_or_ambiguous:
        digest = hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()[:12]
        component = f"{component}_{digest}"
    return component


def _render_discovered_get_parameter(item, endpoint_variants):
    endpoint_url = str(item.get("url") or "")
    if endpoint_url not in endpoint_variants:
        endpoint_variants[endpoint_url] = len(endpoint_variants) + 1
    parameter_name = _safe_report_parameter_name(item.get("name", ""))
    endpoint = _render_report_endpoint(endpoint_url)
    variant = endpoint_variants[endpoint_url]
    return (
        f"  GET: {parameter_name} | Endpoint: {endpoint} "
        f"| Variant: {variant}"
    )


def _escape_report_user_field(value):
    escaped = _escape_report_header_value(value)
    escaped = (
        escaped
        .replace("JARVIS TRUSTED SEVERITY METADATA BEGIN", "JARVIS\\x20TRUSTED SEVERITY METADATA BEGIN")
        .replace("JARVIS TRUSTED SEVERITY METADATA END", "JARVIS\\x20TRUSTED SEVERITY METADATA END")
    )
    url_pattern = re.compile(r"https?://[^\s<>\"']+", re.I)

    def redact(match):
        value = match.group(0)
        suffix = ""
        while value and value[-1] in ".,;)]}":
            suffix = value[-1] + suffix
            value = value[:-1]
        return _render_report_endpoint(value) + suffix

    return url_pattern.sub(redact, escaped)


def _redact_potential_secrets(value):
    """Redact recognizable credential values before report output or logging."""
    text = str(value)
    assignment = re.compile(
        r"(?i)(\b(?:[A-Za-z_][A-Za-z0-9_-]*?)?"
        r"(?:api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|"
        r"auth[_-]?token|private[_-]?key|password|passwd|secret|token|credential)"
        r"\b\s*[:=]\s*)"
        r"(?!(?:%5BREDACTED%5D|\[REDACTED(?:_[A-Z]+)?\]))"
        r"(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;)}]+)"
    )
    header_credential = re.compile(
        r"(?i)(\b(?:authorization|proxy-authorization|cookie|set-cookie)\b\s*[:=]\s*)"
        r"(?:\"[^\"]*\"|'[^']*'|(?:bearer|basic)\s+[^\s,;)}]+|[^\s,;)}]+)"
    )
    text = assignment.sub(r"\1[REDACTED]", text)
    text = header_credential.sub(r"\1[REDACTED]", text)
    text = re.sub(
        r"(?i)\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|"
        r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
        r"xox[baprs]-[A-Za-z0-9-]{10,}|sk_(?:live|test)_[A-Za-z0-9]{12,})\b",
        "[REDACTED_TOKEN]",
        text,
    )
    text = re.sub(
        r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b",
        "[REDACTED_TOKEN]",
        text,
    )
    text = re.sub(
        r"(?i)(https?://)[^/\s:@]+:[^/@\s]+@",
        r"\1[REDACTED]@",
        text,
    )
    text = re.sub(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        "[REDACTED_PRIVATE_KEY]",
        text,
        flags=re.S,
    )
    return text


def check_security_headers(response):
    headers_to_check = {
        "Content-Security-Policy": "Helps reduce content-injection risks.",
        "X-Content-Type-Options": "Helps prevent MIME-type sniffing.",
        "X-Frame-Options": "Helps reduce clickjacking risks.",
        "Strict-Transport-Security": "Helps enforce HTTPS connections."
    }


    results = []
    response_headers = getattr(response, "headers", None)
    headers_available = (
        response_headers is not None
        and callable(getattr(response_headers, "get", None))
        and callable(getattr(response_headers, "__contains__", None))
    )

    for header, explanation in headers_to_check.items():
        if not headers_available:
            results.append({
                "header": header,
                "status": "NOT RECORDED",
                "explanation": explanation
            })
            continue

        try:
            present = header in response_headers
            value = response_headers.get(header) if present else None
        except (AttributeError, TypeError):
            results.append({
                "header": header,
                "status": "NOT RECORDED",
                "explanation": explanation
            })
            continue

        if present:
            escaped_value = _escape_report_user_field(value)
            results.append({
                "header": header,
                "status": "PRESENT",
                "value": escaped_value,
                "explanation": explanation
            })
        else:
            results.append({
                "header": header,
                "status": "MISSING",
                "explanation": explanation
            })

    return results


def get_page_title(response):
    text = response.text

    start = text.lower().find("<title>")

    if start == -1:
        return "Not found"

    start += len("<title>")

    end = text.lower().find("</title>", start)

    if end == -1:
        return "Not found"

    return text[start:end].strip()


def save_report(target, report):
    REPORTS_DIR.mkdir(exist_ok=True)

    safe_target = _report_target_filename_component(target)

    report_file = REPORTS_DIR / f"{safe_target}.txt"

    if isinstance(report, list):
        report = "\n".join(report)

    report = _redact_potential_secrets(report)

    report_file.write_text(report)

    print(f"JARVIS: Report saved to {report_file}")
def inspect_php_inputs(file_path):
    path = Path(file_path)

    if not path.exists() or path.suffix.lower() != ".php":
        print("JARVIS: PHP file not found.")
        return

    try:
        source = path.read_text(errors="ignore")
    except OSError as e:
        print(f"JARVIS: Could not read PHP file: {e}")
        return

    pattern = re.compile(
        r'\$_(GET|POST|REQUEST)\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]'
    )

    findings = []
    seen = set()

    for match in pattern.finditer(source):
        method = match.group(1)
        parameter = match.group(2)
        item = (method, parameter)

        if item not in seen:
            seen.add(item)
            findings.append(item)

    print(f"\nJARVIS: PHP input analysis â€” {path.name}")

    if not findings:
        print("  No GET/POST/REQUEST inputs detected.")
        return

    for method, parameter in findings:
        print(f"  [{method}] {parameter}")

    print(f"JARVIS: Inputs detected: {len(findings)}")
def classify_php_page(filename):
    name = filename.lower()

    categories = [
        ("sqli_", "SQL Injection"),
        ("xss_", "Cross-Site Scripting"),
        ("commandi", "Command Injection"),
        ("csrf_", "Cross-Site Request Forgery"),
        ("directory_traversal_", "Directory Traversal"),
        ("insecure_direct_object_ref_", "Insecure Direct Object Reference"),
    ]

    for prefix, category in categories:
        if name.startswith(prefix):
            return category

    return None
def scan_php_inputs(directory):
    base = Path(directory)

    if not base.is_dir():
        print("JARVIS: Directory not found.")
        return

    php_files = sorted(base.glob("*.php"))

    if not php_files:
        print("JARVIS: No PHP files found.")
        return

    total_files = 0
    total_inputs = 0

    print(f"\nJARVIS: Scanning {base}")
    print(f"JARVIS: PHP files found: {len(php_files)}\n")

    pattern = re.compile(
        r'\$_(GET|POST|REQUEST)\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]'
    )

    for path in php_files:
        try:
            source = path.read_text(errors="ignore")
        except OSError:
            continue

        inputs = []
        seen = set()

        for match in pattern.finditer(source):
            method = match.group(1)
            parameter = match.group(2)
            item = (method, parameter)

            if item not in seen:
                seen.add(item)
                inputs.append(item)

        if inputs:
            total_files += 1
            total_inputs += len(inputs)

            category = classify_php_page(path.name)

            print(f"[{path.name}]")

            if category:
                print(f"  Category: {category}")
                print("  Status: REVIEW REQUIRED")

            for method, parameter in inputs:
                print(f"  [{method}] {parameter}")

    print("\nJARVIS: PHP source scan complete.")
    print(f"JARVIS: Files with inputs: {total_files}")
    print(f"JARVIS: Unique input references: {total_inputs}")


def _begin_source_analysis_provenance():
    analyzer_path = Path(__file__).resolve()
    try:
        analyzer_hash = hashlib.sha256(analyzer_path.read_bytes()).hexdigest()
    except OSError:
        analyzer_hash = None
    return {
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "analyzer_path": analyzer_path,
        "analyzer_sha256": analyzer_hash,
    }


def _format_source_analysis_provenance(
    provenance, source_snapshots, source_read_errors="ignore"
):
    lines = [
        "Report provenance:",
        f"  Analysis started (UTC): {provenance['started_utc']}",
        f"  Report prepared (UTC): {datetime.now(timezone.utc).isoformat()}",
        f"  Analyzer source: {provenance['analyzer_path']}",
        f"  Analyzer source SHA-256: {provenance['analyzer_sha256'] or 'unavailable'}",
    ]
    try:
        current_analyzer_hash = hashlib.sha256(
            Path(provenance["analyzer_path"]).read_bytes()
        ).hexdigest()
        analyzer_current = current_analyzer_hash == provenance["analyzer_sha256"]
        lines.append(
            "  Analyzer source unchanged when report was prepared: "
            + ("YES" if analyzer_current else "NO")
        )
    except OSError:
        lines.append("  Analyzer source unchanged when report was prepared: UNKNOWN")

    source_checks = []
    lines.append("  Analyzed source snapshots:")
    for source_path, source_text in sorted(
        source_snapshots.items(), key=lambda item: str(item[0])
    ):
        source_path = Path(source_path).resolve()
        source_hash = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
        try:
            current_text = source_path.read_text(errors=source_read_errors)
            current = "YES" if current_text == source_text else "NO"
        except OSError:
            current = "UNKNOWN"
        source_checks.append(current)
        lines.extend([
            f"    Source file: {source_path}",
            f"    Source SHA-256: {source_hash}",
            f"    Matches current file when report was prepared: {current}",
        ])
    if source_checks and all(check == "YES" for check in source_checks):
        freshness = "YES (all analyzed source files matched their snapshots)"
    elif any(check == "NO" for check in source_checks):
        freshness = "NO (one or more analyzed source files changed during analysis)"
    else:
        freshness = "UNKNOWN (one or more analyzed source files could not be checked)"
    lines.append(f"  Source matched analyzed snapshot when report was prepared: {freshness}")
    return lines


def _triage_static_severity(evidence):
    """Apply a conservative severity rubric to explicit, structured evidence.

    Static source-to-sink observations alone are deliberately insufficient to
    assign a tier. This helper does not validate a finding or change its status.
    """
    if not isinstance(evidence, dict):
        evidence = {}

    allowed = {
        "impact": {"low", "moderate", "serious", "severe"},
        "exploitability": {"demonstrated", "strong_static", "pattern_only"},
        "authentication": {"none", "low", "standard", "privileged"},
    }
    required = (
        "vulnerability_class", "source_locations", "sink_locations", "impact",
        "exploitability", "trust_boundary", "authentication", "in_scope",
        "controls_reviewed", "controls_effective",
    )
    missing = [key for key in required if key not in evidence or evidence[key] is None]
    for key in ("source_locations", "sink_locations"):
        locations = evidence.get(key)
        if (
            not isinstance(locations, (list, tuple))
            or not locations
            or any(not isinstance(item, str) or not item.strip() for item in locations)
        ) and key not in missing:
            missing.append(key)
    if (
        not isinstance(evidence.get("vulnerability_class"), str)
        or not evidence.get("vulnerability_class", "").strip()
    ) and "vulnerability_class" not in missing:
        missing.append("vulnerability_class")
    for key, choices in allowed.items():
        if evidence.get(key) not in choices and key not in missing:
            missing.append(key)
    if not isinstance(evidence.get("trust_boundary"), str) or not evidence.get("trust_boundary", "").strip():
        if "trust_boundary" not in missing:
            missing.append("trust_boundary")
    if not isinstance(evidence.get("in_scope"), bool) and "in_scope" not in missing:
        missing.append("in_scope")
    if evidence.get("controls_reviewed") is not True and "controls_reviewed" not in missing:
        missing.append("controls_reviewed")
    if not isinstance(evidence.get("controls_effective"), bool) and "controls_effective" not in missing:
        missing.append("controls_effective")

    if missing or evidence.get("exploitability") != "demonstrated" or evidence.get("in_scope") is not True:
        reasons = []
        if missing:
            reasons.append("missing or invalid evidence: " + ", ".join(sorted(set(missing))))
        if evidence.get("exploitability") != "demonstrated":
            reasons.append("static patterns or traces do not demonstrate exploitability")
        if evidence.get("in_scope") is not True:
            reasons.append("in-scope status is not established")
        return {
            "severity": "NEEDS_REVIEW",
            "confidence": "Low",
            "rationale": "; ".join(reasons) or "Evidence is insufficient for severity triage.",
        }

    impact = evidence["impact"]
    boundary = evidence["trust_boundary"].casefold()
    authentication = evidence["authentication"]
    controls_effective = evidence["controls_effective"]
    if (impact == "severe" and "cross-tenant" in boundary
            and authentication == "none" and controls_effective is False):
        severity = "Critical"
    elif impact in {"serious", "severe"} and controls_effective is False:
        severity = "High"
    elif impact == "moderate" and controls_effective is False:
        severity = "Medium"
    elif impact == "low" and controls_effective is False:
        severity = "Low"
    elif impact == "low" and controls_effective is True:
        severity = "Informational"
    else:
        return {
            "severity": "NEEDS_REVIEW",
            "confidence": "Medium",
            "rationale": "Evidence is recorded, but impact and control effectiveness do not match a supported tier rule.",
        }
    return {
        "severity": severity,
        "confidence": "High" if severity in {"Critical", "High"} else "Medium",
        "rationale": (
            f"Recorded impact is {impact}; exploitability is marked demonstrated; "
            f"trust boundary is {evidence['trust_boundary']}; authentication is "
            f"{authentication}; controls were reviewed and recorded as "
            f"{'effective' if controls_effective else 'ineffective'}; scope is established."
        ),
    }


def _source_flow_severity_lines(vulnerability_class, source_locations, sink_locations):
    """Format a severity assessment for static-only source-flow evidence."""
    assessment = _triage_static_severity({
        "vulnerability_class": vulnerability_class,
        "source_locations": source_locations,
        "sink_locations": sink_locations,
        "impact": None,
        "exploitability": "pattern_only",
        "trust_boundary": None,
        "authentication": None,
        "in_scope": None,
        "controls_reviewed": False,
        "controls_effective": None,
    })
    return [
        "Severity triage:",
        f"  Severity: {assessment['severity']}",
        f"  Severity confidence: {assessment['confidence']}",
        f"  Rationale: {assessment['rationale']}.",
        "  Evidence basis: source and sink observations are static code facts only; impact, runtime exploitability, trust-boundary crossing, authentication, scope, and effective protections are not established.",
        "  Coverage limitation: this triage uses narrow source-flow observations for SQL/query, HTML output, selected URL-fetch and file-read calls, direct PHP dangerous operations, and limited PHP upload review; authorization, IDOR, and general SSRF/path traversal are not generally analyzed here; cryptography and security configuration are also outside comprehensive coverage.",
        "  Vulnerability status remains UNCONFIRMED.",
    ]


def _write_php_flow_report(path, report, reports_dir):
    report = _redact_potential_secrets(report)
    reports_dir = Path(reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^a-zA-Z0-9_-]+", "_", path.stem).strip("_").lower()
    base = f"{safe_name}_php_flow"
    for index in range(1000):
        suffix = "" if index == 0 else f"_{index}"
        report_file = reports_dir / f"{base}{suffix}.txt"
        try:
            with report_file.open("x", encoding="utf-8") as handle:
                handle.write(report)
            return report_file
        except FileExistsError:
            continue
    raise OSError("Could not allocate a unique PHP-flow report filename")


def _trace_php_flow(path, source, reports_dir, provenance=None):
    """Trace only explicit request references and supported local assignments."""
    root = path.resolve().parent
    root_file = path.resolve()
    input_pattern = re.compile(r"\$_(GET|POST|REQUEST)\s*\[\s*['\"]([^'\"]+)['\"]\s*\]")
    form_control_pattern = re.compile(r"<\s*(input|textarea|select|button)\b([^>]*)>", re.I | re.S)
    form_name_pattern = re.compile(r"(?:^|\s)name\s*=\s*(?:['\"]([^'\"]*)['\"]|([^\s>]+))", re.I)
    php_region_pattern = re.compile(r"<\?(?:php\b|=).*?\?>", re.I | re.S)
    html_comment_pattern = re.compile(r"<!--.*?-->", re.S)
    sql_statement_pattern = re.compile(
        r"^\s*\$(\w+)\s*=\s*(['\"])\s*(SELECT|INSERT|UPDATE|DELETE)\b", re.I
    )
    presence_ternary_pattern = re.compile(
        r"^isset\s*\(\s*\$_(GET|POST|REQUEST)\s*\[\s*(['\"])([^'\"]+)\2\s*\]\s*\)\s*\?\s*1\s*:\s*0$",
        re.I,
    )
    assignment_pattern = re.compile(r"^\s*\$(\w+)\s*(=|\.=)\s*(.*?)\s*;\s*$")
    variable_pattern = re.compile(r"\$(\w+)")
    include_pattern = re.compile(r"^\s*(include_once|include|require_once|require)\s*(?:\(\s*)?(.+?)\s*\)?\s*;\s*$")
    dangerous_operation_names = (
        "exec", "system", "shell_exec", "passthru", "popen", "proc_open",
        "eval", "unserialize", "file_get_contents", "file_put_contents",
        "fopen", "readfile", "unlink", "move_uploaded_file",
    )
    command_execution_names = {
        "exec", "system", "shell_exec", "passthru", "popen", "proc_open",
    }
    file_read_operation_names = {"file_get_contents", "readfile"}
    origins, edges, inputs, conditional_inputs, presence_inputs = {}, {}, [], [], []
    unresolved_request_inputs, includes, sinks, sink_observations, unresolved = [], [], [], [], []
    form_controls, database_observations = [], []
    stored_data_observations, stored_data_flows, unresolved_stored_data = [], [], []
    select_output_flows = []
    guards_by_source_line = {}
    unsupported_source_lines = set()
    prepared_statement_observations, prepared_statement_flows = [], []
    invalidated = {}
    function_definition_diagnostics_seen = set()
    function_call_diagnostics_seen = set()
    function_expression_diagnostics_seen = set()
    source_lines_by_file = {}
    source_text_by_file = {}
    visited, active = set(), []

    def mask_php_sink_code(line, state):
        """Return executable PHP characters, masking strings and comments."""
        masked = [" "] * len(line)
        index = 0
        while index < len(line):
            if not state["php"]:
                if line[index:index + 5].lower() == "<?php":
                    state["php"] = True
                    index += 5
                    continue
                if line[index:index + 3] == "<?=":
                    state["php"] = True
                    index += 3
                    continue
                if line[index:index + 2] == "<?":
                    state["php"] = True
                    index += 2
                    continue
                index += 1
                continue
            if state["block_comment"]:
                if line[index:index + 2] == "*/":
                    state["block_comment"] = False
                    index += 2
                else:
                    index += 1
                continue
            if state["quote"]:
                char = line[index]
                if state["escaped"]:
                    state["escaped"] = False
                elif char == "\\":
                    state["escaped"] = True
                elif char == state["quote"]:
                    state["quote"] = None
                index += 1
                continue
            if line[index:index + 2] == "?>":
                state["php"] = False
                index += 2
                continue
            if line[index:index + 2] == "/*":
                state["block_comment"] = True
                index += 2
                continue
            if line[index:index + 2] == "//" or (
                line[index] == "#" and line[index:index + 2] != "#["
            ):
                break
            char = line[index]
            if char in ("'", '"', "`"):
                state["quote"] = char
                state["escaped"] = False
                index += 1
                continue
            masked[index] = char
            index += 1
        return "".join(masked)

    def source_references_on_line(line, code_line):
        references = []
        for match in input_pattern.finditer(line):
            if code_line[match.start():match.start() + 2] == "$_":
                references.append((match.group(1), match.group(2)))
        return references

    def static_form_controls(file, source_text):
        """Inventory literal HTML controls separately from PHP request sources."""
        def blank_markup(match):
            return "".join("\n" if char == "\n" else " " for char in match.group())

        html_text = php_region_pattern.sub(blank_markup, source_text)
        html_text = html_comment_pattern.sub(blank_markup, html_text)
        records = []
        for match in form_control_pattern.finditer(html_text):
            name_match = form_name_pattern.search(match.group(2))
            name = (name_match.group(1) if name_match.group(1) is not None else name_match.group(2)) if name_match else None
            records.append((match.group(1).lower(), name or "(unnamed)", file, html_text.count("\n", 0, match.start()) + 1))
        return records

    def classify_request_expression(expression):
        """Separate supported values, known presence flags, and uncertain references."""
        presence = presence_ternary_pattern.fullmatch(expression.strip())
        if presence:
            return [], [(presence.group(1).upper(), presence.group(3))], []
        references = input_pattern.findall(expression)
        if not references:
            return [], [], []
        syntax = re.sub(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"", " ", expression)
        if "?" in syntax or re.search(r"\b[A-Za-z_]\w*\s*\(", syntax):
            return [], [], references
        return references, [], []

    def has_unsupported_assignment_expression(expression):
        # The tracer supports direct references and concatenation, not calls or ternaries.
        syntax = re.sub(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"", " ", expression)
        return "?" in syntax or bool(
            re.search(r"\b[A-Za-z_]\w*\s*\(", syntax)
        )

    function_ranges = {}
    function_candidates = {}
    function_index_unresolved = []
    function_header_pattern = re.compile(
        r"^\s*function\s+(&\s*)?([A-Za-z_]\w*)\s*\((.*)\)\s*(\{\s*)?$",
        re.I,
    )

    def split_top_level_list(text):
        """Split comma-separated syntax while preserving quoted/nested commas."""
        pieces, start, depth, quote, escaped = [], 0, 0, None, False
        for index, char in enumerate(text):
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                continue
            if char in ("'", '"'):
                quote = char
            elif char in "([":
                depth += 1
            elif char in ")]":
                depth -= 1
            elif char == "," and depth == 0:
                pieces.append(text[start:index].strip())
                start = index + 1
        pieces.append(text[start:].strip())
        return pieces

    def supported_include_target(file, line):
        include = include_pattern.match(line)
        if not include:
            return None
        _, expression = include.groups()
        expression = expression.strip().strip("() ")
        literal = re.fullmatch(r"['\"]([^'\"]+\.php)['\"]", expression)
        based = re.fullmatch(
            r"(?:__DIR__|dirname\s*\(\s*__FILE__\s*\))\s*\.\s*['\"]([^'\"]+\.php)['\"]",
            expression,
        )
        name = literal.group(1) if literal else (based.group(1) if based else None)
        if name is None:
            return None
        include_path = name.lstrip("/") if based else name
        target = (file.parent / include_path).resolve()
        if target.is_relative_to(root) and target.is_file():
            return target
        return None

    def transformation_category(name):
        transform_name = name.lower()
        if transform_name in {
            "htmlentities", "htmlspecialchars",
        }:
            return "html-output-encoding"
        if transform_name == "addslashes":
            return "quote-escaping"
        if transform_name in {
            "mysql_real_escape_string", "mysqli_real_escape_string",
        }:
            return "sql-escaping"
        if transform_name == "escapeshellarg":
            return "shell-argument-escaping"
        if transform_name == "escapeshellcmd":
            return "shell-command-escaping"
        if transform_name == "basename":
            return "path-component-reduction"
        if transform_name == "realpath":
            return "path-canonicalization"
        return "other-transformation"

    def transformation_context_note(category, sink_type):
        if category == "quote-escaping":
            if sink_type == "output":
                return "addslashes quote escaping observed; it is not HTML output encoding, and HTML-context protection is not inferred. Transformation effectiveness is not inferred."
            if sink_type == "SQL/query":
                return "addslashes quote escaping observed; SQL-context effectiveness is not inferred. Transformation effectiveness is not inferred."
            return "addslashes quote escaping observed, but the sink context is ambiguous; no protection is inferred."
        if category == "shell-argument-escaping":
            return "escapeshellarg argument transformation observed; safe argument boundaries, option handling, command composition, and runtime behavior are not established."
        if category == "shell-command-escaping":
            return "escapeshellcmd command-string transformation observed; this is not equivalent to safely separating arguments, and command safety is not established."
        if category == "path-component-reduction":
            return "basename path-component reduction observed; this does not establish base-directory containment, symlink safety, or that the transformation is used on every path."
        if category == "path-canonicalization":
            return "realpath canonicalization observed; containment against an intended base, failure handling, symlink policy, and use of the canonical result are not established."
        return None

    def summarize_function(file, start_line, params_text, body_lines):
        raw_params = split_top_level_list(params_text) if params_text.strip() else []
        params = []
        optional_seen = False
        optional_defaults = []
        parameter_excerpt = f"function (...{params_text}...)"
        for item in raw_params:
            match = re.fullmatch(r"\$(\w+)(?:\s*=\s*(.+))?", item)
            if not match or match.group(1) in params:
                return None, "unsupported or ambiguous parameter list", (file, start_line, parameter_excerpt)
            default = match.group(2)
            if default is not None:
                optional_seen = True
                if not re.fullmatch(
                    r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|-?(?:\d+\.\d*|\.\d+|\d+)|true|false",
                    default.strip(),
                    re.I,
                ):
                    return None, "unsupported optional parameter default", (file, start_line, parameter_excerpt)
                optional_defaults.append((match.group(1), default.strip()))
            elif optional_seen:
                return None, "nontrailing optional parameter", (file, start_line, parameter_excerpt)
            params.append(match.group(1))
        required_count = len(params) - len(optional_defaults)

        def reject(reason, line_number, excerpt):
            return None, reason, (file, line_number, excerpt.strip()[:180])

        def summarize_return_expression(expression, allow_helper_call=False):
            expression = expression.strip()
            variable = re.fullmatch(r"\$(\w+)", expression)
            if variable and variable.group(1) in params:
                return {
                    "parameter": variable.group(1),
                    "kind": "identity",
                    "expression": expression,
                }
            call = re.fullmatch(r"([A-Za-z_]\w*)\s*\((.*)\)", expression)
            recognized_transforms = {
                "addslashes": 0,
                "htmlentities": 0,
                "htmlspecialchars": 0,
                "mysql_real_escape_string": 0,
                "mysqli_real_escape_string": 1,
                "escapeshellarg": 0,
                "escapeshellcmd": 0,
                "basename": 0,
                "realpath": 0,
            }
            if not call:
                return None
            arguments = split_top_level_list(call.group(2))
            transform_name = call.group(1).lower()
            parameter_index = recognized_transforms.get(transform_name)
            if parameter_index is not None:
                if parameter_index >= len(arguments):
                    return None
                parameter_match = re.fullmatch(r"\$(\w+)", arguments[parameter_index])
                if not parameter_match or parameter_match.group(1) not in params:
                    return None
                if not all(
                    index == parameter_index or re.fullmatch(
                        r"\$\w+|[A-Za-z_]\w*|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|-?(?:\d+\.\d*|\.\d+|\d+)|true|false|null",
                        argument, re.I,
                    )
                    for index, argument in enumerate(arguments)
                ):
                    return None
                return {
                    "parameter": parameter_match.group(1),
                    "kind": "transformed",
                    "category": transformation_category(call.group(1)),
                    "transform_name": call.group(1),
                    "expression": expression,
                }
            if not allow_helper_call:
                return None
            parameter_arguments = [
                index for index, argument in enumerate(arguments)
                if re.fullmatch(r"\$(\w+)", argument)
                and re.fullmatch(r"\$(\w+)", argument).group(1) in params
            ]
            if len(parameter_arguments) != 1:
                return None
            parameter_index = parameter_arguments[0]
            parameter = re.fullmatch(r"\$(\w+)", arguments[parameter_index]).group(1)
            if not all(
                index == parameter_index or re.fullmatch(
                    r"\$\w+|[A-Za-z_]\w*|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|-?(?:\d+\.\d*|\.\d+|\d+)|true|false|null",
                    argument, re.I,
                )
                for index, argument in enumerate(arguments)
            ):
                return None
            return {
                "parameter": parameter,
                "kind": "helper-call",
                "category": None,
                "transform_name": call.group(1),
                "expression": expression,
            }

        def summarize_switch_branches():
            meaningful = [
                (line_number, text.strip())
                for line_number, text in body_lines
                if text.strip() and not text.strip().startswith(("//", "#", "*"))
            ]
            if not meaningful:
                return None
            switch_index = 0
            while switch_index < len(meaningful) and re.fullmatch(
                r"(?:include|include_once|require|require_once)\s*\(?\s*['\"][^'\"]+\.php['\"]\s*\)?\s*;",
                meaningful[switch_index][1], re.I,
            ):
                switch_index += 1
            if switch_index == len(meaningful):
                return None
            switch = re.fullmatch(r"switch\s*\((.+)\)\s*(\{)?", meaningful[switch_index][1])
            if not switch:
                return None
            switch_expression = switch.group(1).strip()
            supported_switch_expression = (
                re.fullmatch(r"\$\w+", switch_expression)
                or re.fullmatch(r"\$_COOKIE\s*\[\s*['\"][^'\"]+['\"]\s*\]", switch_expression)
            )
            if not supported_switch_expression:
                return None, "unsupported switch condition", (file, meaningful[0][0], meaningful[0][1])
            content_start = switch_index + 1
            if not switch.group(2):
                if len(meaningful) <= switch_index + 1 or meaningful[switch_index + 1][1] != "{":
                    return None, "unsupported switch block syntax", (file, meaningful[switch_index][0], meaningful[switch_index][1])
                content_start = switch_index + 2
            closing_index = next(
                (index for index in range(content_start, len(meaningful)) if meaningful[index][1] == "}"),
                None,
            )
            if closing_index is None:
                return None, "unterminated switch block", (file, meaningful[0][0], meaningful[0][1])
            cases = []
            active_case = None
            for line_number, text in meaningful[content_start:closing_index]:
                label = re.fullmatch(r"case\s+(.+?)\s*:", text, re.I)
                default = re.fullmatch(r"default\s*:", text, re.I)
                if label or default:
                    if active_case is not None:
                        cases.append(active_case)
                    condition = "default" if default else label.group(1).strip()
                    if condition != "default" and not re.fullmatch(
                        r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|-?(?:\d+\.\d*|\.\d+|\d+)|true|false|null",
                        condition,
                        re.I,
                    ):
                        return None, "unsupported switch case label", (file, line_number, text)
                    active_case = {"condition": condition, "line": line_number, "statements": []}
                elif active_case is None:
                    return None, "statement outside a supported switch branch", (file, line_number, text)
                else:
                    active_case["statements"].append((line_number, text))
            if active_case is not None:
                cases.append(active_case)
            if len(cases) < 2 or sum(case["condition"] == "default" for case in cases) != 1:
                return None, "switch branches must include distinct cases and one default", (file, meaningful[0][0], meaningful[0][1])
            if len({case["condition"] for case in cases}) != len(cases):
                return None, "duplicate switch branch labels", (file, meaningful[0][0], meaningful[0][1])

            branch_values = []
            common_return = None
            assignment_style = None
            for case in cases:
                statements = case["statements"]
                if len(statements) == 1:
                    direct_return = re.fullmatch(r"return\s+(.+?)\s*;", statements[0][1])
                    if direct_return:
                        if assignment_style is True:
                            return None, "mixed switch return styles", (file, statements[0][0], statements[0][1])
                        assignment_style = False
                        value = summarize_return_expression(
                            direct_return.group(1), allow_helper_call=True
                        )
                        if value is None:
                            return None, "unsupported switch return expression", (file, statements[0][0], statements[0][1])
                        branch_values.append((case, value, statements[0][0]))
                        continue
                if len(statements) == 2:
                    assignment = re.fullmatch(r"\$(\w+)\s*=\s*(.+?)\s*;", statements[0][1])
                    if assignment and statements[1][1] == "break;":
                        if assignment_style is False:
                            return None, "mixed switch return styles", (file, statements[0][0], statements[0][1])
                        assignment_style = True
                        destination, expression = assignment.groups()
                        if destination not in params:
                            return None, "switch branch reassigns an unsupported local", (file, statements[0][0], statements[0][1])
                        value = summarize_return_expression(
                            expression, allow_helper_call=True
                        )
                        if value is None or value["parameter"] != destination:
                            return None, "unsupported switch branch assignment", (file, statements[0][0], statements[0][1])
                        branch_values.append((case, value, statements[0][0]))
                        continue
                return None, "unsupported switch branch statements", (file, statements[0][0] if statements else case["line"], statements[0][1] if statements else "empty branch")

            tail = meaningful[closing_index + 1:]
            if assignment_style:
                if len(tail) != 1:
                    return None, "switch branches require one shared return", (file, meaningful[closing_index][0], meaningful[closing_index][1])
                result = re.fullmatch(r"return\s+\$(\w+)\s*;", tail[0][1])
                if not result or any(
                    case_value["parameter"] != result.group(1)
                    for _, case_value, _ in branch_values
                ):
                    return None, "switch branches do not share a supported return", (file, tail[0][0], tail[0][1])
                return_line = tail[0][0]
            else:
                if tail:
                    return None, "unsupported statements after switch returns", (file, tail[0][0], tail[0][1])
                return_line = None
            return {
                "file": file,
                "definition_line": start_line,
                "params": params,
                "required_count": required_count,
                "switch_expression": switch_expression,
                "prelude": [
                    (file, line_number, text)
                    for line_number, text in meaningful[:switch_index]
                ],
                "branch_paths": [
                    {
                        **value,
                        "condition": case["condition"],
                        "branch_line": case["line"],
                        "return_line": expression_line,
                        "shared_return_line": return_line,
                    }
                    for case, value, expression_line in branch_values
                ],
            }, None, None

        branch_summary = summarize_switch_branches()
        if (
            isinstance(branch_summary, tuple)
            and branch_summary
            and isinstance(branch_summary[0], dict)
        ):
            return branch_summary

        executable_body = [
            (line_number, text.strip())
            for line_number, text in body_lines
            if text.strip() and not text.strip().startswith(("//", "#", "*"))
        ]
        if len(executable_body) == 1:
            line_number, statement = executable_body[0]
            direct_return = re.fullmatch(r"return\s+(.+?)\s*;", statement)
            returned_expression = (
                summarize_return_expression(direct_return.group(1))
                if direct_return else None
            )
            if returned_expression and returned_expression["kind"] == "transformed":
                return {
                    "file": file,
                    "definition_line": start_line,
                    "params": params,
                    "required_count": required_count,
                    "parameter": returned_expression["parameter"],
                    "return_variable": returned_expression["parameter"],
                    "aliases": [],
                    "return_line": line_number,
                    "return_kind": "transformed",
                    "return_category": returned_expression["category"],
                    "return_expression": direct_return.group(1).strip(),
                }, None, None

        aliases = {}
        alias_lines = []
        return_value = None
        return_line = None
        returned = []
        for body_line_number, body_text in body_lines:
            statement = body_text.strip()
            if not statement or statement.startswith(("//", "#", "*")):
                continue
            alias = re.fullmatch(r"\s*\$(\w+)\s*=\s*\$(\w+)\s*;\s*", body_text)
            result = re.fullmatch(r"\s*return\s+(.+?)\s*;\s*", body_text)
            if alias and return_line is None:
                destination, source = alias.groups()
                if source not in params and source not in aliases:
                    return reject("alias source is not a supported parameter or prior alias", body_line_number, statement)
                if destination in params or destination in aliases:
                    return reject("parameter or local alias is reassigned", body_line_number, statement)
                aliases[destination] = aliases.get(source, source)
                alias_lines.append((file, body_line_number, destination, source))
            elif result:
                returned.append((body_line_number, result.group(1)))
                if return_line is None:
                    return_value = result.group(1)
                    return_line = body_line_number
            else:
                return reject("function body contains unsupported control flow or syntax", body_line_number, statement)
        if len(returned) != 1:
            if len(returned) > 1:
                line_number = returned[1][0]
                excerpt = next((text for number, text in body_lines if number == line_number), "return")
            else:
                line_number, excerpt = start_line, "function has no supported unconditional return"
            return reject("function must have exactly one unconditional return", line_number, excerpt)
        return_source = returned[0][1]
        returned_variable = re.fullmatch(r"\$(\w+)", return_source)
        if returned_variable and returned_variable.group(1) in params:
            parameter = returned_variable.group(1)
        elif returned_variable and returned_variable.group(1) in aliases:
            parameter = aliases[returned_variable.group(1)]
        else:
            transformed_return = summarize_return_expression(return_source)
            if not transformed_return or transformed_return["kind"] != "transformed":
                return reject("return value is not a supported parameter, alias, or recognized transform", returned[0][0], f"return {return_source};")
            parameter = transformed_return["parameter"]
            if params.index(parameter) >= required_count:
                return reject(
                    "return value depends on an optional parameter",
                    returned[0][0],
                    f"return {return_source};",
                )
            return {
                "file": file,
                "definition_line": start_line,
                "params": params,
                "required_count": required_count,
                "parameter": parameter,
                "return_variable": parameter,
                "aliases": alias_lines,
                "return_line": returned[0][0],
                "return_kind": "transformed",
                "return_category": transformed_return["category"],
                "return_expression": return_source,
            }, None, None
        if params.index(parameter) >= required_count:
            return reject(
                "return value depends on an optional parameter",
                returned[0][0],
                f"return ${return_source};",
            )
        return {
            "file": file,
            "definition_line": start_line,
            "params": params,
            "required_count": required_count,
            "parameter": parameter,
            "return_variable": parameter,
            "aliases": alias_lines,
            "return_line": return_line,
        }, None, None

    def index_function_file(file, scanned, include_stack):
        file = file.resolve()
        if file in include_stack or file in scanned:
            return
        scanned.add(file)
        try:
            lines = file.read_text(errors="ignore").splitlines()
        except OSError:
            return
        state = {"php": False, "block_comment": False, "quote": None, "escaped": False}
        depth = 0
        includes_to_scan = []
        ranges = function_ranges.setdefault(file, set())
        line_index = 0
        while line_index < len(lines):
            text = lines[line_index].strip()
            code = mask_php_sink_code(lines[line_index], state)
            header = function_header_pattern.fullmatch(text)
            declaration = re.match(r"^\s*function\s+(?:&\s*)?([A-Za-z_]\w*)\b", text, re.I)
            if header or declaration:
                start = line_index
                if header and not header.group(4) and line_index + 1 < len(lines) and lines[line_index + 1].strip() == "{":
                    line_index += 1
                    code = mask_php_sink_code(lines[line_index], state)
                body_start = line_index + 1
                brace_depth = code.count("{") - code.count("}")
                end = line_index
                found_open_brace = brace_depth > 0 or "{" in code
                while end + 1 < len(lines) and not found_open_brace:
                    end += 1
                    body_code = mask_php_sink_code(lines[end], state)
                    brace_depth += body_code.count("{") - body_code.count("}")
                    found_open_brace = "{" in body_code or brace_depth > 0
                    if found_open_brace:
                        body_start = end + 1
                while end + 1 < len(lines) and brace_depth > 0:
                    end += 1
                    body_code = mask_php_sink_code(lines[end], state)
                    brace_depth += body_code.count("{") - body_code.count("}")
                if not found_open_brace:
                    end = len(lines) - 1
                name = header.group(2) if header else declaration.group(1)
                for skipped in range(start, min(end + 1, len(lines))):
                    ranges.add(skipped + 1)
                if name:
                    body_state = {"php": True, "block_comment": False, "quote": None, "escaped": False}
                    body = []
                    for body_index in range(body_start, min(end, len(lines))):
                        body_number = body_index + 1
                        body_text = lines[body_index]
                        body_code = mask_php_sink_code(body_text, body_state)
                        body.append((body_number, body_text))
                        body_sources = source_references_on_line(body_text, body_code)
                        if body_sources:
                            assignment = assignment_pattern.match(body_text)
                            body_presence = []
                            if assignment:
                                _, _, body_rhs = assignment.groups()
                                _, body_presence, _ = classify_request_expression(body_rhs)
                                for method, key in body_presence:
                                    presence_inputs.append((method, key, file, body_number, body_text.strip()))
                            if not body_presence:
                                for method, key in body_sources:
                                    unresolved_request_inputs.append(
                                        (method, key, file, body_number, body_text.strip())
                                    )
                        if re.search(r"\b(?:mysqli_query|mysqli_multi_query|mysql_query|pg_query|sqlite_query)\s*\(|->\s*(?:query|exec|prepare)\s*\(", body_code, re.I):
                            sink_observations.append(("SQL/query", file, body_number, body_text.strip(), " [function body; execution not established]"))
                        if re.search(r"\b(?:echo|print|printf)\b", body_code):
                            sink_observations.append(("output", file, body_number, body_text.strip(), " [function body; execution not established]"))
                    if not header:
                        summary, reason = None, "unsupported function declaration syntax"
                        failure = (file, start + 1, lines[start].strip()[:180])
                    elif depth != 0 or header.group(1):
                        summary, reason = None, "conditional or by-reference definition is unsupported"
                        failure = (file, start + 1, lines[start].strip()[:180])
                    else:
                        summary, reason, failure = summarize_function(file, start + 1, header.group(3), body)
                    function_candidates.setdefault(name.lower(), []).append(
                        (summary, file, start + 1, reason or "not summarized", failure)
                    )
                line_index = end + 1
                continue
            if depth == 0:
                included = supported_include_target(file, lines[line_index])
                if included is not None:
                    includes_to_scan.append(included)
            depth += code.count("{") - code.count("}")
            line_index += 1
        for included in includes_to_scan:
            index_function_file(included, scanned, include_stack + (file,))

    index_function_file(root_file, set(), ())
    function_summaries = function_candidates

    def split_call_arguments(arguments):
        if not arguments.strip():
            return []
        return split_top_level_list(arguments)

    def validate_branch_return_path(branch_path):
        if branch_path["kind"] == "identity":
            return "identity"
        call = re.fullmatch(
            r"([A-Za-z_]\w*)\s*\((.*)\)", branch_path["expression"]
        )
        if not call:
            return None
        transform_name = call.group(1).lower()
        arguments = split_call_arguments(call.group(2))
        builtin_transforms = {
            "addslashes", "htmlentities", "htmlspecialchars",
            "mysql_real_escape_string", "mysqli_real_escape_string",
            "escapeshellarg", "escapeshellcmd",
            "basename", "realpath",
        }
        if transform_name in builtin_transforms:
            if sum(argument == f"${branch_path['parameter']}" for argument in arguments) == 1:
                return transformation_category(transform_name)
            return None
        candidates = [
            candidate for candidate in function_summaries.get(transform_name, [])
            if candidate[1] == root_file or candidate[1] in visited
        ]
        if len(candidates) != 1 or candidates[0][0] is None:
            return None
        transform_summary = candidates[0][0]
        if transform_summary.get("branch_paths"):
            return None
        if (
            len(arguments) < transform_summary["required_count"]
            or len(arguments) > len(transform_summary["params"])
        ):
            return None
        parameter_index = transform_summary["params"].index(
            transform_summary["parameter"]
        )
        if parameter_index >= len(arguments) or arguments[parameter_index] != f"${branch_path['parameter']}":
            return None
        if transform_summary.get("return_kind") == "transformed":
            return transform_summary.get("return_category", "other-transformation")
        return "identity"

    def split_sink_arguments(arguments):
        pieces, start, depth, quote, escaped = [], 0, 0, None, False
        for index, char in enumerate(arguments):
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                continue
            if char in ("'", '"'):
                quote = char
            elif char in "([":
                depth += 1
            elif char in ")]":
                depth -= 1
            elif char == "," and depth == 0:
                pieces.append(arguments[start:index].strip())
                start = index + 1
        pieces.append(arguments[start:].strip())
        return pieces

    def sink_expression(line, code_line, sink_type):
        if sink_type == "output":
            match = re.search(r"\b(?:echo|print|printf)\b", code_line)
            if not match:
                return None
            start = match.end()
            while start < len(line) and line[start].isspace():
                start += 1
            expression = line[start:].split(";", 1)[0]
            return re.sub(r"\?>\s*$", "", expression).strip()
        dangerous = re.fullmatch(
            r"Dangerous server-side operation: ([A-Za-z_][A-Za-z0-9_]*)",
            sink_type,
        )
        if dangerous:
            function_name = dangerous.group(1)
            match = re.search(
                rf"(?<!->)\b{re.escape(function_name)}\s*\(", code_line, re.I
            )
            if not match:
                return None
            opening = code_line.find("(", match.start(), match.end())
            depth = 1
            closing = opening + 1
            while closing < len(code_line) and depth:
                if code_line[closing] == "(":
                    depth += 1
                elif code_line[closing] == ")":
                    depth -= 1
                closing += 1
            if depth:
                return None
            arguments = split_sink_arguments(line[opening + 1:closing - 1])
            return arguments[0] if arguments else None
        match = re.search(
            r"\b(mysqli_query|mysqli_multi_query|mysql_query|pg_query|sqlite_query)\s*\(|->\s*(query|exec|prepare)\s*\(",
            code_line,
            re.I,
        )
        if not match:
            return None
        opening = code_line.find("(", match.start(), match.end())
        depth = 1
        closing = opening + 1
        while closing < len(code_line) and depth:
            if code_line[closing] == "(":
                depth += 1
            elif code_line[closing] == ")":
                depth -= 1
            closing += 1
        if depth:
            return None
        arguments = split_sink_arguments(line[opening + 1:closing - 1])
        if not arguments:
            return None
        if match.group(1) and match.group(1).lower() in {"mysqli_query", "mysqli_multi_query"}:
            index = 1 if len(arguments) > 1 else 0
        elif match.group(1) and match.group(1).lower() == "pg_query":
            index = 1 if len(arguments) > 1 else 0
        else:
            index = 0
        return arguments[index] if index < len(arguments) else None

    def supported_call_argument(argument):
        return bool(
            re.fullmatch(r"\$\w+", argument)
            or input_pattern.fullmatch(argument)
            or re.fullmatch(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"", argument)
            or re.fullmatch(r"-?(?:\d+\.\d*|\.\d+|\d+)|true|false|null", argument, re.I)
        )

    def supported_call_expression(expression, calls):
        structure = list(expression)
        string_pattern = re.compile(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"")
        spans = [(match.start(), match.end(), "L") for match in string_pattern.finditer(expression)]
        spans.extend((call["start"], call["end"], "C") for call in calls if call["end"] is not None)
        for match in input_pattern.finditer(expression):
            spans.append((match.start(), match.end(), "I"))
        for start, end, marker in sorted(spans, reverse=True):
            structure[start:end] = [marker] + [" "] * (end - start - 1)
        structure = "".join(structure)
        structure = re.sub(r"\$\w+", "V", structure)
        terms = r"(?:L|C|I|V|-?\d+|true|false|null)"
        return bool(re.fullmatch(rf"\s*{terms}(?:\s*\.\s*{terms})*\s*", structure, re.I))

    php_language_constructs = {"array", "empty", "eval", "isset", "list", "unset"}

    def scan_call_sites(expression):
        """Find balanced PHP call spans while retaining offsets and call kind."""
        masked = list(expression)
        index = 0
        quote = None
        escaped = False
        block_comment = False
        while index < len(expression):
            if block_comment:
                if expression.startswith("*/", index):
                    for pos in (index, index + 1):
                        masked[pos] = " "
                    block_comment = False
                    index += 2
                else:
                    if expression[index] != "\n":
                        masked[index] = " "
                    index += 1
                continue
            if quote:
                char = expression[index]
                if expression[index] != "\n":
                    masked[index] = " "
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                index += 1
                continue
            if expression.startswith("/*", index):
                masked[index:index + 2] = [" ", " "]
                block_comment = True
                index += 2
                continue
            if expression.startswith("//", index) or expression[index] == "#":
                end = expression.find("\n", index)
                end = len(expression) if end < 0 else end
                for pos in range(index, end):
                    masked[pos] = " "
                index = end
                continue
            if expression[index] in ("'", '"', "`"):
                quote = expression[index]
                masked[index] = " "
                index += 1
                continue
            index += 1

        code = "".join(masked)
        calls = []
        constructor_matches = list(re.finditer(
            r"\bnew\s+(\\?[A-Za-z_]\w*(?:\\[A-Za-z_]\w*)*)\s*(\()",
            code,
            re.I,
        ))
        constructor_terminal_starts = set()
        for match in constructor_matches:
            class_name = match.group(1)
            terminal_name = class_name.rsplit("\\", 1)[-1]
            constructor_terminal_starts.add(
                match.start(1) + len(class_name) - len(terminal_name)
            )
            depth = 1
            close = match.end(2)
            while close < len(code) and depth:
                if code[close] == "(":
                    depth += 1
                elif code[close] == ")":
                    depth -= 1
                close += 1
            calls.append({
                "name": class_name,
                "kind": "constructor",
                "start": match.start(1),
                "open": match.end(2) - 1,
                "end": close if depth == 0 else None,
                "args_end": close - 1 if depth == 0 else len(expression),
            })
        for match in re.finditer(r"\b([A-Za-z_]\w*)\s*(\()", code):
            name = match.group(1)
            if match.start(1) in constructor_terminal_starts:
                continue
            if name.lower() in php_language_constructs:
                continue
            prefix = code[:match.start(1)].rstrip()
            kind = "method" if prefix.endswith("->") else (
                "static method" if prefix.endswith("::") else "function"
            )
            depth = 1
            close = match.end(2)
            while close < len(code) and depth:
                if code[close] == "(":
                    depth += 1
                elif code[close] == ")":
                    depth -= 1
                close += 1
            calls.append({
                "name": name,
                "kind": kind,
                "start": match.start(1),
                "open": match.end(2) - 1,
                "end": close if depth == 0 else None,
                "args_end": close - 1 if depth == 0 else len(expression),
            })
        return calls

    def evaluate_expression(expression, file, number, diagnostic_only=False, source_column=None):
        """Return only provenance supported by known parameter-to-return summaries."""
        if source_column is None:
            source_text = source_lines_by_file.get(file, [])
            source_line = source_text[number - 1] if 0 < number <= len(source_text) else ""
            offset = source_line.find(expression.strip())
            source_column = offset + 1 if offset >= 0 else 1
        if presence_ternary_pattern.fullmatch(expression.strip()):
            direct, presence, uncertain = classify_request_expression(expression)
            return direct, presence, uncertain, [], [], [], [], [], False
        calls = scan_call_sites(expression)
        base_chars = list(expression)
        call_results, call_edges, unresolved_calls = [], [], []
        unresolved_refs = []
        for call in calls:
            name = call["name"]
            preceding = expression[:call["start"]]
            call_line = number + preceding.count("\n")
            call_column = (
                source_column + len(preceding)
                if "\n" not in preceding
                else len(preceding.rsplit("\n", 1)[-1]) + 1
            )
            if call["end"] is None:
                reason = "incomplete or ambiguous call syntax"
                unresolved_calls.append((name, file, call_line, reason, call_column, call["kind"]))
                continue
            raw_arguments = expression[call["open"] + 1:call["args_end"]]
            arguments = split_call_arguments(raw_arguments)
            available_candidates = [] if call["kind"] != "function" else [
                candidate for candidate in function_summaries.get(name.lower(), [])
                if candidate[1] == root_file or candidate[1] in visited
            ]
            summary_entry = available_candidates[0] if available_candidates else None
            summary = summary_entry[0] if summary_entry else None
            reason = None
            builtin_transform_category = (
                transformation_category(name)
                if call["kind"] == "function"
                and name.lower() in {
                    "escapeshellarg", "escapeshellcmd", "basename", "realpath",
                }
                else None
            )
            if builtin_transform_category:
                if len(arguments) != 1 or not supported_call_argument(arguments[0]):
                    reason = "recognized transformation requires one supported argument"
                else:
                    parameter_name = (
                        re.fullmatch(r"\$(\w+)", arguments[0])
                    )
                    summary = {
                        "params": [parameter_name.group(1) if parameter_name else "value"],
                        "required_count": 1,
                        "parameter": parameter_name.group(1) if parameter_name else "value",
                        "return_variable": parameter_name.group(1) if parameter_name else "value",
                        "return_line": call_line,
                        "aliases": [],
                        "return_kind": "transformed",
                        "return_expression": f"{name}({arguments[0]})",
                        "return_category": builtin_transform_category,
                        "file": file,
                        "definition_line": call_line,
                        "built_in_transform": True,
                    }
                    summary_entry = (summary, file, call_line, "built-in transform", None)
            if call["kind"] == "constructor":
                reason = "constructor behavior is not summarized"
            elif call["kind"] != "function":
                reason = f"{call['kind']} return behavior is not summarized"
            elif summary_entry is None:
                reason = "no statically available definition"
            elif len(available_candidates) > 1:
                reason = "duplicate function definitions"
            elif summary is None:
                reason = summary_entry[3]
                definition_key = (summary_entry[1].resolve(), summary_entry[2], name.lower())
                if definition_key not in function_definition_diagnostics_seen:
                    function_definition_diagnostics_seen.add(definition_key)
                    unresolved.append(
                        f"  Unresolved function definition {name} at {summary_entry[1].name}:{summary_entry[2]}: {reason}."
                    )
                    failure = summary_entry[4]
                    if failure:
                        unresolved.append(
                            f"    First unsupported statement at {failure[0].name}:{failure[1]}: {failure[2]} (cannot summarize: {reason})."
                        )
            elif (
                len(arguments) < summary["required_count"]
                or len(arguments) > len(summary["params"])
            ):
                reason = "argument count does not match the supported definition"
            elif not all(supported_call_argument(arg) for arg in arguments):
                reason = "call arguments use unsupported expressions"
            if reason:
                unresolved_calls.append((name, file, call_line, reason, call_column, call["kind"]))
                for method, key in input_pattern.findall(raw_arguments):
                    unresolved_refs.append((method, key, file, number, expression))
            else:
                branch_paths = summary.get("branch_paths")
                paths = branch_paths or [{
                    "parameter": summary["parameter"],
                    "kind": "identity",
                    "expression": f"${summary['return_variable']}",
                    "return_line": summary["return_line"],
                }]
                if branch_paths:
                    resolved_paths = []
                    for branch_path in paths:
                        resolved_kind = validate_branch_return_path(branch_path)
                        if resolved_kind is None:
                            reason = (
                                "branch return expression "
                                f"{branch_path['expression']} is not a uniquely summarized identity or recognized transform"
                            )
                            break
                        resolved_paths.append({**branch_path, "resolved_kind": resolved_kind})
                    if reason:
                        unresolved_calls.append((name, file, call_line, reason, call_column, call["kind"]))
                        for method, key in input_pattern.findall(raw_arguments):
                            unresolved_refs.append((method, key, file, number, expression))
                    else:
                        paths = resolved_paths
                for branch_path in paths:
                    if reason:
                        break
                    returned_argument_index = summary["params"].index(branch_path["parameter"])
                    if returned_argument_index >= len(arguments):
                        reason = "return value depends on an optional parameter that was omitted"
                        unresolved_calls.append((name, file, call_line, reason, call_column, call["kind"]))
                        for method, key in input_pattern.findall(raw_arguments):
                            unresolved_refs.append((method, key, file, number, expression))
                        continue
                    returned_argument = arguments[returned_argument_index]
                    records = []
                    inherited_edges = []
                    argument_variable = re.fullmatch(r"\$(\w+)", returned_argument)
                    argument_input = input_pattern.fullmatch(returned_argument)
                    if argument_variable:
                        variable = argument_variable.group(1)
                        records.extend(origins.get(variable, []))
                        inherited_edges.extend(edges.get(variable, []))
                    elif argument_input:
                        method, key = argument_input.groups()
                        records.append((method.upper(), key, file, number))
                        if not diagnostic_only:
                            inputs.append((method.upper(), key, file, number, expression))
                    if records:
                        if branch_paths:
                            event = (
                                "function-branch",
                                file,
                                number,
                                name,
                                summary["file"],
                                summary["definition_line"],
                                summary["switch_expression"],
                                branch_path["condition"],
                                branch_path["branch_line"],
                                branch_path["return_line"],
                                branch_path.get("shared_return_line"),
                                branch_path["parameter"],
                                returned_argument,
                                branch_path["resolved_kind"],
                                branch_path["expression"],
                                tuple(summary.get("prelude", [])),
                            )
                        elif summary.get("built_in_transform"):
                            event = (
                                "builtin-transformed",
                                file,
                                call_line,
                                name,
                                returned_argument,
                                summary["return_expression"],
                                summary["return_category"],
                            )
                        elif summary.get("return_kind") == "transformed":
                            event = (
                                "function-transformed",
                                file,
                                number,
                                name,
                                summary["file"],
                                summary["definition_line"],
                                summary["parameter"],
                                returned_argument,
                                summary["return_line"],
                                summary["return_expression"],
                                summary.get("return_category", "other-transformation"),
                            )
                        else:
                            event = (
                                "function",
                                file,
                                number,
                                name,
                                summary["file"],
                                summary["definition_line"],
                                summary["parameter"],
                                returned_argument,
                                summary["return_line"],
                                tuple(summary["aliases"]),
                                summary["return_variable"],
                            )
                        call_results.extend(records)
                        call_edges.extend(inherited_edges)
                        call_edges.append(event)
            if call["end"] is not None:
                for index in range(call["start"], call["end"]):
                    base_chars[index] = " "
        base = "".join(base_chars)
        if calls and not diagnostic_only and not supported_call_expression(
            expression, calls,
        ):
            expression_key = (file.resolve(), number, expression)
            if expression_key not in function_expression_diagnostics_seen:
                function_expression_diagnostics_seen.add(expression_key)
                unresolved.append(
                    f"  Unresolved function-call expression at {file.name}:{number}: {expression} (call-containing expression is unsupported; no additional call site inferred)."
                )
            call_results.clear()
            call_edges.clear()
        if diagnostic_only:
            for call in calls:
                if call["end"] is None and call["kind"] == "function":
                    incomplete_name = call["name"]
                    candidates = [
                        candidate
                        for candidate in function_summaries.get(incomplete_name.lower(), [])
                        if candidate[1] == root_file or candidate[1] in visited
                    ]
                else:
                    candidates = []
                if candidates and len(candidates) == 1 and candidates[0][0] is None:
                    candidate = candidates[0]
                    definition_key = (candidate[1].resolve(), candidate[2], incomplete_name.lower())
                    if definition_key not in function_definition_diagnostics_seen:
                        function_definition_diagnostics_seen.add(definition_key)
                        unresolved.append(
                            f"  Unresolved function definition {incomplete_name} at {candidate[1].name}:{candidate[2]}: {candidate[3]}."
                        )
                        failure = candidate[4]
                        if failure:
                            unresolved.append(
                                f"    First unsupported statement at {failure[0].name}:{failure[1]}: {failure[2]} (cannot summarize: {candidate[3]})."
                            )
            call_results.clear()
            call_edges.clear()
        direct, presence, uncertain = classify_request_expression(base)
        refs = [name for name in variable_pattern.findall(base) if name in origins]
        unsupported = bool(unresolved_calls) or has_unsupported_assignment_expression(base)
        if unsupported:
            call_results.clear()
            call_edges.clear()
        return direct, presence, uncertain, refs, call_results, call_edges, unresolved_calls, unresolved_refs, unsupported

    def record_call_uncertainty(unresolved_calls, file, number, expression):
        for name, call_file, call_line, reason, call_column, call_kind in unresolved_calls:
            key = (call_file.resolve(), call_line, call_column, call_kind, name.lower())
            if key not in function_call_diagnostics_seen:
                function_call_diagnostics_seen.add(key)
                labels = {
                    "method": "method",
                    "static method": "static method",
                    "constructor": "constructor",
                    "function": "function",
                }
                label = labels.get(call_kind, "function")
                unresolved.append(
                    f"  Unresolved {label} call {name} at {call_file.name}:{call_line} (column {call_column}): {reason}; return provenance is not inferred."
                )
        expression_key = (file.resolve(), number, expression)
        if unresolved_calls and expression_key not in function_expression_diagnostics_seen:
            function_expression_diagnostics_seen.add(expression_key)
            unresolved.append(
                f"  Unresolved function-call expression at {file.name}:{number}: {expression}"
            )

    def trace_sink_expression(line, code_line, file, number, sink_type, conditional=False, active_guards=None):
        expression = sink_expression(line, code_line, sink_type)
        if expression is None:
            return [], [], [], [], [], False
        direct, _, uncertain, refs, call_records, call_edges, unresolved_calls, unresolved_refs, unsupported = evaluate_expression(
            expression, file, number
        )
        # Output calls are diagnosed by the bounded source-position collector below.
        # The line-local sink expression can be a partial slice of multiline output.
        if sink_type != "output":
            record_call_uncertainty(unresolved_calls, file, number, expression)
        unresolved_request_inputs.extend(unresolved_refs)
        if unsupported:
            if refs or direct or uncertain:
                unresolved.append(
                    f"  Unresolved sink expression at {file.name}:{number}: {expression}; call result or expression semantics are unsupported."
                )
            return [], [], [], [], [], True
        for method, key in direct:
            input_text = line.strip() + (" [conditional branch]" if conditional else "")
            inputs.append((method, key, file, number, input_text))
            if conditional:
                conditional_inputs.append((method, key, file, number, line.strip()))
        if conditional:
            for method, key, source_file, source_line in call_records:
                if source_file == file and source_line == number:
                    conditional_inputs.append((method, key, file, number, line.strip()))
        tracked = [name for name in refs if name in origins]
        invalidated_refs = [name for name in variable_pattern.findall(expression) if name in invalidated]
        snapshot = [
            (name, list(origins.get(name, [])), list(edges.get(name, [])))
            for name in tracked
        ]
        if call_records:
            snapshot.append(("$function_result", call_records, call_edges))
        if active_guards:
            snapshot.append(("$guard", [], guard_edges(active_guards)))
        return direct, tracked, invalidated_refs, snapshot, call_records, False

    def mask_output_comments(expression):
        """Mask PHP comments while preserving quoted text and source offsets."""
        chars = list(expression)
        quote = None
        escaped = False
        index = 0
        while index < len(expression):
            if quote:
                if escaped:
                    escaped = False
                elif expression[index] == "\\":
                    escaped = True
                elif expression[index] == quote:
                    quote = None
                index += 1
                continue
            if expression[index] in ("'", '"', "`"):
                quote = expression[index]
                index += 1
                continue
            if expression.startswith("/*", index):
                end = expression.find("*/", index + 2)
                stop = len(expression) if end < 0 else end + 2
                for position in range(index, stop):
                    if chars[position] != "\n":
                        chars[position] = " "
                index = stop
                continue
            if expression.startswith("//", index) or expression[index] == "#":
                end = expression.find("\n", index)
                stop = len(expression) if end < 0 else end
                for position in range(index, stop):
                    chars[position] = " "
                index = stop
                continue
            index += 1
        return "".join(chars)

    def collect_output_expression(lines, code_lines, start_index):
        """Collect one bounded output statement for diagnostics only."""
        first_code = code_lines[start_index]
        match = re.search(r"\b(?:echo|print|printf)\b", first_code)
        if not match:
            return None
        expression_start = match.end()
        while expression_start < len(lines[start_index]) and lines[start_index][expression_start].isspace():
            expression_start += 1
        pieces = [lines[start_index][expression_start:]]
        start_column = expression_start + 1
        depth = 0
        for index in range(start_index, len(lines)):
            code = code_lines[index]
            begin = expression_start if index == start_index else 0
            # A new statement at an expression continuation boundary is ambiguous;
            # stop before it so a missing terminator cannot absorb following code.
            if index > start_index and re.match(
                r"\s*(?:\$\w+\s*=|(?:echo|print|printf)\b|(?:mysqli_query|mysql_query|pg_query|sqlite_query)\s*\(|})",
                code,
                re.I,
            ):
                return mask_output_comments("\n".join(pieces)), start_column, True
            terminated = False
            line_piece = lines[index][begin:]
            if index > start_index:
                pieces.append(line_piece)
            for offset, char in enumerate(code[begin:]):
                if char == ";" and depth == 0:
                    if index == start_index:
                        pieces[0] = lines[index][begin:begin + offset]
                    else:
                        pieces[-1] = line_piece[:offset]
                    terminated = True
                    break
                if char in "([":
                    depth += 1
                elif char in ")]":
                    depth -= 1
                    if depth < 0:
                        return mask_output_comments("\n".join(pieces)), start_column, True
            if terminated:
                return mask_output_comments("\n".join(pieces)), start_column, False
        return mask_output_comments("\n".join(pieces)), start_column, True

    def diagnose_output_calls(lines, code_lines, start_index, file, number):
        """Report unresolved output calls without recording any flow evidence."""
        collected = collect_output_expression(lines, code_lines, start_index)
        if collected is None:
            return
        expression, start_column, incomplete = collected
        evaluated = evaluate_expression(
            expression, file, number, diagnostic_only=True,
            source_column=start_column,
        )
        unresolved_calls = evaluated[6]
        if incomplete and not unresolved_calls:
            return
        record_call_uncertainty(unresolved_calls, file, number, expression)

    def simple_if_condition(text):
        match = re.fullmatch(r"if\s*\((.+)\)\s*(\{)?", text)
        if not match:
            return None, False
        condition = match.group(1).strip()
        if not condition or any(char in condition for char in "{};"):
            return None, False
        return condition, bool(match.group(2))

    def guard_edges(guards):
        return [
            ("guard", file, line, condition, arm)
            for file, line, condition, arm in guards
        ]

    def merge_guarded_branch(frame, left_origins, left_edges, right_origins, right_edges, file, number):
        names = set(left_origins) | set(right_origins)
        merged_origins = {}
        merged_edges = {}
        for name in names:
            left = left_origins.get(name, [])
            right = right_origins.get(name, [])
            left_keys = {(record[0], record[1], record[2], record[3]) for record in left}
            right_keys = {(record[0], record[1], record[2], record[3]) for record in right}
            if left_keys == right_keys:
                if left_keys:
                    merged_origins[name] = list(dict.fromkeys(left + right))
                    merged_edges[name] = list(dict.fromkeys(
                        left_edges.get(name, []) + right_edges.get(name, [])
                    ))
            elif left_keys or right_keys or name in frame["changed"]:
                invalidated[name] = (file, number)
                unresolved.append(
                    f"  Unresolved conditional join for ${name} at {file.name}:{number}: branch provenance differs or is incomplete."
                )
        return merged_origins, merged_edges

    def call_arguments_from_line(line, code_line, match):
        opening = code_line.find("(", match.start(), match.end())
        if opening < 0:
            return None
        depth, closing = 1, opening + 1
        while closing < len(code_line) and depth:
            if code_line[closing] == "(":
                depth += 1
            elif code_line[closing] == ")":
                depth -= 1
            closing += 1
        if depth:
            return None
        return split_call_arguments(line[opening + 1:closing - 1])

    def current_guard_context(frame, file, number, text):
        if frame is None or frame["unsupported"]:
            return []
        guards = list(frame["guards"])
        condition, _ = simple_if_condition(text)
        if condition is not None:
            guards.append((file, number, condition, "then"))
        return guards

    def visit(file):
        file = file.resolve()
        if file in active:
            includes.append(f"  Unresolved include cycle at {file.name}; recursion stopped.")
            return
        if file in visited:
            return
        active.append(file)
        visited.add(file)
        try:
            source_text = file.read_text(errors="ignore")
            lines = source_text.splitlines()
        except OSError:
            active.pop()
            return
        source_lines_by_file[file] = lines
        source_text_by_file[file] = source_text
        form_controls.extend(static_form_controls(file, "\n".join(lines)))
        pending_sql_statements = {}
        prepared_query_sources = {}
        prepared_statements = {}
        depth = 0
        lexical_state = {
            "php": False,
            "block_comment": False,
            "quote": None,
            "escaped": False,
        }
        code_lines = []
        for source_line in lines:
            code_lines.append(mask_php_sink_code(source_line, lexical_state))
        conditional_frame = None
        for line_index, line in enumerate(lines):
            number = line_index + 1
            text = line.strip()
            code_line = code_lines[line_index]
            if conditional_frame is not None and conditional_frame["unsupported"]:
                unsupported_source_lines.add((file.resolve(), number))
            guards_by_source_line[(file.resolve(), number)] = current_guard_context(
                conditional_frame, file, number, text
            )
            if number in function_ranges.get(file, set()):
                continue
            statement_match = sql_statement_pattern.match(text)
            if statement_match and code_line.strip():
                variable, _, operation = statement_match.groups()
                operation = operation.upper()
                pending_sql_statements.setdefault(variable, []).append((operation, number))
                action = "retrieval" if operation == "SELECT" else "write"
                database_observations.append((
                    f"Database {action} statement construction ({operation})",
                    file, number, text,
                ))
                literal_match = re.fullmatch(
                    r"\s*\$\w+\s*=\s*(['\"])(.*?)\1\s*;\s*", text
                )
                if literal_match and "\\" not in literal_match.group(2):
                    prepared_query_sources[variable] = {
                        "operation": operation,
                        "query_line": number,
                        "query_text": text,
                        "placeholder_count": literal_match.group(2).count("?"),
                        "guards": current_guard_context(
                            conditional_frame, file, number, text
                        ),
                        "supported": True,
                    }
                else:
                    prepared_query_sources[variable] = {
                        "operation": operation,
                        "query_line": number,
                        "query_text": text,
                        "placeholder_count": None,
                        "guards": current_guard_context(
                            conditional_frame, file, number, text
                        ),
                        "supported": False,
                    }
            query_match = re.search(r"->\s*(?:query|exec)\s*\(\s*\$(\w+)", code_line, re.I)
            if query_match:
                variable = query_match.group(1)
                statements = pending_sql_statements.pop(variable, [])
                operations = {operation for operation, _ in statements}
                if operations:
                    operation_label = next(iter(operations)) if len(operations) == 1 else "operation unresolved"
                    action = "retrieval" if operations == {"SELECT"} else "write" if operations <= {"INSERT", "UPDATE", "DELETE"} else "query"
                    database_observations.append((
                        f"Database {action} execution ({operation_label}) using ${variable}; statement construction line(s) "
                        + (", ".join(str(statement_line) for _, statement_line in statements) or "unknown"),
                        file, number, text,
                    ))

            prepare_match = re.search(
                r"\$(\w+)\s*=\s*\$\w+\s*->\s*prepare\s*\(\s*\$(\w+)\s*\)",
                code_line,
                re.I,
            )
            if prepare_match:
                statement_variable, query_variable = prepare_match.groups()
                query_source = prepared_query_sources.get(query_variable)
                statement = {
                    "file": file,
                    "statement_variable": statement_variable,
                    "query_variable": query_variable,
                    "prepare_line": number,
                    "prepare_text": text,
                    "prepare_guards": current_guard_context(
                        conditional_frame, file, number, text
                    ),
                    "query": dict(query_source) if query_source else None,
                    "bindings": [],
                    "execute_lines": [],
                    "unresolved": None,
                }
                if statement_variable in prepared_statements:
                    statement["unresolved"] = (
                        "statement variable is prepared more than once; query mapping is ambiguous"
                    )
                    prepared_statements[statement_variable]["unresolved"] = statement["unresolved"]
                    unresolved.append(
                        f"  Unresolved prepared-statement mapping at {file.name}:{number}: ${statement_variable} is prepared more than once."
                    )
                elif not query_source:
                    statement["unresolved"] = (
                        f"no supported static query assignment for ${query_variable}"
                    )
                    unresolved.append(
                        f"  Unresolved prepared-statement query at {file.name}:{number}: no supported static query assignment for ${query_variable}."
                    )
                elif not query_source["supported"]:
                    statement["unresolved"] = (
                        "query expression is not one supported static string literal"
                    )
                    unresolved.append(
                        f"  Unresolved prepared-statement query at {file.name}:{query_source['query_line']}: query expression is not one supported static string literal."
                    )
                elif query_source["placeholder_count"] < 1:
                    statement["unresolved"] = "query has no supported positional placeholders"
                    unresolved.append(
                        f"  Unresolved prepared-statement query at {file.name}:{query_source['query_line']}: no positional placeholder was observed."
                    )
                elif conditional_frame is not None and conditional_frame["unsupported"]:
                    statement["unresolved"] = "prepare call is inside unsupported conditional control flow"
                    unresolved.append(
                        f"  Unresolved prepared-statement prepare call at {file.name}:{number}: enclosing conditional control flow is unsupported."
                    )
                prepared_statements[statement_variable] = statement
                prepared_statement_observations.append(statement)

            bind_match = re.search(
                r"\$(\w+)\s*->\s*bind_param\s*\(", code_line, re.I
            )
            if bind_match:
                statement_variable = bind_match.group(1)
                statement = prepared_statements.get(statement_variable)
                arguments = call_arguments_from_line(line, code_line, bind_match)
                reason = None
                if statement is None:
                    reason = "no unique supported prepare() call is associated with this statement variable"
                elif statement["unresolved"]:
                    reason = statement["unresolved"]
                elif arguments is None or not arguments:
                    reason = "bind_param() arguments are incomplete or unsupported"
                else:
                    type_match = re.fullmatch(r"(['\"])([idsb]+)\1", arguments[0])
                    variables = arguments[1:]
                    query = statement["query"]
                    if not type_match:
                        reason = "bind_param() type string is not a supported literal"
                    elif any(not re.fullmatch(r"\$\w+", item) for item in variables):
                        reason = "bind_param() includes an unsupported or ambiguous parameter expression"
                    elif len(type_match.group(2)) != len(variables):
                        reason = "bind_param() type and variable counts do not match"
                    elif len(variables) != query["placeholder_count"]:
                        reason = "bind_param() variable count does not match the query placeholder count"
                if reason:
                    if statement is not None:
                        statement["unresolved"] = reason
                    unresolved.append(
                        f"  Unresolved prepared-statement binding at {file.name}:{number}: {reason}."
                    )
                elif conditional_frame is not None and conditional_frame["unsupported"]:
                    statement["unresolved"] = "binding occurs inside unsupported conditional control flow"
                    unresolved.append(
                        f"  Unresolved prepared-statement binding at {file.name}:{number}: enclosing conditional control flow is unsupported."
                    )
                elif depth > 0 and conditional_frame is None:
                    statement["unresolved"] = "binding occurs inside unsupported enclosing control flow"
                    unresolved.append(
                        f"  Unresolved prepared-statement binding at {file.name}:{number}: enclosing control flow is unsupported."
                    )
                else:
                    variables = arguments[1:]
                    if statement["bindings"]:
                        statement["unresolved"] = "multiple bind_param() calls create an ambiguous parameter mapping"
                        unresolved.append(
                            f"  Unresolved prepared-statement binding at {file.name}:{number}: multiple bind_param() calls create an ambiguous parameter mapping."
                        )
                    else:
                        statement["bindings"] = [
                            {
                                "position": index + 1,
                                "type": type_match.group(2)[index],
                                "variable": item[1:],
                                "line": number,
                                "text": text,
                                "records": list(origins.get(item[1:], [])),
                                "edges": list(edges.get(item[1:], [])),
                                "guards": current_guard_context(
                                    conditional_frame, file, number, text
                                ),
                                "invalidated": item[1:] in invalidated,
                            }
                            for index, item in enumerate(variables)
                        ]

            execute_match = re.search(
                r"\$(\w+)\s*->\s*execute\s*\(", code_line, re.I
            )
            if execute_match:
                statement_variable = execute_match.group(1)
                statement = prepared_statements.get(statement_variable)
                arguments = call_arguments_from_line(line, code_line, execute_match)
                reason = None
                if statement is None:
                    reason = "no unique supported prepare() call is associated with this statement variable"
                elif statement["unresolved"]:
                    reason = statement["unresolved"]
                elif arguments is None or arguments:
                    reason = "execute() arguments are unsupported; parameter mapping cannot be established"
                elif conditional_frame is not None and conditional_frame["unsupported"]:
                    reason = "execute() occurs inside unsupported conditional control flow"
                elif depth > 0 and conditional_frame is None:
                    reason = "execute() occurs inside unsupported enclosing control flow"
                else:
                    expected = statement["query"]["placeholder_count"]
                    if len(statement["bindings"]) != expected:
                        reason = "observed bindings do not cover every query placeholder exactly once"
                if reason:
                    unresolved.append(
                        f"  Unresolved prepared-statement execution at {file.name}:{number}: {reason}."
                    )
                    if statement is not None:
                        statement["unresolved"] = reason
                else:
                    execution_guards = current_guard_context(
                        conditional_frame, file, number, text
                    )
                    statement["execute_lines"].append((number, text, execution_guards))
                    operation = statement["query"]["operation"]
                    database_observations.append((
                        f"Database prepared statement execution ({operation}) using ${statement_variable}; "
                        f"query construction line {statement['query']['query_line']}; binding line(s) "
                        + ", ".join(str(binding["line"]) for binding in statement["bindings"]),
                        file, number, text,
                    ))
                    sink_observations.append((
                        "SQL/prepared statement execution", file, number,
                        text, " [conditional context; flow not established]" if execution_guards else "",
                    ))
                    for binding in statement["bindings"]:
                        if binding["invalidated"]:
                            unresolved.append(
                                f"  Unresolved prepared-statement source at {file.name}:{binding['line']}: ${binding['variable']} provenance was invalidated before binding."
                            )
                            continue
                        if binding["records"]:
                            prepared_statement_flows.append({
                                "statement": statement,
                                "binding": binding,
                                "execute_line": number,
                                "execute_text": text,
                                "guards": list(dict.fromkeys(
                                    statement["prepare_guards"]
                                    + binding["guards"]
                                    + execution_guards
                                )),
                            })
            branch = bool(re.match(r"(?:if|else|elseif|switch|for|foreach|while|function|try|catch)\b", text))
            conditional_context = branch or depth > 0
            observed_sinks = []
            if re.search(
                r"\b(?:mysqli_query|mysqli_multi_query|mysql_query|pg_query|sqlite_query)\s*\(|->\s*(?:query|exec|prepare)\s*\(",
                code_line,
                re.I,
            ):
                observed_sinks.append("SQL/query")
            if re.search(r"\b(?:echo|print|printf)\b", code_line):
                observed_sinks.append("output")
            for operation_name in dangerous_operation_names:
                if re.search(
                    rf"(?<!->)\b{re.escape(operation_name)}\s*\(",
                    code_line,
                    re.I,
                ):
                    observed_sinks.append(
                        f"Dangerous server-side operation: {operation_name}"
                    )
            excerpt = text if len(text) <= 200 else text[:197] + "..."
            for sink_type in observed_sinks:
                context = " [conditional context; flow not established]" if conditional_context else ""
                sink_observations.append(
                    (sink_type, file, number, excerpt, context)
                )
            if "output" in observed_sinks:
                diagnose_output_calls(lines, code_lines, line_index, file, number)

            simple_if = re.fullmatch(r"if\s*\([^{}]*\)\s*\{\s*", text)
            next_line_if = (
                re.fullmatch(r"if\s*\([^{}]*\)\s*", text)
                and line_index + 1 < len(lines)
                and lines[line_index + 1].strip() == "{"
            )
            if conditional_frame is None and (simple_if or next_line_if):
                outer_condition, _ = simple_if_condition(text)
                conditional_frame = {
                    "entry_origins": {key: list(value) for key, value in origins.items()},
                    "entry_edges": {key: list(value) for key, value in edges.items()},
                    "entry_invalidated": dict(invalidated),
                    "then_state": None,
                    "arm": "then",
                    "depth": 1,
                    "unsupported": False,
                    "changed": {},
                    "flow_sink_start": len(sinks),
                    "opening_brace_line": line_index + 1 if next_line_if else None,
                    "nested_blocks": [],
                    "guards": [(file, number, outer_condition or text, "then")],
                }
                depth += 1
                continue

            if conditional_frame is not None:
                frame = conditional_frame
                if frame["opening_brace_line"] == line_index and text == "{":
                    frame["opening_brace_line"] = None
                    continue
                nested_blocks = frame["nested_blocks"]
                if nested_blocks and nested_blocks[-1].get("waiting_open") and text == "{":
                    nested_blocks[-1]["waiting_open"] = False
                    frame["depth"] += code_line.count("{") - code_line.count("}")
                    depth += line.count("{") - line.count("}")
                    continue

                nested_condition, has_open_brace = simple_if_condition(text)
                if nested_condition is not None and frame["depth"] >= 1:
                    if nested_blocks:
                        if not frame["unsupported"]:
                            unresolved.append(
                                f"  Unresolved unsupported conditional structure at {file.name}:{number}: {text}"
                            )
                            del sinks[frame["flow_sink_start"]:]
                        frame["unsupported"] = True
                    else:
                        nested_blocks.append({
                            "condition": nested_condition,
                            "condition_file": file,
                            "condition_line": number,
                            "phase": "then",
                            "waiting_open": not has_open_brace,
                            "entry_origins": {key: list(value) for key, value in origins.items()},
                            "entry_edges": {key: list(value) for key, value in edges.items()},
                            "then_origins": None,
                            "then_edges": None,
                            "changed_before": set(frame["changed"]),
                        })
                        frame["guards"].append((file, number, nested_condition, "then"))
                    frame["depth"] += code_line.count("{") - code_line.count("}")
                    depth += line.count("{") - line.count("}")
                    continue

                if nested_blocks and nested_blocks[-1]["phase"] == "await_else" and text in {"else", "else {"}:
                    nested = nested_blocks[-1]
                    nested["phase"] = "else"
                    nested["waiting_open"] = text == "else"
                    frame["guards"].append((
                        nested["condition_file"], nested["condition_line"],
                        nested["condition"], "else (condition false)"
                    ))
                    frame["depth"] += code_line.count("{") - code_line.count("}")
                    depth += line.count("{") - line.count("}")
                    continue

                if text == "}" and frame["depth"] > 1 and nested_blocks:
                    nested = nested_blocks[-1]
                    if nested["phase"] == "then":
                        frame["guards"] = [
                            guard for guard in frame["guards"]
                            if not (guard[0] == file and guard[2] == nested["condition"] and guard[3] == "then")
                        ]
                        next_index = line_index + 1
                        while next_index < len(lines) and not lines[next_index].strip():
                            next_index += 1
                        next_text = lines[next_index].strip() if next_index < len(lines) else ""
                        if next_text in {"else", "else {"}:
                            nested["phase"] = "await_else"
                            nested["then_origins"] = {key: list(value) for key, value in origins.items()}
                            nested["then_edges"] = {key: list(value) for key, value in edges.items()}
                            origins.clear()
                            origins.update({key: list(value) for key, value in nested["entry_origins"].items()})
                            edges.clear()
                            edges.update({key: list(value) for key, value in nested["entry_edges"].items()})
                        else:
                            changed = set(frame["changed"]) - nested["changed_before"]
                            for name in changed:
                                before = nested["entry_origins"].get(name, [])
                                after = origins.get(name, [])
                                before_keys = {(record[0], record[1], record[2], record[3]) for record in before}
                                after_keys = {(record[0], record[1], record[2], record[3]) for record in after}
                                if not before_keys and after_keys:
                                    # This value is available only on the guarded branch;
                                    # retain its origin with the guard edge attached.
                                    continue
                                if before_keys == after_keys:
                                    origins[name] = list(dict.fromkeys(before + after))
                                    edges[name] = list(dict.fromkeys(
                                        nested["entry_edges"].get(name, []) + edges.get(name, [])
                                    ))
                                else:
                                    origins.pop(name, None)
                                    edges.pop(name, None)
                                    invalidated[name] = (file, number)
                                    unresolved.append(
                                        f"  Unresolved conditional assignment at {file.name}:{number}: ${name} differs across the guarded branch."
                                    )
                            nested_blocks.pop()
                    elif nested["phase"] == "else":
                        frame["guards"] = [
                            guard for guard in frame["guards"]
                            if not (guard[0] == file and guard[2] == nested["condition"] and guard[3] == "else (condition false)")
                        ]
                        merged_origins, merged_edges = merge_guarded_branch(
                            frame,
                            nested["then_origins"] or {}, nested["then_edges"] or {},
                            origins, edges, file, number,
                        )
                        origins.clear()
                        origins.update(merged_origins)
                        edges.clear()
                        edges.update(merged_edges)
                        nested_blocks.pop()
                    else:
                        if not frame["unsupported"]:
                            unresolved.append(
                                f"  Unresolved unsupported conditional structure at {file.name}:{number}: {text}"
                            )
                            del sinks[frame["flow_sink_start"]:]
                        frame["unsupported"] = True
                    frame["depth"] += code_line.count("{") - code_line.count("}")
                    depth += line.count("{") - line.count("}")
                    continue

                if re.fullmatch(r"\}\s*else\s*\{", text) and frame["arm"] == "then" and frame["depth"] == 1:
                    frame["then_state"] = (
                        {key: list(value) for key, value in origins.items()},
                        {key: list(value) for key, value in edges.items()},
                        dict(invalidated),
                    )
                    origins.clear()
                    origins.update({key: list(value) for key, value in frame["entry_origins"].items()})
                    edges.clear()
                    edges.update({key: list(value) for key, value in frame["entry_edges"].items()})
                    invalidated.clear()
                    invalidated.update(frame["entry_invalidated"])
                    frame["arm"] = "else"
                    continue

                if text == "else {" and frame["arm"] == "then" and frame["depth"] == 0:
                    frame["then_state"] = (
                        {key: list(value) for key, value in origins.items()},
                        {key: list(value) for key, value in edges.items()},
                        dict(invalidated),
                    )
                    origins.clear()
                    origins.update({key: list(value) for key, value in frame["entry_origins"].items()})
                    edges.clear()
                    edges.update({key: list(value) for key, value in frame["entry_edges"].items()})
                    invalidated.clear()
                    invalidated.update(frame["entry_invalidated"])
                    frame["arm"] = "else"
                    frame["depth"] = 1
                    depth += 1
                    continue

                if text == "}" and frame["depth"] == 1:
                    next_text = lines[line_index + 1].strip() if line_index + 1 < len(lines) else ""
                    if frame["arm"] == "then" and next_text == "else {":
                        frame["then_state"] = (
                            {key: list(value) for key, value in origins.items()},
                            {key: list(value) for key, value in edges.items()},
                            dict(invalidated),
                        )
                        origins.clear()
                        origins.update({key: list(value) for key, value in frame["entry_origins"].items()})
                        edges.clear()
                        edges.update({key: list(value) for key, value in frame["entry_edges"].items()})
                        invalidated.clear()
                        invalidated.update(frame["entry_invalidated"])
                        frame["depth"] = 0
                        depth -= 1
                        continue

                    if frame["arm"] == "else" and frame["then_state"] is not None:
                        then_origins, then_edges, then_invalidated = frame["then_state"]
                        else_origins = {key: list(value) for key, value in origins.items()}
                        else_edges = {key: list(value) for key, value in edges.items()}
                        else_invalidated = dict(invalidated)
                        all_names = set(frame["entry_origins"]) | set(then_origins) | set(else_origins)
                        origins.clear()
                        edges.clear()
                        invalidated.clear()
                        invalidated.update(frame["entry_invalidated"])
                        for name in all_names:
                            left = then_origins.get(name, [])
                            right = else_origins.get(name, [])
                            left_keys = {(record[0], record[1]) for record in left}
                            right_keys = {(record[0], record[1]) for record in right}
                            if left_keys == right_keys and left_keys:
                                origins[name] = list(dict.fromkeys(left + right))
                                edges[name] = list(dict.fromkeys(then_edges.get(name, []) + else_edges.get(name, [])))
                            elif left_keys or right_keys or name in frame["changed"]:
                                invalidated[name] = (file, number)
                                unresolved.append(
                                    f"  Unresolved conditional join for ${name} at {file.name}:{number}: branch provenance differs or is incomplete."
                                )
                    else:
                        for name, changed_at in frame["changed"].items():
                            if name in frame["entry_origins"] or name in frame["entry_invalidated"]:
                                origins.pop(name, None)
                                edges.pop(name, None)
                                invalidated[name] = changed_at
                                unresolved.append(
                                    f"  Unresolved conditional assignment at {changed_at[0].name}:{changed_at[1]}: ${name} may differ after the if block."
                                )
                            elif name in origins:
                                origins.pop(name, None)
                                edges.pop(name, None)
                                unresolved.append(
                                    f"  Unresolved conditional assignment at {changed_at[0].name}:{changed_at[1]}: ${name} may be unassigned outside the if block."
                                )
                            else:
                                origins.pop(name, None)
                                edges.pop(name, None)
                        for name, value in frame["entry_origins"].items():
                            if name not in frame["changed"]:
                                origins[name] = list(value)
                                edges[name] = list(frame["entry_edges"].get(name, []))
                    conditional_frame = None
                    depth = max(0, depth - 1)
                    continue

                nested_control = bool(
                    re.match(r"(?:if|elseif|else\s+if|else|switch|for|foreach|while|function|try|catch)\b", text)
                    or re.match(r"\}\s*(?:elseif|else\s+if)\b", text)
                )
                if nested_control or (frame["depth"] > 1 and not nested_blocks):
                    if not frame["unsupported"]:
                        unresolved.append(
                            f"  Unresolved unsupported conditional structure at {file.name}:{number}: {text}"
                        )
                        del sinks[frame["flow_sink_start"]:]
                    frame["unsupported"] = True

                if frame["unsupported"]:
                    for method, key in input_pattern.findall(line):
                        conditional_inputs.append((method, key, file, number, text))
                    assignment = assignment_pattern.match(line)
                    if assignment:
                        dest, _, rhs = assignment.groups()
                        direct, presence, uncertain, refs, call_records, _, unresolved_calls, unresolved_refs, _ = evaluate_expression(rhs, file, number)
                        record_call_uncertainty(unresolved_calls, file, number, rhs)
                        unresolved_request_inputs.extend(unresolved_refs)
                        for method, key in presence:
                            presence_inputs.append((method, key, file, number, text))
                        for method, key in direct + uncertain:
                            conditional_inputs.append((method, key, file, number, text))
                        for method, key in uncertain:
                            unresolved_request_inputs.append((method, key, file, number, text))
                        if dest in origins or direct or uncertain or refs or call_records or unresolved_calls:
                            invalidated[dest] = (file, number)
                            origins.pop(dest, None)
                            edges.pop(dest, None)
                else:
                    if include_pattern.match(line):
                        includes.append(
                            f"  Unresolved conditional/nested include at {file.name}:{number}: {text}"
                        )
                    assignment = assignment_pattern.match(line)
                    if assignment:
                        dest, op, rhs = assignment.groups()
                        frame["changed"][dest] = (file, number)
                        direct, presence, uncertain, refs, call_records, call_edges, unresolved_calls, unresolved_refs, unsupported = evaluate_expression(rhs, file, number)
                        record_call_uncertainty(unresolved_calls, file, number, rhs)
                        unresolved_request_inputs.extend(unresolved_refs)
                        for method, key in presence:
                            presence_inputs.append((method, key, file, number, text))
                        supported = (
                            bool(refs or direct or call_records)
                            and not uncertain
                            and not unsupported
                        )
                        prior = list(origins.get(dest, [])) if op == ".=" else []
                        prior_edges = list(edges.get(dest, [])) if op == ".=" else []
                        had_origin = dest in origins
                        origins.pop(dest, None)
                        edges.pop(dest, None)
                        if supported:
                            records, chain = prior + call_records, prior_edges + call_edges
                            chain.extend(guard_edges(frame["guards"]))
                            if call_records:
                                chain.append(("function-assignment", file, number, dest))
                            for method, key in direct:
                                record = (method, key, file, number)
                                records.append(record)
                                chain.append(("source-assignment", file, number, dest, method, key))
                                inputs.append((method, key, file, number, text + " [conditional branch]"))
                                conditional_inputs.append((method, key, file, number, text))
                            for ref in refs:
                                records.extend(origins.get(ref, []))
                                chain.extend(edges.get(ref, []))
                                chain.append((file, number, ref, dest))
                            origins[dest] = list(dict.fromkeys(records))
                            edges[dest] = chain
                        elif refs or direct or uncertain or had_origin or unresolved_calls:
                            invalidated[dest] = (file, number)
                            for method, key in direct + uncertain:
                                conditional_inputs.append((method, key, file, number, text))
                            for method, key in uncertain:
                                unresolved_request_inputs.append((method, key, file, number, text))
                            unresolved.append(
                                f"  Unresolved conditional assignment at {file.name}:{number}: {text} (expression semantics are unsupported)."
                            )

                    if observed_sinks:
                        for sink_type in observed_sinks:
                            direct, tracked, invalidated_refs, flow_snapshot, _, _ = trace_sink_expression(
                                line, code_line, file, number, sink_type, conditional=True,
                                active_guards=frame["guards"],
                            )
                            if direct or tracked or invalidated_refs or flow_snapshot:
                                invalidated_snapshot = {
                                    name: invalidated[name] for name in invalidated_refs
                                }
                                sinks.append((file, number, text, sink_type, direct, tracked, invalidated_refs, True, flow_snapshot, invalidated_snapshot))

                frame["depth"] += code_line.count("{") - code_line.count("}")
                depth += line.count("{") - line.count("}")
                continue

            if not text or text.startswith(("//", "#", "*")):
                depth += line.count("{") - line.count("}")
                continue
            if branch or depth > 0:
                assignment = assignment_pattern.match(line)
                if assignment:
                    dest, _, rhs = assignment.groups()
                    direct, presence, uncertain, refs, call_records, _, unresolved_calls, unresolved_refs, _ = evaluate_expression(rhs, file, number)
                    record_call_uncertainty(unresolved_calls, file, number, rhs)
                    unresolved_request_inputs.extend(unresolved_refs)
                    conditional_sources = direct + uncertain
                    for method, key in presence:
                        presence_inputs.append((method, key, file, number, text))
                    for method, key in uncertain:
                        unresolved_request_inputs.append((method, key, file, number, text))
                    if dest in origins or conditional_sources or refs or call_records or unresolved_calls:
                        unresolved.append(
                            f"  Unresolved conditional assignment at {file.name}:{number}: {text}"
                        )
                    for method, key in conditional_sources:
                        conditional_inputs.append(
                            (method, key, file, number, text)
                        )
                    if dest in origins:
                        invalidated[dest] = (file, number)
                    origins.pop(dest, None)
                    edges.pop(dest, None)
                if include_pattern.match(line):
                    includes.append(f"  Unresolved conditional/nested include at {file.name}:{number}: {text}")
                depth += line.count("{") - line.count("}")
                continue
            assignment = assignment_pattern.match(line)
            if not assignment:
                line_sources = source_references_on_line(line, code_line)
                if line_sources and not observed_sinks:
                    for method, key in line_sources:
                        unresolved_request_inputs.append((method, key, file, number, text))
            include = include_pattern.match(line)
            if include:
                kind, expr = include.groups()
                expr = expr.strip().strip("() ")
                literal = re.fullmatch(r"['\"]([^'\"]+\.php)['\"]", expr)
                based = re.fullmatch(r"(?:__DIR__|dirname\s*\(\s*__FILE__\s*\))\s*\.\s*['\"]([^'\"]+\.php)['\"]", expr)
                name = literal.group(1) if literal else (based.group(1) if based else None)
                if name is None:
                    includes.append(f"  Unresolved dynamic include at {file.name}:{number}: {text}")
                else:
                    include_path = name.lstrip("/") if based else name
                    target = (file.parent / include_path).resolve()
                    if not target.is_relative_to(root):
                        includes.append(f"  Unresolved out-of-root include at {file.name}:{number}: {name}")
                    elif not target.is_file():
                        includes.append(f"  Unresolved missing include at {file.name}:{number}: {name}")
                    else:
                        try:
                            target_lines = target.read_text(errors="ignore").splitlines()
                            target_line = next(
                                (
                                    line_number
                                    for line_number, target_line_text in enumerate(target_lines, 1)
                                    if input_pattern.search(target_line_text)
                                ),
                                1,
                            )
                        except OSError:
                            target_line = 1
                        includes.append(f"  Include evidence: {report_path(file)}:{number} -> {report_path(target)}:{target_line} ({kind}; static path {name})")
                        visit(target)
            assignment = assignment_pattern.match(line)
            if assignment:
                dest, op, rhs = assignment.groups()
                direct, presence, uncertain, refs, call_records, call_edges, unresolved_calls, unresolved_refs, unsupported = evaluate_expression(rhs, file, number)
                record_call_uncertainty(unresolved_calls, file, number, rhs)
                unresolved_request_inputs.extend(unresolved_refs)
                for method, key in presence:
                    presence_inputs.append((method, key, file, number, text))
                supported = (
                    bool(refs or direct or call_records)
                    and not uncertain
                    and not unsupported
                )
                if op == ".=":
                    supported = supported
                had_origin = dest in origins
                previous_records = origins.get(dest, []) if op == ".=" else []
                previous_edges = edges.get(dest, []) if op == ".=" else []
                if had_origin and op == "=" and (presence or uncertain or not supported):
                    invalidated[dest] = (file, number)
                if had_origin and op == "=" and unresolved_calls:
                    invalidated[dest] = (file, number)
                origins.pop(dest, None)
                edges.pop(dest, None)
                if supported:
                    records, chain = list(previous_records) + call_records, list(previous_edges) + call_edges
                    if call_records:
                        chain.append(("function-assignment", file, number, dest))
                    for method, key in direct:
                        record = (method, key, file, number)
                        records.append(record)
                        chain.append(("source-assignment", file, number, dest, method, key))
                        inputs.append((method, key, file, number, text))
                    for ref in refs:
                        records.extend(origins.get(ref, []))
                        chain.extend(edges.get(ref, []))
                        chain.append((file, number, ref, dest))
                    origins[dest] = list(dict.fromkeys(records))
                    edges[dest] = chain
                    invalidated.pop(dest, None)
                elif refs or direct or uncertain or unresolved_calls:
                    for method, key in uncertain:
                        unresolved_request_inputs.append((method, key, file, number, text))
                    unresolved.append(f"  Unresolved assignment at {file.name}:{number}: {text} (expression semantics are unsupported).")
            if observed_sinks:
                for sink_type in observed_sinks:
                    direct, tracked, invalidated_refs, flow_snapshot, _, _ = trace_sink_expression(
                        line, code_line, file, number, sink_type
                    )
                    if direct or tracked or invalidated_refs or flow_snapshot:
                        invalidated_snapshot = {
                            name: invalidated[name] for name in invalidated_refs
                        }
                        sinks.append((file, number, text, sink_type, direct, tracked, invalidated_refs, False, flow_snapshot, invalidated_snapshot))
            depth += line.count("{") - line.count("}")
        if conditional_frame is not None:
            unresolved.append(
                f"  Unresolved unmatched conditional block at {file.name}: end of file reached before its closing brace."
            )
            del sinks[conditional_frame["flow_sink_start"]:]
            origins.clear()
            edges.clear()
        active.pop()

    def report_path(file):
        resolved_file = file.resolve()
        try:
            return resolved_file.relative_to(root_file.parent).as_posix()
        except ValueError:
            return str(resolved_file)

    def php_output_context_evidence(text, tracked_variables):
        """Infer a narrow rendering context from static PHP output fragments."""
        output = re.search(r"\b(?:echo|print|printf)\s+(.*?);?\s*$", text, re.I)
        if not output:
            return "unresolved", "output expression has no supported static template boundary"
        expression = output.group(1).strip().rstrip(";").strip()
        variables = sorted(
            {"$" + name.lstrip("$") for name in tracked_variables if name != "$guard"},
            key=len,
            reverse=True,
        )
        variable_match = None
        for variable in variables:
            variable_match = re.search(re.escape(variable) + r"\b", expression)
            if variable_match:
                break
        if variable_match is None:
            variable_match = re.search(r"\$[A-Za-z_]\w*", expression)
        if variable_match is None:
            variable_match = re.search(r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^]]+\]", expression)
        if variable_match is None:
            return "unresolved", "traced value has no supported position within the output expression"

        literal_pattern = re.compile(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"")
        prefix_parts, suffix_parts = [], []
        for literal in literal_pattern.finditer(expression):
            token = literal.group(0)
            content = token[1:-1]
            content = content.replace("\\'", "'").replace('\\"', '"').replace("\\\\", "\\")
            if literal.end() <= variable_match.start():
                prefix_parts.append(content)
            elif literal.start() >= variable_match.end():
                suffix_parts.append(content)
        prefix, suffix = "".join(prefix_parts), "".join(suffix_parts)
        lower_prefix = prefix.lower()
        script_start = lower_prefix.rfind("<script")
        script_end = lower_prefix.rfind("</script")
        if script_start > script_end:
            script_prefix = lower_prefix[script_start:]
            if ((script_prefix.count('"') % 2) or (script_prefix.count("'") % 2)) and suffix:
                return "JavaScript string", "bounded by static script markup and quote delimiters"
            return "unresolved", "inside a script element, but a JavaScript string boundary is not established"

        open_tag = prefix.rfind("<")
        close_tag = prefix.rfind(">")
        if open_tag > close_tag:
            tag_prefix = prefix[open_tag:]
            attribute = re.search(r"=\s*(['\"])[^'\"]*$", tag_prefix)
            if attribute:
                delimiter = attribute.group(1)
                if suffix.startswith(delimiter):
                    return "HTML attribute", "bounded by a quoted static attribute value"
                return "unresolved", "inside an attribute-like region without a matching static closing quote"
            return "unresolved", "inside an open HTML tag without a supported quoted attribute boundary"
        if close_tag > open_tag and suffix.find("<") >= 0:
            return "HTML text", "bounded by static HTML tag delimiters"
        return "unresolved", "surrounding static markup does not establish a supported output context"

    def is_resource_identifier(key):
        return bool(re.search(
            r"(?:^id$|_id$|Id$|^uuid$|_uuid$|Uuid$|^guid$|_guid$|Guid$)",
            key,
        ))

    def is_authorization_like_guard(condition, tracked_variables):
        # A principal/session check by itself may only establish login state.
        # Require a comparison involving a variable in this traced flow, or a
        # narrow locally visible helper whose parameter is compared to a
        # principal/owner reference. This remains an observation, not proof.
        variables = [re.escape(name.lstrip("$")) for name in tracked_variables]
        tracked_reference = bool(variables) and re.search(
            r"\$(?:" + "|".join(variables) + r")\b", condition
        )
        identity_reference = re.search(
            r"\$_SESSION\s*\[|\b(?:current[_-]?user|owner(?:[_-]?id)?|"
            r"tenant(?:[_-]?id)?|permission|authorized|role|user[_-]?id)\b",
            condition,
            re.I,
        )
        comparison = re.search(r"===|==|!==|!=", condition)
        if tracked_reference and identity_reference and comparison:
            return ("direct", None)

        call = re.search(r"\b([A-Za-z_]\w*)\s*\(([^()]*)\)", condition)
        if not call or not variables:
            return None
        helper_name, arguments = call.groups()
        if not re.search(r"\$(?:" + "|".join(variables) + r")\b", arguments):
            return None
        for helper_file, helper_source in source_text_by_file.items():
            helper_lines = helper_source.splitlines()
            for index, helper_line in enumerate(helper_lines):
                declaration = re.search(
                    r"\bfunction\s+" + re.escape(helper_name)
                    + r"\s*\(([^)]*)\)\s*\{", helper_line, re.I
                )
                if not declaration:
                    continue
                params = re.findall(r"\$([A-Za-z_]\w*)", declaration.group(1))
                depth, body = helper_line.count("{") - helper_line.count("}"), []
                cursor = index + 1
                while cursor < len(helper_lines) and depth > 0:
                    body_line = helper_lines[cursor]
                    body.append(body_line)
                    depth += body_line.count("{") - body_line.count("}")
                    cursor += 1
                if depth != 0 or len(params) != 1:
                    continue
                body_text = "\n".join(body)
                param = re.escape(params[0])
                if (re.search(r"\$" + param + r"\b", body_text)
                        and re.search(r"===|==|!==|!=", body_text)
                        and re.search(
                            r"\$_SESSION\s*\[|\b(?:owner(?:_id)?|tenant(?:_id)?|user_id)\b",
                            body_text, re.I)):
                    return ("helper", (helper_file, index + 1, helper_name))
        return None

    visit(root_file)

    # Separate, bounded $_FILES tracing. Multipart semantics and indirect
    # helper behavior are not treated as a general taint model.
    upload_observations, upload_unresolved, upload_checks, upload_helper_calls = [], [], [], []
    upload_source_pattern = re.compile(
        r"\$_FILES\s*\[\s*(['\"])([^'\"]+)\1\s*\]\s*\[\s*(['\"])([^'\"]+)\3\s*\]"
    )
    upload_array_pattern = re.compile(r"\$_FILES\s*\[\s*(['\"])([^'\"]+)\1\s*\]")
    for upload_file, upload_text in source_text_by_file.items():
        lines = upload_text.splitlines()
        aliases = {}
        user_controlled_variables = set()
        seen_upload = []
        for line_number, line in enumerate(lines, 1):
            refs = list(upload_source_pattern.finditer(line))
            seen_upload.extend((line_number, ref.group(2), ref.group(4), line.strip()) for ref in refs)
            if not refs:
                seen_upload.extend((line_number, ref.group(2), "whole entry", line.strip()) for ref in upload_array_pattern.finditer(line))
            assignment = re.match(r"\s*\$(\w+)\s*=\s*(.*?)\s*;", line)
            if assignment and refs:
                aliases[assignment.group(1)] = refs[0].group(4)
            if assignment:
                assigned_variable, assigned_expression = assignment.groups()
                if re.search(r"\$_(?:GET|POST|REQUEST)\s*\[", assigned_expression) or any(
                    variable in user_controlled_variables
                    for variable in re.findall(r"\$(\w+)", assigned_expression)
                ):
                    user_controlled_variables.add(assigned_variable)
            checks = []
            if re.search(r"pathinfo\s*\([^\n]*PATHINFO_EXTENSION|\b(?:allowed_extensions|valid_extensions)\b|\bextension\b[^\n]*(?:in_array|preg_match|===|==)", line, re.I):
                checks.append("filename/extension check")
            if re.search(r"\b(?:mime_content_type|finfo_file)\s*\(|\$_FILES\s*\[[^\n]*\]\s*\[\s*['\"]type['\"]", line, re.I):
                checks.append("MIME-type check")
            if re.search(r"\$_FILES\s*\[[^\n]*\]\s*\[\s*['\"]error['\"]|\bUPLOAD_ERR_[A-Z_]+\b", line, re.I):
                checks.append("upload error check")
            if re.search(r"\$_FILES\s*\[[^\n]*\]\s*\[\s*['\"]size['\"]|\b(?:filesize|size)\b[^\n]*(?:<|<=|>|>=)|(?:<|<=|>|>=)[^\n]*\b(?:max_size|upload_max)", line, re.I):
                checks.append("upload size check")
            upload_checks.extend((upload_file, line_number, check, line.strip()) for check in checks)
            if not re.search(r"\bfunction\s+", line, re.I):
                for helper_call in re.finditer(r"\b([A-Za-z_]\w*(?:validate|check|upload)[A-Za-z_]*)\s*\(", line, re.I):
                    upload_helper_calls.append((upload_file, line_number, helper_call.group(1), line.strip()))
            operation = re.search(r"\b(move_uploaded_file|file_put_contents)\s*\((.*)", line, re.I)
            if operation:
                args = split_sink_arguments(operation.group(2).rstrip(" );"))
                source_arg = args[0] if operation.group(1).lower() == "move_uploaded_file" and args else (args[1] if len(args) > 1 else "")
                source_var = re.fullmatch(r"\$(\w+)", source_arg.strip())
                source_reaches = ("$_FILES" in source_arg and "tmp_name" in source_arg) or bool(source_var and aliases.get(source_var.group(1)) == "tmp_name")
                if source_reaches and args:
                    destination = args[1] if operation.group(1).lower() == "move_uploaded_file" and len(args) > 1 else args[0]
                    controlled = bool(re.search(r"\$_(?:GET|POST|REQUEST)\s*\[", destination)) or any(
                        variable in user_controlled_variables
                        for variable in re.findall(r"\$(\w+)", destination)
                    )
                    upload_observations.append((upload_file, line_number, operation.group(1), destination, controlled, line.strip()))
        if not any(item[0] == upload_file for item in upload_observations):
            upload_unresolved.extend((upload_file, number, field, key, excerpt) for number, field, key, excerpt in seen_upload)

    def stored_sql_expression(text):
        """Build a conservative SQL template from literals joined by simple variables."""
        assignment = re.fullmatch(r"\s*\$([A-Za-z_]\w*)\s*=\s*(.*?)\s*;\s*", text)
        if not assignment:
            return None, None, []
        variable, expression = assignment.groups()
        token_pattern = re.compile(r"'((?:\\.|[^'\\])*)'|\"((?:\\.|[^\"\\])*)\"|\$([A-Za-z_]\w*)")
        pieces, variables, position, index = [], [], 0, 0
        for token in token_pattern.finditer(expression):
            separator = expression[position:token.start()]
            if pieces:
                if not re.fullmatch(r"\s*\.\s*", separator):
                    return variable, None, variables
            elif separator.strip():
                return variable, None, variables
            if token.group(3):
                pieces.append(f"__JARVIS_VAR_{index}__")
                variables.append(token.group(3))
                index += 1
            else:
                pieces.append(token.group(1) if token.group(1) is not None else token.group(2))
            position = token.end()
        if not pieces or expression[position:].strip():
            return variable, None, variables
        return variable, "".join(pieces), variables

    def stored_sql_parts(template):
        if not template:
            return None
        insert = re.fullmatch(
            r"\s*INSERT\s+INTO\s+([A-Za-z_]\w*)\s*\((.*?)\)\s*VALUES\s*\((.*?)\)\s*;?\s*",
            template, re.I | re.S,
        )
        if insert:
            columns = [item.strip().strip("` ") for item in split_top_level_list(insert.group(2))]
            values = [item.strip() for item in split_top_level_list(insert.group(3))]
            if not columns or len(columns) != len(values) or any(
                not re.fullmatch(r"[A-Za-z_]\w*", column) for column in columns
            ) or len({column.lower() for column in columns}) != len(columns):
                return {"operation": "INSERT", "supported": False}
            mapped = {}
            for column, value in zip(columns, values):
                markers = re.findall(r"__JARVIS_VAR_(\d+)__", value)
                mapped[column.lower()] = {
                    "value": value,
                    "markers": tuple(int(marker) for marker in markers),
                }
            return {"operation": "INSERT", "table": insert.group(1).lower(), "columns": mapped, "supported": True}

        select = re.fullmatch(
            r"\s*SELECT\s+(.*?)\s+FROM\s+([A-Za-z_]\w*)(?:\s+WHERE\s+(.*?))?\s*;?\s*",
            template, re.I | re.S,
        )
        if select:
            projection = select.group(1).strip()
            if "__JARVIS_VAR_" in projection or "__JARVIS_VAR_" in select.group(2):
                return {"operation": "SELECT", "supported": False}
            columns = None if projection == "*" else [
                item.strip().strip("` ").lower()
                for item in split_top_level_list(projection)
            ]
            if columns is not None and any(
                not re.fullmatch(r"[A-Za-z_]\w*", column) for column in columns
            ):
                return {"operation": "SELECT", "supported": False}
            predicate = select.group(3)
            where_match = re.fullmatch(
                r"\s*([A-Za-z_]\w*)\s*=\s*(.*?)\s*", predicate, re.S
            ) if predicate else None
            where = (where_match.group(1).lower(), where_match.group(2)) if where_match else None
            return {
                "operation": "SELECT", "table": select.group(2).lower(),
                "columns": columns, "where": where,
                "where_supported": predicate is None or where_match is not None,
                "where_text": predicate, "supported": True,
            }

        operation = re.match(r"\s*(INSERT|SELECT|UPDATE|DELETE)\b", template, re.I)
        if operation:
            return {"operation": operation.group(1).upper(), "supported": False}
        return None

    def resolve_output_helper(helper_name, argument_expression):
        candidates = [
            candidate for candidate in function_summaries.get(helper_name.lower(), [])
            if candidate[1] == root_file or candidate[1] in visited
        ]
        if len(candidates) != 1 or candidates[0][0] is None:
            return None, "helper definition is missing, ambiguous, or unsupported"
        summary, helper_file, definition_line, _, _ = candidates[0]
        if summary.get("branch_paths"):
            return None, "helper has branch-specific returns that are not resolved for this row expression"
        arguments = split_call_arguments(argument_expression)
        parameter = summary.get("parameter")
        if parameter is None or parameter not in summary.get("params", []):
            return None, "helper return does not identify a supported input parameter"
        parameter_index = summary["params"].index(parameter)
        if parameter_index >= len(arguments) or arguments[parameter_index].strip() != argument_expression:
            return None, "helper argument-to-return mapping is unsupported or ambiguous"
        if summary.get("return_kind") == "transformed":
            category = summary.get("return_category", "other-transformation")
            return {
                "name": helper_name,
                "file": helper_file,
                "definition_line": definition_line,
                "parameter": parameter,
                "argument": argument_expression,
                "return_line": summary["return_line"],
                "return_expression": summary["return_expression"],
                "category": category,
            }, None
        return {
            "name": helper_name,
            "file": helper_file,
            "definition_line": definition_line,
            "parameter": parameter,
            "argument": argument_expression,
            "return_line": summary["return_line"],
            "return_expression": f"${summary['return_variable']}",
            "category": "identity",
        }, None

    for stored_file, stored_lines in source_lines_by_file.items():
        if stored_file.resolve() != root_file:
            continue
        stored_origins = {}
        query_candidates = {}
        executed_operations = []
        result_sources = {}
        fetched_rows = {}
        unresolved_result_sources = {}
        unresolved_fetch_rows = {}
        write_events = []
        read_events = []
        for number, line in enumerate(stored_lines, 1):
            text = line.strip()
            code = mask_php_sink_code(
                line,
                {"php": True, "block_comment": False, "quote": None, "escaped": False},
            )
            assignment = assignment_pattern.match(text)
            sql_variable, sql_template, php_variables = stored_sql_expression(text)
            sql_template_operation = re.match(
                r"\s*(INSERT|SELECT|UPDATE|DELETE)\b", sql_template or "", re.I
            )
            dynamic_sql_operation = (
                re.match(
                    r"\s*(['\"])(?:\s*)(INSERT|SELECT|UPDATE|DELETE)\b",
                    assignment.group(3), re.I,
                )
                if assignment else None
            )
            if sql_variable and (
                sql_template_operation is not None or dynamic_sql_operation is not None
            ):
                parsed = stored_sql_parts(sql_template) if sql_template is not None else None
                if parsed:
                    parsed.update({
                        "file": stored_file, "line": number,
                        "text": text, "template": sql_template,
                        "php_variables": php_variables,
                        "guards": guards_by_source_line.get((stored_file.resolve(), number), []),
                    })
                    query_candidates.setdefault(sql_variable, []).append(parsed)
                else:
                    operation_name = (
                        sql_template_operation.group(1).upper()
                        if sql_template_operation
                        else dynamic_sql_operation.group(2).upper()
                        if dynamic_sql_operation else "SQL"
                    )
                    query_candidates.setdefault(sql_variable, []).append({
                        "operation": operation_name,
                        "supported": False,
                        "file": stored_file,
                        "line": number,
                        "text": text,
                        "guards": guards_by_source_line.get((stored_file.resolve(), number), []),
                    })
                    unresolved_stored_data.append(
                        f"Unresolved {operation_name} stored-data SQL at {stored_file.name}:{number}: dynamic or unsupported query expression."
                    )
                continue

            if assignment:
                destination, operator, expression = assignment.groups()
                direct = input_pattern.fullmatch(expression.strip())
                alias = re.fullmatch(r"\$(\w+)", expression.strip())
                line_key = (stored_file.resolve(), number)
                guard_context = guards_by_source_line.get(line_key, [])
                else_branch = any("else" in arm for _, _, _, arm in guard_context)
                expression_refs = [] if expression.strip().startswith("isset(") else input_pattern.findall(expression)
                tracked_refs = [
                    name for name in variable_pattern.findall(expression)
                    if name in stored_origins
                ]
                relevant_assignment = bool(
                    direct or destination in stored_origins
                    or alias and alias.group(1) in stored_origins
                    or expression_refs or tracked_refs
                )
                if not relevant_assignment:
                    pass
                elif line_key in unsupported_source_lines:
                    stored_origins.pop(destination, None)
                    unresolved_stored_data.append(
                        f"Assignment at {stored_file.name}:{number} occurs in unsupported control flow; stored-data provenance remains unresolved."
                    )
                elif else_branch:
                    stored_origins.pop(destination, None)
                    unresolved_stored_data.append(
                        f"Assignment at {stored_file.name}:{number} is in an else branch whose join is not modeled; stored-data provenance remains unresolved."
                    )
                elif operator == "=" and direct:
                    method, key = direct.groups()
                    stored_origins[destination] = {
                        "source": (method.upper(), key, stored_file, number),
                        "assignments": [(stored_file, number, destination)],
                        "guards": guards_by_source_line.get((stored_file.resolve(), number), []),
                    }
                elif operator == "=" and alias and alias.group(1) in stored_origins:
                    stored_origins[destination] = dict(stored_origins[alias.group(1)])
                    stored_origins[destination]["assignments"] = list(
                        stored_origins[destination]["assignments"]
                    ) + [(stored_file, number, destination)]
                    stored_origins[destination]["guards"] = list(dict.fromkeys(
                        stored_origins[destination]["guards"]
                        + guards_by_source_line.get((stored_file.resolve(), number), [])
                    ))
                elif operator == "=":
                    (
                        helper_direct, _, helper_uncertain, helper_refs,
                        helper_records, helper_edges, helper_unresolved,
                        _, helper_unsupported,
                    ) = evaluate_expression(expression, stored_file, number)
                    if (
                        helper_records and not helper_uncertain and not helper_unsupported
                        and not helper_unresolved and len(set(helper_records)) == 1
                    ):
                        method, key, source_file, source_line = helper_records[0]
                        stored_origins[destination] = {
                            "source": (method, key, source_file, source_line),
                            "assignments": [(stored_file, number, destination)],
                            "guards": guards_by_source_line.get((stored_file.resolve(), number), []),
                            "helper_edges": helper_edges,
                        }
                        for edge in helper_edges:
                            if edge and edge[0] == "function-branch":
                                (
                                    _, call_file, call_line, helper_name, definition_file,
                                    definition_line, switch_expression, condition,
                                    branch_line, return_line, shared_return_line, _parameter,
                                    _argument_expression, return_kind, return_expression,
                                    helper_prelude,
                                ) = edge
                                if return_kind == "quote-escaping":
                                    transform_note = transformation_context_note(return_kind, "SQL/query")
                                elif return_kind == "sql-escaping":
                                    transform_note = "SQL escaping, not HTML output encoding; effectiveness is not inferred."
                                elif return_kind == "html-output-encoding":
                                    transform_note = "HTML output encoding, not SQL escaping; context effectiveness is not inferred."
                                elif return_kind == "identity":
                                    transform_note = "identity return."
                                else:
                                    transform_note = "transformation category unresolved."
                                stored_data_observations.append(
                                    f"Helper call {helper_name} at {call_file.name}:{call_line} resolves branch {condition} of switch ({switch_expression}) in definition at {definition_file.name}:{definition_line}, branch line {branch_line}; branch expression {return_expression} at {definition_file.name}:{return_line} is classified as {transform_note}"
                                )
                                if shared_return_line:
                                    stored_data_observations.append(
                                        f"Shared helper return at {definition_file.name}:{shared_return_line} returns ${_parameter}; this connects the branch assignment to the helper result."
                                    )
                                for prelude_file, prelude_line, prelude_text in helper_prelude:
                                    stored_data_observations.append(
                                        f"Helper context include at {prelude_file.name}:{prelude_line}: {prelude_text} (included context is observed; runtime effects are not validated)."
                                    )
                                nested_call = re.fullmatch(
                                    r"([A-Za-z_]\w*)\s*\((.*)\)", return_expression
                                )
                                if nested_call:
                                    nested_candidates = [
                                        candidate for candidate in function_summaries.get(
                                            nested_call.group(1).lower(), []
                                        ) if candidate[1] == root_file or candidate[1] in visited
                                    ]
                                    if len(nested_candidates) == 1 and nested_candidates[0][0]:
                                        nested_summary, nested_file, nested_line, _, _ = nested_candidates[0]
                                        nested_arguments = split_call_arguments(nested_call.group(2))
                                        parameter_index = nested_summary["params"].index(nested_summary["parameter"])
                                        argument_value = nested_arguments[parameter_index] if parameter_index < len(nested_arguments) else "(unresolved argument)"
                                        if nested_summary.get("return_kind") == "transformed":
                                            nested_kind = nested_summary.get("return_category", "other-transformation")
                                            nested_note = transformation_context_note(
                                                nested_kind, "SQL/query"
                                            )
                                            nested_return = nested_summary["return_expression"]
                                        else:
                                            nested_note = "identity return"
                                            nested_return = f"${nested_summary['return_variable']}"
                                        stored_data_observations.append(
                                            f"Nested helper {nested_call.group(1)} definition at {nested_file.name}:{nested_line}: parameter ${nested_summary['parameter']} receives {argument_value}; return {nested_return} at {nested_file.name}:{nested_summary['return_line']} ({nested_note}; effectiveness is not inferred)."
                                        )
                    else:
                        if destination in stored_origins:
                            stored_origins.pop(destination, None)
                        refs = expression_refs
                        if refs:
                            method, key = refs[0]
                            call_match = re.search(r"([A-Za-z_]\w*)\s*\(", expression)
                            unresolved_stored_data.append(
                                f"Request [{method.upper()}] {key} at {stored_file.name}:{number} is passed through "
                                f"unresolved expression {call_match.group(1) + '()' if call_match else 'an unsupported expression'}; "
                                "the transformed value is not linked to a database write."
                            )
                else:
                    if destination in stored_origins:
                        stored_origins.pop(destination, None)
                    refs = expression_refs
                    if refs:
                        method, key = refs[0]
                        call_match = re.search(r"([A-Za-z_]\w*)\s*\(", expression)
                        unresolved_stored_data.append(
                            f"Request [{method.upper()}] {key} at {stored_file.name}:{number} is passed through "
                            f"unresolved expression {call_match.group(1) + '()' if call_match else 'an unsupported expression'}; "
                            "the transformed value is not linked to a database write."
                        )

            execution = re.search(
                r"\$(\w+)\s*=\s*\$\w+\s*->\s*query\s*\(\s*\$(\w+)\s*\)", code, re.I
            )
            if not execution:
                execution = re.search(
                    r"\$\w+\s*->\s*query\s*\(\s*\$(\w+)\s*\)", code, re.I
                )
                result_variable = None
                query_variable = execution.group(1) if execution else None
            else:
                result_variable, query_variable = execution.groups()
            if query_variable:
                candidates = query_candidates.pop(query_variable, [])
                if len(candidates) != 1 or not candidates[0].get("supported"):
                    if len(candidates) != 1:
                        reason = "multiple or missing query assignments make the statement ambiguous"
                        if len(candidates) > 1 and all(
                            candidate.get("operation") == "SELECT" for candidate in candidates
                        ):
                            reason += " (conflicting SELECT assignments)"
                    else:
                        reason = (
                            f"dynamic or unsupported query expression ({candidates[0].get('operation', 'query')} syntax unsupported)"
                        )
                    unresolved_stored_data.append(
                        f"Unresolved stored-data execution at {stored_file.name}:{number}: {reason}."
                    )
                    executed_operations.append((number, None))
                    if result_variable:
                        query_lines = ", ".join(
                            f"{candidate.get('file', stored_file).name}:{candidate.get('line', 'unknown')}"
                            for candidate in candidates
                        ) or "unknown"
                        candidate_details = "; ".join(
                            f"{candidate.get('file', stored_file).name}:{candidate.get('line', 'unknown')} "
                            + (
                                "wildcard projection leaves columns unresolved"
                                if candidate.get("operation") == "SELECT"
                                and candidate.get("supported")
                                and candidate.get("columns") is None
                                else "dynamic/unsupported query syntax"
                                if not candidate.get("supported")
                                else "supported SELECT query"
                            )
                            for candidate in candidates
                        )
                        unresolved_result_sources[result_variable] = (
                            f"{reason}; SELECT/query assignment location(s): {query_lines}; {candidate_details}"
                        )
                else:
                    query = candidates[0]
                    operation = query["operation"]
                    event = {"query": query, "execution_file": stored_file, "execution_line": number, "guards": guards_by_source_line.get((stored_file.resolve(), number), [])}
                    executed_operations.append((number, query))
                    if operation == "INSERT":
                        for column, value in query.get("columns", {}).items():
                            marker_ids = value["markers"]
                            if len(marker_ids) == 1:
                                marker_index = marker_ids[0]
                                php_variables = query.get("php_variables", [])
                                actual_variable = php_variables[marker_index] if marker_index < len(php_variables) else None
                                origin = stored_origins.get(actual_variable) if actual_variable else None
                                if origin:
                                    event["column"] = column
                                    event["origin"] = origin
                                    event["value_variable"] = actual_variable
                                    write_events.append(event)
                                    source_method, source_key, source_file, source_line = origin["source"]
                                    stored_data_observations.append(
                                        f"Request [{source_method}] {source_key} at {source_file.name}:{source_line} is assigned to ${actual_variable} and appears in INSERT column {column} at {query['file'].name}:{query['line']}, executed at {stored_file.name}:{number}."
                                    )
                                elif len(marker_ids) != 1 or actual_variable:
                                    stored_data_observations.append(
                                        f"INSERT column {column} at {query['file'].name}:{query['line']} contains an unlinked or ambiguous PHP value; request provenance is not established."
                                    )
                    elif operation == "SELECT":
                        event["result_variable"] = result_variable
                        read_events.append(event)
                        projection = "*" if query["columns"] is None else ", ".join(query["columns"])
                        stored_data_observations.append(
                            f"SELECT construction at {query['file'].name}:{query['line']} observes {projection} from {query['table']}; execution at {stored_file.name}:{number}."
                        )
                        if query.get("where_text") and not query.get("where_supported"):
                            unresolved_stored_data.append(
                                f"SELECT at {query['file'].name}:{query['line']} has an unsupported WHERE predicate {query['where_text']}; predicate semantics remain unresolved."
                            )
                        if result_variable:
                            result_sources[result_variable] = event
            fetch = re.search(
                r"(?:\$(\w+)\s*=\s*)?\$(\w+)\s*->\s*(fetch_object|fetch_assoc)\s*\(\s*\)",
                code, re.I,
            )
            any_fetch = re.search(
                r"(?:\$(\w+)\s*=\s*)?\$(\w+)\s*->\s*(fetch_[A-Za-z_]\w*)\s*\(",
                code, re.I,
            )
            if fetch:
                row_variable, result_variable, fetch_method = fetch.groups()
                read_event = result_sources.get(result_variable)
                if row_variable and read_event:
                    fetch_record = {
                        "file": stored_file, "line": number, "text": text,
                        "row_variable": row_variable, "method": fetch_method.lower(),
                        "guards": guards_by_source_line.get((stored_file.resolve(), number), []),
                    }
                    fetched_rows[row_variable] = {"read": read_event, "fetch": fetch_record}
                    read_event.setdefault("fetches", []).append(fetch_record)
                    stored_data_observations.append(
                        f"Fetch observation at {stored_file.name}:{number}: {fetch_method.lower()} assigns ${row_variable} from SELECT result ${result_variable}."
                    )
                elif row_variable and result_variable in unresolved_result_sources:
                    unresolved_fetch_rows[row_variable] = {
                        "result_variable": result_variable,
                        "file": stored_file, "line": number, "text": text,
                        "reason": unresolved_result_sources[result_variable],
                    }
            elif any_fetch:
                row_variable, result_variable, fetch_method = any_fetch.groups()
                if result_variable in result_sources or result_variable in unresolved_result_sources:
                    reason = (
                        f"unsupported fetch method {fetch_method}"
                        if fetch_method.lower() not in {"fetch_object", "fetch_assoc"}
                        else "supported fetch call has unsupported arguments or no row destination"
                    )
                    unresolved_stored_data.append(
                        f"Unresolved fetch at {stored_file.name}:{number} for ${result_variable}: {reason}; fetched-column provenance remains unresolved."
                    )
                    if row_variable:
                        unresolved_fetch_rows[row_variable] = {
                            "result_variable": result_variable,
                            "file": stored_file, "line": number, "text": text,
                            "reason": reason,
                        }

            output = re.search(
                r"\b(echo|print)\b.*?\$(\w+)\s*(?:->\s*(\w+)|\[\s*(['\"])([^'\"]+)\4\s*\])",
                text, re.I,
            )
            if output:
                row_variable = output.group(2)
                if row_variable.startswith("_"):
                    output = None
            if output:
                row_variable = output.group(2)
                object_column = output.group(3)
                array_column = output.group(5)
                column = object_column or array_column
                access_kind = "object" if object_column else "array"
                access_start = line.find(text) + output.start(2) - 1
                executable_access = code[access_start:access_start + len(row_variable) + 1] == "$" + row_variable
                if not executable_access:
                    output = None
                else:
                    helper_match = re.search(
                        r"\b([A-Za-z_]\w*)\s*\(\s*\$" + re.escape(row_variable)
                        + (r"\s*->\s*" + re.escape(column) if access_kind == "object" else r"\s*\[\s*['\"]" + re.escape(column) + r"['\"]\s*\]")
                        + r"\s*\)", text,
                    )
                    helper_evidence = None
                    helper_failure = None
                    if helper_match:
                        argument_expression = helper_match.group(0)[
                            helper_match.group(0).find("$"): -1
                        ]
                        helper_evidence, helper_failure = resolve_output_helper(
                            helper_match.group(1), argument_expression
                        )
                    row_binding = fetched_rows.get(row_variable)
                    if row_binding:
                        read_event = row_binding["read"]
                        output_record = {
                            "file": stored_file, "line": number, "column": column,
                            "text": text,
                            "guards": guards_by_source_line.get((stored_file.resolve(), number), []),
                            "row_variable": row_variable, "access_kind": access_kind,
                            "fetch": row_binding["fetch"],
                            "helper": helper_evidence,
                            "helper_failure": helper_failure,
                        }
                        read_event.setdefault("outputs", []).append(output_record)
                        stored_data_observations.append(
                            f"Output expression observation at {stored_file.name}:{number} references retrieved row column {column} through ${row_variable}: {text}."
                        )
                    elif row_variable in unresolved_fetch_rows:
                        unresolved_fetch = unresolved_fetch_rows[row_variable]
                        unresolved_access = (
                            f"${row_variable}->{column}"
                            if access_kind == "object"
                            else f"${row_variable}['{column}']"
                        )
                        unresolved_stored_data.append(
                            f"Unresolved SELECT-to-output relationship at {stored_file.name}:{number}: output uses {unresolved_access}; fetch at {unresolved_fetch['file'].name}:{unresolved_fetch['line']} from ${unresolved_fetch['result_variable']} is unresolved ({unresolved_fetch['reason']})."
                        )
                    else:
                        stored_data_observations.append(
                            f"Output expression observation at {stored_file.name}:{number} references ${row_variable} column {column}: {text}; no supported fetch-to-SELECT relationship is established."
                        )

        for read in read_events:
            query = read["query"]
            for output in read.get("outputs", []):
                output_column = output["column"].lower()
                selected_columns = query.get("columns")
                if selected_columns is None:
                    unresolved_stored_data.append(
                        f"Unresolved SELECT-to-output relationship: SELECT at {query['file'].name}:{query['line']} uses wildcard projection; source does not identify whether column {output_column} is present in the result."
                    )
                    continue
                if output_column not in selected_columns:
                    unresolved_stored_data.append(
                        f"Unresolved SELECT-to-output relationship: SELECT at {query['file'].name}:{query['line']} projects {', '.join(selected_columns)}, but output at {output['file'].name}:{output['line']} accesses column {output_column}."
                    )
                    continue
                expected_access = "object" if output["fetch"]["method"] == "fetch_object" else "array"
                if output["access_kind"] != expected_access:
                    unresolved_stored_data.append(
                        f"Unresolved SELECT-to-output relationship: {output['fetch']['method']} at {output['fetch']['file'].name}:{output['fetch']['line']} does not establish {output['access_kind']} access ${output['row_variable']} for column {output_column}."
                    )
                    continue
                if output["helper_failure"]:
                    unresolved_stored_data.append(
                        f"Unresolved SELECT-to-output relationship at {output['file'].name}:{output['line']}: retrieved column {output_column} is passed to helper {output['helper_failure']}; helper argument-to-return provenance is unresolved."
                    )
                    continue
                if any(
                    operation is None
                    or operation.get("table") == query["table"]
                    and operation.get("operation") in {"DELETE", "UPDATE", "INSERT"}
                    for execution_line, operation in executed_operations
                    if read["execution_line"] < execution_line < output["line"]
                ):
                    unresolved_stored_data.append(
                        f"Unresolved SELECT-to-output relationship: an intervening or ambiguous database mutation follows SELECT at {query['file'].name}:{query['line']} before output at {output['file'].name}:{output['line']}."
                    )
                    continue
                select_output_flows.append({
                    "read": read,
                    "output": output,
                    "guards": list(dict.fromkeys(
                        query.get("guards", [])
                        + read["guards"]
                        + output["fetch"]["guards"]
                        + output["guards"]
                    )),
                })

        supported_select_output_pairs = {
            (id(flow["read"]), id(flow["output"])) for flow in select_output_flows
        }
        for write in write_events:
            query = write["query"]
            key_column = None
            for column, value in query.get("columns", {}).items():
                if column == "id" or column.endswith("_id"):
                    if len(value["markers"]) == 0:
                        key_column = (column, value["value"])
                        break
            if key_column is None:
                unresolved_stored_data.append(
                    f"INSERT at {query['file'].name}:{query['line']} has no supported literal key value to match a later row read; table/column similarity alone is insufficient."
                )
                continue
            for read in read_events:
                read_query = read["query"]
                if read_query["table"] != query["table"]:
                    unresolved_stored_data.append(
                        f"SELECT at {read_query['file'].name}:{read_query['line']} reads table {read_query['table']}, not INSERT table {query['table']}; no stored-record relationship is inferred."
                    )
                    continue
                projection = read_query["columns"]
                if projection is not None and write["column"] not in projection:
                    continue
                predicate = read_query.get("where")
                if predicate != key_column:
                    unresolved_stored_data.append(
                        f"SELECT at {read_query['file'].name}:{read_query['line']} does not prove a row match to INSERT at {query['file'].name}:{query['line']}; matching table or column alone is insufficient."
                    )
                    continue
                if any(
                    operation is None
                    or operation.get("table") == query["table"]
                    and operation.get("operation") in {"DELETE", "UPDATE", "INSERT"}
                    for execution_line, operation in executed_operations
                    if write["execution_line"] < execution_line < read["execution_line"]
                ):
                    unresolved_stored_data.append(
                        f"An intervening or ambiguous database operation prevents linking INSERT at {query['file'].name}:{query['line']} to SELECT at {read_query['file'].name}:{read_query['line']}."
                    )
                    continue
                for output in read.get("outputs", []):
                    if (id(read), id(output)) not in supported_select_output_pairs:
                        continue
                    output_file = output["file"]
                    output_line = output["line"]
                    output_column = output["column"]
                    output_text = output["text"]
                    output_guards = output["guards"]
                    if output_column.lower() != write["column"]:
                        continue
                    if any(
                        operation is None
                        or operation.get("table") == query["table"]
                        and operation.get("operation") in {"DELETE", "UPDATE", "INSERT"}
                        for execution_line, operation in executed_operations
                        if read["execution_line"] < execution_line < output_line
                    ):
                        unresolved_stored_data.append(
                            f"An intervening or ambiguous database operation prevents linking SELECT at {read_query['file'].name}:{read_query['line']} to output at {output_file.name}:{output_line}."
                        )
                        continue
                    stored_data_flows.append({
                        "write": write, "read": read,
                        "output": (output_file, output_line, output_column, output_text, output_guards),
                        "output_helper": output["helper"],
                        "guards": list(dict.fromkeys(
                            write["origin"]["guards"]
                            + query.get("guards", [])
                            + write["guards"]
                            + read_query.get("guards", [])
                            + read["guards"]
                            + output_guards
                        )),
                        "output_file": output_file,
                    })
        if not write_events and not read_events:
            continue

    def source_is_entry(record):
        return record[2].resolve() == root_file

    report = [
        f"JARVIS: PHP source-flow analysis â€” {path.name}", "=" * 50, "",
        "Form control observations:",
    ]
    if form_controls:
        for control, name, file, number in dict.fromkeys(form_controls):
            report.append(
                f"  [{control}] name={name} at {report_path(file)}:{number} (form control only; not evidence that PHP reads or uses this value)."
            )
    else:
        report.append("  No literal named form controls detected.")
    report.extend([
        "  Request sources below require a PHP request-variable reference; control names alone are not sources.",
        "",
        "Input evidence:",
    ])
    unique_inputs = list(dict.fromkeys(inputs))
    entry_inputs = [record for record in unique_inputs if source_is_entry(record)]
    included_inputs = [record for record in unique_inputs if not source_is_entry(record)]
    if entry_inputs:
        for method, key, file, number, text in entry_inputs:
            report.extend([f"  [{method}] {key}", f"    {report_path(file)}:{number}: {text}"])
    else:
        report.append("  No direct GET/POST/REQUEST inputs detected.")
    report.append(
        "  These are observed request-source patterns; detection alone does not establish a flow or vulnerability."
    )
    traced_conditional_inputs = set()
    for sink_file, sink_line, _, _, direct_refs, _, _, conditional_flow, flow_snapshot, _ in sinks:
        if not conditional_flow:
            continue
        traced_conditional_inputs.update(
            (method, key, sink_file, sink_line) for method, key in direct_refs
        )
        for _, records, _ in flow_snapshot:
            traced_conditional_inputs.update(records)
    all_conditional_inputs = [
        record for record in dict.fromkeys(conditional_inputs)
        if (record[0], record[1], record[2], record[3]) not in traced_conditional_inputs
    ]
    entry_conditional_inputs = [
        record for record in all_conditional_inputs if source_is_entry(record)
    ]
    included_conditional_inputs = [
        record for record in all_conditional_inputs if not source_is_entry(record)
    ]
    report.extend(["", "Unresolved conditional input evidence:"])
    if entry_conditional_inputs:
        for method, key, file, number, text in entry_conditional_inputs:
            report.extend([
                f"  [{method}] {key} (conditional; flow unresolved)",
                f"    {report_path(file)}:{number}: {text}",
            ])
    else:
        report.append("  None detected.")
    unique_presence_inputs = list(dict.fromkeys(presence_inputs))
    entry_presence_inputs = [
        record for record in unique_presence_inputs if source_is_entry(record)
    ]
    included_presence_inputs = [
        record for record in unique_presence_inputs if not source_is_entry(record)
    ]
    report.extend(["", "Request presence evidence:"])
    if entry_presence_inputs:
        report.append(
            "  Presence checks are selection/control evidence only; they do not establish that the submitted parameter value was read or used."
        )
        for method, key, file, number, text in entry_presence_inputs:
            report.extend([
                f"  Presence check: [{method}] {key} (selection/control presence only)",
                f"    {report_path(file)}:{number}: {text} (presence checked; submitted value not assigned).",
            ])
    else:
        report.append("  None detected.")
    unique_unresolved_request_inputs = list(dict.fromkeys(unresolved_request_inputs))
    entry_unresolved_request_inputs = [
        record for record in unique_unresolved_request_inputs if source_is_entry(record)
    ]
    included_unresolved_request_inputs = [
        record for record in unique_unresolved_request_inputs if not source_is_entry(record)
    ]
    report.extend(["", "Unresolved request-reference evidence:"])
    if entry_unresolved_request_inputs:
        for method, key, file, number, text in entry_unresolved_request_inputs:
            report.extend([
                f"  [{method}] {key} (expression value unresolved)",
                f"    {report_path(file)}:{number}: {text}",
            ])
    else:
        report.append("  None detected.")
    report.extend(["", "Included-file input observations:"])
    included_observation_count = 0
    for method, key, file, number, text in included_inputs:
        report.append(
            f"  Direct request-value observation: [{method}] {key} at {report_path(file)}:{number}: {text}"
        )
        included_observation_count += 1
    for method, key, file, number, text in included_conditional_inputs:
        report.append(
            f"  Conditional request-input observation: [{method}] {key} at {report_path(file)}:{number}: {text}"
        )
        included_observation_count += 1
    for method, key, file, number, text in included_presence_inputs:
        report.append(
            f"  Presence-check observation: [{method}] {key} at {report_path(file)}:{number}: {text} (submitted value not assigned)."
        )
        included_observation_count += 1
    for method, key, file, number, text in included_unresolved_request_inputs:
        report.append(
            f"  Unresolved request-reference observation: [{method}] {key} at {report_path(file)}:{number}: {text}"
        )
        included_observation_count += 1
    if not included_observation_count:
        report.append("  None detected.")
    report.extend([
        "", "Sink observations:",
        "  Observed sink patterns are independent of source-to-sink evidence.",
    ])
    if sink_observations:
        for sink_type, file, number, excerpt, context in sink_observations:
            report.append(
                f"  Sink text ({sink_type}) at {report_path(file)}:{number}: {excerpt}{context}"
            )
    else:
        report.append("  No sink observations detected.")
    report.extend([
        "", "File-upload review observations (not vulnerability findings):",
        "  Supported patterns: direct $_FILES field references, simple same-file aliases of tmp_name, and move_uploaded_file() or file_put_contents() calls on the captured line.",
        "  Filename, MIME, upload-error, size, and helper-call patterns are recorded as observations only; none is treated as sufficient validation or proof of safety.",
    ])
    if upload_observations:
        for upload_file, upload_line, operation, destination, controlled, excerpt in upload_observations:
            source_location = next((
                (source_line, match.group(2), match.group(4))
                for source_line, source_text in enumerate(source_text_by_file[upload_file].splitlines(), 1)
                for match in upload_source_pattern.finditer(source_text)
                if match.group(4) == "tmp_name"
            ), None)
            report.extend([
                f"  Upload source: $_FILES[{source_location[1]!r}][{source_location[2]!r}] at {report_path(upload_file)}:{source_location[0] if source_location else 'unknown'}.",
                f"  Storage sink: {operation}() at {report_path(upload_file)}:{upload_line}: {excerpt}",
                f"    Destination expression: {destination} ({'user-controlled expression observed; containment and safe naming are unresolved' if controlled else 'fixed or otherwise unclassified expression; runtime destination is not established'}).",
            ])
        if upload_checks:
            for check_file, check_line, check, excerpt in dict.fromkeys(upload_checks):
                report.append(f"  Observed {check} at {report_path(check_file)}:{check_line}: {excerpt} (effectiveness and enforcement on this path are unresolved).")
        else:
            report.append("  No supported extension, MIME-type, upload-error, or size check pattern was recognized.")
        for helper_file, helper_line, helper_name, helper_excerpt in dict.fromkeys(upload_helper_calls):
            report.append(f"  Validation-like helper call {helper_name}(...) at {report_path(helper_file)}:{helper_line}: {helper_excerpt} (helper behavior and enforcement are not inferred).")
        report.extend([
            "  Unresolved assumptions: uploaded content is not inspected or executed; destination containment, overwrite behavior, web-server execution policy, storage permissions, helper completeness, and runtime success are not established.",
            "  Severity: NEEDS_REVIEW; confidence: Low.",
            "  Vulnerability status: UNCONFIRMED.",
        ])
    elif upload_unresolved:
        for upload_file, number, field, key, excerpt in dict.fromkeys(upload_unresolved):
            report.append(f"  Unresolved upload handling: $_FILES[{field!r}][{key!r}] at {report_path(upload_file)}:{number}: {excerpt} (no supported storage flow was established).")
        report.extend([
            "  Severity: NEEDS_REVIEW; confidence: Low.",
            "  Vulnerability status: UNCONFIRMED.",
        ])
    else:
        report.append("  No $_FILES upload handling detected.")
    report.extend([
        "", "Source-flow evidence:",
        "  Supported source-to-sink evidence is static tracing evidence, not vulnerability confirmation.",
    ])
    object_access_observations = []
    ssrf_review_observations = []
    command_injection_observations = []
    file_access_observations = []
    confirmed = False
    unconditional_confirmed = False
    helper_branch_flow_confirmed = False
    for file, number, text, sink_type, direct, tracked, invalidated_refs, conditional_flow, flow_snapshot, invalidated_snapshot in sinks:
        report.append(f"  Sink text ({sink_type}) at {report_path(file)}:{number}: {text}")
        if sink_type == "output":
            output_variables = [
                name for name, _, _ in flow_snapshot
                if name not in {"$guard", "$function_result"}
            ]
            output_context, output_context_basis = php_output_context_evidence(
                text, output_variables
            )
            report.append(
                f"    Output context evidence: {output_context}; {output_context_basis}."
            )
            report.append(
                "    Context is inferred from static source fragments only; this does not prove browser interpretation, runtime reachability, exploitability, or encoder effectiveness."
            )
        records = [(m, k, file, number) for m, k in direct]
        associated_variables = {}
        branch_conditioned_records = set()
        for variable, variable_records, _ in flow_snapshot:
            records.extend(variable_records)
            if variable != "$function_result":
                for record in variable_records:
                    associated_variables.setdefault(record, set()).add(variable)
        for _variable, variable_records, variable_edges in flow_snapshot:
            if any(edge and edge[0] == "function-branch" for edge in variable_edges):
                branch_conditioned_records.update(variable_records)
        for method, key, source_file, source_line in dict.fromkeys(records):
            record = (method, key, source_file, source_line)
            is_conditional = conditional_flow or record in branch_conditioned_records
            relationship = "Conditional textual relationship" if is_conditional else "Explicit textual relationship"
            report.append(f"    {relationship}: [{method}] {key} at {report_path(source_file)}:{source_line} reaches a referenced variable or appears directly in the sink at {report_path(file)}:{number}.")
            variables = associated_variables.get((method, key, source_file, source_line))
            if variables:
                variable_names = ", ".join(f"${variable}" for variable in sorted(variables))
                report.append(f"      Tracked-variable association: {variable_names}.")
            confirmed = True
            if not is_conditional:
                unconditional_confirmed = True
            if sink_type == "SQL/query" and is_resource_identifier(key):
                tracked_variables = sorted(
                    set(associated_variables.get(record, set()))
                    | {name for name, _, _ in flow_snapshot if name != "$guard"}
                    | {key}
                )
                observed_guards = []
                for flow_variable, flow_records, flow_edges in flow_snapshot:
                    if record not in flow_records and flow_variable != "$guard":
                        continue
                    for edge in flow_edges:
                        if edge and edge[0] == "guard":
                            _, guard_file, guard_line, condition, arm = edge
                            observed_guards.append((guard_file, guard_line, condition, arm))
                object_access_observations.append({
                    "method": method,
                    "key": key,
                    "source_file": source_file,
                    "source_line": source_line,
                    "sink_file": file,
                    "sink_line": number,
                    "sink_type": sink_type,
                    "tracked_variables": tracked_variables,
                    "guards": list(dict.fromkeys(observed_guards)),
                })
            if sink_type == "Dangerous server-side operation: file_get_contents":
                tracked_url_variables = sorted(
                    set(associated_variables.get(record, set()))
                    | {
                        name for name, flow_records, _ in flow_snapshot
                        if record in flow_records and name not in {"$guard", "$function_result"}
                    }
                )
                observed_guards = []
                for flow_variable, flow_records, flow_edges in flow_snapshot:
                    if record not in flow_records and flow_variable != "$guard":
                        continue
                    for edge in flow_edges:
                        if edge and edge[0] == "guard":
                            _, guard_file, guard_line, condition, arm = edge
                            observed_guards.append((guard_file, guard_line, condition, arm))
                recognized_checks = []
                for guard_file, guard_line, condition, arm in dict.fromkeys(observed_guards):
                    for variable in tracked_url_variables:
                        variable_name = re.escape(variable.lstrip("$"))
                        if re.search(
                            r"\bfilter_var\s*\(\s*\$" + variable_name
                            + r"\s*,\s*FILTER_VALIDATE_URL\b",
                            condition,
                            re.I,
                        ):
                            recognized_checks.append((
                                guard_file, guard_line, condition, arm,
                                "URL-format validation",
                            ))
                        elif re.search(
                            r"\bin_array\s*\(\s*\$" + variable_name
                            + r"\s*,\s*\$[A-Za-z_]\w*",
                            condition,
                            re.I,
                        ):
                            recognized_checks.append((
                                guard_file, guard_line, condition, arm,
                                "exact-URL allowlist-like membership",
                            ))
                ssrf_review_observations.append({
                    "method": method,
                    "key": key,
                    "source_file": source_file,
                    "source_line": source_line,
                    "sink_file": file,
                    "sink_line": number,
                    "variables": tracked_url_variables,
                    "guards": list(dict.fromkeys(observed_guards)),
                    "checks": list(dict.fromkeys(recognized_checks)),
                })
            command_name = sink_type.rsplit(": ", 1)[-1].lower()
            if (
                sink_type.startswith("Dangerous server-side operation: ")
                and command_name in command_execution_names
            ):
                tracked_command_variables = sorted(
                    set(associated_variables.get(record, set()))
                    | {
                        name for name, flow_records, _ in flow_snapshot
                        if record in flow_records and name not in {"$guard", "$function_result"}
                    }
                )
                transformations = []
                for _flow_variable, flow_records, flow_edges in flow_snapshot:
                    if record not in flow_records:
                        continue
                    for edge in flow_edges:
                        if edge and edge[0] == "builtin-transformed":
                            (_, transform_file, transform_line, transform_name,
                             argument_expression, return_expression, category) = edge
                            if category in {
                                "shell-argument-escaping", "shell-command-escaping",
                            }:
                                transformations.append({
                                    "file": transform_file,
                                    "line": transform_line,
                                    "name": transform_name,
                                    "expression": return_expression,
                                    "category": category,
                                    "basis": "call",
                                })
                        elif edge and edge[0] == "function-transformed":
                            (_, call_file, call_line, function_name, definition_file,
                             _definition_line, _parameter, _argument, return_line,
                             return_expression, category) = edge
                            if category in {
                                "shell-argument-escaping", "shell-command-escaping",
                            }:
                                transformations.append({
                                    "file": definition_file,
                                    "line": return_line,
                                    "name": function_name,
                                    "expression": return_expression,
                                    "category": category,
                                    "basis": f"helper call at {report_path(call_file)}:{call_line}",
                                })
                command_injection_observations.append({
                    "method": method,
                    "key": key,
                    "source_file": source_file,
                    "source_line": source_line,
                    "sink_file": file,
                    "sink_line": number,
                    "sink_type": sink_type,
                    "variables": tracked_command_variables,
                    "transformations": list({
                        (item["file"].resolve(), item["line"], item["expression"]): item
                        for item in transformations
                    }.values()),
                })
            file_operation = sink_type.rsplit(": ", 1)[-1].lower()
            if (
                sink_type.startswith("Dangerous server-side operation: ")
                and file_operation in file_read_operation_names
            ):
                tracked_path_variables = sorted(
                    set(associated_variables.get(record, set()))
                    | {
                        name for name, flow_records, _ in flow_snapshot
                        if record in flow_records and name not in {"$guard", "$function_result"}
                    }
                )
                observed_guards = []
                transformations = []
                for flow_variable, flow_records, flow_edges in flow_snapshot:
                    if record not in flow_records and flow_variable != "$guard":
                        continue
                    for edge in flow_edges:
                        if edge and edge[0] == "guard":
                            _, guard_file, guard_line, condition, arm = edge
                            observed_guards.append((guard_file, guard_line, condition, arm))
                        elif edge and edge[0] == "builtin-transformed":
                            (_, transform_file, transform_line, transform_name,
                             _argument_expression, return_expression, category) = edge
                            if category in {"path-component-reduction", "path-canonicalization"}:
                                transformations.append((
                                    transform_file, transform_line, transform_name,
                                    return_expression, category, "direct call",
                                ))
                        elif edge and edge[0] == "function-transformed":
                            (_, call_file, call_line, function_name, definition_file,
                             _definition_line, _parameter, _argument, return_line,
                             return_expression, category) = edge
                            if category in {"path-component-reduction", "path-canonicalization"}:
                                transformations.append((
                                    definition_file, return_line, function_name,
                                    return_expression, category,
                                    f"helper call at {report_path(call_file)}:{call_line}",
                                ))
                base_checks = []
                for guard_file, guard_line, condition, arm in dict.fromkeys(observed_guards):
                    for variable in tracked_path_variables:
                        variable_name = re.escape(variable.lstrip("$"))
                        if re.search(
                            r"\b(?:strpos|str_starts_with)\s*\(\s*\$"
                            + variable_name
                            + r"\s*,\s*\$[A-Za-z_]\w*(?:base|root|dir|directory)\w*",
                            condition,
                            re.I,
                        ):
                            base_checks.append((
                                guard_file, guard_line, condition, arm,
                                "base-directory prefix check-like condition",
                            ))
                file_access_observations.append({
                    "method": method,
                    "key": key,
                    "source_file": source_file,
                    "source_line": source_line,
                    "sink_file": file,
                    "sink_line": number,
                    "operation": file_operation,
                    "variables": tracked_path_variables,
                    "guards": list(dict.fromkeys(observed_guards)),
                    "base_checks": list(dict.fromkeys(base_checks)),
                    "transformations": list(dict.fromkeys(transformations)),
                })
        reported_guard_edges = set()
        for variable, _, variable_edges in flow_snapshot:
            for edge in variable_edges:
                if edge and edge[0] == "guard":
                    _, guard_file, guard_line, condition, arm = edge
                    guard_key = (guard_file.resolve(), guard_line, condition, arm)
                    if guard_key in reported_guard_edges:
                        continue
                    reported_guard_edges.add(guard_key)
                    report.append(
                        f"    Guard condition: if ({condition}) at {report_path(guard_file)}:{guard_line}; {arm} path evidence. The condition is not treated as validation or sanitization."
                    )
                elif edge and edge[0] == "source-assignment":
                    _, assignment_file, assignment_line, destination, method, key = edge
                    report.append(
                        f"    Assignment evidence: {report_path(assignment_file)}:{assignment_line} ${destination} receives [{method}] {key}."
                    )
                elif edge and edge[0] == "function-assignment":
                    _, assignment_file, assignment_line, destination = edge
                    report.append(
                        f"    Assignment evidence: {report_path(assignment_file)}:{assignment_line} ${destination} receives a supported function return."
                    )
                elif edge and edge[0] == "function":
                    (
                        _, call_file, call_line, function_name, definition_file,
                        definition_line, parameter, argument_expression, return_line, alias_records,
                        return_variable,
                    ) = edge
                    report.append(
                        f"    Function definition: {report_path(definition_file)}:{definition_line} function {function_name}(...)."
                    )
                    report.append(
                        f"    Function parameter: ${parameter} receives {argument_expression} at the call site."
                    )
                    for alias_file, alias_line, alias_dest, alias_source in alias_records:
                        report.append(
                            f"    Function alias: {report_path(alias_file)}:{alias_line} ${alias_dest} aliases ${alias_source}."
                        )
                    report.append(
                        f"    Function return: {report_path(definition_file)}:{return_line} returns ${return_variable}."
                    )
                    report.append(
                        f"    Function call: {report_path(call_file)}:{call_line} calls {function_name}(...)."
                    )
                elif edge and edge[0] == "function-transformed":
                    (
                        _, call_file, call_line, function_name, definition_file,
                        definition_line, parameter, argument_expression, return_line,
                        return_expression, return_category,
                    ) = edge
                    report.append(
                        f"    Function definition: {report_path(definition_file)}:{definition_line} function {function_name}(...)."
                    )
                    report.append(
                        f"    Function parameter: ${parameter} receives {argument_expression} at the call site."
                    )
                    if return_category == "quote-escaping":
                        category_note = transformation_context_note(return_category, sink_type)
                    elif return_category in {
                        "shell-argument-escaping", "shell-command-escaping",
                        "path-component-reduction", "path-canonicalization",
                    }:
                        category_note = transformation_context_note(return_category, sink_type)
                    elif return_category == "sql-escaping":
                        category_note = "classified as SQL escaping, not HTML output encoding; SQL-context effectiveness is not inferred. Transformation effectiveness is not inferred."
                    elif return_category == "html-output-encoding":
                        category_note = "classified as HTML output encoding, not SQL escaping; context effectiveness is not inferred. Transformation effectiveness is not inferred."
                    else:
                        category_note = "transformation category is not established; effectiveness is not inferred."
                    report.append(
                        f"    Function transformed return expression: {return_expression} at {report_path(definition_file)}:{return_line}; {category_note}"
                    )
                    report.append(
                        f"    Function call: {report_path(call_file)}:{call_line} calls {function_name}(...)."
                    )
                elif edge and edge[0] == "builtin-transformed":
                    (
                        _, transform_file, transform_line, transform_name,
                        argument_expression, return_expression, return_category,
                    ) = edge
                    transformation_label = (
                        "Recognized command argument transformation"
                        if return_category in {"shell-argument-escaping", "shell-command-escaping"}
                        else "Recognized transformation"
                    )
                    report.append(
                        f"    {transformation_label}: {return_expression} at "
                        f"{report_path(transform_file)}:{transform_line}; "
                        f"{transformation_context_note(return_category, sink_type)}"
                    )
                elif edge and edge[0] == "function-branch":
                    (
                        _, call_file, call_line, function_name, definition_file,
                        definition_line, switch_expression, condition, branch_line,
                        return_line, shared_return_line, parameter, argument_expression, return_kind,
                        return_expression, helper_prelude,
                    ) = edge
                    helper_branch_flow_confirmed = True
                    report.append(
                        f"    Function definition: {report_path(definition_file)}:{definition_line} function {function_name}(...)."
                    )
                    report.append(
                        f"    Function parameter: ${parameter} receives {argument_expression} at the call site."
                    )
                    report.append(
                        f"    Helper branch condition: switch ({switch_expression}), case {condition} at {report_path(definition_file)}:{branch_line}."
                    )
                    for prelude_file, prelude_line, prelude_text in helper_prelude:
                        report.append(
                            f"    Helper context include: {report_path(prelude_file)}:{prelude_line} {prelude_text}; source context only."
                        )
                    if return_kind == "identity":
                        identity_suffix = " (assigned before the shared return)" if shared_return_line else ""
                        report.append(
                            f"    Helper branch return: {return_expression} unchanged{identity_suffix} at {report_path(definition_file)}:{return_line}."
                        )
                    elif return_kind == "sql-escaping":
                        report.append(
                            f"    Helper branch return expression: {return_expression} at {report_path(definition_file)}:{return_line}; SQL escaping, not HTML output encoding; SQL-context effectiveness is not inferred. Transformation effectiveness is not inferred."
                        )
                    elif return_kind == "quote-escaping":
                        report.append(
                            f"    Helper branch return expression: {return_expression} at {report_path(definition_file)}:{return_line}; {transformation_context_note(return_kind, sink_type)}"
                        )
                    elif return_kind in {"path-component-reduction", "path-canonicalization"}:
                        report.append(
                            f"    Helper branch return expression: {return_expression} at {report_path(definition_file)}:{return_line}; {transformation_context_note(return_kind, sink_type)}"
                        )
                    elif return_kind == "html-output-encoding":
                        report.append(
                            f"    Helper branch return expression: {return_expression} at {report_path(definition_file)}:{return_line}; HTML output encoding, not SQL escaping; context effectiveness is not inferred. Transformation effectiveness is not inferred."
                        )
                    else:
                        report.append(
                            f"    Helper branch return expression: {return_expression} at {report_path(definition_file)}:{return_line}; transformation category/effectiveness is not established."
                        )
                    if shared_return_line:
                        report.append(
                            f"    Shared helper return: {report_path(definition_file)}:{shared_return_line} returns ${parameter}; this follows the branch assignment."
                        )
                    nested_call = re.fullmatch(
                        r"([A-Za-z_]\w*)\s*\((.*)\)", return_expression
                    )
                    if nested_call:
                        nested_candidates = [
                            candidate for candidate in function_summaries.get(
                                nested_call.group(1).lower(), []
                            ) if candidate[1] == root_file or candidate[1] in visited
                        ]
                        if len(nested_candidates) == 1 and nested_candidates[0][0]:
                            nested_summary, nested_file, nested_line, _, _ = nested_candidates[0]
                            nested_arguments = split_call_arguments(nested_call.group(2))
                            parameter_index = nested_summary["params"].index(nested_summary["parameter"])
                            argument_value = nested_arguments[parameter_index] if parameter_index < len(nested_arguments) else "(unresolved argument)"
                            if nested_summary.get("return_kind") == "transformed":
                                nested_kind = nested_summary.get("return_category", "other-transformation")
                                nested_note = (
                                    transformation_context_note(nested_kind, "SQL/query")
                                    if nested_kind == "quote-escaping"
                                    else "SQL escaping, not HTML output encoding"
                                    if nested_kind == "sql-escaping"
                                    else "HTML output encoding, not SQL escaping"
                                    if nested_kind == "html-output-encoding"
                                    else "transformation category unresolved"
                                )
                                nested_return = nested_summary["return_expression"]
                            else:
                                nested_note = "identity return"
                                nested_return = f"${nested_summary['return_variable']}"
                            report.append(
                                f"    Nested helper definition: {report_path(nested_file)}:{nested_line} {nested_call.group(1)}(...); parameter ${nested_summary['parameter']} receives {argument_value}; return {nested_return} at {report_path(nested_file)}:{nested_summary['return_line']} ({nested_note}; effectiveness is not inferred)."
                            )
                    report.append(
                        f"    Function call: {report_path(call_file)}:{call_line} calls {function_name}(...)."
                    )
                else:
                    edge_file, edge_line, source, dest = edge
                    report.append(f"    Assignment evidence: {report_path(edge_file)}:{edge_line} ${dest} references ${source}.")
        for variable in invalidated_refs:
            invalid_file, invalid_line = invalidated_snapshot[variable]
            report.append(
                f"    Unresolved relationship: ${variable} appears at this sink, but its earlier request provenance was invalidated by reassignment at {report_path(invalid_file)}:{invalid_line}; no source-to-sink link is asserted."
            )
    for flow in prepared_statement_flows:
        statement = flow["statement"]
        binding = flow["binding"]
        query = statement["query"]
        execute_line = flow["execute_line"]
        is_conditional = bool(flow["guards"] or any(
            edge and edge[0] == "guard" for edge in binding["edges"]
        ))
        report.append(
            f"  Sink text (SQL/prepared statement parameter) at {report_path(statement['file'])}:{execute_line}: ${statement['statement_variable']}->execute()."
        )
        for method, key, source_file, source_line in binding["records"]:
            relationship = "Conditional textual relationship" if is_conditional else "Explicit textual relationship"
            report.append(
                f"    {relationship}: [{method}] {key} at {report_path(source_file)}:{source_line} reaches bound parameter #{binding['position']} (${binding['variable']}) at {report_path(statement['file'])}:{binding['line']} and execution at {report_path(statement['file'])}:{execute_line}."
            )
            confirmed = True
            if not is_conditional:
                unconditional_confirmed = True
            if is_resource_identifier(key):
                observed_guards = list(flow["guards"])
                for edge in binding["edges"]:
                    if edge and edge[0] == "guard":
                        _, guard_file, guard_line, condition, arm = edge
                        observed_guards.append((guard_file, guard_line, condition, arm))
                object_access_observations.append({
                    "method": method,
                    "key": key,
                    "source_file": source_file,
                    "source_line": source_line,
                    "sink_file": statement["file"],
                    "sink_line": execute_line,
                    "sink_type": "SQL/prepared statement parameter",
                    "tracked_variables": [f"${binding['variable']}"],
                    "guards": list(dict.fromkeys(observed_guards)),
                })
        report.append(
            f"    Prepared query: {report_path(statement['file'])}:{query['query_line']} contains {query['placeholder_count']} positional placeholder(s)."
        )
        report.append(
            f"    Prepare call: {report_path(statement['file'])}:{statement['prepare_line']} {statement['prepare_text']}"
        )
        report.append(
            f"    Binding evidence: parameter #{binding['position']} uses ${binding['variable']} (type {binding['type']}) at {report_path(statement['file'])}:{binding['line']}."
        )
        report.append(
            f"    Execute evidence: {report_path(statement['file'])}:{execute_line} {flow['execute_text']}"
        )
        described_guards = set()
        for edge in binding["edges"]:
            if edge and edge[0] == "source-assignment":
                _, assignment_file, assignment_line, destination, method, key = edge
                report.append(
                    f"    Assignment evidence: {report_path(assignment_file)}:{assignment_line} ${destination} receives [{method}] {key}."
                )
            elif edge and edge[0] == "guard":
                _, guard_file, guard_line, condition, arm = edge
                guard_key = (guard_file.resolve(), guard_line, condition, arm)
                if guard_key not in described_guards:
                    described_guards.add(guard_key)
                    report.append(
                        f"    Guard condition: if ({condition}) at {report_path(guard_file)}:{guard_line}; {arm} path evidence. The condition is not treated as validation or sanitization."
                    )
            elif edge and len(edge) == 4 and isinstance(edge[0], Path):
                assignment_file, assignment_line, source, destination = edge
                report.append(
                    f"    Assignment evidence: {report_path(assignment_file)}:{assignment_line} ${destination} references ${source}."
                )
        for guard_file, guard_line, condition, arm in flow["guards"]:
            guard_key = (guard_file.resolve(), guard_line, condition, arm)
            if guard_key in described_guards:
                continue
            described_guards.add(guard_key)
            report.append(
                f"    Guard condition: if ({condition}) at {report_path(guard_file)}:{guard_line}; {arm} path evidence. The condition is not treated as validation or sanitization."
            )
        report.append(
            "    This value is represented as a bound parameter, not concatenated into the SQL text; this statement alone does not establish application-wide security."
        )
    if object_access_observations:
        report.extend([
            "",
            "Object-level access-control review observations (not vulnerability findings):",
        ])
        seen_object_observations = set()
        for observation in object_access_observations:
            identity = (
                observation["method"], observation["key"],
                observation["source_file"].resolve(), observation["source_line"],
                observation["sink_file"].resolve(), observation["sink_line"],
            )
            if identity in seen_object_observations:
                continue
            seen_object_observations.add(identity)
            report.append(
                f"  Request identifier [{observation['method']}] {observation['key']} at "
                f"{report_path(observation['source_file'])}:{observation['source_line']} "
                f"reaches {observation['sink_type']} at "
                f"{report_path(observation['sink_file'])}:{observation['sink_line']}."
            )
            if observation["tracked_variables"]:
                report.append(
                    "    Tracked variable(s): "
                    + ", ".join(observation["tracked_variables"])
                    + "; assignment evidence is listed in Source-flow evidence."
                )
            authorization_guards = []
            for guard in observation["guards"]:
                classification = is_authorization_like_guard(
                    guard[2], observation["tracked_variables"]
                )
                if classification:
                    authorization_guards.append((guard, classification))
            if authorization_guards:
                for (guard_file, guard_line, condition, arm), classification in authorization_guards:
                    report.append(
                        f"    Authorization-like condition observed at "
                        f"{report_path(guard_file)}:{guard_line}: if ({condition}) ({arm})."
                    )
                    if classification[0] == "helper":
                        helper_file, helper_line, helper_name = classification[1]
                        report.append(
                            f"      Local helper evidence: {helper_name} at "
                            f"{report_path(helper_file)}:{helper_line} contains a supported "
                            "parameter-to-principal/owner comparison. This does not prove the helper is complete or effective."
                        )
                report.append(
                    "    The condition is structural evidence only; JARVIS does not establish that it checks the requested object's owner or tenant, denies the unauthorized path, or is correct at runtime."
                )
            else:
                report.append(
                    "    No supported authorization-like condition was recognized on this captured path. This does not prove that authorization is missing; checks may exist in middleware, helpers, included code, database policy, or other paths outside the supported analysis."
                )
            report.extend([
                "    Finding confidence: Low; request-to-database flow is evidence for review, not proof of an object-level access flaw.",
                "    Severity: NEEDS_REVIEW; impact, affected object, caller permissions, and complete authorization context are not established.",
                "    Vulnerability status: UNCONFIRMED.",
                "    Review guidance: inspect the complete server-side call chain and verify that each requested object is authorized against the authenticated principal or tenant.",
            ])
    report.extend(["", "URL-fetch / SSRF review observations (not vulnerability findings):"])
    if ssrf_review_observations:
        seen_ssrf_observations = set()
        for observation in ssrf_review_observations:
            identity = (
                observation["method"], observation["key"],
                observation["source_file"].resolve(), observation["source_line"],
                observation["sink_file"].resolve(), observation["sink_line"],
            )
            if identity in seen_ssrf_observations:
                continue
            seen_ssrf_observations.add(identity)
            report.append(
                f"  Request input [{observation['method']}] {observation['key']} at "
                f"{report_path(observation['source_file'])}:{observation['source_line']} "
                f"has a supported flow to file_get_contents() at "
                f"{report_path(observation['sink_file'])}:{observation['sink_line']}."
            )
            if observation["variables"]:
                report.append(
                    "    Tracked URL variable(s): "
                    + ", ".join(observation["variables"])
                    + "; assignment evidence appears above in Source-flow evidence."
                )
            for guard_file, guard_line, condition, arm in observation["guards"]:
                report.append(
                    f"    Nearby guard evidence: if ({condition}) at "
                    f"{report_path(guard_file)}:{guard_line} ({arm}); condition alone is not proof of validation."
                )
            if observation["checks"]:
                for guard_file, guard_line, condition, arm, check_type in observation["checks"]:
                    report.append(
                        f"    Recognized {check_type} evidence at "
                        f"{report_path(guard_file)}:{guard_line}: if ({condition}) ({arm})."
                    )
                    if check_type == "URL-format validation":
                        report.append(
                            "      URL-format validation does not establish an allowed host, scheme, resolved address, redirect policy, or safe destination."
                        )
                    else:
                        report.append(
                            "      Allowlist contents, URL-to-entry equivalence, and enforcement on every path are not established."
                        )
            else:
                report.append(
                    "    No supported URL validation or allowlist condition was recognized on this captured path; this does not prove checks are absent elsewhere."
                )
            report.extend([
                "    Static request-to-URL-fetch flow does not prove that a remote request occurs or that an internal/restricted destination is reachable.",
                "    Finding confidence: Low; destination control, URL parsing, redirects, network policy, and runtime behavior are unresolved.",
                "    Severity: NEEDS_REVIEW; impact and exploitability are not established.",
                "    Vulnerability status: UNCONFIRMED.",
            ])
    else:
        report.append(
            "  No supported request-controlled flow to file_get_contents() was established. Fixed URLs and unsupported or ambiguous network APIs are not SSRF findings in this review."
        )
    report.extend(["", "Command-execution / command-injection review observations (not vulnerability findings):"])
    if command_injection_observations:
        seen_command_observations = set()
        for observation in command_injection_observations:
            identity = (
                observation["method"], observation["key"],
                observation["source_file"].resolve(), observation["source_line"],
                observation["sink_file"].resolve(), observation["sink_line"],
                observation["sink_type"],
            )
            if identity in seen_command_observations:
                continue
            seen_command_observations.add(identity)
            operation = observation["sink_type"].rsplit(": ", 1)[-1]
            report.append(
                f"  Request input [{observation['method']}] {observation['key']} at "
                f"{report_path(observation['source_file'])}:{observation['source_line']} "
                f"has a supported flow to {operation}() at "
                f"{report_path(observation['sink_file'])}:{observation['sink_line']}."
            )
            if observation["variables"]:
                report.append(
                    "    Tracked command variable(s): "
                    + ", ".join(observation["variables"])
                    + "; assignment evidence appears above in Source-flow evidence."
                )
            if observation["transformations"]:
                for transformation in observation["transformations"]:
                    note = transformation_context_note(
                        transformation["category"], observation["sink_type"]
                    )
                    report.append(
                        f"    Transformation evidence: {transformation['expression']} at "
                        f"{report_path(transformation['file'])}:{transformation['line']} "
                        f"({transformation['basis']}); {note}"
                    )
            else:
                report.append(
                    "    No recognized shell-argument handling transformation was observed in this captured trace; this does not establish that none exists elsewhere."
                )
            report.extend([
                "    Static flow does not establish shell interpretation, attacker control of metacharacters, argument position, executable behavior, or runtime command effects.",
                "    Finding confidence: Low; command composition and runtime behavior remain unverified.",
                "    Severity: NEEDS_REVIEW; exploitability and impact are not established.",
                "    Vulnerability status: UNCONFIRMED.",
                "    Review guidance: prefer fixed executable paths with argument-array APIs and keep untrusted values in distinct arguments; validate the required type and domain.",
            ])
    else:
        report.append(
            "  No supported request-controlled flow to an OS command-execution function was established. Static commands, unresolved helper-built commands, and object methods such as $database->exec() are not command-injection findings in this review."
        )
    report.extend(["", "File-access / path-traversal review observations (not vulnerability findings):"])
    if file_access_observations:
        seen_file_observations = set()
        for observation in file_access_observations:
            identity = (
                observation["method"], observation["key"],
                observation["source_file"].resolve(), observation["source_line"],
                observation["sink_file"].resolve(), observation["sink_line"],
                observation["operation"],
            )
            if identity in seen_file_observations:
                continue
            seen_file_observations.add(identity)
            report.append(
                f"  Request input [{observation['method']}] {observation['key']} at "
                f"{report_path(observation['source_file'])}:{observation['source_line']} "
                f"has a supported flow to {observation['operation']}() at "
                f"{report_path(observation['sink_file'])}:{observation['sink_line']}."
            )
            if observation["variables"]:
                report.append(
                    "    Tracked path variable(s): "
                    + ", ".join(observation["variables"])
                    + "; assignment evidence appears above in Source-flow evidence."
                )
            for transform_file, transform_line, transform_name, expression, category, basis in observation["transformations"]:
                report.append(
                    f"    Path transformation evidence: {expression} ({transform_name}) at "
                    f"{report_path(transform_file)}:{transform_line} ({basis}); "
                    f"{transformation_context_note(category, observation['operation'])}"
                )
            for guard_file, guard_line, condition, arm in observation["guards"]:
                report.append(
                    f"    Guard evidence: if ({condition}) at {report_path(guard_file)}:{guard_line} "
                    f"({arm}); path condition only, not proof of containment or validation."
                )
            if observation["base_checks"]:
                for guard_file, guard_line, condition, arm, check_type in observation["base_checks"]:
                    report.append(
                        f"    Recognized {check_type} at {report_path(guard_file)}:{guard_line}: "
                        f"if ({condition}) ({arm})."
                    )
                    report.append(
                        "      Canonical-path equality, path-separator boundaries, symlink behavior, and rejection of failed canonicalization are not established."
                    )
            else:
                report.append(
                    "    No supported base-directory prefix check was recognized on this captured path; this does not prove validation or confinement is absent elsewhere."
                )
            report.extend([
                "    Static request-to-file-read flow does not prove traversal, access outside an intended directory, a successful read, or sensitive-data impact.",
                "    Finding confidence: Low; canonical path, effective base restriction, file permissions, and runtime behavior are unresolved.",
                "    Severity: NEEDS_REVIEW; exploitability and impact are not established.",
                "    Vulnerability status: UNCONFIRMED.",
                "    Review guidance: canonicalize the candidate and intended base, enforce separator-aware containment after canonicalization, handle failure closed, and keep file access within the authorized root.",
            ])
    else:
        report.append(
            "  No supported request-controlled flow to file_get_contents() or readfile() was established. Fixed paths, unresolved helper-built paths, and unsupported file APIs are not path-traversal findings in this review."
        )
    if not confirmed:
        report.append("  No supported source-to-sink relationship established.")
    report.extend([
        "", "Local function analysis:",
        "  Unique straight-line parameter aliases and complete simple switch branches with literal labels may be summarized.",
        "  Function behavior and sanitization effectiveness are not inferred for unresolved bodies; recognized transform expressions retain argument provenance only, and effectiveness for an output context is not inferred.",
        "  Unsupported function bodies or call expressions remain unresolved; request provenance is reported separately.",
        "  Request provenance retained for unsupported calls identifies a source reference, not a verified transformed value or complete stored-data flow.",
        "", "Database operation observations:",
    ])
    if database_observations:
        for label, file, number, text in database_observations:
            report.append(f"  {label} at {report_path(file)}:{number}: {text}")
        report.append(
            "  The presence of database writes, retrievals, and output observations does not establish a joined stored-data flow; shared table names alone are insufficient."
        )
    else:
        report.append("  No supported SQL statement construction or local query execution pairing detected.")
    report.extend(["", "Stored-data provenance observations:"])
    if stored_data_observations or stored_data_flows or unresolved_stored_data:
        for observation in dict.fromkeys(stored_data_observations):
            report.append(f"  {observation}")
        report.append("  SELECT-to-output provenance:")
        if select_output_flows:
            for flow in select_output_flows:
                read = flow["read"]
                query = read["query"]
                output = flow["output"]
                projection = ", ".join(query["columns"])
                if query.get("where_supported") and query.get("where"):
                    where_evidence = f"WHERE {query['where'][0]} = {query['where'][1]}"
                elif query.get("where_text") and not query.get("where_supported"):
                    where_evidence = f"WHERE predicate unresolved ({query['where_text']})"
                else:
                    where_evidence = "no WHERE predicate"
                fetch = output["fetch"]
                report.append(
                    f"    Supported SELECT-to-output path: SELECT {projection} FROM {query['table']} at {report_path(query['file'])}:{query['line']} "
                    f"({where_evidence}); query execution at {report_path(read['execution_file'])}:{read['execution_line']}; "
                    f"{fetch['method']} assigns result to ${fetch['row_variable']} at {report_path(fetch['file'])}:{fetch['line']}; "
                    f"output at {report_path(output['file'])}:{output['line']} uses ${output['row_variable']} column {output['column']}: {output['text']}."
                )
                helper = output.get("helper")
                if helper:
                    if helper["category"] == "identity":
                        helper_note = "identity return."
                    elif helper["category"] == "quote-escaping":
                        helper_note = transformation_context_note(
                            helper["category"], "output"
                        )
                    elif helper["category"] == "html-output-encoding":
                        helper_note = "HTML output encoding, not SQL escaping; effectiveness for the specific output context is not inferred."
                    elif helper["category"] == "sql-escaping":
                        helper_note = "SQL escaping, not HTML output encoding; effectiveness for HTML output is not inferred."
                    else:
                        helper_note = "transformation category is unresolved."
                    report.append(
                        f"      Helper return evidence: {helper['name']} definition at {report_path(helper['file'])}:{helper['definition_line']} "
                        f"receives {helper['argument']} in parameter ${helper['parameter']} and returns {helper['return_expression']} "
                        f"at {report_path(helper['file'])}:{helper['return_line']} ({helper_note} Transformation effectiveness is not inferred.)"
                    )
                for guard_file, guard_line, condition, arm in flow["guards"]:
                    report.append(
                        f"      Guard condition: {condition} at {report_path(guard_file)}:{guard_line} ({arm}); path evidence only."
                    )
                report.append(
                    "      This links the observed SELECT result to the output expression; it does not identify a particular earlier INSERT or confirm runtime database contents."
                )
        else:
            report.append("    No supported SELECT-to-output path established.")
        for flow in stored_data_flows:
            write = flow["write"]
            read = flow["read"]
            query = write["query"]
            read_query = read["query"]
            output_file, output_line, output_column, output_text, _ = flow["output"]
            fetches = read.get("fetches", [])
            fetch_evidence = "; ".join(
                f"{fetch['method']} at {report_path(fetch['file'])}:{fetch['line']} "
                f"assigns ${fetch['row_variable']} ({fetch['text']})"
                for fetch in fetches
            ) or "fetch location unresolved"
            source_method, source_key, source_file, source_line = write["origin"]["source"]
            path_label = "Conditional stored-data path" if flow["guards"] else "Supported stored-data path"
            report.append(
                f"  {path_label}: [{source_method}] {source_key} at {report_path(source_file)}:{source_line} "
                f"is assigned to ${write['value_variable']} at {report_path(write['origin']['assignments'][-1][0])}:{write['origin']['assignments'][-1][1]}, "
                f"written to {query['table']}.{write['column']} by INSERT construction at {report_path(query['file'])}:{query['line']} "
                f"and execution at {report_path(write['execution_file'])}:{write['execution_line']}; "
                f"the matching key predicate is read by SELECT at {report_path(read_query['file'])}:{read_query['line']} "
                f"and executed at {report_path(read['execution_file'])}:{read['execution_line']}; {fetch_evidence}; "
                f"retrieved column {output_column} is observed in output at {report_path(output_file)}:{output_line}: {output_text}."
            )
            for guard_file, guard_line, condition, arm in flow["guards"]:
                report.append(
                    f"    Guard condition: {condition} at {report_path(guard_file)}:{guard_line} ({arm}); path evidence only, not validation or sanitization."
                )
            report.append(
                "    This is static source evidence for a possible row path; query success, database contents, helper effectiveness, and runtime output were not verified."
            )
        for item in dict.fromkeys(unresolved_stored_data):
            report.append(f"  Unresolved stored-data relationship: {item}")
        if not stored_data_flows:
            report.append(
                "  No supported request-to-write-to-read-to-output path established; the listed stages remain separate where provenance or row identity is unresolved."
            )
    else:
        report.append(
            "  No supported request-to-write-to-read-to-output relationship established; database operations remain separate observations."
        )
    report.extend(["", "Prepared-statement observations:"])
    if prepared_statement_observations:
        for statement in prepared_statement_observations:
            query = statement["query"]
            if query and query["supported"]:
                report.append(
                    f"  Query text at {report_path(statement['file'])}:{query['query_line']}: {query['query_text']}"
                )
                report.append(
                    f"  Observed {query['placeholder_count']} positional placeholder(s); prepare call at {report_path(statement['file'])}:{statement['prepare_line']}."
                )
                report.append(f"  Prepare expression: {statement['prepare_text']}")
            else:
                report.append(
                    f"  Prepare call observed at {report_path(statement['file'])}:{statement['prepare_line']}: {statement['prepare_text']}"
                )
            if statement["bindings"]:
                for binding in statement["bindings"]:
                    report.append(
                        f"  Bound parameter #{binding['position']} uses ${binding['variable']} (type {binding['type']}) at {report_path(statement['file'])}:{binding['line']}."
                    )
            elif query and query.get("placeholder_count") == 0:
                report.append("  No positional parameter bindings were present in the observed query.")
            if statement["execute_lines"]:
                for execute_line, execute_text, _ in statement["execute_lines"]:
                    report.append(
                        f"  Execution call observed at {report_path(statement['file'])}:{execute_line}: {execute_text}"
                    )
            if statement["unresolved"]:
                report.append(
                    f"  Parameter mapping remains unresolved: {statement['unresolved']}."
                )
        report.append(
            "  These are source observations; a prepared statement here does not establish that the entire application is secure."
        )
    else:
        report.append("  No supported prepare/bind/execute sequence detected.")
    report.extend(["", "Output branch observations:"])
    output_observations = [item for item in sink_observations if item[0] == "output"]
    if output_observations:
        for _, file, number, excerpt, context in output_observations:
            report.append(
                f"  Output branch observation at {report_path(file)}:{number}: {excerpt}{context}"
            )
        report.append(
            "  The output expression is recorded as source text; helper names and branch presence alone do not establish encoder behavior or exploitability."
        )
    else:
        report.append("  No output sink observations detected.")
    report.extend(["", "Included-file analysis:"])
    report.extend(includes or ["  No supported include statements detected."])
    report.extend(["", "Unresolved analysis candidates:"])
    report.extend(unresolved or ["  None detected."])
    report.extend([
        "", "Evidence and confidence limitations:",
        "  Static source review only; runtime behavior was not validated.",
        "  Unsupported syntax and ambiguous paths remain unresolved.",
    ])
    status = (
        "CONDITIONAL SOURCE-TO-SINK PATHS ESTABLISHED"
        if confirmed and helper_branch_flow_confirmed and not unconditional_confirmed
        else "CONDITIONAL SOURCE PATTERNS; FLOW NOT ESTABLISHED"
        if confirmed and not unconditional_confirmed
        else "SOURCE PATTERNS DETECTED"
        if confirmed
        else "UNRESOLVED INPUT EVIDENCE"
        if entry_conditional_inputs or entry_unresolved_request_inputs
        else "INPUT DETECTED"
        if entry_inputs
        else "REQUEST PRESENCE EVIDENCE ONLY"
        if entry_presence_inputs
        else "INCLUDED-FILE INPUT EVIDENCE"
        if included_inputs or included_conditional_inputs or included_presence_inputs or included_unresolved_request_inputs
        else "NO INPUT DETECTED"
    )
    if any(item.lstrip().startswith("Unresolved ") for item in includes):
        status = f"ANALYSIS INCOMPLETE â€” {status}"
    report.extend([
        "", "Vulnerability status: UNCONFIRMED",
        "  Static observations and traced relationships are review evidence only.",
        "", "Review status:", f"  {status}",
    ])
    if confirmed and entry_conditional_inputs:
        report.append("  UNRESOLVED INPUT EVIDENCE ALSO PRESENT")
    if confirmed and (
        included_inputs
        or included_conditional_inputs
        or included_presence_inputs
        or included_unresolved_request_inputs
    ):
        report.append("  INCLUDED-FILE INPUT EVIDENCE ALSO PRESENT")
    report.extend(["  Input detection, source-to-sink tracing, and vulnerability confirmation are separate assessments.", "  Unsupported syntax and ambiguous conditional paths remain unresolved.", "", "JARVIS assessment:", "  These source patterns are review evidence only; no vulnerability is confirmed."])
    if confirmed:
        report.extend([
            "",
            *_source_flow_severity_lines(
                "SQL injection, output injection, or dangerous server-side operation candidate",
                ["Input evidence and source-flow evidence sections"],
                ["Sink observations and source-flow evidence sections"],
            ),
        ])
    if provenance is not None:
        report.extend([
            "",
            *_format_source_analysis_provenance(
                provenance, source_text_by_file
            ),
        ])
    text = _redact_potential_secrets("\n".join(report))
    print("\n" + text)
    report_file = _write_php_flow_report(path, text + "\n", reports_dir)
    print(f"\nJARVIS: PHP flow evidence saved to {report_file}")


def analyze_php_flow(file_path):
    path = Path(file_path)

    if not path.exists() or path.suffix.lower() != ".php":
        print("JARVIS: PHP file not found.")
        return

    provenance = _begin_source_analysis_provenance()
    try:
        source = path.read_text(errors="ignore")
    except OSError as e:
        print(f"JARVIS: Could not read PHP file: {e}")
        return

    return _trace_php_flow(path, source, REPORTS_DIR, provenance=provenance)


_JS_FLOW_SUPPORTED_EXTENSIONS = {".js", ".mjs", ".cjs"}
_JS_FLOW_SOURCE_EXPRESSIONS = {
    "location.search": "URL query string",
    "window.location.search": "URL query string",
    "location.hash": "URL fragment",
    "window.location.hash": "URL fragment",
    "document.referrer": "document referrer",
    "window.name": "window name",
    "event.data": "message event data",
    "e.data": "message event data",
}


def _js_flow_strip_line_comment(line):
    """Remove a JavaScript line comment while preserving quoted strings."""
    quote_char = None
    escaped = False
    index = 0
    while index < len(line):
        char = line[index]
        if quote_char:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote_char:
                quote_char = None
        elif char in {"'", '"'}:
            quote_char = char
        elif line[index:index + 2] == "//":
            return line[:index]
        index += 1
    return line


def _js_flow_mask_string_literals(line):
    """Mask quoted literal contents before checking syntax markers."""
    masked = list(line)
    quote_char = None
    escaped = False
    for index, char in enumerate(line):
        if quote_char:
            masked[index] = " "
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote_char:
                quote_char = None
        elif char in {"'", '"'}:
            quote_char = char
            masked[index] = " "
    return "".join(masked)


def _js_flow_clean_expression(expression):
    expression = expression.strip().rstrip(";").strip()
    while expression.startswith("(") and expression.endswith(")"):
        expression = expression[1:-1].strip()
    return expression


def _js_flow_source_kind(expression):
    return _JS_FLOW_SOURCE_EXPRESSIONS.get(
        _js_flow_clean_expression(expression)
    )


def _js_flow_secret_literal(line):
    """Return a secret-like identifier for a non-placeholder string literal."""
    match = re.fullmatch(
        r"(?:export\s+)?(?:(?:const|let|var)\s+)?"
        r"(?P<name>[A-Za-z_$][\w$-]*)\s*(?:=|:)\s*"
        r"(?P<quote>['\"])(?P<value>[^'\"\r\n]{8,})(?P=quote)\s*[,;]?",
        line.strip(),
    )
    if not match:
        return None
    name = match.group("name")
    if not re.search(
        r"(?:api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|"
        r"auth[_-]?token|private[_-]?key|password|passwd|secret|token)",
        name,
        re.I,
    ):
        return None
    value = match.group("value").strip().casefold()
    if (
        not value
        or re.fullmatch(r"(?:your|replace|change|insert|enter)[_-].*", value)
        or re.fullmatch(r"(?:example|sample|dummy|test)[_-].*", value)
        or re.fullmatch(r"(?:example|sample|dummy|test|changeme|change_me|"
                        r"placeholder|redacted|not[-_ ]?a[-_ ]?real[-_ ]?secret|"
                        r"none|null|undefined|x{3,}|0{6,})", value)
        or value.startswith("<") and value.endswith(">")
    ):
        return None
    return name


def _js_flow_client_auth_identifiers(line):
    """Find role/permission identifiers in simple client-side if conditions."""
    masked = _js_flow_mask_string_literals(line)
    branch = re.search(r"\bif\s*\(\s*([^()\n]+)\s*\)", masked)
    if not branch:
        return []
    return list(dict.fromkeys(re.findall(
        r"\b(?:is_?admin|is_?owner|is_?authorized|is_?authenticated|"
        r"role|permission|permissions|can[A-Z]\w*|has[A-Z]\w*)\b",
        branch.group(1),
        re.I,
    )))


def _analyze_js_flow_source(path, source):
    """Trace a deliberately small, line-oriented JavaScript subset."""
    path = Path(path)
    assignments = {}
    url_search_params = {}
    write_counts = {}
    invalid_variables = set()
    candidates = []
    secret_literals = []
    client_auth_observations = []
    unresolved = []
    control_flow = re.compile(
        r"\b(if|else|for|while|switch|try|catch|finally)\b|[?:]|&&|\|\|"
    )
    declaration_or_assignment = re.compile(
        r"^(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*(.+?)\s*;?$"
    )
    url_search_params_constructor = re.compile(
        r"^new\s+URLSearchParams\(\s*(location\.search|window\.location\.search)\s*\)$"
    )
    url_search_params_get = re.compile(
        r"^([A-Za-z_$][\w$]*)\.get\(\s*(['\"])([^'\"]+)\2\s*\)$"
    )
    inner_html_assignment = re.compile(
        r"^((?:[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*|document\.getElementById\(\s*(?:'[^'\\]*(?:\\.[^'\\]*)*'|\"[^\"\\]*(?:\\.[^\"\\]*)*\")\s*\)))\.innerHTML\s*=\s*(.+?)\s*;?$"
    )

    for line_number, raw_line in enumerate(source.splitlines(), 1):
        line = _js_flow_strip_line_comment(raw_line).strip()
        if not line:
            continue
        secret_name = _js_flow_secret_literal(line)
        if secret_name:
            secret_literals.append((line_number, secret_name))
        auth_identifiers = _js_flow_client_auth_identifiers(line)
        if auth_identifiers:
            client_auth_observations.append((line_number, auth_identifiers))
        if "`" in line:
            template_sink = inner_html_assignment.fullmatch(line)
            simple_template = None
            if template_sink:
                simple_template = re.fullmatch(
                    r'`\$\{([A-Za-z_$][\w$]*)\}`',
                    template_sink.group(2).strip(),
                )
            if simple_template:
                # Preserve the original .innerHTML sink for the matcher below.
                pass
            else:
                unresolved.append(
                    f"Line {line_number}: template literal syntax is unsupported."
                )
                continue
        if control_flow.search(_js_flow_mask_string_literals(line)):
            unresolved.append(
                f"Line {line_number}: control flow or compound expression is unsupported; traces in this file are withheld."
            )
            candidates = []
            break

        sink_match = inner_html_assignment.fullmatch(line)
        if sink_match:
            sink_expression = _js_flow_clean_expression(sink_match.group(2))
            template_interpolation = re.fullmatch(
                r'`\$\{([A-Za-z_$][\w$]*)\}`',
                sink_expression,
            )
            if template_interpolation:
                sink_expression = template_interpolation.group(1)
            source_kind = _js_flow_source_kind(sink_expression)
            steps = []
            if source_kind:
                source_line = line_number
                source_expression = sink_expression
                source_text = raw_line.strip()
            elif re.fullmatch(r"[A-Za-z_$][\w$]*", sink_expression):
                variable = sink_expression
                trace = assignments.get(variable)
                if trace and variable not in invalid_variables:
                    source_kind, source_expression, source_line, source_text, steps = trace
                else:
                    continue
            else:
                continue
            candidates.append({
                "source_kind": source_kind,
                "source_expression": source_expression,
                "source_line": source_line,
                "source_text": source_text,
                "sink_object": sink_match.group(1),
                "sink_expression": sink_expression,
                "sink_line": line_number,
                "sink_text": raw_line.strip(),
                "steps": steps,
            })
            continue

        # Compound writes are not modeled by this line-oriented analyzer.
        # Invalidate a tracked identifier rather than retaining a stale trace.
        compound_match = re.fullmatch(
            r"([A-Za-z_$][\w$]*)\s*(?:\+=|-=|\*=|/=|%=|\*\*=|<<=|>>=|>>>=|&=|\|=|\^=)\s*.+?;?",
            line,
        )
        if compound_match:
            variable = compound_match.group(1)
            if variable in assignments or variable in url_search_params or variable in invalid_variables:
                assignments.pop(variable, None)
                url_search_params.pop(variable, None)
                invalid_variables.add(variable)
                unresolved.append(
                    f"Line {line_number}: compound assignment to {variable} makes later flows ambiguous."
                )
            else:
                unresolved.append(
                    f"Line {line_number}: compound assignment syntax is unsupported."
                )
            continue

        assignment_match = declaration_or_assignment.fullmatch(line)
        if assignment_match:
            variable = assignment_match.group(1)
            expression = _js_flow_clean_expression(assignment_match.group(2))
            if write_counts.get(variable, 0) or variable in invalid_variables:
                assignments.pop(variable, None)
                url_search_params.pop(variable, None)
                invalid_variables.add(variable)
                write_counts[variable] = write_counts.get(variable, 0) + 1
                unresolved.append(
                    f"Line {line_number}: reassignment of {variable} makes later flows ambiguous."
                )
                continue
            write_counts[variable] = 1

            constructor_match = url_search_params_constructor.fullmatch(expression)
            if constructor_match:
                source_expression = constructor_match.group(1)
                source_kind = _js_flow_source_kind(source_expression)
                if source_kind:
                    url_search_params[variable] = (
                        source_kind, source_expression, line_number, raw_line.strip()
                    )
                else:
                    invalid_variables.add(variable)
                    unresolved.append(
                        f"Line {line_number}: URLSearchParams source expression is unsupported."
                    )
                continue

            get_match = url_search_params_get.fullmatch(expression)
            if get_match:
                receiver, _, parameter = get_match.groups()
                constructor = url_search_params.get(receiver)
                if constructor and receiver not in invalid_variables:
                    source_kind, source_expression, source_line, source_text = constructor
                    assignments[variable] = (
                        source_kind, source_expression, source_line, source_text,
                        [
                            f"Line {source_line}: {source_text}",
                            f"Line {line_number}: {variable} = {receiver}.get(\"{parameter}\")",
                        ],
                    )
                else:
                    unresolved.append(
                        f"Line {line_number}: .get() receiver {receiver} is not connected to a supported URLSearchParams construction."
                    )
                continue

            source_kind = _js_flow_source_kind(expression)
            if source_kind:
                assignments[variable] = (
                    source_kind, expression, line_number, raw_line.strip(), []
                )
                continue
            if re.fullmatch(r"[A-Za-z_$][\w$]*", expression):
                trace = assignments.get(expression)
                if trace and expression not in invalid_variables:
                    kind, origin, origin_line, origin_text, steps = trace
                    assignments[variable] = (
                        kind, origin, origin_line, origin_text,
                        steps + [
                            f"Line {line_number}: {variable} = {expression}"
                        ],
                    )
                elif expression in invalid_variables:
                    invalid_variables.add(variable)
                    unresolved.append(
                        f"Line {line_number}: alias source {expression} has an ambiguous prior assignment."
                    )
                continue
            if re.fullmatch(r"(?:'[^'\\]*(?:\\.[^'\\]*)*'|\"[^\"\\]*(?:\\.[^\"\\]*)*\")", expression):
                continue
            if ".get(" in expression or "URLSearchParams" in expression:
                unresolved.append(
                    f"Line {line_number}: unsupported URLSearchParams or .get() expression."
                )
                continue
            # Unknown writes to a tracked value invalidate it. Other syntax is
            # explicitly unresolved rather than interpreted as a flow.
            if variable in assignments:
                assignments.pop(variable, None)
                invalid_variables.add(variable)
            tracked_names = set(assignments) | invalid_variables
            if any(
                __import__("re").search(rf"\b{__import__('re').escape(name)}\b", expression)
                for name in tracked_names
            ):
                unresolved.append(
                    f"Line {line_number}: unsupported assignment expression involving tracked data."
                )
            continue

        if "innerHTML" in line or "location." in line or "event.data" in line:
            unresolved.append(
                f"Line {line_number}: syntax relevant to source/sink tracing is unsupported."
            )

    report = [
        "JARVIS Offline JavaScript Source-Flow Review",
        f"File: {path}",
        "Analysis mode: static source text only; JavaScript was not executed.",
        "Supported subset: exact URL/referrer/window/message sources, URLSearchParams(location.search) followed by a static-key .get() assignment, simple identifier assignments and aliases, and single-line .innerHTML assignments.",
        "",
    ]
    if candidates:
        for number, candidate in enumerate(candidates, 1):
            report.extend([
                f"Candidate {number}: Potential unsafe HTML insertion",
                "Vulnerability status: UNCONFIRMED",
                f"Input source: {candidate['source_kind']} â€” {candidate['source_expression']} at {path.name}:{candidate['source_line']}",
                f"Source evidence: {candidate['source_text']}",
            ])
            report.extend(
                f"Assignment evidence: {step}"
                for step in candidate["steps"]
            )
            report.extend([
                f"Potential sink: {candidate['sink_object']}.innerHTML at {path.name}:{candidate['sink_line']}",
                f"Sink evidence: {candidate['sink_text']}",
                "Reasoning: a recognized untrusted source is directly traceable to an innerHTML assignment in the supported syntax subset.",
                *_source_flow_severity_lines(
                    "cross-site scripting / unsafe HTML rendering",
                    [f"{path.name}:{candidate['source_line']}"],
                    [f"{path.name}:{candidate['sink_line']}"],
                ),
                "Limitations: this static trace does not prove runtime reachability, attacker control, browser parsing, or exploitability; intervening runtime behavior and unsupported syntax may change the result.",
                "Remediation: use textContent for plain text, or apply a vetted context-appropriate HTML sanitizer when HTML rendering is required.",
                "",
            ])
    else:
        report.append("No complete supported source-to-innerHTML trace detected.")
    if secret_literals:
        report.extend(["", "Potential hard-coded secret-like literals:"])
        for number, name in secret_literals:
            report.extend([
                f"  Candidate: {name} at {path.name}:{number}",
                "  Vulnerability status: UNCONFIRMED",
                "  Severity: NEEDS_REVIEW",
                "  Severity confidence: Low; validity, permissions, reachability, and impact are unknown.",
                "  Finding confidence: Low; the literal may be a placeholder, inactive value, or non-credential.",
                "  Pattern confidence: High that a secret-named variable/property has a non-placeholder string literal.",
                f"  Evidence: {path.name}:{number}: {name} = \"[REDACTED]\" (literal value withheld).",
                "  Impact hypothesis: if the literal is a valid privileged credential included in client-delivered code, users may be able to recover and misuse it.",
                "  Limitations: static text cannot establish credential validity, privilege, distribution, or whether the value is a harmless test constant.",
                "  Remediation: keep privileged credentials server-side; rotate the value if it is confirmed to be active.",
                "",
            ])
    if client_auth_observations:
        report.extend([
            "Client-side authorization-related review notes (not vulnerability findings):",
        ])
        for number, identifiers in client_auth_observations:
            report.append(
                f"  {path.name}:{number}: condition references {', '.join(identifiers)}."
            )
        report.extend([
            "  These are client-side code observations only. They do not establish a server-side authorization failure, IDOR, privilege escalation, or account takeover.",
            "  Review the corresponding server-side handler or API authorization code if it is available and authorized for local analysis.",
        ])
    if unresolved:
        report.extend(["Unresolved or unsupported evidence:", *[f"  {item}" for item in unresolved]])
    report.extend([
        "",
        "Assessment: candidates are pattern-based review leads only; no vulnerability is confirmed.",
    ])
    return _redact_potential_secrets("\n".join(report) + "\n")


def _write_js_flow_report(path, report, reports_dir=None):
    report = _redact_potential_secrets(report)
    reports_dir = Path(reports_dir) if reports_dir is not None else Path(REPORTS_DIR)
    reports_dir.mkdir(parents=True, exist_ok=True)
    safe_stem = re.sub(r"[^A-Za-z0-9_-]+", "_", Path(path).stem).strip("_").lower() or "javascript"
    source_hash = hashlib.sha256(str(Path(path).resolve()).encode("utf-8")).hexdigest()[:10]
    base = f"{safe_stem}_{source_hash}_js_flow"
    for index in range(1000):
        suffix = "" if index == 0 else f"_{index}"
        report_file = reports_dir / f"{base}{suffix}.txt"
        try:
            with report_file.open("x", encoding="utf-8") as handle:
                handle.write(report)
            return report_file
        except FileExistsError:
            continue
    raise OSError("Could not allocate a unique JavaScript report filename")


def analyze_js_flow(file_path):
    path = Path(file_path)
    if not path.is_file() or path.suffix.lower() not in _JS_FLOW_SUPPORTED_EXTENSIONS:
        print("JARVIS: JavaScript file not found or unsupported; use a local .js, .mjs, or .cjs file.")
        return
    provenance = _begin_source_analysis_provenance()
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        print(f"JARVIS: Could not read JavaScript file: {error}")
        return
    report = _analyze_js_flow_source(path, source).rstrip() + "\n\n"
    report += "\n".join(
        _format_source_analysis_provenance(
            provenance, {path.resolve(): source}, source_read_errors="replace"
        )
    ) + "\n"
    report = _redact_potential_secrets(report)
    print("\n" + report)
    try:
        report_file = _write_js_flow_report(path, report)
    except OSError as error:
        print(f"JARVIS: Could not save JavaScript report: {error}")
        return
    print(f"JARVIS: JavaScript flow evidence saved to {report_file}")


def php_summary(directory):
    base = Path(directory)

    if not base.is_dir():
        print("JARVIS: Directory not found.")
        return

    php_files = sorted(base.glob("*.php"))

    categories = {
        "SQL Injection": 0,
        "Cross-Site Scripting": 0,
        "Command Injection": 0,
        "Cross-Site Request Forgery": 0,
        "Directory Traversal": 0,
        "Insecure Direct Object Reference": 0,
    }

    for path in php_files:
        category = classify_php_page(path.name)

        if category in categories:
            categories[category] += 1

    lines = [
        "",
        "JARVIS: PHP Training Page Summary",
        f"Directory: {base}",
        f"PHP files found: {len(php_files)}",
        "",
    ]

    for category, count in categories.items():
        lines.append(f"  {category}: {count}")

    lines.extend([
        "",
        "JARVIS: This is a training-page classification.",
        "JARVIS: It does NOT confirm that these pages contain vulnerabilities.",
    ])

    report = "\n".join(lines)

    print(report)

    REPORTS_DIR.mkdir(exist_ok=True)
    report_file = REPORTS_DIR / "php_summary.txt"
    report_file.write_text(report + "\n")

    print(f"\nJARVIS: Summary saved to {report_file}")
def php_report(directory):
    base = Path(directory)

    if not base.is_dir():
        print("JARVIS: Directory not found.")
        return

    php_files = sorted(base.glob("*.php"))

    categories = {
        "SQL Injection": 0,
        "Cross-Site Scripting": 0,
        "Command Injection": 0,
        "Cross-Site Request Forgery": 0,
        "Directory Traversal": 0,
        "Insecure Direct Object Reference": 0,
    }

    total_inputs = 0
    files_with_inputs = 0

    pattern = re.compile(
        r'\$_(GET|POST|REQUEST)\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]'
    )

    for path in php_files:
        try:
            source = path.read_text(errors="ignore")
        except OSError:
            continue

        inputs = set()

        for match in pattern.finditer(source):
            inputs.add((match.group(1), match.group(2)))

        if inputs:
            files_with_inputs += 1
            total_inputs += len(inputs)

        category = classify_php_page(path.name)

        if category in categories:
            categories[category] += 1

    lines = [
        "JARVIS PHP REVIEW REPORT",
        "========================",
        "",
        f"Directory: {base}",
        f"PHP files found: {len(php_files)}",
        f"Files with inputs: {files_with_inputs}",
        f"Unique input references: {total_inputs}",
        "",
        "Training-page classification:",
    ]

    for category, count in categories.items():
        lines.append(f"  {category}: {count}")

    lines.extend([
        "",
        "Manual review status:",
        "  These classifications identify areas for review.",
        "  They do NOT confirm vulnerabilities.",
        "",
        "Recommended next step:",
        "  Manually verify any candidate before reporting.",
        "  Submit only findings within the authorized program scope.",
    ])

    report = "\n".join(lines)

    print("\n" + report)

    REPORTS_DIR.mkdir(exist_ok=True)
    report_file = REPORTS_DIR / "php_review_report.txt"
    report_file.write_text(report + "\n")

    print(f"\nJARVIS: PHP review report saved to {report_file}")
def php_review_checklist():
    checklist = {
        "SQL Injection": [
            "Review how user input reaches database queries.",
            "Check whether queries use parameterized statements.",
            "Review input validation and error handling.",
        ],
        "Cross-Site Scripting": [
            "Review where user input is reflected or stored.",
            "Check whether output is properly encoded.",
            "Review input validation and content handling.",
        ],
        "Command Injection": [
            "Review whether user input reaches operating-system commands.",
            "Check for strict input validation and safe APIs.",
            "Review whether unnecessary command execution can be removed.",
        ],
        "Cross-Site Request Forgery": [
            "Review state-changing requests.",
            "Check whether anti-CSRF protections are present.",
            "Review cookie and request validation.",
        ],
        "Directory Traversal": [
            "Review file paths that use user-controlled input.",
            "Check whether paths are validated and restricted.",
            "Review access controls around local files.",
        ],
        "Insecure Direct Object Reference": [
            "Review object identifiers supplied by users.",
            "Check authorization for each requested object.",
            "Verify that users cannot access objects they are not authorized to access.",
        ],
    }

    print("\nJARVIS: Manual Review Checklist")
    print("================================")

    for category, checks in checklist.items():
        print(f"\n[{category}]")

        for check in checks:
            print(f"  - {check}")

    print("\nJARVIS: Checklist only.")
    print("JARVIS: No exploit requests or vulnerability confirmation performed.")


def hackerone_policy_review_checklist():
    """Print a manual checklist based on the user-supplied Anthropic policy summary."""
    items = [
        "Verify the exact asset, scheme, port, and path are explicitly authorized in current scope.",
        "Confirm every proposed testing method is allowed by the current program rules.",
        "Manually reproduce a security impact; scanner or AI alerts remain unverified.",
        "Provide safe, repeatable steps and enough evidence for another researcher to reproduce.",
        "Check the current official program policy for exclusions; this supplied checklist may be outdated.",
        "Check for duplicates or a shared root cause, including the Claude Code permission-modal bypass remediation.",
        "Demonstrate the issue without accessing other users' accounts, private data, or causing disruption.",
        "Include only the minimum evidence needed; redact credentials, tokens, and private information.",
        "Do not test denial of service, disruptive behavior, brute force, or unauthenticated rate limits.",
        "Do not test social engineering, phishing, or accounts you do not own.",
        "Clickjacking requires a sensitive action; missing cookie flags alone are not sufficient.",
        "Generic TLS or security best-practice issues need working proof of impact.",
        "Model jailbreaks, harmful outputs, and hallucinations may be excluded under the technical program.",
    ]
    print("\nJARVIS: Anthropic HackerOne Policy Review Checklist (manual review only)")
    print("=======================================================================")
    for item in items:
        print(f"[ ] {item}")
    print("\nThis is a review aid based on supplied policy text, not current authorization.")
    print("It does not validate eligibility, severity, exploitability, or bounty status.")
    print("All automated and AI-generated alerts remain unverified until manually validated.")

def get_info(target):

    if not check_scope(target):
        return

    url = get_url(target)

    print("\nJARVIS WEB INFORMATION REPORT")
    print("================================\n")

    response = None
    try:

        response = scoped_get(
            url,
            timeout=10,
            headers={
                "User-Agent": "JARVIS-Lab-Assistant/1.0"
            }
        )

        status = response.status_code
        final_url = response.url
        https = final_url.startswith("https://")
        response_headers = getattr(response, "headers", None)
        can_read_headers = callable(getattr(response_headers, "get", None))
        server = (
            response_headers.get("Server", "Not disclosed")
            if can_read_headers else "Not recorded"
        )
        content_type = (
            response_headers.get("Content-Type", "Not disclosed")
            if can_read_headers else "Not recorded"
        )
        server = _escape_report_user_field(server)
        content_type = _escape_report_user_field(content_type)

        title = _escape_report_user_field(get_page_title(response))

        security_headers = check_security_headers(response)

        safe_target = _render_report_target(target)
        safe_final_url = _render_report_endpoint(final_url)
        print(f"Target: {safe_target}\n")

        print(f"Status       : {status}")
        print(f"Final URL    : {safe_final_url}")
        print(f"HTTPS        : {https}")
        print(f"Server       : {server}")
        print(f"Content-Type : {content_type}")
        print(f"Page title   : {title}")

        print("\nSecurity Headers:")

        for item in security_headers:
            line = (
                f"[{item['status']}] "
                f"{item['header']} - "
                f"{item['explanation']}"
            )
            print(line)
            if item.get("value") is not None:
                print(f"  Observed value: {item['value']}")

        timestamp = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        report = f"""JARVIS WEB INFORMATION REPORT
================================

Target: {safe_target}
Timestamp: {timestamp}

Status       : {status}
Final URL    : {safe_final_url}
HTTPS        : {https}
Server       : {server}
Content-Type : {content_type}
Page title   : {title}

Security Headers:
"""

        for item in security_headers:
            report += (
                f"[{item['status']}] "
                f"{item['header']} - "
                f"{item['explanation']}\n"
            )
            if item.get("value") is not None:
                report += f"  Observed value: {item['value']}\n"

        report += """
Note:
Missing security headers are observations and are not automatically confirmed vulnerabilities.
Further testing and human review are required before classifying a security finding.
"""

        save_report(target, report)

    except requests.RequestException as error:

        print(f"JARVIS: Unable to connect to {_render_report_target(target)}.")
        print(f"JARVIS: Request failed ({type(error).__name__}).")
    finally:
        if response is not None:
            response.close()


def _build_findings_summary(reports_dir, only_report=None):
    """Summarize saved report text without running analysis or writing files."""
    root = Path(reports_dir)
    try:
        resolved_root = root.resolve()
    except OSError:
        resolved_root = root

    report_files = []
    if root.is_dir():
        for candidate in sorted(root.glob("*.txt")):
            if only_report is not None and candidate.name != only_report:
                continue
            try:
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(resolved_root)
                if resolved.is_file():
                    report_files.append((candidate.name, resolved))
            except (OSError, ValueError):
                # Ignore broken and out-of-root symlinks without reading them.
                continue

    records = {}
    report_statuses = []
    report_severities = []
    completeness = []
    unknown_reports = []
    report_titles = []
    remediation_guidance = []
    analysis_statements = []
    review_priorities = []
    structured_test_observations = []
    location_pattern = re.compile(
        r"(?P<file>(?:[A-Za-z]:)?[^\s:]+?\.(?:php|py|js|html|sql)):(?P<line>\d+)",
        re.I,
    )

    def source_location(text):
        match = location_pattern.search(text)
        if not match:
            return None, None
        return match.group("file"), int(match.group("line"))

    def is_placeholder_text(value):
        normalized = " ".join(str(value).split()).strip().casefold().strip(" .")
        return normalized in {
            "saved", "describe your evidence", "describe your issue", "unknown",
            "none", "not provided", "n/a", "not assessed",
        } or normalized.startswith((
            "describe your ", "enter your ", "add your ", "unknown;", "no evidence was",
        ))

    def safe_summary_value(value):
        rendered = _escape_report_user_field(" ".join(str(value).split()))
        for field_label in (
            "Vulnerability status", "Review status", "Severity assessment",
            "Severity rationale", "Severity",
        ):
            rendered = re.sub(
                rf"(?i){re.escape(field_label)}\s*:",
                lambda match: match.group(0)[:-1] + r"\x3a",
                rendered,
            )
        return rendered

    def add_record(kind, report_name, file_name=None, line_number=None, evidence=""):
        excerpt = safe_summary_value(evidence) or "Unknown; no evidence excerpt was recorded."
        location = (
            str(Path(file_name)) if file_name else None,
            line_number,
        )
        identity = (kind, location[0], location[1], excerpt.casefold())
        if identity not in records:
            records[identity] = {
                "kind": kind,
                "file": location[0],
                "line": location[1],
                "evidence": excerpt,
                "reports": {report_name},
            }
        else:
            records[identity]["reports"].add(report_name)

    for report_name, report_path in report_files:
        try:
            text = report_path.read_text(errors="replace")
        except OSError:
            report_statuses.append((report_name, "UNCONFIRMED"))
            report_severities.append((report_name, "Unassessed", None))
            completeness.append((report_name, "Incomplete"))
            unknown_reports.append(report_name)
            continue

        lines = _split_saved_report_lines(text)
        first_line = next((line.strip() for line in lines if line.strip()), "")
        is_php_flow = first_line.startswith("JARVIS: PHP source-flow analysis")
        is_candidate = first_line.startswith("[+] Vulnerability candidate found")
        is_finding = first_line.startswith("JARVIS POTENTIAL SECURITY FINDING")
        is_web_report = first_line.startswith("JARVIS WEB INFORMATION REPORT") or any(
            line.strip().startswith(("HTTP Status:", "Security Header Observations:")) for line in lines
        )
        is_php_review = first_line.startswith(("JARVIS PHP REVIEW REPORT", "JARVIS: PHP Training Page Summary"))
        recognized = is_php_flow or is_candidate or is_finding or first_line.startswith(
            ("JARVIS WEB INFORMATION REPORT", "JARVIS PHP REVIEW REPORT", "JARVIS PHP SUMMARY", "JARVIS: PHP Training Page Summary")
        ) or is_web_report
        if not recognized:
            unknown_reports.append(report_name)

        # Parse only the single, exact schema block emitted by record_candidate.
        # Its presence records a test observation; it never promotes report status.
        structured_record = None
        result_begin = "JARVIS STRUCTURED TEST RESULT BEGIN"
        result_end = "JARVIS STRUCTURED TEST RESULT END"
        result_begin_positions = [i for i, item in enumerate(lines) if item.strip() == result_begin]
        result_end_positions = [i for i, item in enumerate(lines) if item.strip() == result_end]
        if is_candidate and len(result_begin_positions) == 1 and len(result_end_positions) == 1:
            begin = result_begin_positions[0]
            end = result_end_positions[0]
            expected_layout = (
                end == begin + 2
                and begin >= 3
                and lines[begin - 3].strip() == "Validation limitations:"
                and bool(lines[begin - 2].strip())
                and not lines[begin - 1].strip()
                and end + 2 < len(lines)
                and lines[end + 1].strip() == ""
                and lines[end + 2].strip() == "Potential impact (conditional; not demonstrated):"
                and lines[begin + 1].startswith("Structured test result (JSON): ")
            )
            if expected_layout:
                try:
                    serialized_result = json.loads(
                        lines[begin + 1].removeprefix("Structured test result (JSON): ")
                    )
                    normalized_result = _normalize_structured_test_result(serialized_result)
                    if normalized_result == serialized_result:
                        structured_record = normalized_result
                except (TypeError, ValueError):
                    structured_record = None
        if structured_record is not None:
            structured_test_observations.append((
                report_name,
                structured_record["test_type"],
                structured_record["observation"],
                structured_record["response_origin"],
                structured_record["evidence_completeness"],
            ))

        severity_begin = "JARVIS TRUSTED SEVERITY METADATA BEGIN"
        severity_end = "JARVIS TRUSTED SEVERITY METADATA END"
        begin_positions = [i for i, item in enumerate(lines) if item.strip() == severity_begin]
        end_positions = [i for i, item in enumerate(lines) if item.strip() == severity_end]
        trusted_severity_lines = set()
        if len(begin_positions) == 1 and len(end_positions) == 1:
            begin = begin_positions[0]
            end = end_positions[0]
            block_contents_valid = (
                end == begin + 3
                and lines[begin + 1].strip().startswith("Severity assessment:")
                and bool(lines[begin + 1].split(":", 1)[1].strip())
                and lines[begin + 2].strip().startswith("Severity rationale:")
                and bool(lines[begin + 2].split(":", 1)[1].strip())
            )
            if is_candidate:
                expected_location = (
                    begin > 0
                    and lines[begin - 1].strip().startswith("Vulnerability status:")
                    and end + 1 < len(lines)
                    and lines[end + 1].strip() == "Severity: Not assessed"
                )
            elif is_finding:
                expected_location = (
                    begin >= 3
                    and lines[begin - 3].strip() == "Testing context:"
                    and bool(lines[begin - 2].strip())
                    and not lines[begin - 1].strip()
                    and end + 2 < len(lines)
                    and not lines[end + 1].strip()
                    and lines[end + 2].strip() == "Severity:"
                )
            else:
                expected_location = False
            if block_contents_valid and expected_location and begin < end:
                trusted_severity_lines = {begin + 1, begin + 2}

        # Extract only explicitly labeled title fields or report-header titles.
        title = None
        for index, line in enumerate(lines):
            stripped_title = line.strip()
            if stripped_title.startswith("User-provided title (unverified):"):
                title = stripped_title.split(":", 1)[1].strip() or "Unknown"
                break
            if stripped_title == "Title:":
                title = next((item.strip() for item in lines[index + 1:] if item.strip()), "Unknown")
                break
        if not title:
            header_match = re.match(r"JARVIS: PHP source-flow analysis\s*[â€”-]\s*(.+)", first_line)
            page_match = next((re.match(r"(?:Page title|Page Title)\s*:\s*(.+)", item.strip(), re.I) for item in lines if re.match(r"(?:Page title|Page Title)\s*:", item.strip(), re.I)), None)
            type_match = next((re.match(r"Type:\s*(.+)", item.strip(), re.I) for item in lines if re.match(r"Type:\s*", item.strip(), re.I)), None)
            if header_match:
                title = f"PHP source-flow analysis: {header_match.group(1).strip()}"
            elif page_match:
                title = page_match.group(1).strip()
            elif type_match:
                title = type_match.group(1).strip()
            elif is_php_review:
                title = first_line.removeprefix("JARVIS: ").strip()
            elif is_finding:
                title = "Potential security finding (title Unknown)"
            elif is_web_report:
                title = "Web information report"
        report_titles.append((report_name, safe_summary_value(title or "Unknown")))

        section = None
        pending_input = None
        pending_source_assignment = None
        pending_source_step = None
        pending_legacy_query = None
        current_sink = None
        evidence_lines = []
        in_evidence = False
        in_recommendation = False
        report_has_evidence = False
        report_has_location = False
        report_has_context = is_php_flow and "Static source review only" in text
        has_explicit_input_status = False
        vulnerability_value = ""
        in_validation = False
        severity_assessment = ""
        severity_rationale = ""
        severity_suggestion = None
        explicit_evidence_location = None

        for line_index, line in enumerate(lines):
            stripped = line.strip()
            lower = stripped.lower()

            if stripped in {"Remediation:", "Recommended next step:", "Recommended remediation:"}:
                in_recommendation = True
                continue
            if in_recommendation:
                if not stripped or stripped.endswith(":") or stripped.startswith(("Important:", "---")):
                    in_recommendation = False
                else:
                    remediation_guidance.append((report_name, safe_summary_value(stripped)))
                    in_recommendation = True

            if stripped.startswith("Vulnerability status:"):
                vulnerability_value = stripped.split(":", 1)[1].strip()
            elif vulnerability_value and not stripped and not in_validation:
                vulnerability_value = vulnerability_value
            elif stripped.startswith("Independent validation evidence:"):
                in_validation = True
                continue
            elif in_validation:
                if not stripped:
                    in_validation = False
                continue

            if line_index in trusted_severity_lines and stripped.startswith("Severity assessment:"):
                severity_assessment = stripped.split(":", 1)[1].strip()
            elif line_index in trusted_severity_lines and stripped.startswith("Severity rationale:"):
                severity_rationale = stripped.split(":", 1)[1].strip()
            elif stripped.startswith((
                "User-provided severity suggestion (unverified):",
                "Severity suggestion (unverified):",
            )):
                severity_suggestion = safe_summary_value(stripped.split(":", 1)[1]) or "Unknown"
            elif stripped.startswith("Potential severity:"):
                severity_suggestion = safe_summary_value(stripped.split(":", 1)[1]) or "Unknown"
            elif stripped.startswith("Evidence location:"):
                explicit_evidence_location = stripped.split(":", 1)[1].strip()
                loc_file, loc_line = source_location(explicit_evidence_location)
                if loc_file:
                    report_has_location = True
            elif stripped.startswith("Testing context:"):
                value = stripped.split(":", 1)[1].strip()
                report_has_context = bool(value and not value.lower().startswith("unknown"))

            if stripped == "No direct GET/POST/REQUEST inputs detected.":
                has_explicit_input_status = True
                analysis_statements.append((report_name, "Saved analysis reports no direct GET/POST/REQUEST input evidence; this is not a safety determination."))
            elif stripped in {"NO INPUT DETECTED", "INPUT DETECTED", "SOURCE FLOW DETECTED"} or stripped.startswith("ANALYSIS INCOMPLETE â€” "):
                has_explicit_input_status = True
                analysis_statements.append((report_name, safe_summary_value(f"Saved analysis status: {stripped}; this is not vulnerability confirmation.")))

            if stripped in {
                "Form control observations:",
                "Input evidence:",
                "Unresolved conditional input evidence:",
                "Request presence evidence:",
                "Unresolved request-reference evidence:",
                "Included-file input observations:",
                "Included-file analysis:",
                "Sink observations:",
                "Source-flow evidence:",
                "Local function analysis:",
                "Database operation observations:",
                "Output branch observations:",
                "Unresolved analysis candidates:",
                "Evidence details:",
                "Evidence:",
                "Query-flow evidence:",
                "Data-flow verification:",
                "XSS output flow:",
                "Security Headers:",
                "Security Header Observations:",
            } or stripped.startswith((
                "Evidence details (", "Observed evidence (", "Unverified information ("
            )):
                section = stripped.rstrip(":")
                if (
                    section.startswith((
                        "Evidence details", "Observed evidence", "Unverified information"
                    ))
                    or (section == "Evidence" and is_finding)
                ):
                    in_evidence = True
                    evidence_lines = []
                else:
                    in_evidence = False
                pending_input = None
                if section != "Source-flow evidence":
                    pending_source_assignment = None
                    pending_source_step = None
                if section != "Query-flow evidence":
                    pending_legacy_query = None
                continue

            if in_evidence:
                if stripped.startswith(("Status:", "Description:", "Recorded:", "Important:", "Potential severity:", "Target:", "Type:")):
                    in_evidence = False
                elif not stripped:
                    in_evidence = False
                elif not stripped.startswith(("Evidence location:", "Testing context:")):
                    if not is_placeholder_text(stripped):
                        evidence_lines.append(stripped)
                        report_has_evidence = True

            if section in {
                "Input evidence",
                "Unresolved conditional input evidence",
                "Request presence evidence",
                "Unresolved request-reference evidence",
            }:
                input_match = re.match(r"\[(GET|POST|REQUEST)\]\s+([^\s(]+)", stripped, re.I)
                if input_match:
                    pending_input = (section, input_match.group(1).upper(), input_match.group(2))
                    continue
                if pending_input:
                    file_name, line_number = source_location(stripped)
                    if file_name:
                        kind_section, method, parameter = pending_input
                        label = {
                            "Input evidence": "Observed input pattern",
                            "Unresolved conditional input evidence": "Unresolved conditional input",
                            "Request presence evidence": "Observed presence check",
                            "Unresolved request-reference evidence": "Unresolved request reference",
                        }[kind_section]
                        excerpt = stripped.split(":", 2)[-1].strip()
                        request_ref = re.search(r"\$_(GET|POST|REQUEST)\s*\[\s*(['\"])(.*?)\2\s*\]", excerpt, re.I)
                        presence_match = re.fullmatch(
                            r"\s*\$[A-Za-z_]\w*\s*=\s*isset\s*\(\s*\$_(GET|POST|REQUEST)\s*\[\s*(['\"])(.*?)\2\s*\]\s*\)\s*\?\s*(?:1|true)\s*:\s*(?:0|false)\s*;?\s*",
                            excerpt, re.I,
                        )
                        presence_only = bool(
                            presence_match and presence_match.group(1).upper() == method
                            and presence_match.group(3) == parameter
                        )
                        direct_value = bool(request_ref and re.search(r"=\s*\$_(?:GET|POST|REQUEST)\s*\[", excerpt, re.I))
                        is_guard = bool(re.search(r"\bif\s*\(.*\bisset\s*\(", excerpt, re.I))
                        if presence_only:
                            label = "Observed presence-check assignment"
                        elif direct_value:
                            label = "Observed input value assignment"
                        elif is_guard:
                            label = "Observed request guard"
                        add_record(f"{label} [{method}] {parameter}", report_name, file_name, line_number, excerpt)
                        if presence_only:
                            add_record(
                                "Presence-check limitation", report_name, file_name, line_number,
                                "This expression records whether the request parameter exists; it does not establish that the submitted parameter value reaches a sink.",
                            )
                        report_has_evidence = True
                        report_has_location = True
                        pending_input = None
                        continue

                # Older PHP-flow reports omit the source filename in line records;
                # use only the analyzed entry filename printed in their header.
                if pending_input:
                    legacy_line = re.match(r"Line\s+(\d+)\s*:\s*(.*)", stripped, re.I)
                    if legacy_line:
                        header_match = re.match(r"JARVIS: PHP source-flow analysis\s*[â€”-]\s*(.+)", first_line)
                        file_name = header_match.group(1).strip() if header_match else None
                        kind_section, method, parameter = pending_input
                        label = {
                            "Input evidence": "Observed input pattern",
                            "Unresolved conditional input evidence": "Unresolved conditional input",
                            "Request presence evidence": "Observed presence check",
                            "Unresolved request-reference evidence": "Unresolved request reference",
                        }[kind_section]
                        excerpt = legacy_line.group(2)
                        request_ref = re.search(r"\$_(GET|POST|REQUEST)\s*\[\s*(['\"])(.*?)\2\s*\]", excerpt, re.I)
                        presence_match = re.fullmatch(
                            r"\s*\$[A-Za-z_]\w*\s*=\s*isset\s*\(\s*\$_(GET|POST|REQUEST)\s*\[\s*(['\"])(.*?)\2\s*\]\s*\)\s*\?\s*(?:1|true)\s*:\s*(?:0|false)\s*;?\s*",
                            excerpt, re.I,
                        )
                        presence_only = bool(
                            presence_match and presence_match.group(1).upper() == method
                            and presence_match.group(3) == parameter
                        )
                        direct_value = bool(request_ref and re.search(r"=\s*\$_(?:GET|POST|REQUEST)\s*\[", excerpt, re.I))
                        is_guard = bool(re.search(r"\bif\s*\(.*\bisset\s*\(", excerpt, re.I))
                        if presence_only:
                            label = "Observed presence-check assignment"
                        elif direct_value:
                            label = "Observed input value assignment"
                        elif is_guard:
                            label = "Observed request guard"
                        add_record(f"{label} [{method}] {parameter}", report_name, file_name, int(legacy_line.group(1)), excerpt)
                        if presence_only:
                            add_record(
                                "Presence-check limitation", report_name, file_name, int(legacy_line.group(1)),
                                "This expression records whether the request parameter exists; it does not establish that the submitted parameter value reaches a sink.",
                            )
                        report_has_evidence = True
                        report_has_location = bool(file_name) or report_has_location
                        pending_input = None
                        continue

            if section == "Source-flow evidence":
                if re.match(r"-\s*Input assignment\s*$", stripped, re.I):
                    pending_source_assignment = True
                    continue
                if re.match(r"-\s*Input reaches function call\s*$", stripped, re.I):
                    pending_source_step = "Input reaches function call"
                    continue
                if pending_source_assignment:
                    legacy_line = re.match(r"Line\s+(\d+)\s*:\s*(.*)", stripped, re.I)
                    if legacy_line:
                        request_ref = re.search(r"\$_(GET|POST|REQUEST)\s*\[\s*(['\"])(.*?)\2\s*\]", legacy_line.group(2), re.I)
                        if request_ref:
                            header_match = re.match(r"JARVIS: PHP source-flow analysis\s*[â€”-]\s*(.+)", first_line)
                            entry_file = header_match.group(1).strip() if header_match else None
                            add_record(
                                f"Observed input value assignment [{request_ref.group(1).upper()}] {request_ref.group(3)}",
                                report_name, entry_file, int(legacy_line.group(1)), legacy_line.group(2),
                            )
                            report_has_evidence = True
                            report_has_location = bool(entry_file) or report_has_location
                        pending_source_assignment = None
                        continue
                if pending_source_step:
                    legacy_line = re.match(r"Line\s+(\d+)\s*:\s*(.*)", stripped, re.I)
                    if legacy_line:
                        header_match = re.match(r"JARVIS: PHP source-flow analysis\s*[â€”-]\s*(.+)", first_line)
                        entry_file = header_match.group(1).strip() if header_match else None
                        add_record(
                            "Reported source-flow step (unverified)", report_name, entry_file,
                            int(legacy_line.group(1)),
                            f"{pending_source_step}: {legacy_line.group(2)}",
                        )
                        report_has_evidence = True
                        report_has_location = bool(entry_file) or report_has_location
                        pending_source_step = None
                        continue

            if section in {"Query-flow evidence", "Data-flow verification"}:
                if section == "Query-flow evidence" and re.search(r"database query execution", stripped, re.I):
                    pending_legacy_query = "database execution"
                    continue
                if section == "Query-flow evidence" and re.search(r"query construction", stripped, re.I):
                    pending_legacy_query = "query construction"
                    continue
                legacy_line = re.search(r"Line\s+(\d+)\s*:\s*(.+)", stripped, re.I)
                header_match = re.match(r"JARVIS: PHP source-flow analysis\s*[â€”-]\s*(.+)", first_line)
                entry_file = header_match.group(1).strip() if header_match else None
                if section == "Query-flow evidence" and legacy_line and pending_legacy_query == "database execution":
                    add_record("Observed sink pattern [SQL/database execution]", report_name, entry_file, int(legacy_line.group(1)), legacy_line.group(2))
                    report_has_evidence = True
                    report_has_location = bool(entry_file) or report_has_location
                    pending_legacy_query = None
                    continue
                if section == "Query-flow evidence" and legacy_line and pending_legacy_query == "query construction":
                    add_record("Observed query construction pattern", report_name, entry_file, int(legacy_line.group(1)), legacy_line.group(2))
                    report_has_evidence = True
                    report_has_location = bool(entry_file) or report_has_location
                    pending_legacy_query = None
                    continue
                if section == "Data-flow verification" and stripped.startswith("SQL flow:") and legacy_line:
                    # Preserve historical analyzer claims without upgrading them to
                    # supported relationships from the current evidence model.
                    add_record("Legacy reported source-to-sink claim (unverified)", report_name, entry_file, int(legacy_line.group(1)), legacy_line.group(2))
                    report_has_evidence = True
                    report_has_location = bool(entry_file) or report_has_location
                    continue
                if section == "Data-flow verification" and stripped.startswith("Output sink for") and legacy_line:
                    add_record("Observed sink pattern [output]", report_name, entry_file, int(legacy_line.group(1)), legacy_line.group(2))
                    report_has_evidence = True
                    report_has_location = bool(entry_file) or report_has_location
                    continue

            if section == "XSS output flow" and re.search(r"\[\s*(GET|POST|REQUEST)\s*\].*â†’.*â†’", stripped, re.I):
                add_record("Legacy reported source-to-sink claim (unverified)", report_name, None, None, stripped)
                report_has_evidence = True

            if (
                is_web_report
                and section in {"Security Headers", "Security Header Observations"}
                and stripped.startswith("[MISSING]")
            ):
                add_record("Observed web security-header pattern", report_name, None, None, stripped)
                report_has_evidence = True

            if (
                is_web_report
                and section in {"Security Headers", "Security Header Observations"}
                and re.match(r"(?:Content-Security-Policy|X-Content-Type-Options|X-Frame-Options|Strict-Transport-Security):\s*MISSING", stripped, re.I)
            ):
                add_record("Observed web security-header pattern", report_name, None, None, stripped)
                report_has_evidence = True

            if is_php_review:
                category_match = re.match(r"\s*(SQL Injection|Cross-Site Scripting|Command Injection|Cross-Site Request Forgery|Directory Traversal|Insecure Direct Object Reference):\s*(\d+)\s*$", line, re.I)
                if category_match:
                    add_record(
                        "Training-page classification (not a finding)", report_name, None, None,
                        f"{category_match.group(1)}: {category_match.group(2)} pages",
                    )
                    report_has_evidence = True

            if section == "Included-file input observations":
                included_match = re.match(
                    r"(Direct request-value observation|Conditional request-input observation|Presence-check observation|Unresolved request-reference observation):\s*(.*)",
                    stripped,
                )
                if included_match:
                    file_name, line_number = source_location(included_match.group(2))
                    if file_name:
                        add_record(included_match.group(1), report_name, file_name, line_number, included_match.group(2))
                        report_has_evidence = True
                        report_has_location = True
                        continue

            if section == "Included-file analysis":
                include_match = re.search(r"Include evidence:\s*(.+?)\s*->\s*(.+?)\s*\(([^)]*)\)", stripped)
                if include_match:
                    source_file, source_line = source_location(include_match.group(1))
                    destination_file, destination_line = source_location(include_match.group(2))
                    if source_file:
                        destination = (
                            f"{destination_file}:{destination_line}"
                            if destination_file else "Unknown destination"
                        )
                        excerpt = f"{source_file}:{source_line} -> {destination} ({include_match.group(3)})"
                        add_record("Included-file relationship observation", report_name, source_file, source_line, excerpt)
                        report_has_evidence = True
                        report_has_location = True
                        continue
                if stripped.startswith("Unresolved "):
                    file_name, line_number = source_location(stripped)
                    add_record("Unresolved analysis candidate", report_name, file_name, line_number, stripped)
                    report_has_evidence = True
                    report_has_location = report_has_location or bool(file_name)
                    continue

            if section in {"Sink observations", "Source-flow evidence"}:
                sink_match = re.search(r"Sink text \(([^)]+)\) at (.+)", stripped)
                if sink_match:
                    file_name, line_number = source_location(sink_match.group(2))
                    if file_name:
                        location_match = location_pattern.search(sink_match.group(2))
                        excerpt = sink_match.group(2)[location_match.end():].lstrip(": ")
                        add_record(f"Observed sink pattern [{sink_match.group(1)}]", report_name, file_name, line_number, excerpt)
                        current_sink = (file_name, line_number, sink_match.group(1))
                        report_has_evidence = True
                        report_has_location = True
                        continue
                relationship = re.search(
                    r"(Explicit|Conditional) textual relationship: (.+?) at (.+?) reaches (.+)",
                    stripped,
                )
                if relationship:
                    file_name, line_number = source_location(relationship.group(3))
                    if file_name:
                        sink_context = (
                            f"; sink {current_sink[2]} at {current_sink[0]}:{current_sink[1]}"
                            if current_sink else ""
                        )
                        evidence = f"{relationship.group(2)} at {file_name}:{line_number} reaches {relationship.group(4)}{sink_context}"
                        add_record(f"Supported static relationship [{relationship.group(1)}]", report_name, file_name, line_number, evidence)
                        report_has_evidence = True
                        report_has_location = True
                        continue

            if section == "Unresolved analysis candidates" and stripped.startswith("Unresolved "):
                file_name, line_number = source_location(stripped)
                add_record("Unresolved analysis candidate", report_name, file_name, line_number, stripped)
                report_has_evidence = True
                report_has_location = report_has_location or bool(file_name)
            elif re.search(r"unsupported syntax.*remain unresolved|unresolved.*unsupported syntax", stripped, re.I):
                add_record("Unresolved analysis candidate", report_name, None, None, stripped)
                report_has_evidence = True

        if is_finding or is_candidate:
            evidence = " ".join(item for item in evidence_lines if not is_placeholder_text(item)).strip()
            if not evidence and explicit_evidence_location:
                evidence = explicit_evidence_location
            file_name, line_number = source_location(explicit_evidence_location or "")
            add_record(
                "User-provided finding evidence" if is_finding else "Recorded candidate evidence",
                report_name,
                file_name,
                line_number,
                evidence or "Unknown; no evidence was recorded.",
            )
            report_has_evidence = report_has_evidence or bool(evidence and not evidence.lower().startswith("unknown"))
            report_has_location = report_has_location or bool(file_name)

        # Saved statuses and free-form narratives are claims in text. The current
        # workflow records observations, but has no type-specific confirmation
        # process that can establish exploitability or impact.
        if re.match(r"^confirmed(?:\b|[:;])", vulnerability_value, re.I):
            status = (
                "UNCONFIRMED (saved status is a text claim; no current candidate-type workflow "
                "can independently establish confirmation)"
            )
        elif structured_record is not None:
            status = "UNCONFIRMED (structured test observation recorded; vulnerability not established)"
        else:
            status = "UNCONFIRMED"
        report_statuses.append((report_name, status))

        assessed = severity_assessment.strip()
        rationale = severity_rationale.strip()
        valid_severities = {"informational", "low", "medium", "high", "critical"}
        if assessed.lower() in valid_severities and rationale and not rationale.lower().startswith(("unknown", "none", "not provided")):
            severity_label = f"{assessed} (assessment and rationale recorded)"
        else:
            severity_label = "Unassessed"
        report_severities.append((report_name, severity_label, severity_suggestion))

        if report_has_evidence and report_has_location and report_has_context:
            completeness_label = (
                "Complete; Evidence: recorded; Source location: recorded; "
                "Testing context: recorded (not independently validated)"
            )
        elif report_has_evidence or report_has_location or report_has_context:
            completeness_label = (
                "Partial; Evidence: " + ("recorded" if report_has_evidence else "Unknown")
                + "; Source location: " + ("recorded" if report_has_location else "Unknown")
                + "; Testing context: " + ("recorded" if report_has_context else "Unknown")
            )
        else:
            completeness_label = (
                "Incomplete; Evidence: Unknown; Source location: Unknown; Testing context: Unknown"
            )
        completeness.append((report_name, f"Evidence completeness: {completeness_label}"))

        if not recognized:
            add_record("Unknown report content", report_name, None, None, "Unknown report format; content was not interpreted.")
        elif not report_has_evidence and not has_explicit_input_status:
            add_record("Unknown report content", report_name, None, None, "No recognized evidence content; details are Unknown.")

        report_records = [
            record for record in records.values()
            if report_name in record["reports"]
        ]
        source_kinds = (
            "Observed input value assignment",
            "Observed input pattern",
            "Direct request-value observation",
        )
        source_records = [
            record for record in report_records
            if record["kind"].startswith(source_kinds)
        ]
        sink_records = [
            record for record in report_records
            if record["kind"].startswith("Observed sink pattern")
        ]
        flow_review_kinds = (
            "Supported static relationship",
            "Legacy reported source-to-sink claim (unverified)",
            "Unresolved analysis candidate",
            "Unresolved conditional input",
            "Unresolved request reference",
            "Reported source-flow step (unverified)",
        )
        has_flow_review_question = any(
            record["kind"].startswith(flow_review_kinds)
            for record in report_records
        )
        located_source = any(record["file"] and record["line"] for record in source_records)
        located_sink = any(record["file"] and record["line"] for record in sink_records)
        concrete_evidence = any(
            not record["kind"].startswith("Unknown report content")
            and not is_placeholder_text(record["evidence"])
            and not record["evidence"].casefold().startswith(("unknown", "no evidence"))
            for record in report_records
        )

        if located_source and located_sink and has_flow_review_question:
            priority = "High"
            priority_reason = (
                "Located request-value evidence and a located sink are recorded with relationship or unresolved-flow evidence; review that path and its context."
            )
        elif concrete_evidence and (located_source or located_sink):
            priority = "Medium"
            missing = []
            if not located_source:
                missing.append("request-value source location")
            if not located_sink:
                missing.append("sink location")
            if not has_flow_review_question:
                missing.append("source-to-sink relationship evidence")
            priority_reason = "Concrete located evidence is available, but " + ", ".join(missing) + " is missing or unresolved."
        else:
            priority = "Low"
            if not concrete_evidence:
                priority_reason = "Only placeholder or missing evidence is recorded."
            elif any(record["kind"].startswith("Observed presence-check assignment") for record in report_records):
                priority_reason = "The report records a presence check, but no direct request value or located sink evidence."
            else:
                priority_reason = "Evidence is insufficient or lacks an identifiable request-value source or sink location."
        review_priorities.append((report_name, priority, priority_reason))

    output = [
        "JARVIS FINDINGS SUMMARY",
        "=======================",
        f"Reports read: {len(report_files)}",
        "",
        "Evidence grouped by source location:",
    ]
    grouped = {}
    for record in records.values():
        key = (record["file"], record["line"])
        grouped.setdefault(key, []).append(record)
    if grouped:
        for (file_name, line_number), items in sorted(
            grouped.items(), key=lambda item: (item[0][0] or "", item[0][1] or 0)
        ):
            heading = f"{file_name}:{line_number}" if file_name and line_number else "Unknown source location"
            output.append(f"  {heading}:")
            for item in sorted(items, key=lambda value: (value["kind"], value["evidence"].casefold())):
                output.append(f"    - {item['kind']}: {item['evidence']}")
    else:
        output.append("  No saved report observations found.")

    output.extend(["", "Saved report titles and types:"])
    if report_titles:
        output.extend(f"  {name}: {title}" for name, title in report_titles)
    else:
        output.append("  None")
    output.extend(["", "Remediation or review guidance recorded:"])
    if remediation_guidance:
        output.extend(f"  {name}: {guidance}" for name, guidance in remediation_guidance)
    else:
        output.append("  Unknown; no remediation guidance was recorded in the reports.")

    output.extend(["", "Saved analysis statements:"])
    if analysis_statements:
        output.extend(f"  {name}: {statement}" for name, statement in sorted(set(analysis_statements)))
    else:
        output.append("  None recorded.")

    output.extend(["", "Saved structured test records (report text; not independently authenticated):"])
    if structured_test_observations:
        output.extend(
            f"  {name}: recorded fields claim {test_type}; observation={observation}; "
            f"source={origin}; completeness={completeness_label}; not a vulnerability verdict"
            for name, test_type, observation, origin, completeness_label in structured_test_observations
        )
    else:
        output.append("  None recorded.")

    output.extend(["", "Report status:"])
    if report_statuses:
        output.extend(f"  {name}: {status}" for name, status in report_statuses)
    else:
        output.append("  None")
    output.extend(["", "Severity:"])
    if report_severities:
        for name, severity_label, suggestion in report_severities:
            suffix = f"; user-provided severity suggestion (unverified): {suggestion}" if suggestion else ""
            output.append(f"  {name}: {severity_label}{suffix}")
    else:
        output.append("  None")
    notes, malformed_validation_notes, validation_note_error = _read_review_notes(root)
    latest_validation = {
        report_name: _latest_validation_status(notes, report_name)
        for report_name, _report_path in report_files
    }
    status_labels = (
        "OBSERVED", "UNVERIFIED", "VALIDATED", "NOT_REPRODUCIBLE", "FALSE_POSITIVE",
    )
    output.extend([
        "", "Reviewer validation status (sidecar record; reviewer-reported, not authenticated by JARVIS):"
    ])
    if validation_note_error:
        output.append("  Counts: Unknown (review-note storage could not be read).")
    else:
        output.extend(
            f"  {status}: {sum(value == status for value in latest_validation.values())}"
            for status in status_labels
        )
        if malformed_validation_notes:
            output.append(f"  Malformed review-note records skipped: {malformed_validation_notes}")
    output.append(
        "  These reviewer statuses do not alter each saved report's automated Vulnerability status."
    )

    output.extend(["", "Evidence completeness:"])
    if completeness:
        output.extend(f"  {name}: {label}" for name, label in completeness)
    else:
        output.append("  No reports available; evidence is Unknown.")
    output.extend(["", "Manual-review priority (evidence completeness, not severity):"])
    if review_priorities:
        output.extend(f"  {name}: {priority} â€” {reason}" for name, priority, reason in review_priorities)
    else:
        output.append("  None")
    output.append("  Priority guides review order only; it is not a vulnerability or severity rating.")
    if unknown_reports:
        output.extend(["", "Unknown or unrecognized report content:"])
        output.extend(
            f"  {name}: Unrecognized report format; report content and evidence are Unknown."
            for name in unknown_reports
        )
    output.extend([
        "",
        "Known limitations:",
        "  This summary reads saved text only; it does not rerun analysis or independently validate report claims.",
        "  Static relationships are review evidence. Missing locations, unsupported syntax, and runtime behavior remain unresolved.",
        "",
        "Recommended manual review:",
        "  Open each source report with 'view <listed alias>', verify the cited source-to-sink path and impact in authorized context, and record any independent validation evidence separately.",
    ])
    return "\n".join(output)


def show_findings_summary():
    summary_text = _build_findings_summary(REPORTS_DIR)
    print(_safe_report_output_text(summary_text, REPORTS_DIR))


def _split_saved_report_lines(report_text):
    """Split report structure only on LF; render other separators as text."""
    normalized = str(report_text).replace("\r\n", "\n").replace("\r", r"\r")
    return [_escape_report_header_value(line) for line in normalized.split("\n")]


def _build_review_queue(reports_dir):
    """Build a human review queue from saved reports without rerunning analysis."""
    root = Path(reports_dir)
    try:
        resolved_root = root.resolve()
    except OSError:
        resolved_root = root

    report_names = []
    if root.is_dir():
        for candidate in sorted(root.glob("*.txt")):
            try:
                if candidate.is_symlink():
                    continue
                resolved = candidate.resolve(strict=True)
                if resolved.parent == resolved_root and resolved.is_file():
                    report_names.append(candidate.name)
            except (OSError, ValueError):
                # Ignore broken, inaccessible, or escaping report paths.
                continue

    priority_rank = {"High": 0, "Medium": 1, "Low": 2}
    location_pattern = re.compile(
        r"(?P<file>(?:[A-Za-z]:)?[^\s:]+?\.(?:php|py|js|html|sql)):(?P<line>\d+)",
        re.I,
    )
    queue_items = []
    for report_name in report_names:
        # Reuse the established report parser and priority calculation, scoped to
        # one saved report so observations cannot be attributed across reports.
        summary = _build_findings_summary(root, only_report=report_name)
        priority_match = re.search(
            rf"(?m)^\s+{re.escape(report_name)}: (High|Medium|Low) â€” (.+)$",
            summary,
        )
        priority = priority_match.group(1) if priority_match else "Low"
        rationale = (
            priority_match.group(2) if priority_match
            else "Priority could not be derived from recognized saved evidence."
        )

        source_locations = set()
        sink_locations = set()
        unresolved = []
        in_evidence = False
        current_location = None
        for line in summary.splitlines():
            if line == "Evidence grouped by source location:":
                in_evidence = True
                continue
            if line == "Saved report titles and types:":
                in_evidence = False
            if not in_evidence:
                continue
            heading = re.match(r"^  (.+?):(\d+):$", line)
            if heading:
                current_location = f"{heading.group(1)}:{heading.group(2)}"
                continue
            record_match = re.match(r"^    - ([^:]+):\s*(.*)$", line)
            if not record_match:
                continue
            kind, evidence = record_match.groups()
            loc = location_pattern.search(current_location or "")
            location = f"{loc.group('file')}:{loc.group('line')}" if loc else None
            if kind.startswith((
                "Observed input", "Direct request-value", "Conditional request-input",
                "Presence-check observation", "Unresolved request-reference",
            )) and location:
                source_locations.add(location)
            if kind.startswith("Observed sink pattern") and location:
                sink_locations.add(location)
            if kind.startswith((
                "Unresolved analysis candidate", "Unresolved conditional input",
                "Unresolved request reference", "Legacy reported source-to-sink claim",
                "Reported source-flow step",
            )):
                unresolved.append(f"{location + ': ' if location else ''}{evidence}")
            elif kind.startswith("Presence-check limitation"):
                unresolved.append(f"{location + ': ' if location else ''}{evidence}")

        status_match = re.search(
            rf"(?m)^\s+{re.escape(report_name)}: (.+)$\n(?=Severity:)",
            summary[summary.find("Report status:"):],
        ) if "Report status:" in summary else None
        status = status_match.group(1).strip() if status_match else "UNCONFIRMED"
        analysis_status_match = re.search(
            rf"(?m)^\s+{re.escape(report_name)}: Saved analysis status: (ANALYSIS INCOMPLETE â€” .+?); this is not vulnerability confirmation\.$",
            summary,
        )
        analysis_status = analysis_status_match.group(1) if analysis_status_match else None
        completeness_match = re.search(
            rf"(?m)^\s+{re.escape(report_name)}: (Evidence completeness: .+)$",
            summary,
        )
        completeness = completeness_match.group(1) if completeness_match else "Evidence completeness: Unknown"

        if source_locations and sink_locations:
            next_step = "Verify the cited input-to-sink path, runtime conditions, and any validation or encoding before changing the saved status."
        elif not source_locations:
            next_step = "Verify the originating input and relevant sink in the source; both remain necessary to assess a flow."
        elif not sink_locations:
            next_step = "Locate the relevant sink and determine whether the observed input reaches it."
        else:
            next_step = "Review the unresolved analysis evidence and verify the relevant source and sink in context."
        if unresolved:
            next_step = "Review the unresolved questions below, then verify the relevant source-to-sink path in authorized context."

        queue_items.append({
            "name": report_name,
            "priority": priority,
            "rationale": rationale,
            "sources": sorted(source_locations),
            "sinks": sorted(sink_locations),
            "unresolved": sorted(set(unresolved)),
            "status": status,
            "analysis_status": analysis_status,
            "completeness": completeness,
            "next_step": next_step,
        })

    queue_items.sort(key=lambda item: (priority_rank.get(item["priority"], 3), item["name"].casefold()))
    output = [
        "JARVIS REVIEW QUEUE",
        "===================",
        f"Saved reports read: {len(queue_items)}",
        "Priority reflects evidence completeness and is not a severity or exploitability rating.",
        "Priority counts include all saved reports, including reports with review notes; review-progress counts only outstanding reports.",
    ]
    if not queue_items:
        output.extend(["", "No saved reports available for review."])
        return _safe_report_output_text("\n".join(output), root)

    for item in queue_items:
        output.extend([
            "",
            f"{item['name']}",
            f"  Priority: {item['priority']} â€” {item['rationale']}",
            f"  Vulnerability status: {item['status']}",
        ])
        if item["analysis_status"]:
            output.append(f"  Review status: {item['analysis_status']}")
        output.extend([
            f"  {item['completeness']}",
            "  Source locations: " + (", ".join(item["sources"]) if item["sources"] else "Unknown"),
            "  Sink locations: " + (", ".join(item["sinks"]) if item["sinks"] else "Unknown"),
            "  Unresolved questions:",
        ])
        if item["unresolved"]:
            output.extend(f"    - {question}" for question in item["unresolved"])
        else:
            output.append("    Unknown; no unresolved question was recorded in the saved report.")
        output.append(f"  Verify next: {item['next_step']}")
    output.extend([
        "",
        "Review priority never confirms a vulnerability or establishes exploitability.",
        "The queue reads saved reports only; it does not rerun scans or change report status or severity.",
    ])
    return _safe_report_output_text("\n".join(output), root)


def show_review_queue():
    print(_build_review_queue(REPORTS_DIR))


def _build_review_progress(reports_dir):
    """Summarize saved-report review coverage without changing either data source."""
    root = Path(reports_dir)
    report_names = _reviewable_report_names(root)
    report_name_set = set(report_names)
    priority_by_report = {}
    for report_name in report_names:
        saved_summary = _build_findings_summary(root, only_report=report_name)
        match = re.search(
            rf"(?m)^\s+{re.escape(report_name)}: (High|Medium|Low) â€”",
            saved_summary,
        )
        priority_by_report[report_name] = match.group(1) if match else "Unknown"

    notes, malformed_count, note_error = _read_review_notes(root)
    conclusion_names = (
        "Needs more evidence",
        "Not reproduced",
        "Verified in authorized lab",
    )
    priority_order = {"High": 0, "Medium": 1, "Low": 2, "Unknown": 3}
    output = [
        "JARVIS REVIEW PROGRESS",
        "======================",
        f"Saved reports: {len(report_names)}",
        "Reviewer conclusions are reviewer-provided notes, not automated vulnerability statuses.",
    ]

    if note_error:
        output.extend([
            "Reports with at least one valid review note: Unknown (note storage could not be read)",
            "Reports without review notes: Unknown (note storage could not be read)",
            "",
            "Unreviewed reports by manual-review priority:",
            "  High: Unknown",
            "  Medium: Unknown",
            "  Low: Unknown",
            "  Unknown priority: Unknown",
            "",
            "Reviewer-provided conclusion counts:",
        ])
        output.extend(f"  {conclusion}: Unknown" for conclusion in conclusion_names)
        output.extend([
            "",
            "Unreviewed reports:",
            "  Not listed because review-note coverage could not be determined.",
            "",
            "Review-note data integrity:",
            "  Malformed JSONL records: Unknown",
            "  Exact duplicate note records: Unknown",
            "  Orphaned valid notes: Unknown",
            f"  Storage issue: {note_error}",
        ])
        return _safe_report_output_text("\n".join(output), root)

    # Canonical JSON makes key ordering irrelevant while preserving distinctions
    # between records with different timestamps, conclusions, or evidence.
    unique_notes = []
    seen_notes = set()
    for note in notes:
        identity = json.dumps(note, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if identity in seen_notes:
            continue
        seen_notes.add(identity)
        unique_notes.append(note)
    duplicate_count = len(notes) - len(unique_notes)
    orphaned_notes = [note for note in unique_notes if note["report_filename"] not in report_name_set]
    orphan_count = len(orphaned_notes)
    current_notes = [note for note in unique_notes if note["report_filename"] in report_name_set]
    reviewed_reports = {note["report_filename"] for note in current_notes}
    unreviewed = [name for name in report_names if name not in reviewed_reports]

    output.extend([
        f"Reports with at least one valid review note: {len(reviewed_reports)}",
        f"Reports without review notes: {len(unreviewed)}",
        "",
        "Unreviewed reports by manual-review priority:",
    ])
    unreviewed_by_priority = {priority: [] for priority in priority_order}
    for report_name in unreviewed:
        unreviewed_by_priority[priority_by_report[report_name]].append(report_name)
    for priority in ("High", "Medium", "Low", "Unknown"):
        output.append(f"  {priority}: {len(unreviewed_by_priority[priority])}")

    output.extend(["", "Reviewer-provided conclusion counts (not automated statuses):"])
    conclusion_counts = {conclusion: 0 for conclusion in conclusion_names}
    for note in current_notes:
        conclusion_counts[note["reviewer_conclusion"]] += 1
    output.extend(f"  {conclusion}: {conclusion_counts[conclusion]}" for conclusion in conclusion_names)

    output.extend(["", "Unreviewed reports (High, Medium, Low, then Unknown):"])
    for priority in ("High", "Medium", "Low", "Unknown"):
        for report_name in sorted(unreviewed_by_priority[priority], key=str.casefold):
            output.append(f"  {priority}: {report_name}")
    if not unreviewed:
        output.append("  None")

    output.extend([
        "",
        "Review-note data integrity:",
        f"  Malformed JSONL records skipped: {malformed_count}",
        f"  Exact duplicate note records ignored: {duplicate_count}",
        f"  Orphaned valid notes (report no longer present): {orphan_count}",
        "  Reviewer conclusions do not change saved report vulnerability statuses.",
    ])
    return _safe_report_output_text("\n".join(output), root)


def show_review_progress():
    print(_build_review_progress(REPORTS_DIR))


def _reviewable_report_names(reports_dir):
    """Return safe, immediate .txt report names; sidecar directories are excluded."""
    root = Path(reports_dir)
    try:
        resolved_root = root.resolve(strict=True)
    except OSError:
        return []
    if not root.is_dir():
        return []
    names = []
    try:
        candidates = sorted(root.glob("*.txt"))
    except OSError:
        return []
    for candidate in candidates:
        try:
            if candidate.is_symlink():
                continue
            resolved = candidate.resolve(strict=True)
            if resolved.parent == resolved_root and resolved.is_file():
                names.append(candidate.name)
        except OSError:
            continue
    return names


_VALIDATION_STATUSES = {
    "OBSERVED", "UNVERIFIED", "VALIDATED", "NOT_REPRODUCIBLE", "FALSE_POSITIVE",
}
_VALIDATION_DETAIL_FIELDS = (
    "endpoint", "category", "severity", "severity_justification", "preconditions",
    "reproduction_steps", "expected_behavior", "actual_behavior", "evidence",
    "impact", "limitations", "remediation",
)
_VALIDATION_TRANSITIONS = {
    "OBSERVED": {"OBSERVED", "UNVERIFIED", "VALIDATED", "NOT_REPRODUCIBLE", "FALSE_POSITIVE"},
    "UNVERIFIED": {"OBSERVED", "UNVERIFIED", "VALIDATED", "NOT_REPRODUCIBLE", "FALSE_POSITIVE"},
    "VALIDATED": {"UNVERIFIED"},
    "NOT_REPRODUCIBLE": {"UNVERIFIED"},
    "FALSE_POSITIVE": {"UNVERIFIED"},
}


def _sanitize_reviewer_text(value):
    """Redact common secrets and personal identifiers in reviewer-authored text."""
    escaped = _escape_report_user_field(str(value).strip())
    safe_lines = []
    sensitive_header = re.compile(
        r"(?i)^\s*[\"']?(?:authorization|proxy-authorization|cookie|set-cookie|"
        r"x-[a-z0-9-]*(?:api[-_]?key|auth[-_]?key|token|secret|password|"
        r"session[-_]?id))[\"']?\s*[:=]"
    )
    credential_assignment = re.compile(
        r"(?i)([\"']?(?:authorization|proxy-authorization|cookie|set-cookie|"
        r"x-[a-z0-9-]*(?:api[-_]?key|auth[-_]?key|token|secret|password|"
        r"session[-_]?id))[\"']?\s*[:=]\s*)"
        r"(?:\"[^\"]*\"|'[^']*'|(?:bearer|basic)\s+[^\s,;&}]+|[^\s,;&}]+)"
    )
    secret_assignment = re.compile(
        r"(?i)(\b(?:password|passwd|token|access[-_]?token|auth[-_]?key|"
        r"api[-_]?key|client[-_]?secret|secret|session[-_]?id)\b\s*[=:]\s*)"
        r"(?:\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
    )
    email_address = re.compile(
        r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"
    )
    phone_number = re.compile(
        r"(?<!\w)(?:\+?\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?)?\d{3}[ .-]?\d{4}(?!\w)"
    )
    for line in escaped.split(r"\n"):
        if sensitive_header.match(line):
            label = re.split(r"[:=]", line, maxsplit=1)[0]
            line = label.strip(" '\"") + ": [REDACTED]"
        else:
            line = credential_assignment.sub(r"\1[REDACTED]", line)
            line = secret_assignment.sub(r"\1[REDACTED]", line)
        line = email_address.sub("[REDACTED_EMAIL]", line)
        line = phone_number.sub("[REDACTED_PHONE]", line)
        safe_lines.append(line)
    return r"\n".join(safe_lines)


def _normalize_validation_record(status, details, require_scope=True):
    """Validate and safely render a structured, reviewer-authored validation record."""
    if status not in _VALIDATION_STATUSES or not isinstance(details, dict):
        raise ValueError("Choose a supported validation status and provide structured details.")
    if not all(
        isinstance(details.get(field), str) and details[field].strip()
        for field in _VALIDATION_DETAIL_FIELDS
    ):
        raise ValueError("All validation record fields are required; enter Unknown when unavailable.")

    raw = {field: details[field].strip() for field in _VALIDATION_DETAIL_FIELDS}
    if require_scope and not check_scope(raw["endpoint"], announce=False):
        raise ValueError("Validation endpoint must be inside the current authorized scope.")
    try:
        endpoint_parts = urlsplit(raw["endpoint"])
        if endpoint_parts.scheme.lower() not in {"http", "https"} or not endpoint_parts.netloc:
            raise ValueError
    except (TypeError, ValueError):
        raise ValueError("Validation endpoint must be an absolute HTTP or HTTPS URL.")

    safe = {field: _sanitize_reviewer_text(value) for field, value in raw.items()}
    safe["endpoint"] = _render_report_endpoint(raw["endpoint"])
    if safe["endpoint"] == "<unavailable endpoint>":
        raise ValueError("Validation endpoint could not be rendered safely.")

    placeholders = {"", "unknown", "n/a", "not provided", "none"}
    required_by_status = {
        "OBSERVED": ("actual_behavior", "evidence"),
        "UNVERIFIED": ("evidence", "limitations"),
        "VALIDATED": (
            "category", "severity_justification", "preconditions", "reproduction_steps",
            "expected_behavior", "actual_behavior", "evidence", "impact", "limitations",
            "remediation",
        ),
        "NOT_REPRODUCIBLE": (
            "preconditions", "reproduction_steps", "expected_behavior", "actual_behavior",
            "evidence", "limitations",
        ),
        "FALSE_POSITIVE": ("category", "actual_behavior", "evidence", "limitations"),
    }
    for field in required_by_status[status]:
        if " ".join(raw[field].split()).casefold().strip(" .") in placeholders:
            raise ValueError(f"{field.replace('_', ' ').capitalize()} is required for {status}.")

    if status in {"VALIDATED", "NOT_REPRODUCIBLE"}:
        steps = [
            line.strip()
            for line in re.split(r"\r\n|\n|\\n", raw["reproduction_steps"])
            if line.strip()
        ]
        numbered_steps = re.findall(
            r"(?m)^\s*\d+[.)]\s+|(?:;\s*)\d+[.)]\s+",
            raw["reproduction_steps"],
        )
        if max(len(steps), len(numbered_steps)) < 2:
            raise ValueError("Record at least two reproducible steps for this status.")
    if status == "VALIDATED":
        if raw["expected_behavior"].strip().casefold() == raw["actual_behavior"].strip().casefold():
            raise ValueError("VALIDATED requires distinct expected and actual behavior.")
        if raw["severity"].strip().casefold() in placeholders:
            raise ValueError("Record a reviewer severity or explicitly enter Not assessed.")
    return safe


def _latest_validation_status(notes, report_name):
    status = "UNVERIFIED"
    for note in notes:
        if note.get("report_filename") == report_name and note.get("validation_status") in _VALIDATION_STATUSES:
            status = note["validation_status"]
    return status


def _save_review_note(
    reports_dir, selection, conclusion, evidence, uncertainties,
    validation_status=None, validation_details=None,
):
    """Append a reviewer-authored note without modifying its source report."""
    root = Path(reports_dir)
    if not isinstance(selection, str) or not selection.strip():
        raise ValueError("Select a report filename or list number.")
    report_names = _reviewable_report_names(root)
    if not report_names:
        raise ValueError("No saved .txt reports are available for review.")

    selected = selection.strip()
    if selected.isdecimal():
        index = int(selected)
        if index < 1 or index > len(report_names):
            raise ValueError("Report selection number is out of range.")
        report_name = report_names[index - 1]
    else:
        if Path(selected).name != selected or "/" in selected or "\\" in selected:
            raise ValueError("Select a report by filename only; path components are not allowed.")
        if selected not in report_names:
            raise ValueError("Selected report was not found in the reports directory.")
        report_name = selected

    allowed_conclusions = {
        "Needs more evidence",
        "Not reproduced",
        "Verified in authorized lab",
    }
    if not isinstance(conclusion, str) or conclusion not in allowed_conclusions:
        raise ValueError("Choose one of the listed reviewer conclusions.")
    if not isinstance(evidence, str) or not evidence.strip():
        raise ValueError("Supporting evidence is required; enter Unknown if none is available.")
    if not isinstance(uncertainties, str) or not uncertainties.strip():
        raise ValueError("Remaining uncertainties are required; enter None if no uncertainty remains.")

    note = {
        "report_filename": report_name,
        "reviewed_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "reviewer_conclusion": conclusion,
        "conclusion_attribution": "Reviewer-provided; not independently verified by JARVIS",
        "supporting_evidence": evidence.strip(),
        "remaining_uncertainties": uncertainties.strip(),
    }
    note["supporting_evidence"] = _sanitize_reviewer_text(note["supporting_evidence"])
    note["remaining_uncertainties"] = _sanitize_reviewer_text(note["remaining_uncertainties"])

    if validation_status is not None:
        validation_record = _normalize_validation_record(validation_status, validation_details)
        existing_notes, _malformed, note_error = _read_review_notes(root)
        if note_error:
            raise OSError("Cannot determine the prior validation status from review-note storage.")
        previous_status = _latest_validation_status(existing_notes, report_name)
        if validation_status not in _VALIDATION_TRANSITIONS.get(previous_status, set()):
            raise ValueError(
                f"Invalid validation status transition: {previous_status} -> {validation_status}. "
                "Reopen a completed assessment as UNVERIFIED before recording a new outcome."
            )
        note["validation_status"] = validation_status
        note["validation_details"] = validation_record

    try:
        resolved_root = root.resolve(strict=True)
        review_dir = root / "review_notes"
        if review_dir.is_symlink():
            raise OSError("Review-notes directory must not be a symlink.")
        review_dir.mkdir(exist_ok=True)
        resolved_review_dir = review_dir.resolve(strict=True)
        if resolved_review_dir.parent != resolved_root or not resolved_review_dir.is_dir():
            raise OSError("Review-notes directory is outside the reports directory.")
        notes_path = review_dir / "notes.jsonl"
        if notes_path.is_symlink() or (notes_path.exists() and not notes_path.is_file()):
            raise OSError("Review-note storage path is not a regular file.")
        serialized = json.dumps(note, ensure_ascii=False, separators=(",", ":")) + "\n"
        with notes_path.open("a", encoding="utf-8", newline="\n") as notes_file:
            notes_file.write(serialized)
            notes_file.flush()
    except (OSError, UnicodeError) as error:
        raise OSError(f"Could not append review note; existing notes were left untouched: {error}") from error
    return note


def review_note_workflow(reports_dir):
    """Prompt for a report review and save it to the separate JSONL sidecar."""
    report_names = _reviewable_report_names(reports_dir)
    print("JARVIS MANUAL REVIEW NOTE")
    print("=========================")
    if not report_names:
        print("JARVIS: No saved .txt reports are available for review.")
        return
    for index, name in enumerate(report_names, start=1):
        print(f"  {index}. {name}")
    try:
        selection = input("Select report by number or filename: ").strip()
        print("Reviewer conclusion options:")
        print("  1. Needs more evidence")
        print("  2. Not reproduced")
        print("  3. Verified in authorized lab")
        conclusion_choice = input("Choose conclusion (1-3): ").strip()
        conclusions = {
            "1": "Needs more evidence",
            "2": "Not reproduced",
            "3": "Verified in authorized lab",
        }
        conclusion = conclusions.get(conclusion_choice, conclusion_choice)
        evidence = input("Supporting evidence (required; enter Unknown if unavailable): ")
        uncertainties = input("Remaining uncertainties (required; enter None if none): ")
        note = _save_review_note(reports_dir, selection, conclusion, evidence, uncertainties)
    except EOFError:
        print("JARVIS: Review note input ended early; no note was saved.")
        return
    except (ValueError, OSError, UnicodeError) as error:
        print(f"JARVIS: Review note was not saved: {error}")
        return
    print("JARVIS: Reviewer note appended; it does not change automated findings or status.")
    print(f"JARVIS: Note recorded for {note['report_filename']} at {note['reviewed_at']}.")


def validation_note_workflow(reports_dir):
    """Record a structured, reviewer-authored outcome without editing a report."""
    report_names = _reviewable_report_names(reports_dir)
    print("JARVIS STRUCTURED VALIDATION NOTE")
    print("==================================")
    print("This records reviewer input only; it sends no requests and changes no saved report.")
    if not report_names:
        print("JARVIS: No saved .txt reports are available for validation notes.")
        return
    for index, name in enumerate(report_names, start=1):
        safe_name = _safe_report_output_text(name, reports_dir)
        print(f"  {index}. {safe_name}")
    print("Status options: OBSERVED, UNVERIFIED, VALIDATED, NOT_REPRODUCIBLE, FALSE_POSITIVE")
    try:
        selection = input("Select report by number: ").strip()
        status = input("Reviewer status: ").strip().upper()
        if status not in _VALIDATION_STATUSES:
            raise ValueError("Choose one of the listed validation statuses.")
        print("Enter Unknown for unavailable details; VALIDATED requires complete reproducible evidence.")
        details = {}
        for field in _VALIDATION_DETAIL_FIELDS:
            prompt = field.replace("_", " ").capitalize()
            details[field] = input(f"{prompt}: ")
        evidence = details["evidence"]
        uncertainties = details["limitations"]
        conclusion = {
            "VALIDATED": "Verified in authorized lab",
            "NOT_REPRODUCIBLE": "Not reproduced",
        }.get(status, "Needs more evidence")
        note = _save_review_note(
            reports_dir,
            selection,
            conclusion,
            evidence,
            uncertainties,
            validation_status=status,
            validation_details=details,
        )
    except EOFError:
        print("JARVIS: Validation-note input ended early; no note was saved.")
        return
    except (OSError, UnicodeError, ValueError) as error:
        print(f"JARVIS: Validation note was not saved: {error}")
        return
    print(
        "JARVIS: Reviewer validation record appended. "
        "It does not change the saved report's automated status or severity."
    )
    print(
        f"JARVIS: {_escape_report_user_field(note['validation_status'])} "
        f"record recorded for {_escape_report_user_field(note['report_filename'])}."
    )


def _is_safe_review_note_filename(filename):
    return (
        isinstance(filename, str)
        and bool(filename)
        and filename.endswith(".txt")
        and Path(filename).name == filename
        and "/" not in filename
        and "\\" not in filename
        and filename not in {".", ".."}
    )


def _read_review_notes(reports_dir):
    """Read valid reviewer-note records without opening or changing reports."""
    root = Path(reports_dir)
    try:
        resolved_root = root.resolve(strict=True)
        if not resolved_root.is_dir():
            return [], 0, "Reports directory is unavailable."
        review_dir = root / "review_notes"
        notes_path = review_dir / "notes.jsonl"
        if not review_dir.exists() and not review_dir.is_symlink():
            return [], 0, None
        if review_dir.is_symlink():
            return [], 0, "Review-note storage is outside the reports directory or is a symlink."
        resolved_review_dir = review_dir.resolve(strict=True)
        if resolved_review_dir.parent != resolved_root or not resolved_review_dir.is_dir():
            return [], 0, "Review-note storage is outside the reports directory."
        if not notes_path.exists() and not notes_path.is_symlink():
            return [], 0, None
        if notes_path.is_symlink():
            return [], 0, "Review-note file must not be a symlink."
        resolved_notes = notes_path.resolve(strict=True)
        if resolved_notes.parent != resolved_review_dir or not resolved_notes.is_file():
            return [], 0, "Review-note path is not a regular file inside review_notes."
        text = resolved_notes.read_text(encoding="utf-8")
    except FileNotFoundError:
        return [], 0, None
    except (OSError, UnicodeError) as error:
        return [], 0, f"Could not read review notes: {error}"

    required_fields = {
        "report_filename", "reviewed_at", "reviewer_conclusion",
        "conclusion_attribution", "supporting_evidence", "remaining_uncertainties",
    }
    allowed_conclusions = {
        "Needs more evidence", "Not reproduced", "Verified in authorized lab",
    }
    notes = []
    latest_status_by_report = {}
    seen_validation_records = set()
    malformed = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            note = json.loads(line)
            if not isinstance(note, dict) or not required_fields.issubset(note):
                raise ValueError("missing required note fields")
            if (
                not _is_safe_review_note_filename(note["report_filename"])
                or not all(isinstance(note[field], str) and note[field].strip() for field in required_fields)
                or note["reviewer_conclusion"] not in allowed_conclusions
                or "reviewer-provided" not in note["conclusion_attribution"].casefold()
                or "not independently verified by jarvis" not in note["conclusion_attribution"].casefold()
            ):
                raise ValueError("invalid note fields")
            parsed_timestamp = datetime.fromisoformat(note["reviewed_at"])
            if parsed_timestamp.utcoffset() is None:
                raise ValueError("review timestamp is not timezone-aware")
            has_status = "validation_status" in note
            has_details = "validation_details" in note
            if has_status != has_details:
                raise ValueError("incomplete validation record")
            if has_status:
                normalized_details = _normalize_validation_record(
                    note["validation_status"],
                    note["validation_details"],
                    require_scope=False,
                )
                if normalized_details != note["validation_details"]:
                    raise ValueError("validation record is not safely normalized")
                note_identity = json.dumps(
                    note, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                )
                if note_identity not in seen_validation_records:
                    previous_status = latest_status_by_report.get(
                        note["report_filename"], "UNVERIFIED"
                    )
                    if note["validation_status"] not in _VALIDATION_TRANSITIONS.get(previous_status, set()):
                        raise ValueError("invalid validation status transition")
                    latest_status_by_report[note["report_filename"]] = note["validation_status"]
                    seen_validation_records.add(note_identity)
        except (json.JSONDecodeError, TypeError, ValueError):
            malformed += 1
            continue
        notes.append(note)
    return notes, malformed, None


def review_notes_workflow(reports_dir):
    """List reviewer notes and optionally show details for one report filename."""
    print("JARVIS REVIEW NOTES (READ ONLY)")
    print("===============================")
    notes, malformed, error = _read_review_notes(reports_dir)
    if error:
        print(f"JARVIS: {error}")
        return
    if malformed:
        print(f"JARVIS: Skipped {malformed} malformed review-note record(s).")
    if not notes:
        print("JARVIS: No saved reviewer notes found.")
        return

    report_names = set(_reviewable_report_names(reports_dir))
    print("Saved notes:")
    for index, note in enumerate(notes, start=1):
        evidence_summary = _sanitize_reviewer_text(note["supporting_evidence"])
        evidence_summary = " ".join(evidence_summary.split())
        if len(evidence_summary) > 120:
            evidence_summary = evidence_summary[:117] + "..."
        orphaned_label = (
            " | ORPHANED: referenced report is missing"
            if note["report_filename"] not in report_names else ""
        )
        print(f"  {index}. {_escape_report_user_field(note['report_filename'])} | {note['reviewed_at']} | "
              f"Reviewer-provided conclusion (not independently verified by JARVIS): "
              f"{note['reviewer_conclusion']}{orphaned_label}")
        print(f"     Evidence summary: {evidence_summary}")

    try:
        selection = input("Enter a report filename to inspect, or press Enter to return: ").strip()
    except EOFError:
        print("JARVIS: Review-note inspection ended; no data was changed.")
        return
    if not selection:
        return
    if not _is_safe_review_note_filename(selection):
        print("JARVIS: Invalid report filename; enter a .txt basename only.")
        return
    selected_notes = [note for note in notes if note["report_filename"] == selection]
    if not selected_notes:
        print(f"JARVIS: No reviewer notes found for {selection}.")
        return
    for index, note in enumerate(selected_notes, start=1):
        print("")
        print(f"Review note {index} for {_escape_report_user_field(note['report_filename'])}")
        if note["report_filename"] not in report_names:
            print("Report availability: ORPHANED; referenced report is missing.")
        print(f"Reviewed at: {note['reviewed_at']}")
        print("Reviewer-provided conclusion (not independently verified by JARVIS): "
              f"{note['reviewer_conclusion']}")
        print(f"Supporting evidence: {_sanitize_reviewer_text(note['supporting_evidence'])}")
        print(f"Remaining uncertainties: {_sanitize_reviewer_text(note['remaining_uncertainties'])}")
        if note.get("validation_status"):
            print(
                "Manual validation status (reviewer-reported; not authenticated by JARVIS): "
                f"{note['validation_status']}"
            )
            for field in _VALIDATION_DETAIL_FIELDS:
                print(
                    f"  {field.replace('_', ' ').title()}: "
                    f"{_sanitize_reviewer_text(note['validation_details'][field])}"
                )
    print("Automated report content and vulnerability status were not read or changed.")


def _report_display_entries(reports_dir=None):
    """Return stable, safe aliases for report files contained in REPORTS_DIR."""
    global _REPORT_DISPLAY_ALIASES
    reports_directory = Path(reports_dir) if reports_dir is not None else Path(REPORTS_DIR)
    try:
        resolved_root = reports_directory.resolve()
    except OSError:
        return []

    valid_reports = []
    used_aliases = set()
    for report_file in sorted(reports_directory.glob("*.txt"), key=lambda path: path.name):
        try:
            resolved_file = report_file.resolve(strict=True)
            resolved_file.relative_to(resolved_root)
            if not resolved_file.is_file():
                continue
        except (OSError, ValueError, RuntimeError):
            continue
        valid_reports.append((report_file.name, resolved_file))

    valid_names = {name for name, _path in valid_reports}
    _REPORT_DISPLAY_ALIASES = {
        alias: name for alias, name in _REPORT_DISPLAY_ALIASES.items()
        if name in valid_names
    }
    aliases_by_name = {
        name: alias for alias, name in _REPORT_DISPLAY_ALIASES.items()
    }

    entries = []
    for report_name, resolved_file in valid_reports:
        alias = aliases_by_name.get(report_name)
        if alias is None:
            alias = "@" + secrets.token_urlsafe(12)
            collision_number = 2
            while alias in used_aliases or (
                alias in _REPORT_DISPLAY_ALIASES
                and _REPORT_DISPLAY_ALIASES[alias] != report_name
            ):
                alias = f"@{secrets.token_urlsafe(12)}-{collision_number}"
                collision_number += 1
            _REPORT_DISPLAY_ALIASES[alias] = report_name
        if alias in used_aliases:
            collision_number = 2
            base_alias = alias
            while alias in used_aliases:
                alias = f"{base_alias}-{collision_number}"
                collision_number += 1
            _REPORT_DISPLAY_ALIASES[alias] = report_name
        used_aliases.add(alias)
        entries.append((alias, resolved_file))
    return entries


def _safe_report_display_text(report_text):
    """Redact sensitive URLs and neutralize controls in displayed report lines."""
    lines = str(report_text).split("\n")
    rendered = [_escape_report_user_field(line) for line in lines]
    return "\n".join(f"  | {line}" for line in rendered)


def _safe_report_output_text(output_text, reports_dir=None):
    """Render summary and review output with safe aliases and field escaping."""
    aliases = {}
    for alias, _report_path in _report_display_entries(reports_dir):
        report_name = _REPORT_DISPLAY_ALIASES.get(alias)
        if report_name:
            aliases[report_name] = alias
    output_text = str(output_text)
    if aliases:
        names = sorted(aliases, key=len, reverse=True)
        pattern = re.compile("|".join(re.escape(name) for name in names))
        output_text = pattern.sub(lambda match: aliases[match.group(0)], output_text)
    return "\n".join(
        _escape_report_user_field(line) for line in output_text.split("\n")
    )


def list_reports():
    REPORTS_DIR.mkdir(exist_ok=True)
    entries = _report_display_entries()

    print("JARVIS: Available reports:")
    print("  Select a listed alias with 'view <alias>'.")

    if not entries:
        print("  (none)")
        return

    for alias, _report_file in entries:
        print(f"  - {alias}")


def view_report(filename):
    selection = str(filename)
    entries = _report_display_entries()
    report_file = next(
        (path for alias, path in entries if alias == selection),
        None,
    )

    if report_file is None:
        try:
            report_file = (REPORTS_DIR / selection).resolve(strict=True)
            reports_directory = REPORTS_DIR.resolve()
            report_file.relative_to(reports_directory)
            if not report_file.is_file():
                raise ValueError("not a report file")
        except (OSError, ValueError, RuntimeError):
            print("JARVIS: Invalid report path or report not found.")
            return

    try:
        report_text = report_file.read_bytes().decode("utf-8", errors="replace")
    except OSError:
        print("JARVIS: Report could not be read.")
        return

    print("\nJARVIS REPORT VIEWER â€” saved text is displayed as untrusted content")
    print("====================================================================\n")
    print(_safe_report_display_text(report_text))


def _report_remediation(finding_type, description=""):
    finding_kind = str(finding_type).lower()
    description_kind = str(description).lower()
    kind = f"{finding_kind} {description_kind}"
    if "sql" in finding_kind:
        return "If query construction from untrusted input is confirmed, use parameterized queries and validate input according to its expected type. Verify the relevant code path first."
    if any(term in finding_kind for term in ("xss", "reflect", "output")):
        return "If untrusted data is confirmed to reach this rendering context, apply context-appropriate output encoding. Confirm the rendered context before selecting an encoding strategy."
    if any(term in finding_kind for term in ("access", "authorization", "idor")):
        return "If an authorization gap is confirmed, enforce server-side authorization for each requested object or action and verify controls with an authorized test account."
    if "header" in finding_kind:
        return "If the header behavior is confirmed to be unintended, configure it according to the application's requirements and deployment needs."

    # Fall back to the description only when the finding type is generic.
    if "sql" in kind:
        return "If query construction from untrusted input is confirmed, use parameterized queries and validate input according to its expected type. Verify the relevant code path first."
    if "xss" in kind or "reflect" in kind or "output" in kind:
        return "If untrusted data is confirmed to reach this rendering context, apply context-appropriate output encoding. Confirm the rendered context before selecting an encoding strategy."
    if "access" in kind or "authorization" in kind or "idor" in kind:
        return "If an authorization gap is confirmed, enforce server-side authorization for each requested object or action and verify controls with an authorized test account."
    if "header" in kind:
        return "If the header behavior is confirmed to be unintended, configure it according to the application's requirements and deployment needs."
    return "Review the cited input, processing, and output path. Apply a control appropriate to verified behavior, then retest locally or within authorized scope."


def _candidate_report_title_and_impact(finding_type):
    """Use controlled titles and conditional impact text for known candidate classes."""
    known_candidates = {
        "reflected input": (
            "Potential reflected-input candidate (unverified)",
            "If untrusted data is confirmed to reach a browser-interpreted context, it could affect page behavior. Browser execution and impact were not tested.",
        ),
        "sql injection": (
            "Potential SQL injection candidate (unverified)",
            "If untrusted input is confirmed to alter a database query, it could change query behavior or data access. Query execution and impact were not verified.",
        ),
        "high-risk input": (
            "Potential high-risk input candidate (unverified)",
            "A parameter-name match alone does not demonstrate impact. Consequences depend on how the input is used and must be independently verified.",
        ),
        "broken access control": (
            "Potential access-control candidate (unverified)",
            "If an authorization gap is confirmed, an unauthorized user could access an object or action. No access-control failure was demonstrated.",
        ),
    }
    return known_candidates.get(
        str(finding_type).strip().casefold(),
        (
            "Unverified security candidate",
            "Potential impact is unknown until the behavior and affected assets are independently verified.",
        ),
    )


def _normalize_structured_test_result(result):
    """Accept only the small, controlled test-observation schema JARVIS emits."""
    if not isinstance(result, dict) or set(result) != {
        "schema_version", "method", "test_type", "observation",
        "requested_endpoint", "final_response_endpoint", "response_origin",
        "evidence_completeness", "not_established",
    }:
        return None
    if type(result.get("schema_version")) is not int or result.get("schema_version") != 1:
        return None
    if result.get("method") != "scoped_get":
        return None
    if result.get("test_type") != "harmless_reflection_marker":
        return None
    observation = result.get("observation")
    if not isinstance(observation, str) or observation not in {"marker_reflected", "marker_not_reflected"}:
        return None
    response_origin = result.get("response_origin")
    if not isinstance(response_origin, str) or response_origin not in {"fresh", "cached", "unknown"}:
        return None
    evidence_completeness = result.get("evidence_completeness")
    if not isinstance(evidence_completeness, str) or evidence_completeness not in {"complete", "incomplete", "inconclusive"}:
        return None
    not_established = result.get("not_established")
    if (
        not isinstance(not_established, list)
        or not not_established
        or any(
            not isinstance(item, str)
            or item not in {"browser_execution", "exploitability", "impact"}
            for item in not_established
        )
    ):
        return None
    requested_endpoint = result.get("requested_endpoint")
    final_endpoint = result.get("final_response_endpoint")
    if not isinstance(requested_endpoint, str) or not requested_endpoint.strip():
        return None
    if not isinstance(final_endpoint, str) or not final_endpoint.strip():
        return None
    if observation == "marker_not_reflected" and evidence_completeness != "complete":
        return None

    return {
        "schema_version": 1,
        "method": "scoped_get",
        "test_type": "harmless_reflection_marker",
        "observation": observation,
        "requested_endpoint": _render_report_endpoint(requested_endpoint),
        "final_response_endpoint": _render_report_endpoint(final_endpoint),
        "response_origin": response_origin,
        "evidence_completeness": evidence_completeness,
        "not_established": sorted(set(not_established)),
    }


def _report_evidence_location(evidence):
    if not evidence or not str(evidence).strip():
        return "Unknown; no source file and line were provided."
    evidence = str(evidence)
    match = re.search(r"(?:^|\s)([^\s:]+\.(?:php|py|js|html|sql)):(\d+)\b", evidence, re.I)
    if match:
        return f"{match.group(1)}:{match.group(2)}"
    return "Unknown; no source file and line were provided."


def record_finding(
    target, title, description, evidence,
    observation_confidence="User-provided evidence; unverified",
    testing_context="Unknown; no testing context was provided.",
    remediation=None,
):

    if not check_scope(target):
        return

    REPORTS_DIR.mkdir(exist_ok=True)

    safe_target = _report_target_filename_component(target)

    safe_title_source = _escape_report_user_field(title)
    safe_title = re.sub(r"[^a-zA-Z0-9_-]+", "_", safe_title_source).strip("_").lower()

    finding_file = REPORTS_DIR / f"{safe_target}_{safe_title}_finding.txt"

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    remediation = remediation or _report_remediation(title, description)
    evidence_location = _report_evidence_location(evidence)
    supplied_title = _escape_report_user_field(str(title).strip()) if title and str(title).strip() else "Unknown; no title was provided."
    supplied_description = _escape_report_user_field(str(description).strip()) if description and str(description).strip() else "Unknown; no description was provided."
    supplied_confidence = _escape_report_user_field(str(observation_confidence).strip()) if observation_confidence and str(observation_confidence).strip() else "Unknown; no confidence context was provided."
    supplied_evidence = _escape_report_user_field(str(evidence).strip()) if evidence and str(evidence).strip() else "Unknown; no evidence was provided."
    supplied_context = _escape_report_user_field(str(testing_context).strip()) if testing_context and str(testing_context).strip() else "Unknown; no testing context was provided."
    remediation = _escape_report_user_field(str(remediation).strip()) if remediation and str(remediation).strip() else "Review the relevant behavior and choose a control only after the issue is verified."
    reported_target = _render_report_target(target)
    evidence_location = _escape_report_user_field(evidence_location)

    finding = f"""JARVIS POTENTIAL SECURITY FINDING
====================================

Target: {reported_target}
Date: {timestamp}

Title:
Unverified security observation
User-provided title (unverified): {supplied_title}

Description (user-provided; unverified):
{supplied_description}

Observation confidence:
Not independently assessed.
User-provided confidence text (unverified): {supplied_confidence}

Evidence location:
{evidence_location}

Evidence details (user-provided; not independently verified):
{supplied_evidence}

Evidence and confidence limitations:
JARVIS has not independently validated the supplied material. Missing details are marked Unknown.

Testing context:
{supplied_context}

JARVIS TRUSTED SEVERITY METADATA BEGIN
Severity assessment: Not assessed
Severity rationale: No severity is inferred from user-provided title, description, confidence, or evidence.
JARVIS TRUSTED SEVERITY METADATA END

Severity:
Not assessed; available information does not establish exploitability or impact.

Remediation:
Guidance only; verify the behavior before applying a fix:
{remediation}

Vulnerability status:
UNCONFIRMED; JARVIS has not independently validated this observation.

Status:
NEEDS HUMAN REVIEW

Important:
This is a user-provided observation recorded by JARVIS, not a verified conclusion.
It is NOT a confirmed vulnerability.
Verify the issue and its impact before submitting any report.
"""

    finding = _redact_potential_secrets(finding)
    finding_file.write_text(finding)

    print("JARVIS: Potential finding recorded.")
    print(f"JARVIS: Review file: {finding_file.name}")


def record_candidate(
    target, finding_type, severity, description, evidence,
    observation_confidence="Heuristic candidate; underlying behavior is unverified",
    testing_context="Unknown; no testing context was provided.",
    remediation=None,
    observed_evidence=None,
    evidence_source=None,
    evidence_endpoint=None,
    scanner_interpretation=None,
    validation_limitations=None,
    structured_test_result=None,
):

    if not check_scope(target):
        return

    REPORTS_DIR.mkdir(exist_ok=True)
    safe_target = _report_target_filename_component(target)
    candidate_stem = f"{safe_target}_candidate"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    remediation = remediation or _report_remediation(finding_type, description)
    evidence_location = _report_evidence_location(evidence)
    supplied_type = _escape_report_user_field(str(finding_type).strip()) if finding_type and str(finding_type).strip() else "Unknown; no finding type was provided."
    supplied_severity = _escape_report_user_field(str(severity).strip()) if severity and str(severity).strip() else "Unknown; no severity suggestion was provided."
    supplied_description = _escape_report_user_field(str(description).strip()) if description and str(description).strip() else "Unknown; no description was provided."
    supplied_evidence = _escape_report_user_field(str(evidence).strip()) if evidence and str(evidence).strip() else "Unknown; no evidence was provided."
    supplied_confidence = _escape_report_user_field(str(observation_confidence).strip()) if observation_confidence and str(observation_confidence).strip() else "Unknown; no confidence context was provided."
    supplied_context = _escape_report_user_field(str(testing_context).strip()) if testing_context and str(testing_context).strip() else "Unknown; no testing context was provided."
    remediation = _escape_report_user_field(str(remediation).strip()) if remediation and str(remediation).strip() else "Review the relevant behavior and choose a control only after the issue is verified."
    reported_target = _render_report_target(target)
    report_title, potential_impact = _candidate_report_title_and_impact(finding_type)
    evidence_location = _escape_report_user_field(evidence_location)
    if observed_evidence is None:
        evidence_section = (
            "Observed evidence:\n"
            "Unknown; no source-tagged direct observation was provided.\n\n"
            "Unverified information (caller-provided; not independently verified):\n"
            f"{supplied_evidence}"
        )
    else:
        observed_value = (
            _escape_report_user_field(str(observed_evidence).strip())
            if observed_evidence and str(observed_evidence).strip()
            else "Unknown; no observed evidence was provided."
        )
        source_value = (
            _escape_report_user_field(str(evidence_source).strip())
            if evidence_source and str(evidence_source).strip()
            else "Unknown; evidence source was not recorded."
        )
        endpoint_value = (
            _render_report_endpoint(evidence_endpoint)
            if evidence_endpoint
            else "Unknown; no endpoint was recorded."
        )
        evidence_section = (
            "Observed evidence (recorded observation; not independent validation):\n"
            f"Source: {source_value}\n"
            f"Endpoint: {endpoint_value}\n"
            f"{observed_value}"
        )
    scanner_interpretation = (
        _escape_report_user_field(str(scanner_interpretation).strip())
        if scanner_interpretation and str(scanner_interpretation).strip()
        else "Unknown; no scanner interpretation was recorded."
    )
    validation_limitations = (
        _escape_report_user_field(str(validation_limitations).strip())
        if validation_limitations and str(validation_limitations).strip()
        else "The candidate has not been independently validated; exploitability and impact remain unknown."
    )
    normalized_test_result = _normalize_structured_test_result(structured_test_result)
    structured_test_result_section = ""
    if normalized_test_result is not None:
        structured_test_result_section = (
            "JARVIS STRUCTURED TEST RESULT BEGIN\n"
            "Structured test result (JSON): "
            + json.dumps(normalized_test_result, sort_keys=True, ensure_ascii=True)
            + "\nJARVIS STRUCTURED TEST RESULT END\n\n"
        )

    report = f"""[+] Vulnerability candidate found
Type: Candidate category (unverified)
Title: {report_title}
Candidate type (unverified): {supplied_type}
Target: {reported_target}
Observation confidence: Not independently assessed.
Confidence note (unverified): {supplied_confidence}
Vulnerability status: UNCONFIRMED; no independent validation evidence is recorded.
JARVIS TRUSTED SEVERITY METADATA BEGIN
Severity assessment: Not assessed
Severity rationale: Available evidence does not establish exploitability or impact; the supplied suggestion is not adopted as a JARVIS assessment.
JARVIS TRUSTED SEVERITY METADATA END
Severity: Not assessed
Severity suggestion (unverified): {supplied_severity}
Potential bounty: Check program policy
Evidence: recorded below; not independently verified
Status: Requires manual verification

Candidate description (unverified):
{supplied_description}

{evidence_section}

Evidence location:
{evidence_location}

Evidence and confidence limitations:
JARVIS has not independently validated the supplied material. Missing details are marked Unknown.

Scanner interpretation (not directly observed):
{scanner_interpretation}

Validation limitations:
{validation_limitations}

{structured_test_result_section}Potential impact (conditional; not demonstrated):
{potential_impact}

Testing context:
{supplied_context}

Reproduction notes (recorded testing context only; no additional steps inferred):
{supplied_context}

Remediation:
Guidance only; verify the behavior before applying a fix:
{remediation}

Recorded: {timestamp}

Important: This is an unverified candidate, not a confirmed vulnerability.
Only submit findings that are within the program's authorized scope and rules.
"""

    report = _redact_potential_secrets(report)
    candidate_number = 1
    while True:
        suffix = "" if candidate_number == 1 else f"_{candidate_number}"
        finding_file = REPORTS_DIR / f"{candidate_stem}{suffix}.txt"
        try:
            with finding_file.open("x") as report_file:
                report_file.write(report)
            break
        except FileExistsError:
            candidate_number += 1

    print(report, end="")
    print(f"JARVIS: Candidate report saved to {finding_file.name}")
def check_bWAPP_session():
    response = None
    try:
        response = scoped_get(
            "http://127.0.0.1/bWAPP/",
            timeout=10,
        )

        if "login.php" not in response.url.lower():
            print("JARVIS: bWAPP session appears authenticated.")
            return True

        print("JARVIS: bWAPP session is not authenticated.")
        return False

    except requests.RequestException as e:
        print(
            "JARVIS: Could not check bWAPP session "
            f"({type(e).__name__})."
        )
        return False
    finally:
        if response is not None:
            response.close()
def set_session_cookie(cookie):
    cookie = cookie.strip()

    if "=" not in cookie:
        print("JARVIS: Expected format NAME=VALUE")
        return

    name, value = cookie.split("=", 1)

    session.cookies.set(
        name.strip(),
        value.strip(),
        domain="127.0.0.1",
        path="/bWAPP/"
    )

    print(f"JARVIS: Session cookie '{name.strip()}' loaded.")
def show_help():

    print("""
JARVIS: Available commands:

  status
      Check JARVIS status.

  scope
      Show authorized targets.

  check <target>
      Check whether a target is authorized.

  info <target>
      Gather basic web information from an authorized target.

  audit <target> [--active] [--request-budget N]
      Run a bounded passive inventory; --active opts into reflection probes.
      Request budget applies to all audit requests and redirect hops (max 100).

    finding <target> <title> | <description> | <evidence>
      Record a potential security finding with evidence.

  candidate <target> <type> | <severity> | <description> | <evidence>
      Save and display a structured, unverified vulnerability candidate.

  session <cookie>
      Load a bWAPP session cookie.

  session-check
      Check whether the bWAPP session is authenticated.

  reports
      List saved reports.

  summary
      Summarize saved findings without rerunning analysis.

  review-queue
      Queue saved reports for manual review by evidence completeness.

  review-note
      Record a reviewer note separately from a saved report.

  validation-note
      Record a structured manual status and evidence without editing the report.

  review-notes
      Read and inspect saved reviewer notes without changing any files.

  review-progress
      Summarize saved-report review coverage without changing files.

  hackerone-review
      Print the draft manual policy checklist; this does not authorize testing.

  view <filename>
      Display a saved report.
  php-summary <directory>
      Summarize categorized PHP training pages.

  php-report <directory>
      Generate a consolidated PHP review report.

  php-scan <directory>
      Scan PHP files for GET/POST/REQUEST inputs.

  js-flow <file.js|file.mjs|file.cjs>
      Analyze a local JavaScript file as text; this command makes no requests.

  help
      Show this help message.

  exit
      Quit JARVIS.
""")


print("JARVIS is online.")
print("Type 'help' to see commands or 'exit' to quit.")

while True:

    try:
        command = input("You: ").strip()
    except EOFError:
        print("JARVIS: Input closed; exiting.")
        break

    if not command:
        continue

    parts = command.split(maxsplit=2)

    action = parts[0].lower()

    if action == "exit":

        print("JARVIS: Goodbye.")
        break

    elif action == "help":

        show_help()

    elif action == "status":

        print("JARVIS: All systems operational.")

    elif action == "scope":

        show_scope()

    elif action == "check":

        if len(parts) < 2:
            print("JARVIS: Usage: check <target>")
        else:
            check_scope(parts[1])

    elif action == "info":

        if len(parts) < 2:
            print("JARVIS: Usage: info <target>")
        else:
            get_info(parts[1])

    elif action == "audit":

        if len(parts) < 2:
            print("JARVIS: Usage: audit <target> [--active] [--request-budget N]")
        else:
            try:
                active_checks, request_budget = _parse_audit_options(
                    parts[2] if len(parts) > 2 else ""
                )
            except ValueError as error:
                print(f"JARVIS: Invalid audit options: {error}")
            else:
                audit_target(
                    parts[1],
                    active_checks=active_checks,
                    request_budget=request_budget,
                )

    elif action == "finding":

        if len(parts) < 3:
            print(
                "JARVIS: Usage: "
                "finding <target> <title> | <description> | <evidence>"
            )
        else:

            target = parts[1]
            finding_text = parts[2]

            fields = finding_text.split("|", 2)

            if len(fields) == 3:

                title = fields[0].strip()
                description = fields[1].strip()
                evidence = fields[2].strip()

                record_finding(
                    target,
                    title,
                    description,
                    evidence,
                    testing_context="User-entered finding command; JARVIS did not independently validate the supplied evidence.",
                )

            else:

                print(
                    "JARVIS: Provide title, description, "
                    "and evidence separated by |"
                )

    elif action == "candidate":

        if len(parts) < 3:
            print(
                "JARVIS: Usage: candidate <target> <type> | "
                "<severity> | <description> | <evidence>"
            )
        else:
            target = parts[1]
            fields = [field.strip() for field in parts[2].split("|", 3)]

            if len(fields) == 4 and all(fields):
                finding_type, severity, description, evidence = fields
                record_candidate(
                    target, finding_type, severity, description, evidence,
                    observation_confidence="User-entered candidate; underlying observation is unverified",
                    testing_context="User-entered candidate command; JARVIS did not independently validate the supplied evidence.",
                )
            else:
                print(
                    "JARVIS: Provide type, severity, description, "
                    "and evidence separated by |"
                )

    elif action == "php-inspect":

        if len(parts) < 2:
            print("JARVIS: Usage: php-inspect <file>")
        else:
            inspect_php_inputs(parts[1])
    elif action == "php-summary":
        if len(parts) < 2:
            print("JARVIS: Usage: php-summary <directory>")
        else:
            php_summary(parts[1])

    elif action == "php-review":
        php_review_checklist()

    elif action == "php-report":
        if len(parts) < 2:
            print("JARVIS: Usage: php-report <directory>")
        else:
            php_report(parts[1])

    elif action == "php-flow":
        if len(parts) < 2:
            print("JARVIS: Usage: php-flow <file>")
        else:
            analyze_php_flow(parts[1])

    elif action == "js-flow":
        if len(parts) < 2:
            print("JARVIS: Usage: js-flow <file.js|file.mjs|file.cjs>")
        else:
            analyze_js_flow(parts[1])

    elif action == "php-scan":
        if len(parts) < 2:
            print("JARVIS: Usage: php-scan <directory>")
        else:
            scan_php_inputs(parts[1])

    elif action == "session":

        if len(parts) < 2:
            print("JARVIS: Usage: session <cookie>")
        else:
            set_session_cookie(parts[1])

    elif action == "session-check":

        check_bWAPP_session()

    elif action == "reports":

        list_reports()
    elif action == "summary":

        show_findings_summary()
    elif action == "review-queue":

        show_review_queue()
    elif action == "review-note":

        review_note_workflow(REPORTS_DIR)
    elif action == "validation-note":

        validation_note_workflow(REPORTS_DIR)
    elif action == "review-notes":

        review_notes_workflow(REPORTS_DIR)
    elif action == "review-progress":

        show_review_progress()
    elif action == "hackerone-review":
        hackerone_policy_review_checklist()
    elif action == "view":
        if len(parts) < 2:
            print("JARVIS: Usage: view <filename>")
        else:
            view_report(parts[1])

    else:

                print("JARVIS: I don't recognize that command yet.")
