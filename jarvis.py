
from html import unescape
from types import SimpleNamespace
from urllib.parse import quote, quote_from_bytes, unquote, urljoin, urlparse, urlsplit, urlunsplit
import hashlib
import ipaddress
import secrets
import requests

session = requests.Session()
session.headers.update({
    "User-Agent": "JARVIS-Lab-Assistant/1.0"
})
from pathlib import Path
import re
import json
from datetime import datetime


SCOPE_FILE = Path("scope.txt")
REPORTS_DIR = Path("reports")
DEFAULT_AUDIT_REQUEST_BUDGET = 25
MAX_AUDIT_REQUEST_BUDGET = 100
_ACTIVE_AUDIT_REQUEST_BUDGET = None
_REPORT_DISPLAY_ALIASES = {}


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


def scoped_get(url, **kwargs):
    if not check_scope(url, announce=False):
        raise requests.RequestException(
            f"Request blocked outside authorized scope: {url}"
        )

    kwargs["allow_redirects"] = False
    redirects = 0
    max_redirects = getattr(session, "max_redirects", 30)

    while True:
        budget = _ACTIVE_AUDIT_REQUEST_BUDGET
        if budget is not None:
            if budget["used"] >= budget["limit"]:
                budget["exhausted"] = True
                raise requests.RequestException("Audit request budget exhausted")
            budget["used"] += 1
        response = session.get(url, **kwargs)

        if not response.is_redirect:
            return response

        location = response.headers.get("Location")
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
                f"Redirect blocked outside authorized scope: {redirect_url}"
            )

        if redirects >= max_redirects:
            response.close()
            raise requests.TooManyRedirects(
                f"Exceeded {max_redirects} redirects", response=response
            )

        response.close()
        url = redirect_url
        redirects += 1


def _get_audit_page_data(url, response_cache):
    """Return a per-audit response snapshot keyed by the exact requested URL."""
    if not check_scope(url, announce=False):
        raise requests.RequestException(
            f"Request blocked outside authorized scope: {url}"
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
        page_data = SimpleNamespace(
            requested_url=url,
            final_url=response.url,
            url=response.url,
            status_code=response.status_code,
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

    if not targets:
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
            if marker in response.text:
                safe_parameter = _safe_report_parameter_name(parameter)
                print(f"  [POTENTIAL] Parameter '{safe_parameter}' is reflected in the response.")

                record_candidate(
                    url,
                    "Reflected Input",
                    "Potential",
                    f"Parameter '{parameter}' reflected the harmless JARVIS test marker.",
                    f"Marker: {marker}\nTest URL: {_render_report_endpoint(response.url)}\n"
                    f"HTTP status: {response.status_code}\n"
                    f"Observation: marker appeared in response text; output context and browser execution were not assessed.",
                    observation_confidence="Confirmed observation: test marker appeared in response text",
                    testing_context=(
                        f"GET parameter: {parameter}; harmless marker only; "
                        "no exploit payload sent."
                    ),
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
                report.append(f"  Not analyzed: {safe_issue_url} — {safe_reason}")

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
                    "Potential Critical",
                    f"JARVIS identified an input that may require deeper security review: {item}",
                    f"Target URL: {url}\nParameter: {item}\n"
                    "Evidence basis: parameter name classification only.",
                    observation_confidence="Heuristic candidate: parameter-name match",
                    testing_context="Observed during authorized-scope page/form inventory; no exploit payload sent.",
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

        if sql_review_parameters:
            for method, name, endpoint_url in sql_review_parameters:
                print(
                    f"  [POTENTIAL] {_safe_report_parameter_name(method)} parameter "
                    f"'{_safe_report_parameter_name(name)}' "
                    "may reach database query logic."
                )

                endpoint_evidence = (
                    f"Discovered GET endpoint (variant {report_endpoint_variants.get(endpoint_url, 'unknown')}): "
                    f"{_render_report_endpoint(endpoint_url)}\n"
                    if method == "GET" and endpoint_url
                    else "Source: local form inventory; endpoint provenance was not retained.\n"
                )

                record_candidate(
                    url,
                    "SQL Injection",
                    "Potential High",
                    f"Parameter '{name}' is a plausible database-query input.",
                    f"Method: {method}\nParameter: {name}\n"
                    + endpoint_evidence
                    + "Evidence basis: parameter-name match only; query handling was not observed.\n"
                    + "No exploit payload was sent; manual verification required.",
                    observation_confidence="Heuristic candidate: parameter-name match",
                    testing_context=f"{method} parameter found in authorized-scope page/form inventory; no exploit payload sent.",
                )
        else:
            print("  None")
        if active_checks:
            print(f"Active Reflection Checks (request budget: {request_budget}):")
            report.append(
                f"Active Reflection Checks: opted in; request budget {request_budget}."
            )
            for item in parameters:
                if item["method"] == "GET":
                    check_reflection(item["url"], item["name"], enabled=True)
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

                record_finding(
                    url,
                    f"Input Review Area - {safe_area}",
                    f"JARVIS identified an input requiring manual review: {safe_area}",
                    f"Target URL: {_render_report_endpoint(url)}\nReview area: {safe_area}",
                    observation_confidence="Heuristic review area based on discovered parameter metadata",
                    testing_context=f"Authorized-scope audit of {url}; input discovery only, no exploit payload sent.",
                )
        else:
            print("  None")

        report.append("Review Areas:")
        if review_areas:
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
        controls.append({
            "kind": kind,
            "type": attributes.get("type", "text"),
            "name": attributes.get("name", ""),
            "disabled": disabled,
            "option_count": len(re.findall(r"<option\b", body, re.I)),
            "multiple": kind == "Select" and bool(
                re.search(r"(?:^|\s)multiple(?:\s|=|/|$)", attribute_text, re.I)
            ),
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

    print(f"\nJARVIS: PHP input analysis — {path.name}")

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


def _trace_php_flow(path, source, reports_dir):
    """Trace only explicit request references and supported local assignments."""
    root = path.resolve().parent
    root_file = path.resolve()
    input_pattern = re.compile(r"\$_(GET|POST|REQUEST)\s*\[\s*['\"]([^'\"]+)['\"]\s*\]")
    presence_ternary_pattern = re.compile(
        r"^isset\s*\(\s*\$_(GET|POST|REQUEST)\s*\[\s*(['\"])([^'\"]+)\2\s*\]\s*\)\s*\?\s*1\s*:\s*0$",
        re.I,
    )
    assignment_pattern = re.compile(r"^\s*\$(\w+)\s*(=|\.=)\s*(.*?)\s*;\s*$")
    variable_pattern = re.compile(r"\$(\w+)")
    include_pattern = re.compile(r"^\s*(include_once|include|require_once|require)\s*(?:\(\s*)?(.+?)\s*\)?\s*;\s*$")
    origins, edges, inputs, conditional_inputs, presence_inputs = {}, {}, [], [], []
    unresolved_request_inputs, includes, sinks, sink_observations, unresolved = [], [], [], [], []
    invalidated = {}
    function_definition_diagnostics_seen = set()
    function_call_diagnostics_seen = set()
    function_expression_diagnostics_seen = set()
    source_lines_by_file = {}
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
            result = re.fullmatch(r"\s*return\s+\$(\w+)\s*;\s*", body_text)
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
        if return_source in params:
            parameter = return_source
        elif return_source in aliases:
            parameter = aliases[return_source]
        else:
            return reject("return value is not a supported parameter or alias", returned[0][0], f"return ${return_source};")
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
            "return_variable": return_source,
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
                returned_argument_index = summary["params"].index(summary["parameter"])
                if returned_argument_index >= len(arguments):
                    reason = "return value depends on an optional parameter that was omitted"
                    unresolved_calls.append((name, file, call_line, reason, call_column, call["kind"]))
                    for method, key in input_pattern.findall(raw_arguments):
                        unresolved_refs.append((method, key, file, number, expression))
                    for index in range(call["start"], call["end"]):
                        base_chars[index] = " "
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

    def trace_sink_expression(line, code_line, file, number, sink_type, conditional=False):
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
            lines = file.read_text(errors="ignore").splitlines()
        except OSError:
            active.pop()
            return
        source_lines_by_file[file] = lines
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
            if number in function_ranges.get(file, set()):
                continue
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
                }
                depth += 1
                continue

            if conditional_frame is not None:
                frame = conditional_frame
                if frame["opening_brace_line"] == line_index and text == "{":
                    frame["opening_brace_line"] = None
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
                if nested_control or frame["depth"] > 1:
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
                            if call_records:
                                chain.append(("function-assignment", file, number, dest))
                            for method, key in direct:
                                record = (method, key, file, number)
                                records.append(record)
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
                                line, code_line, file, number, sink_type, conditional=True
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

    visit(root_file)

    def source_is_entry(record):
        return record[2].resolve() == root_file

    report = [
        f"JARVIS: PHP source-flow analysis — {path.name}", "=" * 50, "",
        "Input evidence:",
    ]
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
        for method, key, file, number, text in entry_presence_inputs:
            report.extend([
                f"  Presence check: [{method}] {key}",
                f"    {report_path(file)}:{number}: {text} (parameter presence checked; submitted value not assigned).",
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
        "", "Source-flow evidence:",
        "  Supported source-to-sink evidence is static tracing evidence, not vulnerability confirmation.",
    ])
    confirmed = False
    unconditional_confirmed = False
    for file, number, text, sink_type, direct, tracked, invalidated_refs, conditional_flow, flow_snapshot, invalidated_snapshot in sinks:
        report.append(f"  Sink text ({sink_type}) at {report_path(file)}:{number}: {text}")
        records = [(m, k, file, number) for m, k in direct]
        associated_variables = {}
        for variable, variable_records, _ in flow_snapshot:
            records.extend(variable_records)
            for record in variable_records:
                associated_variables.setdefault(record, set()).add(variable)
        for method, key, source_file, source_line in dict.fromkeys(records):
            relationship = "Conditional textual relationship" if conditional_flow else "Explicit textual relationship"
            report.append(f"    {relationship}: [{method}] {key} at {report_path(source_file)}:{source_line} reaches a referenced variable or appears directly in the sink at {report_path(file)}:{number}.")
            variables = associated_variables.get((method, key, source_file, source_line))
            if variables:
                variable_names = ", ".join(f"${variable}" for variable in sorted(variables))
                report.append(f"      Tracked-variable association: {variable_names}.")
            confirmed = True
            if not conditional_flow:
                unconditional_confirmed = True
        for variable, _, variable_edges in flow_snapshot:
            for edge in variable_edges:
                if edge and edge[0] == "function-assignment":
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
                else:
                    edge_file, edge_line, source, dest = edge
                    report.append(f"    Assignment evidence: {report_path(edge_file)}:{edge_line} ${dest} references ${source}.")
        for variable in invalidated_refs:
            invalid_file, invalid_line = invalidated_snapshot[variable]
            report.append(
                f"    Unresolved relationship: ${variable} appears at this sink, but its earlier request provenance was invalidated by reassignment at {report_path(invalid_file)}:{invalid_line}; no source-to-sink link is asserted."
            )
    if not confirmed:
        report.append("  No supported source-to-sink relationship established.")
    report.extend(["", "Local function analysis:", "  Only unique, straight-line parameter aliases with one direct return and trailing literal optional defaults are summarized.", "  Function names do not establish sanitization or vulnerability status.", "  Unknown function behavior and sanitization effectiveness are not inferred.", "", "Included-file analysis:"])
    report.extend(includes or ["  No supported include statements detected."])
    report.extend(["", "Unresolved analysis candidates:"])
    report.extend(unresolved or ["  None detected."])
    report.extend([
        "", "Evidence and confidence limitations:",
        "  Static source review only; runtime behavior was not validated.",
        "  Unsupported syntax and ambiguous paths remain unresolved.",
    ])
    status = (
        "CONDITIONAL SOURCE PATTERNS; FLOW NOT ESTABLISHED"
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
        status = f"ANALYSIS INCOMPLETE — {status}"
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
    text = "\n".join(report)
    print("\n" + text)
    reports_dir.mkdir(exist_ok=True)
    safe_name = re.sub(r"[^a-zA-Z0-9_-]+", "_", path.stem).strip("_").lower()
    report_file = reports_dir / f"{safe_name}_php_flow.txt"
    report_file.write_text(text + "\n")
    print(f"\nJARVIS: PHP flow evidence saved to {report_file}")


def analyze_php_flow(file_path):
    path = Path(file_path)

    if not path.exists() or path.suffix.lower() != ".php":
        print("JARVIS: PHP file not found.")
        return

    try:
        source = path.read_text(errors="ignore")
    except OSError as e:
        print(f"JARVIS: Could not read PHP file: {e}")
        return

    return _trace_php_flow(path, source, REPORTS_DIR)


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

def get_info(target):

    if not check_scope(target):
        return

    url = get_url(target)

    print("\nJARVIS WEB INFORMATION REPORT")
    print("================================\n")

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

    def add_record(kind, report_name, file_name=None, line_number=None, evidence=""):
        excerpt = " ".join(str(evidence).split()) or "Unknown; no evidence excerpt was recorded."
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

        lines = text.splitlines()
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
            header_match = re.match(r"JARVIS: PHP source-flow analysis\s*[—-]\s*(.+)", first_line)
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
        report_titles.append((report_name, title or "Unknown"))

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
        validation_evidence = []
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
                    remediation_guidance.append((report_name, stripped))
                    in_recommendation = True

            if stripped.startswith("Vulnerability status:"):
                vulnerability_value = stripped.split(":", 1)[1].strip()
            elif vulnerability_value and not stripped and not in_validation:
                vulnerability_value = vulnerability_value
            elif stripped.startswith("Independent validation evidence:"):
                in_validation = True
                value = stripped.split(":", 1)[1].strip()
                if value:
                    validation_evidence.append(value)
                continue
            elif in_validation:
                if not stripped:
                    in_validation = False
                elif not lower.startswith(("unknown", "none", "not provided", "n/a")):
                    validation_evidence.append(stripped)
                continue

            if line_index in trusted_severity_lines and stripped.startswith("Severity assessment:"):
                severity_assessment = stripped.split(":", 1)[1].strip()
            elif line_index in trusted_severity_lines and stripped.startswith("Severity rationale:"):
                severity_rationale = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("User-provided severity suggestion (unverified):"):
                severity_suggestion = stripped.split(":", 1)[1].strip() or "Unknown"
            elif stripped.startswith("Potential severity:"):
                severity_suggestion = stripped.split(":", 1)[1].strip() or "Unknown"
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
            elif stripped in {"NO INPUT DETECTED", "INPUT DETECTED", "SOURCE FLOW DETECTED"} or stripped.startswith("ANALYSIS INCOMPLETE — "):
                has_explicit_input_status = True
                analysis_statements.append((report_name, f"Saved analysis status: {stripped}; this is not vulnerability confirmation."))

            if stripped in {
                "Input evidence:",
                "Unresolved conditional input evidence:",
                "Request presence evidence:",
                "Unresolved request-reference evidence:",
                "Included-file input observations:",
                "Included-file analysis:",
                "Sink observations:",
                "Source-flow evidence:",
                "Unresolved analysis candidates:",
                "Evidence details:",
                "Evidence:",
                "Query-flow evidence:",
                "Data-flow verification:",
                "XSS output flow:",
            } or stripped.startswith("Evidence details ("):
                section = stripped.rstrip(":")
                if section.startswith("Evidence details") or (section == "Evidence" and is_finding):
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
                        header_match = re.match(r"JARVIS: PHP source-flow analysis\s*[—-]\s*(.+)", first_line)
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
                            header_match = re.match(r"JARVIS: PHP source-flow analysis\s*[—-]\s*(.+)", first_line)
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
                        header_match = re.match(r"JARVIS: PHP source-flow analysis\s*[—-]\s*(.+)", first_line)
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
                header_match = re.match(r"JARVIS: PHP source-flow analysis\s*[—-]\s*(.+)", first_line)
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

            if section == "XSS output flow" and re.search(r"\[\s*(GET|POST|REQUEST)\s*\].*→.*→", stripped, re.I):
                add_record("Legacy reported source-to-sink claim (unverified)", report_name, None, None, stripped)
                report_has_evidence = True

            if is_web_report and stripped.startswith("[MISSING]"):
                add_record("Observed web security-header pattern", report_name, None, None, stripped)
                report_has_evidence = True

            if is_web_report and re.match(r"(?:Content-Security-Policy|X-Content-Type-Options|X-Frame-Options|Strict-Transport-Security):\s*MISSING", stripped, re.I):
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
                "User-provided finding evidence" if is_finding else "User-provided candidate evidence",
                report_name,
                file_name,
                line_number,
                evidence or "Unknown; no evidence was recorded.",
            )
            report_has_evidence = report_has_evidence or bool(evidence and not evidence.lower().startswith("unknown"))
            report_has_location = report_has_location or bool(file_name)

        status_value = vulnerability_value.lower()
        validation_text = " ".join(validation_evidence)
        validation_is_negative = bool(re.search(
            r"\b(?:not|no|never|unable|cannot|can't|couldn't|failed|inconclusive|pending|unknown|none|n/?a)\b",
            validation_text,
            re.I,
        ))
        validation_has_action = bool(re.search(
            r"\b(?:retest|test(?:ed|ing)?|replay(?:ed)?|sent|submitted|request(?:ed)?|payload)\b",
            validation_text,
            re.I,
        ))
        validation_has_observed_result = bool(re.search(
            r"\b(?:(?:observed|reproduced|demonstrated|returned|accessed|retrieved|executed|exploited|exposed)\s+(?:the\s+|a\s+|an\s+)?[\w'$\"-]+|[\w'$\"-]+\s+(?:observed|reproduced|demonstrated|returned|accessed|retrieved|executed|exploited|exposed)|resulted\s+in\s+(?:the\s+|a\s+|an\s+)?[\w'$\"-]+)\b",
            validation_text,
            re.I,
        ))
        validation_tokens = set(re.findall(r"[a-z0-9_$'-]+", validation_text.lower()))
        validation_boilerplate = {
            "authorized", "independent", "validation", "evidence", "expected",
            "the", "a", "an", "and", "or", "was", "were", "is", "are",
            "been", "being", "then", "before", "after", "it", "this", "that",
            "these", "those", "recorded", "record", "verified", "confirmed",
            "retest", "test", "testing", "tested", "replay", "replayed",
            "sent", "submitted", "request", "requested", "payload", "observed",
            "reproduced", "demonstrated", "returned", "accessed", "retrieved",
            "executed", "exploited", "exposed", "resulted", "in",
            "http", "https", "response", "status", "request",
        }
        validation_has_result_detail = bool(
            validation_tokens - validation_boilerplate
        )
        validation_is_affirmative = (
            validation_has_action
            and validation_has_observed_result
            and validation_has_result_detail
        )
        explicit_confirmed = bool(
            is_finding
            and
            re.match(r"^confirmed(?:\b|[:;])", status_value)
            and validation_evidence
            and not any(is_placeholder_text(item) for item in validation_evidence)
            and not validation_is_negative
            and validation_is_affirmative
        )
        status = (
            "CONFIRMED (as recorded) — not independently verified by this summary"
            if explicit_confirmed else "UNCONFIRMED"
        )
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
    output.extend(["", "Evidence completeness:"])
    if completeness:
        output.extend(f"  {name}: {label}" for name, label in completeness)
    else:
        output.append("  No reports available; evidence is Unknown.")
    output.extend(["", "Manual-review priority (evidence completeness, not severity):"])
    if review_priorities:
        output.extend(f"  {name}: {priority} — {reason}" for name, priority, reason in review_priorities)
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
        "  Open each source report with 'view <filename>', verify the cited source-to-sink path and impact in authorized context, and record any independent validation evidence separately.",
    ])
    return "\n".join(output)


def show_findings_summary():
    print(_build_findings_summary(REPORTS_DIR))


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
            rf"(?m)^\s+{re.escape(report_name)}: (High|Medium|Low) — (.+)$",
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
            rf"(?m)^\s+{re.escape(report_name)}: Saved analysis status: (ANALYSIS INCOMPLETE — .+?); this is not vulnerability confirmation\.$",
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
        return "\n".join(output)

    for item in queue_items:
        output.extend([
            "",
            f"{item['name']}",
            f"  Priority: {item['priority']} — {item['rationale']}",
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
    return "\n".join(output)


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
            rf"(?m)^\s+{re.escape(report_name)}: (High|Medium|Low) —",
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
        return "\n".join(output)

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
    return "\n".join(output)


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


def _save_review_note(reports_dir, selection, conclusion, evidence, uncertainties):
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
        evidence_summary = " ".join(note["supporting_evidence"].split())
        if len(evidence_summary) > 120:
            evidence_summary = evidence_summary[:117] + "..."
        orphaned_label = (
            " | ORPHANED: referenced report is missing"
            if note["report_filename"] not in report_names else ""
        )
        print(f"  {index}. {note['report_filename']} | {note['reviewed_at']} | "
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
        print(f"Review note {index} for {note['report_filename']}")
        if note["report_filename"] not in report_names:
            print("Report availability: ORPHANED; referenced report is missing.")
        print(f"Reviewed at: {note['reviewed_at']}")
        print("Reviewer-provided conclusion (not independently verified by JARVIS): "
              f"{note['reviewer_conclusion']}")
        print(f"Supporting evidence: {note['supporting_evidence']}")
        print(f"Remaining uncertainties: {note['remaining_uncertainties']}")
    print("Automated report content and vulnerability status were not read or changed.")


def _report_display_entries():
    """Return stable, safe aliases for report files contained in REPORTS_DIR."""
    global _REPORT_DISPLAY_ALIASES
    reports_directory = REPORTS_DIR
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

    print("\nJARVIS REPORT VIEWER — saved text is displayed as untrusted content")
    print("====================================================================\n")
    print(_safe_report_display_text(report_text))


def _report_remediation(finding_type, description=""):
    kind = f"{finding_type} {description}".lower()
    if "sql" in kind:
        return "If query construction from untrusted input is confirmed, use parameterized queries and validate input according to its expected type. Verify the relevant code path first."
    if "xss" in kind or "reflect" in kind or "output" in kind:
        return "If untrusted data is confirmed to reach this rendering context, apply context-appropriate output encoding. Confirm the rendered context before selecting an encoding strategy."
    if "access" in kind or "authorization" in kind or "idor" in kind:
        return "If an authorization gap is confirmed, enforce server-side authorization for each requested object or action and verify controls with an authorized test account."
    if "header" in kind:
        return "If the header behavior is confirmed to be unintended, configure it according to the application's requirements and deployment needs."
    return "Review the cited input, processing, and output path. Apply a control appropriate to verified behavior, then retest locally or within authorized scope."


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

    finding_file.write_text(finding)

    print("JARVIS: Potential finding recorded.")
    print(f"JARVIS: Review file: {finding_file.name}")


def record_candidate(
    target, finding_type, severity, description, evidence,
    observation_confidence="Heuristic candidate; underlying behavior is unverified",
    testing_context="Unknown; no testing context was provided.",
    remediation=None,
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
    evidence_location = _escape_report_user_field(evidence_location)

    report = f"""[+] Vulnerability candidate found
Type: User-provided category (unverified)
Title: Unverified security candidate
User-provided type (unverified): {supplied_type}
Target: {reported_target}
Observation confidence: Not independently assessed.
User-provided confidence text (unverified): {supplied_confidence}
Vulnerability status: UNCONFIRMED; no independent validation evidence is recorded.
JARVIS TRUSTED SEVERITY METADATA BEGIN
Severity assessment: Not assessed
Severity rationale: Available evidence does not establish exploitability or impact; the supplied suggestion is not adopted as a JARVIS assessment.
JARVIS TRUSTED SEVERITY METADATA END
Severity: Not assessed
User-provided severity suggestion (unverified): {supplied_severity}
Potential bounty: Check program policy
Evidence: recorded below; not independently verified
Status: Requires manual verification

Description (user-provided; unverified):
{supplied_description}

Evidence details (user-provided; not independently verified):
{supplied_evidence}

Evidence location:
{evidence_location}

Evidence and confidence limitations:
JARVIS has not independently validated the supplied material. Missing details are marked Unknown.

Testing context:
{supplied_context}

Remediation:
Guidance only; verify the behavior before applying a fix:
{remediation}

Recorded: {timestamp}

Important: This is an unverified candidate, not a confirmed vulnerability.
Only submit findings that are within the program's authorized scope and rules.
"""

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
        print(f"JARVIS: Could not check bWAPP session: {e}")
        return False
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
        path="/"
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

  review-notes
      Read and inspect saved reviewer notes without changing any files.

  review-progress
      Summarize saved-report review coverage without changing files.

  view <filename>
      Display a saved report.
  php-summary <directory>
      Summarize categorized PHP training pages.

  php-report <directory>
      Generate a consolidated PHP review report.

  php-scan <directory>
      Scan PHP files for GET/POST/REQUEST inputs.

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
    elif action == "review-notes":

        review_notes_workflow(REPORTS_DIR)
    elif action == "review-progress":

        show_review_progress()
    elif action == "view":
        if len(parts) < 2:
            print("JARVIS: Usage: view <filename>")
        else:
            view_report(parts[1])

    else:

                print("JARVIS: I don't recognize that command yet.")
