
#!/usr/bin/env python3
"""Split ModSecurity v3 JSON audit log entries into one flat JSON line per
matched rule, for ingestion by the Wazuh agent.

Usage:
  modsec-wazuh-split.py INPUT OUTPUT [--from-start] [--once]

  INPUT         ModSecurity JSON audit log (SecAuditLogFormat JSON, Serial)
  OUTPUT        File to append to, or "-" for stdout
  --from-start  Read INPUT from the beginning (default: only new entries)
  --once        Process what is in INPUT now, then exit (for testing)

Each output line carries Wazuh's standard fields at the top level, following
Wazuh's web access log convention: srcip, srcport, dstip, dstport,
protocol (HTTP method), url (path + query), id (HTTP status code) and
action ("blocked" or "detected"). Everything else is under "modsec"
(rule match, request incl. scheme and full URL, response).

Request/response headers and bodies are included when the audit log has
them (SecAuditLogParts B/C for the request, F/E for the response).
Authorization and cookie headers are redacted.
"""
import argparse
import json
import os
import sys
import time

# CRS rule ID prefix (first 3 digits = rule file) -> category
CATEGORIES = {
    "901": "initialization",
    "905": "common-exceptions",
    "911": "method-enforcement",
    "913": "scanner-detection",
    "920": "protocol-enforcement",
    "921": "protocol-attack",
    "922": "multipart-attack",
    "930": "lfi",
    "931": "rfi",
    "932": "rce",
    "933": "php",
    "934": "generic",
    "941": "xss",
    "942": "sqli",
    "943": "session-fixation",
    "944": "java",
    "949": "inbound-anomaly",
    "950": "data-leakage",
    "951": "data-leakage-sql",
    "952": "data-leakage-java",
    "953": "data-leakage-php",
    "954": "data-leakage-iis",
    "955": "web-shell",
    "959": "outbound-anomaly",
    "980": "correlation",
}

# Scheme by the port NGINX received the request on (this WAF: 443 TLS, 80 redirect)
SCHEMES = {"443": "https", "80": "http"}

SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie"}

MAX_FIELD = 1024             # single values (URI, message, matched data)
MAX_HEADERS = 4096           # all headers of a request or response, as text
MAX_BODY = 2048              # request or response body
# Together these keep each event well under Wazuh's ~64 KB limit.

MAX_LINE = 10 * 1024 * 1024  # drop runaway lines without a newline
POLL = 0.5


def trunc(value, limit=MAX_FIELD):
    s = "" if value is None else str(value)
    return s if len(s) <= limit else s[:limit] + "...[truncated]"


def header(headers, name):
    for key, value in (headers or {}).items():
        if key.lower() == name:
            return value
    return ""


def headers_text(headers):
    """All headers as one 'Name: value' text block, secrets redacted.

    One text field rather than one field per header: header names are chosen
    by the client, and indexing each as its own field would let anyone
    create unlimited fields in the Wazuh indexer.
    """
    lines = []
    for key, value in (headers or {}).items():
        if str(key).lower() in SENSITIVE_HEADERS:
            value = "[redacted]"
        lines.append(f"{key}: {value}")
    return trunc("\n".join(lines), MAX_HEADERS)


def split(entry):
    """Yield one flat event per message in a ModSecurity transaction."""
    t = entry.get("transaction") or {}
    req = t.get("request") or {}
    resp = t.get("response") or {}
    prod = t.get("producer") or {}
    msgs = t.get("messages") or []
    req_headers = req.get("headers") or {}
    resp_headers = resp.get("headers") or {}

    dstport = str(t.get("host_port", ""))
    scheme = SCHEMES.get(dstport, "")
    host = str(header(req_headers, "host"))
    uri = str(req.get("uri", ""))
    if scheme and host:
        full_url = f"{scheme}://{host}{uri}"
    else:
        full_url = host + uri

    http_code = str(resp.get("http_code", ""))
    engine = str(prod.get("secrules_engine", ""))
    # Blocked = engine in blocking mode and ModSecurity returned its 403
    action = "blocked" if engine == "Enabled" and http_code == "403" else "detected"

    base = {
        "srcip": str(t.get("client_ip", "")),
        "srcport": str(t.get("client_port", "")),
        "dstip": str(t.get("host_ip", "")),
        "dstport": dstport,
        "protocol": str(req.get("method", "")),
        "url": trunc(uri),
        "id": http_code,
        "action": action,
    }
    request = {
        "scheme": scheme,
        "full_url": trunc(full_url),
        "http_version": str(req.get("http_version", "")),
        "host": trunc(host, 256),
        "user_agent": trunc(header(req_headers, "user-agent"), 256),
        "referer": trunc(header(req_headers, "referer"), 256),
        "content_type": trunc(header(req_headers, "content-type"), 256),
        "headers": headers_text(req_headers),
        "body": trunc(req.get("body", ""), MAX_BODY),
    }
    response = {
        "http_code": http_code,
        "content_type": trunc(header(resp_headers, "content-type"), 256),
        "headers": headers_text(resp_headers),
        "body": trunc(resp.get("body", ""), MAX_BODY),
    }
    context = {
        "unique_id": str(t.get("unique_id", "")),
        "time_stamp": str(t.get("time_stamp", "")),
        "engine": engine,
    }

    for index, msg in enumerate(msgs):
        details = msg.get("details") or {}
        rule_id = str(details.get("ruleId", ""))
        tags = [str(x) for x in (details.get("tags") or [])]
        paranoia = next((x.split("/", 1)[1] for x in tags
                         if x.startswith("paranoia-level/")), "")
        event = dict(base)
        event["modsec"] = dict(
            context,
            rule_id=rule_id,
            category=CATEGORIES.get(rule_id[:3], "other"),
            msg=trunc(msg.get("message", "")),
            data=trunc(details.get("data", "")),
            severity=str(details.get("severity", "")),
            tags=",".join(tags),
            paranoia_level=paranoia,
            crs_version=str(details.get("ver", "")),
            rule_file=os.path.basename(str(details.get("file", ""))),
            match_index=index + 1,
            match_count=len(msgs),
            request=request,
            response=response,
        )
        yield event


def follow(path, from_start, once):
    """Yield complete lines from path, surviving rotation and truncation."""
    f, inode, buf = None, None, b""
    while True:
        if f is None:
            try:
                f = open(path, "rb")
            except FileNotFoundError:
                if once:
                    return
                time.sleep(POLL * 2)
                from_start = True  # file created later: read it all
                continue
            inode = os.fstat(f.fileno()).st_ino
            if not from_start:
                f.seek(0, os.SEEK_END)
            from_start = True  # any later (rotated) file is read in full

        chunk = f.read(65536)
        if chunk:
            buf += chunk
            *lines, buf = buf.split(b"\n")
            if len(buf) > MAX_LINE:
                print("dropping oversized line", file=sys.stderr)
                buf = b""
            yield from lines
            continue

        if once:
            return
        try:
            st = os.stat(path)
        except FileNotFoundError:
            st = None
        if st is None or st.st_ino != inode:   # rotated (moved/recreated)
            f.close()
            f, buf = None, b""
            continue
        if st.st_size < f.tell():              # truncated (copytruncate)
            f.seek(0)
            buf = b""
            continue
        time.sleep(POLL)


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("input")
    p.add_argument("output")
    p.add_argument("--from-start", action="store_true")
    p.add_argument("--once", action="store_true")
    args = p.parse_args()

    out = (sys.stdout if args.output == "-"
           else open(args.output, "a", buffering=1, encoding="utf-8"))
    bad = 0
    for raw in follow(args.input, args.from_start, args.once):
        raw = raw.strip()
        if not raw:
            continue
        try:
            entry = json.loads(raw)
            if not isinstance(entry, dict):
                raise ValueError("not a JSON object")
        except ValueError as exc:
            bad += 1
            print(f"skipping unparsable line #{bad}: {exc}", file=sys.stderr)
            continue
        for event in split(entry):
            out.write(json.dumps(event, separators=(",", ":")) + "\n")
        out.flush()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass