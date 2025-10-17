import os
import re
import sys
import time
import json
import ssl
import threading
from datetime import datetime, timedelta
from urllib.parse import urlparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


# --- Configuration ---
HOST = os.environ.get("IPTV_HOST", "0.0.0.0")
PORT = int(os.environ.get("IPTV_PORT", "8000"))
SOURCES_FILE_CANDIDATE = os.environ.get("IPTV_SOURCES_FILE", "播放源.txt")
USER_AGENT = os.environ.get("IPTV_UA", "TVProbe/1.0")
TIMEOUT_SEC = int(os.environ.get("IPTV_TIMEOUT", "7"))
MAX_WORKERS = int(os.environ.get("IPTV_MAX_WORKERS", "30"))
REFRESH_INTERVAL_MIN = int(os.environ.get("IPTV_REFRESH_MIN", "60"))
DATA_DIR = os.environ.get("IPTV_DATA_DIR", "data")

os.makedirs(DATA_DIR, exist_ok=True)


def now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


class Channel:
    def __init__(self, name, url, group=None, tvg_id=None, tvg_name=None, logo=None):
        self.name = (name or "").strip() or None
        self.url = (url or "").strip()
        self.group = (group or "").strip() or None
        self.tvg_id = (tvg_id or "").strip() or None
        self.tvg_name = (tvg_name or "").strip() or None
        self.logo = (logo or "").strip() or None

    def key_for_dedupe(self):
        name_key = (self.name or "").strip().lower()
        url_key = normalize_url(self.url)
        return (name_key, url_key)

    def merge_from(self, other):
        # Keep existing values; fill missing metadata from other
        if not self.group and other.group:
            self.group = other.group
        if not self.tvg_id and other.tvg_id:
            self.tvg_id = other.tvg_id
        if not self.tvg_name and other.tvg_name:
            self.tvg_name = other.tvg_name
        if not self.logo and other.logo:
            self.logo = other.logo

    def to_dict(self):
        return {
            "name": self.name,
            "url": self.url,
            "group": self.group,
            "tvg_id": self.tvg_id,
            "tvg_name": self.tvg_name,
            "logo": self.logo,
        }


def normalize_url(u: str) -> str:
    try:
        p = urlparse(u)
        # Normalize by scheme/host/port/path/query (strip fragments and trailing spaces)
        netloc = p.hostname or ""
        if p.port:
            netloc = f"{netloc}:{p.port}"
        path = p.path or "/"
        # Keep query; some streams use tokens there
        q = ("?" + p.query) if p.query else ""
        return f"{p.scheme}://{netloc}{path}{q}"
    except Exception:
        return u.strip()


def read_sources_file() -> list[str]:
    # Try the exact configured name first
    candidates = []
    if os.path.exists(SOURCES_FILE_CANDIDATE):
        candidates.append(SOURCES_FILE_CANDIDATE)
    # Fallback: find any .txt that looks like the sources file
    for nm in os.listdir("."):
        if nm.lower().endswith(".txt"):
            if nm not in candidates:
                candidates.append(nm)
    if not candidates:
        return []
    src_path = candidates[0]
    try:
        with open(src_path, "r", encoding="utf-8") as f:
            content = f.read()
    except UnicodeDecodeError:
        # Fallback to system default
        with open(src_path, "r", encoding=sys.getdefaultencoding(), errors="ignore") as f:
            content = f.read()
    urls = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        urls.append(line)
    return urls


def fetch_text(url: str, timeout: int) -> str | None:
    req = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(req, timeout=timeout, context=ssl.create_default_context()) as resp:
            data = resp.read()
            try:
                return data.decode("utf-8", errors="replace")
            except Exception:
                return data.decode(errors="ignore")
    except Exception:
        return None


EXTINF_RE = re.compile(r"#EXTINF:-?\d+\s*(?P<attrs>[^,]*)\s*,\s*(?P<name>.*)$")
# 支持  key="value" 或 key=value 两种写法
ATTR_RE = re.compile(r"(\w+)=\"([^\"]*)\"|(\w+)=([^\"\s]+)")


def parse_m3u(text: str) -> list[Channel]:
    if not text:
        return []
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    channels: list[Channel] = []
    if lines and lines[0].startswith("#EXTM3U"):
        i = 0
        idx = 0
        while i < len(lines):
            line = lines[i]
            if line.startswith("#EXTINF"):
                m = EXTINF_RE.match(line)
                name = None
                attrs: dict[str, str] = {}
                if m:
                    name = m.group("name").strip()
                    raw_attrs = m.group("attrs") or ""
                    for am in ATTR_RE.finditer(raw_attrs):
                        if am.group(1) is not None:  # quoted
                            k = am.group(1).lower()
                            v = am.group(2)
                        else:  # unquoted
                            k = am.group(3).lower()
                            v = am.group(4)
                        attrs[k] = v
                # find next non-comment as URL
                url = None
                j = i + 1
                group_from_extgrp = None
                while j < len(lines):
                    if not lines[j].startswith("#"):
                        url = lines[j]
                        break
                    # 兼容 #EXTGRP: 分组行
                    if lines[j].startswith("#EXTGRP:") and not attrs.get("group-title"):
                        group_from_extgrp = lines[j].split(":", 1)[1].strip()
                    j += 1
                i = j
                if url:
                    idx += 1
                    group_val = attrs.get("group-title") or attrs.get("group") or group_from_extgrp
                    logo_val = attrs.get("tvg-logo") or attrs.get("logo")
                    ch = Channel(
                        name or f"CH-{idx}",
                        url,
                        group=group_val,
                        tvg_id=attrs.get("tvg-id"),
                        tvg_name=attrs.get("tvg-name"),
                        logo=logo_val,
                    )
                    channels.append(ch)
            i += 1
        return channels
    else:
        # Plain list of URLs
        idx = 0
        for ln in lines:
            if ln.startswith("#"):
                continue
            idx += 1
            channels.append(Channel(f"CH-{idx}", ln))
        return channels


def head_request(url: str, timeout: int) -> tuple[bool, int, str]:
    req = Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(req, timeout=timeout, context=ssl.create_default_context()) as resp:
            code = getattr(resp, "status", 200)
            return True, int(code), "HEAD OK"
    except HTTPError as he:
        return False, int(he.code), str(he)
    except URLError as ue:
        return False, 0, str(ue)
    except Exception as e:
        return False, 0, str(e)


def range_get_request(url: str, timeout: int) -> tuple[bool, int, int, str]:
    req = Request(url, headers={"User-Agent": USER_AGENT, "Range": "bytes=0-1023"})
    t0 = time.time()
    try:
        with urlopen(req, timeout=timeout, context=ssl.create_default_context()) as resp:
            code = getattr(resp, "status", 200)
            chunk = resp.read(64)
            ms = int((time.time() - t0) * 1000)
            if chunk:
                return True, int(code), ms, f"Range {len(chunk)} B"
            return False, int(code), ms, "Empty"
    except HTTPError as he:
        ms = int((time.time() - t0) * 1000)
        return False, int(he.code), ms, str(he)
    except URLError as ue:
        ms = int((time.time() - t0) * 1000)
        return False, 0, ms, str(ue)
    except Exception as e:
        ms = int((time.time() - t0) * 1000)
        return False, 0, ms, str(e)


def check_channel(ch: Channel, timeout: int) -> dict:
    ok, code, msg = head_request(ch.url, timeout)
    ms = 0
    if not ok:
        ok2, code2, ms2, msg2 = range_get_request(ch.url, timeout)
        ok, code, ms, msg = ok2, code2, ms2, msg2
    return {
        "name": ch.name,
        "url": ch.url,
        "group": ch.group,
        "tvg_id": ch.tvg_id,
        "tvg_name": ch.tvg_name,
        "logo": ch.logo,
        "ok": ok,
        "code": code,
        "ms": ms,
        "msg": msg,
    }


class State:
    def __init__(self):
        self.lock = threading.RLock()
        self.last_scan_started = None
        self.last_scan_finished = None
        self.sources = []  # list of source URLs
        self.all_channels = []  # raw parsed channels
        self.checked = []  # list of dicts from check_channel
        self.ok_channels = []  # list[Channel] that passed
        self.m3u_text = "#EXTM3U\n"


STATE = State()


def scan_and_update():
    with STATE.lock:
        STATE.last_scan_started = now_iso()
    sources = read_sources_file()
    all_channels: list[Channel] = []
    for src in sources:
        txt = fetch_text(src, TIMEOUT_SEC)
        if not txt:
            continue
        chs = parse_m3u(txt)
        all_channels.extend(chs)

    # Deduplicate identical (name,url) pairs across sources
    dedup_map: dict[tuple[str, str], Channel] = {}
    for ch in all_channels:
        key = ch.key_for_dedupe()
        if key in dedup_map:
            dedup_map[key].merge_from(ch)
        else:
            dedup_map[key] = ch
    deduped = list(dedup_map.values())

    # Check channels in parallel
    results = []
    ok_list: list[Channel] = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        future_map = {ex.submit(check_channel, ch, TIMEOUT_SEC): ch for ch in deduped}
        for fut in as_completed(future_map):
            res = fut.result()
            results.append(res)
            if res.get("ok"):
                # keep the original channel object to retain metadata
                ok_list.append(future_map[fut])

    # Classify and assign new sequential channel numbers (tvg-chno)
    def group_key(c: Channel):
        return (c.group or "Unknown", (c.name or "").lower())

    ok_list.sort(key=group_key)
    m3u_lines = ["#EXTM3U"]
    chno = 1
    for ch in ok_list:
        attrs = []
        if ch.tvg_id:
            attrs.append(f"tvg-id=\"{escape_attr(ch.tvg_id)}\"")
        if ch.tvg_name or ch.name:
            attrs.append(f"tvg-name=\"{escape_attr(ch.tvg_name or ch.name)}\"")
        if ch.logo:
            attrs.append(f"tvg-logo=\"{escape_attr(ch.logo)}\"")
        if ch.group:
            attrs.append(f"group-title=\"{escape_attr(ch.group)}\"")
        attrs.append(f"tvg-chno=\"{chno}\"")
        line = f"#EXTINF:-1 {' '.join(attrs)},{ch.name or f'CH-{chno}'}"
        m3u_lines.append(line)
        m3u_lines.append(ch.url)
        chno += 1
    m3u_text = "\n".join(m3u_lines) + "\n"

    # Persist snapshot
    snapshot = {
        "timestamp": now_iso(),
        "sources": sources,
        "counts": {
            "parsed": len(all_channels),
            "deduped": len(deduped),
            "ok": len(ok_list),
        },
        "checked": results,
    }
    with open(os.path.join(DATA_DIR, "snapshot.json"), "w", encoding="utf-8") as f:
        json.dump(snapshot, f, ensure_ascii=False, indent=2)
    with open(os.path.join(DATA_DIR, "playlist.m3u"), "w", encoding="utf-8") as f:
        f.write(m3u_text)

    with STATE.lock:
        STATE.sources = sources
        STATE.all_channels = [c.to_dict() for c in all_channels]
        STATE.checked = results
        STATE.ok_channels = [c.to_dict() for c in ok_list]
        STATE.m3u_text = m3u_text
        STATE.last_scan_finished = now_iso()


def escape_attr(v: str) -> str:
    return (v or "").replace("\"", "\\\"")


def scheduler_loop():
    # Run immediately on startup
    try:
        print("[IPTV] Initial scan starting...")
        scan_and_update()
        print("[IPTV] Initial scan finished.")
    except Exception as e:
        print(f"[IPTV] Initial scan error: {e}")

    # Then every REFRESH_INTERVAL_MIN minutes
    interval = max(1, REFRESH_INTERVAL_MIN)
    while True:
        try:
            time.sleep(interval * 60)
            print("[IPTV] Scheduled scan starting...")
            scan_and_update()
            print("[IPTV] Scheduled scan finished.")
        except Exception as e:
            print(f"[IPTV] Scheduled scan error: {e}")


class Handler(BaseHTTPRequestHandler):
    def _set_common_headers(self, code=200, content_type="text/plain; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def do_GET(self):
        if self.path.startswith("/playlist.m3u"):
            with STATE.lock:
                body = STATE.m3u_text
            self._set_common_headers(200, "application/x-mpegURL; charset=utf-8")
            self.wfile.write(body.encode("utf-8"))
            return

        if self.path.startswith("/stats"):
            with STATE.lock:
                body_obj = {
                    "last_scan_started": STATE.last_scan_started,
                    "last_scan_finished": STATE.last_scan_finished,
                    "sources": STATE.sources,
                    "counts": {
                        "all": len(STATE.all_channels),
                        "checked": len(STATE.checked),
                        "ok": len(STATE.ok_channels),
                    },
                }
            body = json.dumps(body_obj, ensure_ascii=False, indent=2)
            self._set_common_headers(200, "application/json; charset=utf-8")
            self.wfile.write(body.encode("utf-8"))
            return

        if self.path.startswith("/health"):
            self._set_common_headers(200, "text/plain; charset=utf-8")
            self.wfile.write(b"OK")
            return

        if self.path.startswith("/refresh"):
            # Trigger an immediate refresh (non-blocking)
            threading.Thread(target=scan_and_update, daemon=True).start()
            self._set_common_headers(202, "application/json; charset=utf-8")
            self.wfile.write(json.dumps({"status": "refreshing"}).encode("utf-8"))
            return

        # Default index
        self._set_common_headers(200, "text/plain; charset=utf-8")
        self.wfile.write(
            (
                "IPTV Service\n\n"
                "Endpoints:\n"
                "- /playlist.m3u  (current valid playlist)\n"
                "- /stats         (scan stats)\n"
                "- /refresh       (trigger scan)\n"
                "- /health        (health check)\n"
            ).encode("utf-8")
        )

    def log_message(self, format, *args):
        # Quieter logging to stdout
        sys.stdout.write("[HTTP] " + (format % args) + "\n")


def main():
    # Start scheduler
    th = threading.Thread(target=scheduler_loop, daemon=True)
    th.start()

    # Start HTTP server
    srv = HTTPServer((HOST, PORT), Handler)
    print(f"[IPTV] Serving on http://{HOST}:{PORT}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("[IPTV] Shutting down...")
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
