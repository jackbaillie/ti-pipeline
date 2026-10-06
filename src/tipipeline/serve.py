"""Dashboard server: the static output plus live manual investigations.

``ti-pipeline serve`` serves ``output/`` and renders the investigation pages
from the database on every request. Submitted investigations run one at a time
on a single background worker. URL corpus changes wait for the pipeline lock;
other lookups use their own SQLite connections with a long busy timeout and
can proceed alongside a scheduled run.
"""

from __future__ import annotations

import ipaddress
import logging
import mimetypes
import queue
import re
import sqlite3
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from tipipeline.dashboard.investigations import live_form, live_investigation
from tipipeline.db import connect, now_iso
from tipipeline.investigate import create_investigation, recover_interrupted, run_investigation
from tipipeline.pipeline import Context, open_context

log = logging.getLogger("tipipeline.serve")

BUSY_TIMEOUT_MS = 120_000
# Room for a 2,000-character value even when every character is percent-encoded UTF-8.
MAX_FORM_BYTES = 32_768
_INVESTIGATION_PAGE = re.compile(r"/dashboard/investigations/(\d+)\.html")
_CONTENT_TYPES = {".md": "text/markdown", ".yaml": "text/plain", ".yml": "text/plain"}


def open_db(path: Path) -> sqlite3.Connection:
    conn = connect(path)
    conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    return conn


class InvestigationWorker:
    """Runs queued investigations one at a time on a single thread."""

    def __init__(self, make_context: Callable[[], Context], runner: Callable[[Context, int], object]) -> None:
        self._make_context = make_context
        self._runner = runner
        self._queue: queue.Queue[int | None] = queue.Queue()
        self._thread = threading.Thread(target=self._loop, name="investigations", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def submit(self, investigation_id: int) -> None:
        self._queue.put(investigation_id)

    def stop(self, timeout: float | None = None) -> None:
        """Finish queued work, then exit. An interrupted run is failed on the next start."""
        self._queue.put(None)
        self._thread.join(timeout)

    def _loop(self) -> None:
        ctx = self._make_context()  # this thread's own connection
        try:
            while (investigation_id := self._queue.get()) is not None:
                try:
                    self._runner(ctx, investigation_id)
                except Exception as exc:  # keep serving later investigations
                    ctx.db.rollback()
                    ctx.db.execute(
                        "UPDATE investigations SET status='error', error=?, updated_at=? WHERE id=?",
                        (f"{type(exc).__name__}: {exc}"[:2000], now_iso(), investigation_id),
                    )
                    ctx.db.commit()
                    log.exception("investigation %s: worker error", investigation_id)
        finally:
            ctx.db.close()


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], context: Context, *,
                 runner: Callable[[Context, int], object] = run_investigation,
                 hostnames: tuple[str, ...] = ()) -> None:
        # ``context`` is a template: every thread gets a copy with its own connection.
        self.context = context
        self.trusted_hosts = {address[0].lower().rstrip("."), *(name.lower().rstrip(".") for name in hostnames)}
        try:
            loopback = ipaddress.ip_address(address[0]).is_loopback
        except ValueError:
            loopback = address[0].lower() == "localhost"
        if loopback:
            self.trusted_hosts.add("localhost")
        else:
            self.trusted_hosts.discard("localhost")
        self.output_root = context.output_dir.resolve()
        self.db_path = context.root / context.settings.db_path
        self.worker = InvestigationWorker(self.thread_context, runner)
        super().__init__(address, DashboardHandler)

    def thread_context(self) -> Context:
        return replace(self.context, db=open_db(self.db_path))

    def start_worker(self) -> None:
        conn = open_db(self.db_path)
        try:
            pending = recover_interrupted(conn)
        finally:
            conn.close()
        self.worker.start()
        for investigation_id in pending:
            self.worker.submit(investigation_id)


class DashboardHandler(BaseHTTPRequestHandler):
    server: DashboardServer
    server_version = "ti-pipeline"
    sys_version = ""

    @contextmanager
    def _context(self) -> Iterator[Context]:
        ctx = self.server.thread_context()
        try:
            yield ctx
        finally:
            ctx.db.close()

    def do_GET(self) -> None:
        self._get(head=False)

    def do_HEAD(self) -> None:
        self._get(head=True)

    def _get(self, *, head: bool) -> None:
        if self._trusted_host(head=head) is None:
            return
        path = urlsplit(self.path).path
        if path == "/":
            self._redirect("/dashboard/", HTTPStatus.FOUND)
            return
        if path == "/dashboard/investigate.html":
            with self._context() as ctx:
                page = live_form(ctx)
            self._html(page, head=head)
            return
        match = _INVESTIGATION_PAGE.fullmatch(path)
        if match:
            with self._context() as ctx:
                page = live_investigation(ctx, int(match[1]))
            if page is None:
                self._text(HTTPStatus.NOT_FOUND, "No such investigation.", head=head)
            else:
                self._html(page, head=head)
            return
        self._static(path, head=head)

    def _static(self, path: str, *, head: bool) -> None:
        relative = unquote(path).lstrip("/")
        root = self.server.output_root
        target = (root / relative).resolve() if "\x00" not in relative else None
        if target is None or not target.is_relative_to(root):
            self._text(HTTPStatus.NOT_FOUND, "Not found.", head=head)
            return
        if target.is_dir():
            if not path.endswith("/"):
                self._redirect(path + "/", HTTPStatus.MOVED_PERMANENTLY)
                return
            target = (target / "index.html").resolve()
        if not target.is_relative_to(root) or not target.is_file():
            self._text(HTTPStatus.NOT_FOUND, "Not found.", head=head)
            return
        content_type = _CONTENT_TYPES.get(target.suffix) or mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type in {"application/javascript", "application/json"}:
            content_type += "; charset=utf-8"
        self._send(HTTPStatus.OK, content_type, target.read_bytes(), head=head)

    def do_POST(self) -> None:
        host = self._trusted_host()
        if host is None:
            return
        if urlsplit(self.path).path != "/dashboard/investigate":
            self._text(HTTPStatus.NOT_FOUND, "Not found.")
            return
        # Origin is checked against the validated literal hostname and actual listener port.
        origin = self.headers.get("Origin")
        if origin is not None:
            try:
                parsed = urlsplit(origin)
                origin_host = (parsed.hostname or "").lower().rstrip(".")
                origin_port = parsed.port or (443 if parsed.scheme == "https" else 80)
                valid = parsed.scheme in {"http", "https"} and parsed.username is None and parsed.password is None
                valid = valid and not parsed.path and not parsed.query and not parsed.fragment
                valid = valid and origin_host == host and origin_port == self.server.server_port
            except ValueError:
                valid = False
            if not valid:
                self._text(HTTPStatus.FORBIDDEN, "Cross-site form submissions are refused.")
                return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0:
            self._text(HTTPStatus.BAD_REQUEST, "Invalid Content-Length.")
            return
        if length > MAX_FORM_BYTES:
            self._text(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Form too large.")
            return
        form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"), keep_blank_values=True)
        values = {
            "value": form.get("value", [""])[0],
            "kind": form.get("kind", ["auto"])[0],
            "customer": form.get("customer", [""])[0],
            "include_scraped": "include_scraped" in form,
        }
        with self._context() as ctx:
            try:
                investigation_id = create_investigation(
                    ctx, values["value"], kind=values["kind"], profile_id=values["customer"] or None,
                    include_scraped=values["include_scraped"],
                )
            except ValueError as exc:
                self._html(live_form(ctx, error=str(exc), values=values), status=HTTPStatus.BAD_REQUEST)
                return
        self.server.worker.submit(investigation_id)
        log.info("investigation %s queued (%s)", investigation_id, values["kind"])
        self._redirect(f"/dashboard/investigations/{investigation_id}.html", HTTPStatus.SEE_OTHER)

    def _trusted_host(self, *, head: bool = False) -> str | None:
        """Literal allowlist only: DNS answers never grant a request access."""
        values = self.headers.get_all("Host", [])
        try:
            raw = values[0] if len(values) == 1 else ""
            parsed = urlsplit("//" + raw)
            host = (parsed.hostname or "").lower().rstrip(".")
            port = parsed.port if parsed.port is not None else 80
            valid = parsed.username is None and parsed.password is None and not parsed.path
            valid = valid and not parsed.query and not parsed.fragment
            valid = valid and host in self.server.trusted_hosts and port == self.server.server_port
        except ValueError:
            valid = False
        if valid:
            return host
        self._text(HTTPStatus.FORBIDDEN, "Unrecognised dashboard host.", head=head)
        return None

    # -- responses ---------------------------------------------------------

    def _send(self, status: HTTPStatus, content_type: str, body: bytes, *, head: bool = False,
              headers: tuple[tuple[str, str], ...] = ()) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def _html(self, page: str, *, head: bool = False, status: HTTPStatus = HTTPStatus.OK) -> None:
        self._send(status, "text/html; charset=utf-8", page.encode("utf-8"), head=head,
                   headers=(("Cache-Control", "no-store"),))

    def _text(self, status: HTTPStatus, message: str, *, head: bool = False) -> None:
        self._send(status, "text/plain; charset=utf-8", message.encode("utf-8"), head=head)

    def _redirect(self, location: str, status: HTTPStatus) -> None:
        self.send_response(status)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        # One line per form submission or failure; page and asset loads stay at debug.
        failed = isinstance(code, int) and code >= 400
        level = logging.INFO if self.command == "POST" or failed else logging.DEBUG
        log.log(level, "%s %s %s", self.command, self.path, int(code) if isinstance(code, int) else code)

    def log_message(self, format: str, *args) -> None:
        log.info("%s %s", self.client_address[0], format % args)


def serve(root: Path, host: str = "127.0.0.1", port: int = 8765, *, hostnames: tuple[str, ...] = ()) -> None:
    """Serve ``output/`` and live investigations until interrupted."""
    template = open_context(root)  # also creates the investigations table on older databases
    template.db.close()
    server = DashboardServer((host, port), template, hostnames=hostnames)
    server.start_worker()
    log.info("serving %s at http://%s:%d/dashboard/", template.output_dir, host, server.server_address[1])
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
