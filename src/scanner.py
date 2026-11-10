"""
scanner.py — フェッチ処理とスキャン実行 / Fetching and scan orchestration

標準ライブラリ urllib のみ使用。ページを「読むだけ」で取得し、
checks.py に渡します。POSTや認証試行は行いません。

Uses only the standard library. It READS pages (GET only) and
hands the responses to checks.py. No POSTs, no login attempts.
"""

import urllib.request
import urllib.error
from http.client import HTTPMessage

from safety import validate_target, RateLimiter, SafetyError
from checks import run_all_checks


def _headers_to_dict(msg: HTTPMessage):
    """HTTPMessageを普通のdictに変換 / Convert headers to a plain dict."""
    return {k: v for k, v in msg.items()}


def _set_cookies(msg: HTTPMessage):
    """Set-Cookieは複数あるのでリストで取得 / get_all for multiple Set-Cookie."""
    return msg.get_all("Set-Cookie") or []


def fetch(url, limiter, config, audit):
    """
    1ページをGETして (status, headers, set_cookies, body) を返す。
    GET one page and return (status, headers, set_cookies, body).
    """
    limiter.acquire()  # レート制限 / rate limiting
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": config["user_agent"]},
    )
    try:
        with urllib.request.urlopen(req, timeout=config["timeout_seconds"]) as res:
            body = res.read(500_000).decode("utf-8", errors="replace")  # 読みすぎ防止
            status, msg = res.status, res.headers
    except urllib.error.HTTPError as e:
        # 404なども「確認対象の情報」として扱う / 404s are useful evidence too
        body = e.read(500_000).decode("utf-8", errors="replace")
        status, msg = e.code, e.headers
    audit.log("http_get", url=url, status=status)
    return status, _headers_to_dict(msg), _set_cookies(msg), body


def scan(target_url, config, audit, confirm=True):
    """
    スキャンの本体。安全確認 → ページ取得 → チェック実行。
    Main scan flow: safety checks -> fetch pages -> run checks.
    """
    # 1. 対象の安全性チェック / validate the target first
    parsed = validate_target(target_url, config)
    base = f"{parsed.scheme}://{parsed.netloc}"
    audit.log("scan_start", target=base)

    # 2. 実行前の対話的確認 / interactive confirmation before running
    if confirm:
        answer = input(
            f"対象 {base} は自分のローカル練習環境ですか？ "
            f"(Is this YOUR local practice environment?) [yes/no]: "
        )
        if answer.strip().lower() != "yes":
            audit.log("scan_aborted", reason="user did not confirm local environment")
            raise SafetyError("確認されなかったため中止しました / Aborted: not confirmed.")
    audit.log("user_confirmed_local", target=base)

    # 3. ページを取得（設定された少数のパスのみ）/ fetch the few configured paths
    limiter = RateLimiter(config["max_requests_per_scan"], config["request_interval_seconds"])
    responses = []
    for path in config["probe_paths"]:
        try:
            responses.append((path, *fetch(base + path, limiter, config, audit)))
        except SafetyError:
            raise
        except Exception as e:
            audit.log("fetch_error", url=base + path, error=type(e).__name__)
            print(f"  ⚠ 取得できませんでした: {path} ({type(e).__name__})")

    # 4. チェック実行 / run all passive checks
    findings = run_all_checks(parsed, base, responses)
    audit.log("scan_complete", target=base, findings=len(findings))
    return findings
