"""
safety.py — 安全ガード / Safety guard

このモジュールは「本ツールがローカル環境以外に使われないようにする」
一番大事な部分です。スキャン前に必ずここを通します。

This module makes sure the scanner can ONLY be used against
your own local practice environment. Every scan must pass through here.
"""

from urllib.parse import urlparse


class SafetyError(Exception):
    """安全チェックに失敗したときに投げる例外 / Raised when a safety check fails."""


def load_config(path="config.json"):
    """設定ファイルを読み込む / Load the JSON configuration file."""
    import json

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_target(url, config):
    """
    対象URLが「許可されたローカル環境」かを確認する。
    ダメなら SafetyError を投げて絶対にスキャンさせない。

    Check that the target URL is an allowed local environment.
    Raises SafetyError (and the scan never starts) if not allowed.
    """
    parsed = urlparse(url)

    # 1. スキームは http/https のみ / Only http or https schemes
    if parsed.scheme not in ("http", "https"):
        raise SafetyError(f"許可されないスキームです / Disallowed scheme: {parsed.scheme}")

    host = (parsed.hostname or "").lower()

    # 2. ホストが許可リストにあるか / Host must be in the allow-list
    if host not in [h.lower() for h in config["allowed_hosts"]]:
        raise SafetyError(
            f"ホスト '{host}' は許可されていません。"
            f"localhost/127.0.0.1 のみ使用できます。 / "
            f"Only local hosts are allowed, got: {host}"
        )

    # 3. ポートが許可リストにあるか（省略時はスキームの既定ポート）
    #    Port must be in the allow-list (default port per scheme if omitted)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in config["allowed_ports"]:
        raise SafetyError(f"ポート {port} は許可されていません / Port not allowed: {port}")

    # 4. URLに認証情報（user:pass@）が含まれていたら拒否
    #    Reject URLs containing embedded credentials
    if parsed.username or parsed.password:
        raise SafetyError("URLに認証情報を含めないでください / Credentials in URL are not allowed.")

    return parsed


class RateLimiter:
    """
    短時間に大量アクセスしないための簡単なリクエスト制限。
    A tiny rate limiter so we never hammer the practice app.
    """

    def __init__(self, max_requests, interval_seconds):
        self.max_requests = max_requests
        self.interval = interval_seconds
        self.count = 0

    def acquire(self):
        """1リクエスト分の許可を得る。上限超過なら SafetyError。
        Get permission for one request. Raises SafetyError when over the limit."""
        if self.count >= self.max_requests:
            raise SafetyError(
                f"リクエスト上限（{self.max_requests}回）に達しました。"
                f" / Request limit reached."
            )
        self.count += 1
        if self.count > 1:  # 初回以外は待つ / wait between requests
            import time

            time.sleep(self.interval)
