"""
audit.py — 監査ログ / Audit logging

すべての処理を JSON Lines 形式（1行1JSON）で記録します。
「いつ・何を・どう確認したか」を後から振り返れるようにするためです。
秘密情報（パスワードやトークン）は絶対に書き込みません。

Every action is recorded as JSON Lines so you can review
what was checked and when. Secrets are never logged.
"""

import json
import os
from datetime import datetime, timezone


class AuditLogger:
    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def log(self, event, **details):
        """1件のイベントを記録する / Record one audit event."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "details": details,
        }
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
