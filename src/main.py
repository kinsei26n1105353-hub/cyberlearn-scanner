"""
main.py — CyberLearn Scanner のエントリーポイント / CLI entry point

使い方 / Usage:
    python src/main.py http://localhost:3000 [--learn] [--report out.md] [--yes]
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # 同一ディレクトリをimport可能に

from safety import load_config, SafetyError
from audit import AuditLogger
from scanner import scan
from report import render_console, save_reports

BANNER = r"""
   ____      _               _
  / ___|   _| |__   ___ _ __| |    ___  __ _ _ __ _ __
 | |  | | | | '_ \ / _ \ '__| |   / _ \/ _` | '__| '_ \
 | |__| |_| | |_) |  __/ |  | |__|  __/ (_| | |  | | | |
  \____\__, |_.__/ \___|_|  |_____\___|\__,_|_|  |_| |_|
       |___/  Scanner  — ローカル練習専用 / local practice only
"""


def main():
    parser = argparse.ArgumentParser(
        description="CyberLearn Scanner — 教育目的・ローカル専用の脆弱性学習ツール"
    )
    parser.add_argument("url", help="対象URL（localhost/127.0.0.1 のみ）")
    parser.add_argument("--learn", action="store_true", help="学習モード（詳しい解説を表示）")
    parser.add_argument("--report", help="Markdownレポートの出力先")
    parser.add_argument("--json", dest="json_path", help="JSON結果の出力先")
    parser.add_argument("--yes", action="store_true", help="確認プロンプトをスキップ（自動テスト用）")
    parser.add_argument("--config", default="config.json", help="設定ファイルのパス")
    args = parser.parse_args()

    print(BANNER)
    config = load_config(args.config)
    audit = AuditLogger(config["audit_log_path"])

    try:
        findings = scan(args.url, config, audit, confirm=not args.yes)
    except SafetyError as e:
        audit.log("scan_blocked", reason=str(e))
        print(f"\n🛑 安全チェックにより停止 / Blocked by safety check:\n   {e}\n")
        sys.exit(2)

    render_console(findings, learn_mode=args.learn)
    md_path, json_path = save_reports(args.url, findings, args.report, args.json_path)
    audit.log("report_saved", markdown=md_path, json=json_path)
    print(f"📄 レポート: {md_path}\n📦 JSON: {json_path}\n🧾 監査ログ: {config['audit_log_path']}\n")


if __name__ == "__main__":
    main()
