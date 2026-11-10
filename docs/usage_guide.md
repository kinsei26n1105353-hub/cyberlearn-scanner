# 使い方ガイド / Usage Guide

## 1. 準備 / Setup

必要なもの: **Python 3.10+**（外部ライブラリ不要・標準ライブラリのみ）

練習用の脆弱なアプリをローカルで起動します。おすすめ:

| アプリ | 起動例 |
|---|---|
| OWASP Juice Shop | `docker run --rm -p 3000:3000 bkimminich/juice-shop` |
| DVWA | `docker run --rm -p 8080:80 vulnerables/web-dvwa` |
| 自作のFlask/Expressアプリ | 自分で `localhost` に立てる |

> ⚠️ これらのアプリは**わざと脆弱**に作られています。必ずローカルだけで動かし、ポートを外部に公開しないでください。

## 2. スキャン実行 / Run a scan

```bash
python src/main.py http://localhost:3000
```

実行すると最初に確認されます:

```
対象 http://localhost:3000 は自分のローカル練習環境ですか？ [yes/no]:
```

`yes` と答えるとスキャンが始まります（最大10リクエスト・1秒間隔。やさしく確認します）。

## 3. 学習モード / Learning mode

```bash
python src/main.py http://localhost:3000 --learn
```

各検出について「なぜ危険か」「どう確認したか」「どう直すか」に加え、
証拠と次の学習ステップが表示されます。`docs/vulnerabilities/` の解説と一緒に読みましょう。

## 4. 修正 → 再スキャン / Fix and re-scan

1. アプリの設定を修正（例: ヘッダー追加、デバッグモードOFF）
2. もう一度スキャン
3. 検出数が減っていれば改善成功！
4. 前後のレポート（`reports/`）を比較してポートフォリオにまとめる

## 5. 出力ファイル / Outputs

| ファイル | 内容 |
|---|---|
| `reports/report_*.md` | GitHubに貼れるMarkdownレポート |
| `reports/scan_*.json` | 機械可読な結果JSON |
| `reports/audit_log.jsonl` | 全操作の監査ログ（JSON Lines） |

## トラブルシューティング

- **「ホストは許可されていません」** → 外部URLは使えません。`localhost` / `127.0.0.1` を指定してください。
- **「ポートは許可されていません」** → `config.json` の `allowed_ports` に練習アプリのポートを追加してください。
- **接続できない** → 練習アプリが起動しているか `curl http://localhost:3000` で確認。
