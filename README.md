# CyberLearn Scanner 🛡️

> ローカルの練習用Webアプリ「だけ」を対象にした、初心者向けの安全な脆弱性学習スキャナーです。
> A safe, beginner-friendly vulnerability *learning* scanner that works **only against your own local practice apps**.

![screenshot](docs/screenshot.png)

---

## ⚠️ 安全上の注意（必ず読んでください / Safety First）

- これは **教育目的** のツールです。 / This tool is for **education only**.
- **許可されていないシステムには絶対に使用しないでください。** / Never use it on systems you do not own or have permission to test.
- 対象は **自分のローカル環境（localhost / 127.0.0.1）に限ります。** 設定ファイルで外部ドメインは既定で拒否されます。
- セキュリティ学習は「攻撃方法」より **「防御・修正・説明力」** を重視します。
- 本ツールは受動的な確認（設定・レスポンスヘッダー・公開情報）だけを行い、破壊的な操作・ログイン試行・ブルートフォース等は一切行いません。

---

## 🎯 目的 / Purpose

高校生が自分のPCで練習用の脆弱なWebアプリ（例: OWASP Juice Shop, DVWA, 自作アプリ）を動かし、

1. 基本的な設定ミスを **検出** し、
2. **なぜ危険か** を学び、
3. **安全な修正方法** を試し、
4. 再スキャンで **改善を確認** し、
5. Markdownレポートを **GitHubポートフォリオ** に残す

……という一連の学習サイクルを回すためのツールです。

## 📚 学べる脆弱性 / What You Can Learn

| チェック項目 | OWASP対応 | 重要度 |
|---|---|---|
| HTTPSが使われていない | A02: Cryptographic Failures | Medium |
| セキュリティヘッダー不足 (CSP, X-Frame-Options 等) | A05: Security Misconfiguration | Low–Medium |
| Server/X-Powered-By によるバージョン露出 | A05: Security Misconfiguration | Low |
| エラーページのデバッグ情報・スタックトレース | A05 / A09 | Medium |
| フォームのバリデーション不足（type=email 等の欠如） | A03: Injection（予防知識） | Info |
| Cookieの Secure / HttpOnly / SameSite 属性不足 | A07: Auth Failures | Medium |

## 🚀 使い方 / Usage

```bash
# 1. 練習用アプリをローカルで起動（例: Docker）
docker run --rm -p 3000:3000 bkimminich/juice-shop

# 2. スキャン実行（実行前に「自分のローカル環境ですか？」と確認されます）
python src/main.py http://localhost:3000

# 学習モード（各検出の詳しい解説つき）
python src/main.py http://localhost:3000 --learn

# 修正したら再スキャンして改善を確認！
python src/main.py http://localhost:3000 --report reports/after-fix.md
```

出力: コンソール表示 + `reports/` に Markdown / JSON / 監査ログ(JSON Lines)。

詳しくは [docs/usage_guide.md](docs/usage_guide.md) を参照。

## 📁 プロジェクト構成

```
├── src/            # スキャナー本体（標準ライブラリのみ）
├── tests/          # 単体テスト (unittest)
├── config.json     # 許可ホスト・レート制限などの安全設定
├── docs/           # 学習ノート・脆弱性解説・使い方ガイド
├── reports/        # 生成されたレポート
└── .github/        # CI（テスト＋lint）
```

## 📝 レポートの考え方

発見した問題は「攻撃手順」ではなく、**影響 → 原因 → 修正方法 → 再発防止** の4点で整理します。
この「説明力」こそが、セキュリティ職に一番求められるスキルです。

## 🔮 今後の改善案

- [ ] 簡単なWeb UI（Flask）
- [ ] 修正前後スキャンの自動差分比較
- [ ] チェック項目の追加（Directory listing, CORS設定 など）
- [ ] 英語版レポート出力

## 📄 ライセンス

MIT — ただし [SECURITY.md](SECURITY.md) の利用制限を必ず守ってください。
