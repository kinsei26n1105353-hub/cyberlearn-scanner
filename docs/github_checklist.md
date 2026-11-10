# GitHub公開前チェックリスト / Pre-publish Checklist

## 安全・法律 / Safety & Legal

- [ ] READMEに「教育目的」「ローカル専用」「許可のないシステムに使わない」が明記されている
- [ ] SECURITY.md に利用制限が書かれている
- [ ] 外部サイトを対象にできるコード・設定が残っていない
- [ ] 攻撃的ペイロード・悪用手法がコードやドキュメントに含まれていない
- [ ] **APIキー・パスワード・トークン・個人情報がどのファイルにも含まれていない**
  - `git log -p | grep -i -E "password|token|apikey"` などで履歴も確認！
- [ ] レポート出力に対象の秘密情報（Cookie値等）が含まれないことを確認

## コード品質 / Code Quality

- [ ] `python -m unittest discover tests -v` が全てパスする
- [ ] CI（GitHub Actions）がグリーン
- [ ] コードに初心者向けコメントがある
- [ ] 外部依存なし（または requirements.txt に明記）

## ドキュメント / Documentation

- [ ] READMEにスクリーンショット（`docs/screenshot.png`）がある
- [ ] 使い方がコピペで再現できる
- [ ] 学習ノート・脆弱性解説が自分の言葉で書かれている
- [ ] 「今後の改善案」がある（成長の記録になる！）

## ポートフォリオとして / Portfolio Tips

- [ ] 修正前後のレポート2つを `reports/` またはdocsで比較掲載している
- [ ] 各検出を「影響→原因→修正→再発防止」で説明できている
- [ ] コミットメッセージが分かりやすい（例: `fix: HSTSヘッダーを追加`）
- [ ] LICENSE（MIT）が含まれている
