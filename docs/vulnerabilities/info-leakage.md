# 情報漏えい（デバッグ情報・バージョン表示）/ Information Leakage

## 図解 / How it works

```
攻撃者「存在しないページを開いてみよう」
   |
   v
サーバー「エラーだ！詳しく教えるね:
  Traceback... File "/app/secret/config.py", line 42 ...」
   |
   v
→ 内部のファイル構成・使っている技術・バージョンがバレる
→ そのバージョンの「既知の弱点」を調べられてしまう
```

## なぜ起こるのか / Why it happens

- 開発中に ON にしたデバッグモードを本番で OFF にし忘れた
- サーバーソフトの既定設定がバージョンを表示する

## どう確認したか（スキャナーの動作）

1. 存在しないページ（`/nonexistent-page-for-404-test`）を1回だけ開く
2. 返ってきたエラーページに「スタックトレースの特徴的な文字列」があるか観察
3. `Server:` / `X-Powered-By:` ヘッダーの値を確認

## どう防ぐのか / How to fix

1. **デバッグモードを本番で OFF** にする（Flask: `debug=False`）
2. エラーページは「問題が発生しました」だけ表示し、詳細は**サーバー内部のログ**に記録
3. バージョン表示を消す:
   - Nginx: `server_tokens off;`
   - Express: `app.disable("x-powered-by");`

## 修正前後の比較 / Before & After

| | 修正前 | 修正後 |
|---|---|---|
| 404ページ | Pythonのトレース全文 + ファイルパス | 「ページが見つかりません」のみ |
| Server ヘッダー | `Apache/2.4.1 (Ubuntu)` | `Apache` または非表示 |

## 参考 / References

- OWASP A05: Security Misconfiguration — https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
