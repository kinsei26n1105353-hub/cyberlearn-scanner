# セキュリティヘッダー不足 / Missing Security Headers

## 図解 / How it works

```
ブラウザ                サーバー
   |  ページをください  |
   | -----------------> |
   |                     |
   |  HTML + ヘッダー    |   ← ここに「お願い」が書ける！
   | <-----------------  |
   |
 [ヘッダーの指示に従って安全に表示する]
```

レスポンスヘッダーは、サーバーからブラウザへの「安全のお願い」です。
書かなければ、ブラウザの保護機能は働きません。

## なぜ起こるのか / Why it happens

- フレームワークの既定では付かないヘッダーがある
- 「動けばOK」で設定を見直していない

## 主なヘッダー / Key headers

| ヘッダー | 役割 | 設定例 |
|---|---|---|
| Content-Security-Policy | XSSで読み込めるリソースを制限 | `default-src 'self'` |
| X-Frame-Options | 罠ページへの埋め込みを防ぐ | `DENY` |
| X-Content-Type-Options | 勝手なファイル判別を防ぐ | `nosniff` |
| Strict-Transport-Security | HTTPSを強制 | `max-age=63072000` |
| Referrer-Policy | 遷移先にURLを渡しすぎない | `no-referrer` |

## どう防ぐのか / How to fix

Express (Node.js) の例:

```js
const helmet = require("helmet");  // 主要ヘッダーをまとめて付けてくれる
app.use(helmet());
```

Flask (Python) の例:

```python
@app.after_request
def add_headers(res):
    res.headers["X-Frame-Options"] = "DENY"
    res.headers["X-Content-Type-Options"] = "nosniff"
    return res
```

修正したら **再スキャン** して検出が消えるか確認しましょう！

## 参考 / References

- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
