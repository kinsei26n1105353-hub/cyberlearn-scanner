# Cookieの安全属性（HttpOnly / Secure / SameSite）/ Cookie Security Flags

## 図解 / Why each flag matters

```
HttpOnly なし → JavaScriptから document.cookie で読める → XSSで盗まれる！
Secure    なし → http通信で平文送信 → 盗聴される！
SameSite  なし → 他サイトからのリクエストにも付く → CSRFに悪用される！
```

セッションCookieは「ログイン済みの証明書」。盗まれたらなりすまされます。

## なぜ起こるのか / Why it happens

- フレームワークの既定値が緩い
- Cookieの属性を意識せずに発行している

## どう防ぐのか / How to fix

```
Set-Cookie: session=xxxxx; HttpOnly; Secure; SameSite=Lax
```

Express の例:

```js
app.use(session({
  cookie: { httpOnly: true, secure: true, sameSite: "lax" }
}));
```

> ※ 本スキャナーはCookieの**属性の有無だけ**を確認し、Cookieの**値は記録しません**。

## 参考 / References

- OWASP A07: Identification and Authentication Failures — https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- MDN: Set-Cookie — https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Set-Cookie
