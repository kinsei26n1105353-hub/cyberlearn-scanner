# HTTPSが使われていない / Missing HTTPS

## 図解 / How it works

```
[http]  あなた ----（平文: 誰でも読める）----> サーバー
                  ↑ 同じWi-Fiの人が盗み見できる

[https] あなた ----（暗号化: 🔒）-----------> サーバー
                  ↑ 盗み見ても読めない
```

## なぜ起こるのか / Why it happens

- 「ローカルだから大丈夫」と思いがち（学習環境では許容。ただし本番では必須）
- 証明書の設定が面倒で後回し

## どう防ぐのか / How to fix

1. 本番: **Let's Encrypt** で無料の証明書を取得しHTTPS化
2. あわせて `Strict-Transport-Security` ヘッダーでHTTPSを強制
3. ローカル学習: 自己署名証明書でHTTPSの練習もできる（例: `mkcert`）

## 参考 / References

- OWASP A02: Cryptographic Failures — https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
