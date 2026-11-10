"""
checks.py — 受動的チェック群 / Passive security checks

ここにあるチェックは、すべて「普通にページを1回開いて、
返ってきたヘッダーやHTMLを読む」だけの受動的なものです。
攻撃的な入力（ペイロード）は一切送りません。

All checks here are PASSIVE: we fetch a page once and read its
headers and HTML. No attack payloads are ever sent.
"""

import re
from dataclasses import dataclass, field


@dataclass
class Finding:
    """1件の検出結果 / One finding."""

    id: str
    name_ja: str
    name_en: str
    severity: str          # Info / Low / Medium / High
    owasp: str             # OWASPカテゴリと参考リンク
    why_dangerous_ja: str  # なぜ危険なのか
    how_detected_ja: str   # どう確認したのか
    how_to_fix_ja: str     # 修正方法
    evidence: str = ""     # 観測された証拠（秘密情報は含めない）


# 推奨されるセキュリティヘッダーと説明
RECOMMENDED_HEADERS = {
    "content-security-policy": ("Content-Security-Policy", "XSSを防ぐ強力なルール"),
    "x-frame-options": ("X-Frame-Options", "クリックジャッキング（罠ページへの埋め込み）を防ぐ"),
    "x-content-type-options": ("X-Content-Type-Options", "ブラウザの勝手なファイル判別を防ぐ"),
    "strict-transport-security": ("Strict-Transport-Security", "HTTPS強制（httpsの場合のみ期待）"),
    "referrer-policy": ("Referrer-Policy", "リンク遷移時の情報漏えいを抑える"),
}


def check_https(parsed, base_url):
    """HTTPSが使われているか / Is HTTPS in use?"""
    if parsed.scheme == "https":
        return None
    return Finding(
        id="no-https",
        name_ja="HTTPSが使われていない",
        name_en="Missing HTTPS",
        severity="Medium",
        owasp="A02: Cryptographic Failures — https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        why_dangerous_ja="通信内容（パスワードやCookie）が盗み見・改ざんされる可能性があります。",
        how_detected_ja=f"URLのスキームを確認: {base_url}",
        how_to_fix_ja="本番ではTLS証明書（Let's Encrypt等）を設定しHTTPS化。ローカル学習でも自己署名証明書で練習できます。",
        evidence=f"scheme=http ({base_url})",
    )


def check_security_headers(headers, scheme):
    """セキュリティヘッダーの不足を調べる / Find missing security headers."""
    findings = []
    lower = {k.lower(): v for k, v in headers.items()}
    for key, (name, desc) in RECOMMENDED_HEADERS.items():
        if key == "strict-transport-security" and scheme != "https":
            continue  # HSTSはHTTPSのときだけ意味がある
        if key not in lower:
            findings.append(Finding(
                id=f"missing-header-{key}",
                name_ja=f"セキュリティヘッダー不足: {name}",
                name_en=f"Missing header: {name}",
                severity="Low",
                owasp="A05: Security Misconfiguration — https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                why_dangerous_ja=f"{name} は「{desc}」ためのヘッダーです。ないとブラウザの保護機能が働きません。",
                how_detected_ja="レスポンスヘッダー一覧を確認しました。",
                how_to_fix_ja=f"サーバー/フレームワークの設定で {name} ヘッダーを追加してください。",
                evidence=f"レスポンスに {name} が存在しない",
            ))
    return findings


def check_version_disclosure(headers):
    """バージョン情報の露出 / Server version disclosure."""
    findings = []
    for key in ("server", "x-powered-by"):
        value = headers.get(key) or headers.get(key.title())
        if value:
            findings.append(Finding(
                id=f"version-disclosure-{key}",
                name_ja=f"バージョン情報の露出: {key.title()}",
                name_en=f"Version disclosure: {key.title()}",
                severity="Low",
                owasp="A05: Security Misconfiguration — https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                why_dangerous_ja="ソフト名やバージョンが分かると、既知の脆弱性を調べる手がかりを与えてしまいます。",
                how_detected_ja=f"レスポンスヘッダー {key.title()}: {value} を確認しました。",
                how_to_fix_ja="サーバー設定でバージョン表示を無効化（例: Nginxの server_tokens off;、Expressの app.disable('x-powered-by')）。",
                evidence=f"{key.title()}: {value}",
            ))
    return findings


# デバッグ情報の典型パターン（スタックトレース等）
DEBUG_PATTERNS = [
    (r"Traceback \(most recent call last\)", "Pythonのスタックトレース"),
    (r"at [\w.$]+\([\w.]+\.java:\d+\)", "Javaのスタックトレース"),
    (r"Debug mode is on|FLASK_DEBUG|DEBUG = True", "デバッグモード表示"),
    (r"Stack trace:|Exception in thread", "例外情報"),
]


def check_info_leakage(body, status_code):
    """エラーページのデバッグ情報漏えい / Debug info leakage in error pages."""
    findings = []
    if status_code < 400:
        return findings  # エラーページ（404テスト等）でのみ確認
    for pattern, desc in DEBUG_PATTERNS:
        if re.search(pattern, body):
            findings.append(Finding(
                id="debug-info-leak",
                name_ja="エラーページからのデバッグ情報漏えい",
                name_en="Debug information leakage",
                severity="Medium",
                owasp="A05: Security Misconfiguration — https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                why_dangerous_ja="内部のファイルパスやコードが見えると、攻撃の足がかりになります。",
                how_detected_ja=f"存在しないページを開いた際の応答（HTTP {status_code}）に「{desc}」のパターンを検出しました。",
                how_to_fix_ja="本番ではデバッグモードをOFFにし、エラーページは一般的なメッセージだけを表示。詳細はサーバー内部のログだけに記録します。",
                evidence=f"HTTP {status_code} の応答内に {desc} を検出",
            ))
            break
    return findings


def check_cookie_flags(set_cookie_headers, scheme):
    """Cookieの安全属性（Secure/HttpOnly/SameSite）/ Cookie security flags."""
    findings = []
    for cookie in set_cookie_headers:
        name = cookie.split("=", 1)[0].strip()
        lower = cookie.lower()
        missing = []
        if "httponly" not in lower:
            missing.append("HttpOnly")
        if scheme == "https" and "secure" not in lower:
            missing.append("Secure")
        if "samesite" not in lower:
            missing.append("SameSite")
        if missing:
            findings.append(Finding(
                id=f"cookie-flags-{name}",
                name_ja=f"Cookieの安全属性が不足: {name}",
                name_en=f"Missing cookie flags: {name}",
                severity="Medium",
                owasp="A07: Identification and Authentication Failures — https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                why_dangerous_ja="HttpOnlyがないとXSSでCookieを読まれ、Secureがないと平文通信で盗まれ、SameSiteがないとCSRFに使われる恐れがあります。",
                how_detected_ja="Set-Cookieヘッダーの属性を確認しました（Cookieの値そのものは記録していません）。",
                how_to_fix_ja="Cookie発行時に HttpOnly; Secure; SameSite=Lax（またはStrict）を付けるようフレームワークを設定してください。",
                evidence=f"Cookie '{name}' に不足: {', '.join(missing)}",
            ))
    return findings


def check_form_validation(body):
    """
    フォームの基本的なバリデーション不足（情報提供レベル）。
    HTMLのフォームに type 属性や required があるかを「観察」するだけです。
    Basic form validation hints (informational). Observation only.
    """
    findings = []
    forms = re.findall(r"<form\b.*?</form>", body, re.DOTALL | re.IGNORECASE)
    for i, form in enumerate(forms, 1):
        inputs = re.findall(r"<input\b[^>]*>", form, re.IGNORECASE)
        for tag in inputs:
            name = re.search(r'name=["\']?([\w-]+)', tag, re.IGNORECASE)
            itype = re.search(r'type=["\']?([\w-]+)', tag, re.IGNORECASE)
            label = name.group(1) if name else "(名前なし)"
            # 「emailやpasswordっぽい名前なのに type=text」は学習ポイント
            if itype and itype.group(1) == "text" and re.search(r"mail|password", label, re.IGNORECASE):
                findings.append(Finding(
                    id=f"form-validation-{i}-{label}",
                    name_ja=f"フォームの入力種別が不適切かも: {label}",
                    name_en=f"Form input type may be wrong: {label}",
                    severity="Info",
                    owasp="A03: Injection（予防知識）— https://owasp.org/Top10/A03_2021-Injection/",
                    why_dangerous_ja="type=email 等を使うとブラウザが最初の検査をしてくれます。ただし最重要なのはサーバー側の検証です。",
                    how_detected_ja=f"フォーム{i}内の input 要素（name={label}）が type=text になっていました。",
                    how_to_fix_ja="適切な type（email/password等）と required を付け、さらにサーバー側でも必ず検証・エスケープを行う（SQLにはプレースホルダを使用）。",
                    evidence=f'<input name="{label}" type="text" ...>',
                ))
    return findings


def run_all_checks(parsed, base_url, responses):
    """
    すべてのチェックを実行して結果をまとめる。
    responses: [(path, status, headers_dict, set_cookie_list, body_text), ...]
    Run every check and return a flat list of findings.
    """
    findings = []
    https_finding = check_https(parsed, base_url)
    if https_finding:
        findings.append(https_finding)

    for path, status, headers, cookies, body in responses:
        if path == "/":
            findings += check_security_headers(headers, parsed.scheme)
            findings += check_version_disclosure(headers)
            findings += check_cookie_flags(cookies, parsed.scheme)
            findings += check_form_validation(body)
        findings += check_info_leakage(body, status)

    # 同じidの重複を除去 / de-duplicate by id
    seen, unique = set(), []
    for f in findings:
        if f.id not in seen:
            seen.add(f.id)
            unique.append(f)
    return unique
