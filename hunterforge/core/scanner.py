import aiohttp
import asyncio

async def check_xss(session, url):
    payload = "<script>alert(1)</script>"
    test_url = url + ("&" if "?" in url else "?") + f"q={payload}"
    try:
        async with session.get(test_url, timeout=10) as resp:
            text = await resp.text()
            if payload in text:
                return "Possible XSS"
    except:
        pass
    return "Safe"

async def check_open_redirect(session, url):
    payload = "https://evil.com"
    test_url = url + ("&" if "?" in url else "?") + f"redirect={payload}"
    try:
        async with session.get(test_url, timeout=10, allow_redirects=False) as resp:
            location = resp.headers.get("Location", "")
            if payload in location:
                return "Vulnerable"
    except:
        pass
    return "Safe"

async def check_cors(session, url):
    try:
        async with session.get(url, timeout=10, headers={"Origin": "https://evil.com"}) as resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == "*":
                return "Wildcard (*)"
            elif "evil.com" in acao:
                return "Misconfigured"
    except:
        pass
    return "Safe"

async def check_security_headers(session, url):
    try:
        async with session.get(url, timeout=10) as resp:
            headers = resp.headers
            missing = []
            for h in ["Content-Security-Policy", "X-Frame-Options", "X-XSS-Protection"]:
                if h not in headers:
                    missing.append(h)
            if missing:
                return f"Missing: {', '.join(missing)}"
    except:
        pass
    return "OK"

async def scan_target(session, url):
    return {
        "url": url,
        "xss": await check_xss(session, url),
        "redirect": await check_open_redirect(session, url),
        "cors": await check_cors(session, url),
        "headers": await check_security_headers(session, url)
    }

async def run_scanner(urls):
    results = []
    async with aiohttp.ClientSession(headers={"User-Agent": "HunterForge/1.0"}) as session:
        tasks = [scan_target(session, url) for url in urls]
        results = await asyncio.gather(*tasks)
    return results
