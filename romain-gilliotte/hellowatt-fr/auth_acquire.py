import urllib.request
import urllib.parse
import http.cookiejar
import json
import time

# Global cookie jar to maintain session across requests
_cookie_jar = http.cookiejar.CookieJar()
_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(_cookie_jar))

def acquire_token():
    """
    Authenticate to HelloWatt using email and password.
    Returns session-based auth headers with CSRF token.
    """
    email = prompt_text("Email")
    password = prompt_secret("Password")
    
    login_url = "https://www.hellowatt.fr/accounts/login/"
    common_headers = {
        "accept": "application/json; version=1.54",
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
    }

    # Step 1: GET the login page to obtain the initial CSRF cookie
    preflight = urllib.request.Request(login_url, headers=common_headers)
    _opener.open(preflight)

    csrf_token = None
    for cookie in _cookie_jar:
        if cookie.name == "csrftoken":
            csrf_token = cookie.value
            break
    debug(f"Preflight CSRF token: {csrf_token}")

    # Step 2: POST login with CSRF token
    login_data = urllib.parse.urlencode({
        "login": email,
        "password": password,
    }).encode("utf-8")

    headers = {
        **common_headers,
        "content-type": "application/x-www-form-urlencoded",
        "referer": login_url,
        "x-csrftoken": csrf_token or "",
        "x-requested-with": "XMLHttpRequest",
    }

    request = urllib.request.Request(login_url, data=login_data, headers=headers)
    
    try:
        response = _opener.open(request)
        response_data = json.loads(response.read().decode("utf-8"))
        
        if response.status != 200:
            raise Exception(f"Login failed with status {response.status}")
        
        debug(f"Login response: {response_data}")
        
        # Extract cookies
        cookies = {cookie.name: cookie.value for cookie in _cookie_jar}
        debug(f"Cookies acquired: {list(cookies.keys())}")

        csrf_token = cookies.get("csrftoken")
        if not csrf_token:
            raise Exception("No CSRF token found in response cookies")

        cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())

        return {
            "headers": {
                "Cookie": cookie_header,
                "x-csrftoken": csrf_token,
                "accept": "application/json; version=1.54",
                "content-type": "application/json",
            },
            "expires_at": time.time() + 34560000,  # sessionid Max-Age
        }
    
    except Exception as e:
        raise Exception(f"Authentication failed: {str(e)}")
