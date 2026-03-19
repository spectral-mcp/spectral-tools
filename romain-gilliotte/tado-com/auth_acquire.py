import json
import base64
import hashlib
import secrets
import urllib.parse
import urllib.request
import urllib.error
import http.cookiejar

def acquire_token():
    """
    Implements OAuth 2.0 PKCE flow for tado.com authentication.
    Returns a dict with Authorization header containing Bearer token.
    """
    # Step 1: Get user credentials
    email = prompt_text("Email")
    password = prompt_secret("Password")
    
    # Step 2: Generate PKCE parameters
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode('utf-8').rstrip('=')
    
    # Step 3: Get authorization code via OAuth flow
    auth_code = _get_authorization_code(email, password, code_challenge)
    
    # Step 4: Exchange authorization code for tokens
    tokens = _exchange_code_for_tokens(auth_code, code_verifier)
    
    return {
        "headers": {
            "Authorization": f"Bearer {tokens['access_token']}"
        },
        "refresh_token": tokens.get("refresh_token"),
        "expires_in": tokens.get("expires_in", 600)
    }

def refresh_token(current_refresh_token):
    """
    Refreshes the access token using the refresh token.
    """
    tokens = _refresh_access_token(current_refresh_token)
    
    return {
        "headers": {
            "Authorization": f"Bearer {tokens['access_token']}"
        },
        "refresh_token": tokens.get("refresh_token", current_refresh_token),
        "expires_in": tokens.get("expires_in", 600)
    }

def _get_authorization_code(email, password, code_challenge):
    """
    Performs the login and returns the authorization code via OAuth flow.
    Uses a custom redirect handler to intercept the final authorization response.
    """
    client_id = "af44f89e-ae86-4ebe-905f-6bf759cf6473"
    redirect_uri = "https://app.tado.com/en/auth/authorize"
    state = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    
    # Create cookie jar to maintain session
    cookie_jar = http.cookiejar.CookieJar()
    
    # Custom redirect handler that captures the authorization code from Location headers
    class AuthCodeRedirectHandler(urllib.request.HTTPRedirectHandler):
        def __init__(self):
            self.auth_code = None
        
        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            # Check if this is the callback with the authorization code
            debug(f"Redirect {code} to: {newurl[:100]}")
            if 'code=' in newurl and 'app.tado.com' in newurl:
                parsed = urllib.parse.urlparse(newurl)
                params = urllib.parse.parse_qs(parsed.query)
                if 'code' in params:
                    self.auth_code = params['code'][0]
                    debug(f"Captured authorization code: {self.auth_code[:20]}...")
            return super().redirect_request(req, fp, code, msg, hdrs, newurl)
    
    redirect_handler = AuthCodeRedirectHandler()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cookie_jar),
        redirect_handler
    )
    
    # Step 1: POST login credentials to /oauth2/authorize
    login_data = {
        "loginId": email,
        "password": password,
        "client_id": client_id,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "home.user offline_access",
        "state": state,
        "tenantId": "1d543ad5-a8ac-4704-b9e2-26838b4d6513",
        "timezone": "Europe/Paris",
        "userVerifyingPlatformAuthenticatorAvailable": "true",
        "metaData.device.name": "Linux Chrome",
        "metaData.device.type": "BROWSER",
        "captcha_token": "",
        "nonce": "",
        "oauth_context": "",
        "pendingIdPLinkId": "",
        "response_mode": "",
        "user_code": ""
    }
    
    body = urllib.parse.urlencode(login_data).encode('utf-8')
    req = urllib.request.Request(
        "https://login.tado.com/oauth2/authorize",
        data=body,
        method="POST"
    )
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36")
    req.add_header("Origin", "https://login.tado.com")
    req.add_header("Referer", "https://login.tado.com/")
    
    try:
        resp = opener.open(req)
        debug(f"Login completed with status {resp.getcode()}")
    except urllib.error.HTTPError as e:
        debug(f"Login raised HTTPError {e.code}: {e.reason}")
        raise Exception(f"Login failed with status {e.code}")
    
    # Check if we captured the authorization code during redirects
    if redirect_handler.auth_code:
        debug(f"Authorization code captured from redirects: {redirect_handler.auth_code[:20]}...")
        return redirect_handler.auth_code
    
    raise Exception("Failed to capture authorization code from OAuth redirect chain")

def _exchange_code_for_tokens(code, code_verifier):
    """
    Exchanges authorization code for access and refresh tokens.
    """
    client_id = "af44f89e-ae86-4ebe-905f-6bf759cf6473"
    redirect_uri = "https://app.tado.com/en/auth/authorize"
    
    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": code_verifier,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "home.user offline_access"
    }
    
    body = urllib.parse.urlencode(token_data).encode('utf-8')
    req = urllib.request.Request(
        "https://login.tado.com/oauth2/token?ngsw-bypass=true",
        data=body,
        method="POST"
    )
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36")
    req.add_header("Origin", "https://app.tado.com")
    req.add_header("Referer", "https://app.tado.com/")
    
    try:
        resp = urllib.request.urlopen(req)
        response_body = json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8')
        raise Exception(f"Token exchange failed: {error_body}")
    
    if "access_token" not in response_body:
        raise Exception(f"No access token in response: {response_body}")
    
    debug(f"Access token obtained, expires in {response_body.get('expires_in')}s")
    
    return response_body

def _refresh_access_token(refresh_token_value):
    """
    Uses refresh token to obtain a new access token.
    """
    client_id = "af44f89e-ae86-4ebe-905f-6bf759cf6473"
    
    token_data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token_value,
        "client_id": client_id,
        "scope": "home.user offline_access"
    }
    
    body = urllib.parse.urlencode(token_data).encode('utf-8')
    req = urllib.request.Request(
        "https://login.tado.com/oauth2/token?ngsw-bypass=true",
        data=body,
        method="POST"
    )
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36")
    req.add_header("Origin", "https://app.tado.com")
    req.add_header("Referer", "https://app.tado.com/")
    
    try:
        resp = urllib.request.urlopen(req)
        response_body = json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8')
        raise Exception(f"Token refresh failed: {error_body}")
    
    if "access_token" not in response_body:
        raise Exception(f"No access token in refresh response: {response_body}")
    
    debug(f"Token refreshed, new token expires in {response_body.get('expires_in')}s")
    
    return response_body
