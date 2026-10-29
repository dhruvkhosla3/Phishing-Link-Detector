from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, unquote
from pathlib import Path
import json
import re

# ---------------- CONFIGURATION ----------------

BASE_DIR = Path(__file__).resolve().parent
PORT = 8000
HOST = "127.0.0.1"

MAX_REQUEST_SIZE = 16 * 1024

MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css":  "text/css; charset=utf-8",
    ".js":   "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png":  "image/png",
    ".jpg":  "image/jpeg",
    ".jpeg": "image/jpeg",
    ".ico":  "image/x-icon",
    ".svg":  "image/svg+xml",
}

# ---------------- KEYWORD LIST ----------------
# Any URL whose full text (scheme + domain + path + query) contains
# one of these words/phrases is flagged UNSAFE.

UNSAFE_KEYWORDS = {
    # ── Gambling & rummy ──────────────────────────────────────────────
    "rummy", "rummycircle", "rummy-circle", "rummytime", "rummy-time",
    "rummywealth", "rummygold", "rummyrich", "rummyking", "rummyplay",
    "rummyplus", "rummyroyal", "a23rummy", "a23games", "junglerummy",
    "gamezy", "mpl", "mpl-games", "winzo", "winzogames",
    "bet", "betting", "bets", "betway", "bet365", "1xbet", "betvisa",
    "dafabet", "parimatch", "sportsbet", "betfair", "melbet",
    "casino", "casinoonline", "casinobonus", "casinowin",
    "slot", "slots", "slotgame", "slotwin", "jackpot",
    "poker", "teenpatti", "teen-patti", "andar-bahar", "andarbahaar",
    "satta", "sattamatka", "matka", "lottery", "lotto",
    "keno", "bingo", "roulette", "blackjack",
    "gamble", "gambling", "gambler",
    "fantasy", "dream11", "myteam11", "teams11",

    # ── Money / financial fraud ───────────────────────────────────────
    "free-money", "freemoney", "getrich", "get-rich",
    "earn-daily", "earndaily", "daily-earning", "passive-income",
    "doubleup", "double-up", "doublemoney", "money-double",
    "money-making", "moneymaking",
    "instant-cash", "instantcash", "cash-reward", "cashreward",
    "cashback-offer", "paytm-cash", "upi-cash", "upi-reward",
    "money-transfer", "moneytransfer", "quickmoney", "quick-money",
    "money2", "moneyfast", "fastmoney", "fast-cash",
    "loan-offer", "loanoffer", "instant-loan", "easyloan",
    "loanapproval", "loan-approval", "personal-loan", "netloan",
    "credit-offer", "creditoffer", "creditscore-hack",

    # ── Scam / fraud generic ─────────────────────────────────────────
    "scam", "fraud", "fake", "hoax", "cheat", "cheating",
    "hack", "hacked", "hacker", "hacking",
    "phish", "phishing", "spoof", "spoofing",
    "malware", "virus", "trojan", "ransomware", "spyware",
    "clickbait", "click-here-now", "clicknow",

    # ── Prize & giveaway scams ────────────────────────────────────────
    "prize", "prize-winner", "prizewinner", "claim-prize", "claimprice",
    "you-won", "youwon", "youvewon", "winner-selected",
    "congratulations-winner", "free-gift", "freegift",
    "gift-card", "giftcard", "giftcardwin",
    "lucky-draw", "luckydraw", "lucky-winner", "luckyuser",
    "spin-win", "spinwin", "spin-and-win",
    "offer-claim", "offerclaim", "claim-reward", "claimreward",
    "limited-offer", "limitedoffer", "exclusive-offer",
    "special-offer", "specialoffer",

    # ── Crypto & NFT scams ────────────────────────────────────────────
    "crypto", "cryptocurrency", "cryptowin", "crypto-win",
    "bitcoin", "btc", "ethereum", "eth-airdrop",
    "airdrop", "nft-drop", "nftdrop", "nft-claim",
    "defi-earn", "defiearn", "yield-farm", "yieldfarming",
    "token-sale", "tokensale", "presale", "ico",
    "binance-reward", "coinbase-gift", "wallet-connect",
    "metamask-login", "trustwallet-claim",

    # ── Account / identity phishing ───────────────────────────────────
    "verify-account", "verifyaccount", "verify-now", "verifynow",
    "update-account", "updateaccount", "confirm-account",
    "account-suspended", "accountsuspended", "account-locked",
    "account-restricted", "account-recover",
    "unlock-account", "unlockaccount",
    "password-reset", "passwordreset", "reset-password",
    "change-password", "login-required", "loginrequired",
    "sign-in-alert", "signin-alert",
    "otp-verify", "otpverify", "otp-confirm",
    "2fa-bypass", "bypass-verification",

    # ── Banking & payment fraud ───────────────────────────────────────
    "bank-login", "banklogin", "netbanking-login",
    "netbanking-verify", "paytm-login", "googlepay-hack",
    "phonepe-fraud", "upi-fraud", "upifraud",
    "sbi-login", "icici-login", "hdfc-login", "axis-login",
    "fake-bank", "fakebank", "bankfraud",
    "credit-card-hack", "ccdetails", "card-details-steal",
    "atm-pin", "cvv-grab",

    # ── Adult / explicit ─────────────────────────────────────────────
    "porn", "xxx", "adult-only", "sex", "nude", "nudepic",
    "onlyfans-leak", "nsfw", "18plus",

    # ── Drug / illegal goods ─────────────────────────────────────────
    "buydrugs", "buy-drugs", "darkweb", "dark-web",
    "onion-market", "silkroad",

    # ── Survey / data harvesting ──────────────────────────────────────
    "survey-win", "surveywin", "survey-reward", "surveycash",
    "paid-survey", "take-survey",
    "fill-form-win", "formwin",

    # ── App / software piracy ─────────────────────────────────────────
    "mod-apk", "modapk", "cracked-apk", "crackedapp",
    "free-premium", "freepremium", "premium-unlock",
    "pirated", "piratebay",
    "serial-key", "serialkey", "activation-keygen", "keygen",

    # ── Social-engineering phrases ────────────────────────────────────
    "act-now", "act-immediately", "urgent-action",
    "final-warning", "finalwarning", "last-warning",
    "account-expire", "accountexpire", "subscription-expire",
    "service-suspended", "servicesuspended",
    "security-alert", "securityalert", "critical-alert",
    "suspicious-activity", "suspicious-login",
    "system-error-fix", "systemerrorfix",
    "click-to-claim", "clicktoclaim",
    "tap-to-win", "taptowin",
}

# ── Additional single-word unsafe terms (short, common in bad URLs) ──
UNSAFE_KEYWORDS.update({
    "win", "winning", "winner",
    "earn", "earning", "earnings",
    "money", "cash", "reward", "rewards",
    "invest", "investment", "returns",
    "rich", "wealth", "profit",
    "illegal", "banned", "darknet",
    "adult", "explicit",
    "download-virus", "installvirus",
})

# ── Compile each keyword into a word-boundary regex for accuracy ─────
_COMPILED_PATTERNS = [
    (kw, re.compile(r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])", re.IGNORECASE))
    for kw in sorted(UNSAFE_KEYWORDS)
]

# ---------------- URL VALIDATION ----------------

def _valid_prefix(url: str) -> bool:
    """Accept only http://, https://, or www. prefixes."""
    lower = url.lower()
    return (
        lower.startswith("http://")
        or lower.startswith("https://")
        or lower.startswith("www.")
    )


def _normalize_for_scan(url: str) -> str:
    """Return the full URL text lowercased and percent-decoded for scanning."""
    return unquote(url).lower()

# ---------------- CORE ANALYSIS ----------------

def analyze_url(url):
    """
    Check a URL and return a simple safe / unsafe verdict.

    Rules
    -----
    1. Input must be a non-empty string ≤ 4 096 characters.
    2. URL must start with http://, https://, or www.
    3. If any unsafe keyword is found anywhere in the URL → UNSAFE.
    4. Otherwise → SAFE.
    """
    # ── Input sanity ────────────────────────────────────────────────
    if not isinstance(url, str):
        return {"verdict": "error", "reason": "URL must be a string.", "matched_keywords": []}

    url = url.strip()

    if not url:
        return {"verdict": "error", "reason": "URL is empty.", "matched_keywords": []}

    if len(url) > 4096:
        return {"verdict": "error", "reason": "URL is too long (max 4 096 characters).", "matched_keywords": []}

    # ── Prefix check ────────────────────────────────────────────────
    if not _valid_prefix(url):
        return {
            "verdict": "error",
            "reason": "URL must start with http://, https://, or www.",
            "matched_keywords": [],
        }

    # ── Keyword scan ────────────────────────────────────────────────
    text = _normalize_for_scan(url)
    matched = [kw for kw, pattern in _COMPILED_PATTERNS if pattern.search(text)]

    if matched:
        return {
            "verdict": "unsafe",
            "reason": f"This URL contains known threat indicators.",
            "matched_keywords": sorted(matched),
        }

    return {
        "verdict": "safe",
        "reason": "No threat indicators detected. This URL appears clean.",
        "matched_keywords": [],
    }

# ---------------- HTTP SERVER ----------------

class RequestHandler(BaseHTTPRequestHandler):

    server_version = "PhishingDetector"
    sys_version = ""

    def log_message(self, format, *args):
        pass  # suppress default access logs

    def send_json(self, status_code, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type",  "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control",  "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        try:
            request_path = unquote(urlsplit(self.path).path)
            if request_path == "/":
                request_path = "/index.html"

            relative_path = request_path.lstrip("/")
            file_path = (BASE_DIR / relative_path).resolve()

            if not file_path.is_relative_to(BASE_DIR):
                self.send_error(403, "Forbidden")
                return

            if not file_path.is_file():
                self.send_error(404, "File not found")
                return

            content_type = MIME_TYPES.get(file_path.suffix.lower(), "application/octet-stream")
            content = file_path.read_bytes()

            self.send_response(200)
            self.send_header("Content-Type",   content_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(content)

        except (OSError, ValueError):
            self.send_error(400, "Unable to serve requested file")

    def do_POST(self):
        if urlsplit(self.path).path != "/check_url":
            self.send_json(404, {"error": "Endpoint not found."})
            return

        content_type = self.headers.get("Content-Type", "")
        if content_type.split(";")[0].strip().lower() != "application/json":
            self.send_json(415, {"error": "Content-Type must be application/json."})
            return

        try:
            length_header = self.headers.get("Content-Length")
            if length_header is None:
                self.send_json(411, {"error": "Content-Length is required."})
                return

            content_length = int(length_header)
            if content_length < 0:
                self.send_json(400, {"error": "Invalid content length."})
                return
            if content_length > MAX_REQUEST_SIZE:
                self.send_json(413, {"error": "Request body is too large."})
                return

            raw_body = self.rfile.read(content_length)
            data = json.loads(raw_body.decode("utf-8"))

            if not isinstance(data, dict):
                self.send_json(400, {"error": "JSON body must be an object."})
                return
            if "url" not in data:
                self.send_json(400, {"error": "Missing 'url' field."})
                return

            result = analyze_url(data["url"])

            if result.get("verdict") == "error":
                self.send_json(400, result)
                return

            self.send_json(200, result)

        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            self.send_json(400, {"error": "Invalid JSON or request data."})
        except (ConnectionError, OSError):
            return


# ---------------- START SERVER ----------------

def run():
    with ThreadingHTTPServer((HOST, PORT), RequestHandler) as server:
        print(f"Phishing detector running at http://{HOST}:{PORT}")
        print("Press Ctrl+C to stop.")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server...")


if __name__ == "__main__":
    run()
