import re

# =======================================================
# Entity Extraction Patterns
# =======================================================

URL_PATTERN = re.compile(
    r"(https?://[^\s]+|www\.[^\s]+)",
    re.IGNORECASE
)

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

PHONE_PATTERN = re.compile(
    r"(?:\+91[- ]?)?[6-9]\d{9}"
)

UPI_PATTERN = re.compile(
    r"\b[a-zA-Z0-9._-]{2,}@[a-zA-Z]{2,}\b"
)

IFSC_PATTERN = re.compile(
    r"\b[A-Z]{4}0[A-Z0-9]{6}\b"
)

PAN_PATTERN = re.compile(
    r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"
)

AADHAAR_PATTERN = re.compile(
    r"\b\d{4}\s?\d{4}\s?\d{4}\b"
)

BANK_ACCOUNT_PATTERN = re.compile(
    r"\b\d{9,18}\b"
)

MONEY_PATTERN = re.compile(
    r"(₹\s?\d[\d,]*(?:\.\d+)?|Rs\.?\s?\d[\d,]*(?:\.\d+)?|INR\s?\d[\d,]*(?:\.\d+)?)",
    re.IGNORECASE
)

PERCENTAGE_PATTERN = re.compile(
    r"\b\d{1,3}(?:\.\d+)?%"
)

SEBI_PATTERN = re.compile(
    r"\b(?:INA|INZ|INS|INH)\d{9}\b",
    re.IGNORECASE
)

DATE_PATTERN = re.compile(
    r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b"
)

# =======================================================
# Fraud Detection Patterns
# =======================================================

GUARANTEED_RETURN_PATTERN = re.compile(
    r"(guaranteed|assured|risk[- ]?free|fixed\s+return|zero\s+risk)",
    re.IGNORECASE
)

HIGH_RETURN_PATTERN = re.compile(
    r"\b(\d{2,3})\s*%",
    re.IGNORECASE
)

URGENCY_PATTERN = re.compile(
    r"(urgent|act\s+now|today\s+only|limited\s+time|last\s+chance|offer\s+expires|immediately)",
    re.IGNORECASE
)

PAYMENT_REQUEST_PATTERN = re.compile(
    r"(transfer|pay|deposit|send|remit|wire|upi|bank)",
    re.IGNORECASE
)

OTP_PATTERN = re.compile(
    r"(otp|one\s*time\s*password)",
    re.IGNORECASE
)

PASSWORD_PATTERN = re.compile(
    r"(password|pin|cvv|mpin)",
    re.IGNORECASE
)

LOGIN_PATTERN = re.compile(
    r"(login|log\s*in|sign\s*in|verify\s+your\s+account)",
    re.IGNORECASE
)

QR_PATTERN = re.compile(
    r"(scan\s+the\s+qr|qr\s+code)",
    re.IGNORECASE
)

# =======================================================
# Suspicious URL Indicators
# =======================================================

SUSPICIOUS_DOMAINS = {

    "bit.ly",
    "tinyurl",
    "goo.gl",
    "ow.ly",
    "t.me",
    "telegram",
    "joinchat",
    "wa.me",
    "whatsapp",

}

# =======================================================
# Investment Keywords
# =======================================================

INVESTMENT_KEYWORDS = {

    "investment",
    "invest",
    "stock",
    "stocks",
    "share",
    "shares",
    "mutual fund",
    "mutual funds",
    "portfolio",
    "ipo",
    "equity",
    "returns",
    "profit",
    "profits",
    "wealth",
    "dividend",
    "trading",
    "forex",
    "crypto",
    "cryptocurrency"

}

# =======================================================
# Payment Keywords
# =======================================================

PAYMENT_KEYWORDS = {

    "transfer",
    "pay",
    "deposit",
    "wire",
    "upi",
    "bank",
    "neft",
    "rtgs",
    "imps",
    "remit"

}

# =======================================================
# Educational Keywords
# =======================================================

EDUCATIONAL_KEYWORDS = {

    "exam",
    "question",
    "semester",
    "assignment",
    "student",
    "college",
    "school",
    "syllabus",
    "laboratory",
    "lab",
    "university",
    "course",
    "lecture",
    "marks",
    "internal",
    "external"

}

# =======================================================
# Banking Keywords
# =======================================================

BANKING_KEYWORDS = {

    "bank",
    "account",
    "ifsc",
    "branch",
    "upi",
    "rtgs",
    "neft",
    "imps",
    "beneficiary"

}

# =======================================================
# Government Keywords
# =======================================================

GOVERNMENT_KEYWORDS = {

    "aadhaar",
    "pan",
    "passport",
    "government",
    "income tax",
    "gst",
    "municipality",
    "election",
    "ration"

}