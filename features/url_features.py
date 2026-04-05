from urllib.parse import urlparse
import re

SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "bank",
    "paypal",
    "signin",
    "confirm",
    "password"
]


def extract_features(url):

    parsed = urlparse(url)

    features = {}

    # URL length
    features["url_length"] = len(url)

    # dot count
    features["num_dots"] = url.count(".")

    # digits
    features["num_digits"] = sum(c.isdigit() for c in url)

    # hyphens
    features["num_hyphens"] = url.count("-")

    # special characters
    features["special_chars"] = len(re.findall(r"[^a-zA-Z0-9]", url))

    # subdomain depth
    features["subdomain_depth"] = parsed.netloc.count(".")

    # https usage
    features["has_https"] = 1 if parsed.scheme == "https" else 0

    # IP address detection
    features["has_ip"] = 1 if re.match(r"\d+\.\d+\.\d+\.\d+", parsed.netloc) else 0

    # suspicious keyword detection
    features["suspicious_words"] = 1 if any(word in url.lower() for word in SUSPICIOUS_WORDS) else 0

    # @ symbol
    features["has_at_symbol"] = 1 if "@" in url else 0

    # double slash redirect
    features["double_slash_redirect"] = 1 if "//" in url[8:] else 0

    # prefix suffix in domain
    features["prefix_suffix"] = 1 if "-" in parsed.netloc else 0

    # path length
    features["path_length"] = len(parsed.path)

    # query length
    features["query_length"] = len(parsed.query)

    # fragment length
    features["fragment_length"] = len(parsed.fragment)

    # count parameters
    features["param_count"] = url.count("=")

    # ampersand count
    features["ampersand_count"] = url.count("&")

    # percent encoding
    features["percent_count"] = url.count("%")

    # question marks
    features["question_mark_count"] = url.count("?")

    # port in domain
    features["has_port"] = 1 if ":" in parsed.netloc else 0

    # domain length
    features["domain_length"] = len(parsed.netloc)

    return list(features.values()), features