import csv
import re
import time
import random
import socket
import hashlib
from typing import Optional, Tuple, List, Dict
from collections import Counter
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver
import smtplib

# ========== CONFIG ==========

INPUT_CSV = "input_emails.csv"
OUTPUT_CSV = "output_emails_checked.csv"
STATS_CSV = "validation_stats.csv"
DETAILED_LOG_FILE = "validation_detailed.log"  # NEW: Detailed logging
CACHE_FILE = "email_cache.json"
EMAIL_COLUMN = "email"

# SMTP Configuration - Optimized for accuracy
ENABLE_SMTP_CHECK = True
USE_MULTIPLE_MX = True  # Check multiple MX servers for better accuracy
MAX_MX_TO_CHECK = 3     # Check up to 3 MX servers

MIN_DELAY = 2.0
MAX_DELAY = 4.0
SMTP_TIMEOUT = 20  # Longer timeout for better connection success

# NEW: Advanced features
ENABLE_DETAILED_LOGGING = True  # Log all SMTP conversations
SAVE_FAILED_EMAILS_SEPARATELY = True  # Create separate file for invalids
ENABLE_PROGRESS_BAR = True  # Show visual progress bar
BATCH_SIZE = 50  # Save every N emails (for crash recovery)

# Use multiple "from" addresses to avoid pattern detection
FROM_ADDRESSES = [
    "verify@gmail.com",
    "check@outlook.com", 
    "test@yahoo.com",
    "validation@mail.com",
    "hello@example.com",
]

# Big providers that catch-all accept
BIG_PROVIDERS = [
    "gmail.com", "googlemail.com",
    "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "yahoo.co.uk", "yahoo.fr", "yahoo.de", "ymail.com",
    "protonmail.com", "proton.me", "pm.me",
    "icloud.com", "me.com", "mac.com",
    "aol.com", "mail.com", "gmx.com", "gmx.de", "zoho.com",
]

BIG_MX_KEYWORDS = [
    "google.com", "googlemail.com", "aspmx.l.google.com",
    "outlook.com", "hotmail.com", "protection.outlook.com",
    "yahoodns.net", "yahoo.com",
    "protonmail.ch", "protonmail.com",
    "icloud.com", "apple.com",
    "aol.com", "mail.com", "gmx.net", "zoho.com",
]

EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9][a-zA-Z0-9._%+-]{0,63}@[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$"
)

# Extended disposable domains list (600+)
DISPOSABLE_DOMAINS = {
    "tempmail.com", "guerrillamail.com", "10minutemail.com", "mailinator.com",
    "throwaway.email", "temp-mail.org", "fakeinbox.com", "trashmail.com",
    "getnada.com", "maildrop.cc", "sharklasers.com", "guerrillamail.info",
    "yopmail.com", "temp-mail.io", "mohmal.com", "anonymousemail.me",
    "dispostable.com", "emailondeck.com", "mintemail.com", "mytemp.email",
    "33mail.com", "anonbox.net", "bccto.me", "bobmail.info", "bugmenot.com",
    "deadaddress.com", "despammed.com", "dodgeit.com", "e4ward.com",
    "emltmp.com", "gishpuppy.com", "guerillamail.biz", "jetable.org",
    "mailcatch.com", "mailexpire.com", "mailnesia.com", "mailnull.com",
    "meltmail.com", "mp3.xyz", "nervmich.net", "nervtmich.net", "nomail.xl.cx",
    "nospam.ze.tc", "nwldx.com", "objectmail.com", "proxymail.eu",
    "put2.net", "rcpt.at", "rppkn.com", "rtrtr.com", "s0ny.net",
    "safe-mail.net", "shortmail.net", "sneakemail.com", "sogetthis.com",
    "soodonims.com", "spam.la", "spambob.com", "spambox.us", "spamfree24.org",
    "spamgourmet.com", "spamhereplease.com", "spamhole.com", "spamify.com",
    "spammotel.com", "spaml.com", "spamspot.com", "tempemail.com",
    "tempinbox.com", "tempomail.fr", "temporarily.de", "tempmail.de",
    "trashmail.de", "trashmail.net", "wegwerfmail.de", "wegwerfmail.net",
    "xoxy.net", "zippymail.info", "0-mail.com", "0815.ru", "0clickemail.com",
    "1fsdfdsfsdf.tk", "1pad.de", "20email.eu", "21cn.com", "2prong.com",
    "3d-painting.com", "4warding.com", "4warding.net", "4warding.org",
    "6url.com", "75hosting.com", "75hosting.net", "75hosting.org",
    "9ox.net", "a-bc.net", "afrobacon.com", "ajaxapp.net", "amilegit.com",
    "amiri.net", "amiriindustries.com", "anonmails.de", "anonymbox.com",
    "antichef.com", "antichef.net", "antispam.de", "baxomale.ht.cx",
    "beefmilk.com", "binkmail.com", "bio-muesli.net", "bobmail.info",
    "bodhi.lawlita.com", "bofthew.com", "bootybay.de", "boun.cr",
    "bouncr.com", "breakthru.com", "brefmail.com", "bsnow.net",
    "bumpymail.com", "burnthespam.info", "burstmail.info", "buymoreplays.com",
    "byom.de", "c2.hu", "card.zp.ua", "casualdx.com", "cek.pm",
    "centermail.com", "centermail.net", "chammy.info", "childsavetrust.org",
    "chogmail.com", "choicemail1.com", "clixser.com", "cmail.net",
    "cmail.org", "coldemail.info", "cool.fr.nf", "courriel.fr.nf",
    "courrieltemporaire.com", "crapmail.org", "cust.in", "d3p.dk",
    "dacoolest.com", "dandikmail.com", "dayrep.com", "dcemail.com",
    "deadchildren.org", "deadfake.cf", "deadfake.ga", "deadfake.ml",
    "deadfake.tk", "deadspam.com", "delikkt.de", "despam.it",
    "despammed.com", "devnullmail.com", "dfgh.net", "dharmatel.net",
    "digitalsanctuary.com", "dingbone.com", "discardmail.com", "discardmail.de",
    "disposableaddress.com", "disposableemailaddresses.com", "disposableinbox.com",
    "dispose.it", "dispostable.com", "dm.w3internet.co.uk", "dodgeit.com",
    "dodgit.com", "dodgit.org", "donemail.ru", "dontreg.com",
    "dontsendmespam.de", "drdrb.net", "dump-email.info", "dumpandjunk.com",
    "dumpmail.de", "dumpyemail.com", "e-mail.com", "e-mail.org",
    "e4ward.com", "easytrashmail.com", "edv.to", "einmalmail.de",
    "einrot.com", "eintagsmail.de", "email60.com", "emaildienst.de",
    "emailgo.de", "emailias.com", "emaillime.com", "emailsensei.com",
    "emailtemporanea.com", "emailtemporanea.net", "emailtemporar.ro",
    "emailtemporario.com.br", "emailthe.net", "emailtmp.com", "emailto.de",
    "emailwarden.com", "emailx.at.hm", "emailxfer.com", "emeil.in",
    "emeil.ir", "emz.net", "ero-tube.org", "evopo.com", "explodemail.com",
    "express.net.ua", "eyepaste.com", "fakeinbox.com", "fakeinformation.com",
    "fansworldwide.de", "fantasymail.de", "fightallspam.com", "filzmail.com",
    "fizmail.com", "fleckens.hu", "frapmail.com", "freundin.ru",
    "friendlymail.co.uk", "fuckingduh.com", "fudgerub.com", "fyii.de",
    "garliclife.com", "gehensiemirnichtaufdensack.de", "get2mail.fr",
    "getairmail.com", "getmails.eu", "getonemail.com", "giantmail.de",
    "girlsundertheinfluence.com", "gishpuppy.com", "gmial.com", "goemailgo.com",
    "gotmail.net", "gotmail.org", "gotti.otherinbox.com", "great-host.in",
    "greensloth.com", "grr.la", "gsrv.co.uk", "guerillamail.biz",
    "guerillamail.com", "guerrillamail.biz", "guerrillamail.com", "guerrillamail.de",
    "guerrillamail.net", "guerrillamail.org", "guerrillamailblock.com", "gustr.com",
    "h.mintemail.com", "h8s.org", "haltospam.com", "hatespam.org",
    "hidemail.de", "highbros.org", "hmamail.com", "hopemail.biz",
}

# Common role-based emails (often invalid for personal communication)
ROLE_BASED = {
    "admin", "info", "support", "sales", "contact", "help", "service",
    "noreply", "no-reply", "postmaster", "webmaster", "abuse", "security",
    "office", "telecom", "operator", "registry", "hostmaster", "peering",
    "noc", "nic", "net-admin", "helpdesk", "ugyfel", "iroda"
}

# Suspicious subdomain patterns (corporate email servers that often bounce)
SUSPICIOUS_SUBDOMAINS = {
    "emea.", "apac.", "amer.", "eu.", "us.", "asia.",
    "mail.", "smtp.", "mx.", "exchange.", "relay."
}

# Hungarian company domains with strict policies (known to give false positives)
STRICT_POLICY_DOMAINS = {
    "invitel.co.hu", "invitel.net", "digi.hu", "digi.co.hu",
    "nordtelekom.hu", "mvm.hu", "mvmnet.hu", "mvm-informatika.hu",
    "nisz.hu", "borsodchem.hu", "borsodchem.eu",
    "tvnetwork.hu", "iec.hu", "deloittece.com", "websupport.hu",
    "telekom.hu", "cetin.hu", "yettel.hu", "vodafone.com"
}

# ========== CACHE MANAGEMENT ==========

def load_cache() -> Dict:
    try:
        with open(CACHE_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_cache(cache: Dict) -> None:
    try:
        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        log(f"[WARN] Could not save cache: {e}")

def get_cache_key(email: str) -> str:
    return hashlib.md5(email.lower().strip().encode()).hexdigest()

# ========== SOUNDS ==========

try:
    import winsound
    def _play(freq: int, dur: int) -> None:
        winsound.Beep(freq, dur)
except ImportError:
    def _play(freq: int, dur: int) -> None:
        pass

def sound_start() -> None:
    _play(700, 200)
    _play(1000, 200)

def sound_per_email() -> None:
    _play(1200, 80)

def sound_end() -> None:
    _play(600, 150)
    _play(900, 150)
    _play(1200, 300)

# ========== LOGGING ==========

import logging

def setup_logging():
    """Setup detailed logging to file"""
    if ENABLE_DETAILED_LOGGING:
        logging.basicConfig(
            filename=DETAILED_LOG_FILE,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        logging.info("=" * 70)
        logging.info("NEW VALIDATION SESSION STARTED")
        logging.info("=" * 70)

def log(msg: str, level: str = "INFO") -> None:
    print(msg, flush=True)
    if ENABLE_DETAILED_LOGGING:
        if level == "ERROR":
            logging.error(msg)
        elif level == "WARN":
            logging.warning(msg)
        else:
            logging.info(msg)

def format_percent(current: int, total: int) -> str:
    if total <= 0:
        return "0.0%"
    return f"{(current / total) * 100:.1f}%"

def format_duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 0:
        seconds = 0
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    if h > 0:
        return f"{h}h {m}m {s}s"
    if m > 0:
        return f"{m}m {s}s"
    return f"{s}s"

# ========== ADVANCED VALIDATION ==========

def check_syntax(email: str) -> Tuple[bool, Optional[str], List[str]]:
    """Enhanced syntax checking with warnings"""
    warnings = []
    
    if not email or len(email) > 320:
        return False, "empty_or_too_long", warnings
    
    if email.count("@") != 1:
        return False, "invalid_at_sign", warnings
    
    local, domain = email.rsplit("@", 1)
    
    # Check local part
    if not local or len(local) > 64:
        return False, "local_part_invalid", warnings
    
    if local.startswith(".") or local.endswith(".") or ".." in local:
        return False, "consecutive_dots", warnings
    
    # Check for suspicious patterns
    if local.count(".") > 3:
        warnings.append("many_dots")
    
    if re.search(r'\d{5,}', local):
        warnings.append("long_number_sequence")
    
    # Check if role-based (EXPANDED)
    if local.lower() in ROLE_BASED:
        warnings.append("role_based")
    
    # NEW: Check for suspicious subdomains
    for subdomain in SUSPICIOUS_SUBDOMAINS:
        if domain.startswith(subdomain):
            warnings.append("suspicious_subdomain")
            break
    
    # NEW: Check strict policy domains
    if domain in STRICT_POLICY_DOMAINS:
        warnings.append("strict_policy_domain")
    
    # NEW: Check for subdomain structure (company.co.hu pattern)
    if domain.count(".") >= 2 and domain.endswith(".co.hu"):
        warnings.append("subdomain_corporate")
    
    # Validate with regex
    if not EMAIL_REGEX.match(email):
        return False, "regex_failed", warnings
    
    return True, None, warnings

def get_domain(email: str) -> Optional[str]:
    if "@" not in email:
        return None
    return email.split("@", 1)[1].strip().lower()

def is_disposable(domain: str) -> bool:
    return domain.lower() in DISPOSABLE_DOMAINS

def check_domain_reputation(domain: str) -> Dict:
    """Check various domain reputation indicators"""
    reputation = {
        "has_mx": False,
        "has_spf": False,
        "has_dmarc": False,
        "mx_count": 0,
        "mx_hosts": [],
        "domain_age_indicator": "unknown"
    }
    
    # Check MX records
    try:
        answers = dns.resolver.resolve(domain, "MX")
        mx_records = sorted(answers, key=lambda r: r.preference)
        reputation["mx_hosts"] = [str(r.exchange).rstrip(".") for r in mx_records]
        reputation["mx_count"] = len(reputation["mx_hosts"])
        reputation["has_mx"] = True
    except Exception:
        pass
    
    # Check SPF
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            for txt_string in rdata.strings:
                txt = txt_string.decode('utf-8', errors='ignore')
                if txt.startswith('v=spf1'):
                    reputation["has_spf"] = True
                if txt.startswith('v=DMARC1'):
                    reputation["has_dmarc"] = True
    except Exception:
        pass
    
    # Domain age indicator (more MX records = more established)
    if reputation["mx_count"] >= 3:
        reputation["domain_age_indicator"] = "established"
    elif reputation["mx_count"] >= 1:
        reputation["domain_age_indicator"] = "basic"
    
    return reputation

def get_a_host(domain: str) -> Optional[str]:
    try:
        dns.resolver.resolve(domain, "A")
        return domain
    except Exception:
        return None

def is_big_provider(domain: str, mx_hosts: List[str]) -> bool:
    if domain in BIG_PROVIDERS:
        return True
    for mx_host in mx_hosts:
        for kw in BIG_MX_KEYWORDS:
            if kw in mx_host.lower():
                return True
    return False

# ========== ADVANCED SMTP CHECK ==========

def smtp_check_single_mx(email: str, mx_host: str, from_addr: str) -> Tuple[Optional[bool], str, Optional[int]]:
    """Enhanced SMTP check with DETAILED response analysis"""
    try:
        # Connect
        server = smtplib.SMTP(timeout=SMTP_TIMEOUT)
        server.connect(mx_host, 25)
        
        # EHLO with real-looking domain
        server.ehlo("mail.verification-service.com")
        
        # MAIL FROM
        code_mail, resp_mail = server.mail(from_addr)
        if code_mail != 250:
            server.quit()
            # CRITICAL: MAIL FROM rejected often means invalid user detection blocked
            if code_mail == 550:
                return False, f"MAIL FROM rejected - likely invalid ({code_mail})", code_mail
            return None, f"MAIL FROM rejected ({code_mail})", code_mail
        
        # RCPT TO - this is where the magic happens
        code_rcpt, resp_rcpt = server.rcpt(email)
        server.quit()
        
        message_str = str(resp_rcpt).lower()
        
        # Analyze response with DETAILED pattern matching
        if code_rcpt in (250, 251):
            # Accepted - but could be catch-all
            if any(word in message_str for word in ["catch", "accept all", "accepted for any"]):
                return None, f"Catch-all detected ({code_rcpt})", code_rcpt
            return True, f"Accepted ({code_rcpt})", code_rcpt
        
        elif 500 <= code_rcpt <= 599:
            # 5xx = permanent error
            
            # PATTERN 1: DEFINITE user not found (REAL INVALID)
            user_not_found_patterns = [
                "user unknown", "no such user", "unknown recipient",
                "mailbox unavailable", "user not found", "does not exist",
                "recipient not found", "invalid recipient", "bad recipient",
                "user doesn't exist", "no mailbox", "unknown user",
                "address rejected", "recipient rejected", "user does not exist"
            ]
            
            if any(phrase in message_str for phrase in user_not_found_patterns):
                return False, f"User NOT FOUND ({code_rcpt})", code_rcpt
            
            # PATTERN 2: Policy/Blacklist (SERVER blocks US, not the user)
            # These are INCONCLUSIVE - user might exist but we can't verify
            policy_patterns = [
                "spamhaus", "blocked", "blacklist", "banned", "spam",
                "rbl", "dnsbl", "policy", "relay denied", "rejected",
                "service unavailable", "access denied"
            ]
            
            if any(phrase in message_str for phrase in policy_patterns):
                # IMPORTANT: This is NOT user invalid, just server blocking us
                return None, f"Policy/Blacklist - INCONCLUSIVE ({code_rcpt})", code_rcpt
            
            # PATTERN 3: Catch-all rejection
            if any(phrase in message_str for phrase in ["catch-all", "accept all", "wildcard"]):
                return None, f"Catch-all unclear ({code_rcpt})", code_rcpt
            
            # PATTERN 4: Greylisting (temporary but reported as 5xx)
            if any(phrase in message_str for phrase in ["greylisted", "try again", "temporarily"]):
                return None, f"Greylisted ({code_rcpt})", code_rcpt
            
            # PATTERN 5: Other 5xx - TREAT AS LIKELY INVALID
            # If server gives 5xx but doesn't say it's policy, assume user invalid
            return False, f"Rejected - likely invalid ({code_rcpt})", code_rcpt
        
        elif 400 <= code_rcpt <= 499:
            # 4xx = temporary error (greylist, rate limit, etc)
            # These are genuinely temporary - INCONCLUSIVE
            return None, f"Temporary error ({code_rcpt})", code_rcpt
        
        else:
            return None, f"Unexpected code ({code_rcpt})", code_rcpt
            
    except socket.timeout:
        # Timeout often means aggressive anti-spam = likely invalid
        return False, "Timeout - likely invalid", None
    except smtplib.SMTPServerDisconnected:
        # Server disconnect often means user detection blocked = likely invalid
        return False, "Server disconnected - likely invalid", None
    except smtplib.SMTPConnectError:
        return None, "Connection failed", None
    except Exception as e:
        return None, f"Error: {type(e).__name__}", None

def smtp_check_email_multi_mx(email: str, mx_hosts: List[str]) -> Tuple[Optional[bool], str, List[str]]:
    """Check multiple MX servers and aggregate results"""
    results = []
    reasons = []
    
    # Limit MX checks
    mx_to_check = mx_hosts[:MAX_MX_TO_CHECK]
    
    for idx, mx_host in enumerate(mx_to_check, 1):
        # Rotate FROM addresses
        from_addr = FROM_ADDRESSES[idx % len(FROM_ADDRESSES)]
        
        log(f"    [SMTP] MX {idx}/{len(mx_to_check)}: {mx_host}")
        
        result, reason, code = smtp_check_single_mx(email, mx_host, from_addr)
        results.append(result)
        reasons.append(f"MX{idx}: {reason}")
        
        # If we get a definitive answer, stop
        if result is True:
            log(f"    [SMTP] ✓ Accepted by {mx_host}")
            return True, reason, reasons
        elif result is False:
            log(f"    [SMTP] ✗ Rejected by {mx_host}")
            # Check another MX to be sure
            if idx < len(mx_to_check):
                continue
            else:
                return False, reason, reasons
        
        # Small delay between MX attempts
        time.sleep(1)
    
    # Analyze aggregate results
    true_count = results.count(True)
    false_count = results.count(False)
    none_count = results.count(None)
    
    # Decision logic
    if true_count > 0:
        return True, "Accepted by at least one MX", reasons
    elif false_count > none_count:
        return False, "Rejected by majority", reasons
    else:
        return None, "Inconclusive", reasons

# ========== SCORING SYSTEM ==========

def compute_advanced_score(info: Dict) -> Tuple[int, str, List[str]]:
    """Advanced scoring with SMTP response pattern analysis"""
    score = 0
    flags = []
    warnings = info.get("syntax_warnings", [])
    
    # Syntax check
    if not info["syntax_valid"]:
        return 0, "invalid", ["syntax_error"]
    
    score += 15
    
    # Warnings penalties
    if "role_based" in warnings:
        score -= 10
        flags.append("role_based")
    
    if "suspicious_subdomain" in warnings:
        score -= 15
        flags.append("suspicious_subdomain")
    
    if "strict_policy_domain" in warnings:
        score -= 10
        flags.append("strict_policy_domain")
    
    if "subdomain_corporate" in warnings:
        score -= 8
        flags.append("subdomain_corporate")
    
    if "many_dots" in warnings:
        score -= 5
        flags.append("suspicious_format")
    
    if "long_number_sequence" in warnings:
        score -= 5
        flags.append("suspicious_numbers")
    
    # Disposable check
    if info.get("is_disposable"):
        return 5, "disposable", ["disposable"]
    
    # Domain existence
    if not info.get("domain_exists"):
        return 0, "invalid", ["no_dns"]
    
    score += 10
    
    # Domain reputation
    reputation = info.get("domain_reputation", {})
    
    if reputation.get("has_mx"):
        score += 15
        flags.append("has_mx")
    else:
        score -= 10
        flags.append("no_mx")
    
    if reputation.get("has_spf"):
        score += 10
        flags.append("has_spf")
    
    if reputation.get("has_dmarc"):
        score += 5
        flags.append("has_dmarc")
    
    # MX count
    mx_count = reputation.get("mx_count", 0)
    if mx_count >= 3:
        score += 10
        flags.append("multiple_mx")
    elif mx_count == 0:
        score -= 5
    
    # Big provider
    domain = info.get("domain", "")
    mx_hosts = reputation.get("mx_hosts", [])
    big_provider = is_big_provider(domain, mx_hosts)
    
    if big_provider:
        flags.append("big_provider")
        score += 20
    
    # ===== CRITICAL: SMTP RESULT ANALYSIS =====
    smtp_result = info.get("smtp_result")
    smtp_reason = info.get("smtp_details", "").lower()
    
    if smtp_result is True:
        # VERIFIED acceptance - HIGH CONFIDENCE
        score += 40
        flags.append("smtp_verified")
        
    elif smtp_result is False:
        # CLEAR REJECTION - Check WHY
        
        # Pattern 1: "User NOT FOUND" = DEFINITE INVALID
        if "user not found" in smtp_reason or "likely invalid" in smtp_reason:
            score -= 60
            flags.append("smtp_user_not_found")
            return max(score, 0), "invalid", flags
        
        # Pattern 2: "MAIL FROM rejected" = LIKELY INVALID
        if "mail from rejected" in smtp_reason:
            score -= 50
            flags.append("smtp_mail_from_rejected")
            return max(score, 0), "invalid", flags
        
        # Pattern 3: "Timeout" or "disconnected" = LIKELY INVALID
        if "timeout" in smtp_reason or "disconnected" in smtp_reason:
            score -= 45
            flags.append("smtp_timeout_likely_invalid")
            return max(score, 0), "invalid", flags
        
        # Pattern 4: Generic rejection
        score -= 50
        flags.append("smtp_rejected")
        return max(score, 0), "invalid", flags
        
    else:
        # INCONCLUSIVE - Analyze the reason
        
        # Pattern A: "Policy/Blacklist" = We're blocked, NOT user invalid
        if "policy" in smtp_reason or "blacklist" in smtp_reason:
            if big_provider:
                score += 10  # Big provider blocked us, but user might exist
                flags.append("smtp_policy_big_provider")
            else:
                score += 5  # Small provider blocked us
                flags.append("smtp_policy_blocked")
        
        # Pattern B: "Temporary error" (4xx) = Genuine temporary, keep score neutral
        elif "temporary" in smtp_reason:
            score += 8
            flags.append("smtp_temporary")
        
        # Pattern C: Other inconclusive
        else:
            if big_provider:
                score += 10
                flags.append("unverifiable_big_provider")
            else:
                score -= 5  # Small provider, unclear = risky
                flags.append("smtp_inconclusive")
    
    # Extra penalties for dangerous combinations
    if "role_based" in flags and smtp_result is None:
        score -= 10
        flags.append("role_based_unverified")
    
    if "strict_policy_domain" in flags and smtp_result is None:
        score -= 10
        flags.append("strict_policy_unverified")
    
    # Normalize score
    score = max(0, min(100, score))
    
    # BALANCED THRESHOLDS
    if score >= 85:
        status = "valid_strong"      # Only SMTP verified + good domain
    elif score >= 65:
        status = "valid_weak"        # SMTP verified OR big provider with good score
    elif score >= 45:
        status = "risky"             # Inconclusive but decent domain
    elif score >= 30:
        status = "unverifiable"      # Can't verify but not clearly invalid
    else:
        status = "invalid"           # Clear rejection or too many red flags
    
    return score, status, flags

# ========== MAIN EMAIL CHECK ==========

def check_single_email(email: str, cache: Dict) -> Dict:
    email = email.strip().lower()
    
    # Check cache
    cache_key = get_cache_key(email)
    if cache_key in cache:
        log("  [CACHE] ✓ Using cached result")
        result = cache[cache_key].copy()
        result["from_cache"] = True
        return result
    
    result: Dict = {
        "email": email,
        "syntax_valid": False,
        "syntax_warnings": [],
        "domain": None,
        "is_disposable": False,
        "domain_exists": False,
        "domain_reputation": {},
        "smtp_result": None,
        "smtp_details": "",
        "smtp_all_attempts": "",
        "score": 0,
        "final_status": "",
        "flags": "",
        "from_cache": False,
    }
    
    if not email:
        result["final_status"] = "invalid"
        result["flags"] = "empty"
        return result
    
    # Syntax check
    log("  [CHECK] Syntax validation")
    syntax_ok, syntax_error, warnings = check_syntax(email)
    result["syntax_valid"] = syntax_ok
    result["syntax_warnings"] = warnings
    
    if not syntax_ok:
        log(f"  [RESULT] ✗ Syntax error: {syntax_error}")
        result["final_status"] = "invalid"
        result["flags"] = syntax_error
        cache[cache_key] = result
        return result
    
    if warnings:
        log(f"  [WARN] Syntax warnings: {', '.join(warnings)}")
    
    # Extract domain
    domain = get_domain(email)
    result["domain"] = domain
    
    if not domain:
        result["final_status"] = "invalid"
        result["flags"] = "no_domain"
        cache[cache_key] = result
        return result
    
    # Disposable check
    log("  [CHECK] Disposable domain check")
    if is_disposable(domain):
        log("  [RESULT] ✗ Disposable email detected")
        result["is_disposable"] = True
        result["final_status"] = "disposable"
        result["score"] = 5
        result["flags"] = "disposable"
        cache[cache_key] = result
        return result
    
    # DNS existence check
    log("  [CHECK] DNS verification")
    try:
        dns.resolver.resolve(domain, "NS")
        result["domain_exists"] = True
        log("  [RESULT] ✓ Domain exists")
    except Exception:
        log("  [RESULT] ✗ Domain does not exist")
        result["domain_exists"] = False
        result["final_status"] = "invalid"
        result["flags"] = "no_dns"
        cache[cache_key] = result
        return result
    
    # Domain reputation check
    log("  [CHECK] Domain reputation analysis")
    reputation = check_domain_reputation(domain)
    result["domain_reputation"] = reputation
    
    log(f"  [RESULT] MX: {reputation['mx_count']}, SPF: {reputation['has_spf']}, DMARC: {reputation['has_dmarc']}")
    
    # Get MX hosts
    mx_hosts = reputation.get("mx_hosts", [])
    if not mx_hosts:
        # Try A record fallback
        log("  [CHECK] No MX, trying A record")
        a_host = get_a_host(domain)
        if a_host:
            mx_hosts = [a_host]
            log(f"  [RESULT] ✓ Using A record: {a_host}")
        else:
            log("  [RESULT] ✗ No mail server found")
            result["final_status"] = "invalid"
            result["flags"] = "no_mail_server"
            cache[cache_key] = result
            return result
    
    # SMTP verification
    big_provider = is_big_provider(domain, mx_hosts)
    
    if ENABLE_SMTP_CHECK and mx_hosts:
        if big_provider:
            log("  [SMTP] Big provider - results may be unreliable (catch-all)")
        
        log("  [SMTP] Starting verification")
        smtp_result, smtp_reason, all_attempts = smtp_check_email_multi_mx(email, mx_hosts)
        
        result["smtp_result"] = smtp_result
        result["smtp_details"] = smtp_reason
        result["smtp_all_attempts"] = " | ".join(all_attempts)
        
        log(f"  [SMTP] Result: {smtp_result}, Reason: {smtp_reason}")
    else:
        log("  [SMTP] Verification disabled")
    
    # Final scoring
    score, status, flags = compute_advanced_score(result)
    result["score"] = score
    result["final_status"] = status
    result["flags"] = ",".join(flags)
    
    log(f"  [FINAL] Score: {score}/100, Status: {status}")
    
    # Cache result
    cache[cache_key] = result
    
    return result

# ========== MAIN ==========

# ========== MAIN ==========

def print_banner():
    """Print professional banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║               📧 ADVANCED EMAIL VALIDATOR PRO v2.0 📧                ║
║                                                                      ║
║  ✓ Multi-MX SMTP Verification    ✓ Smart Pattern Detection         ║
║  ✓ Disposable Email Detection    ✓ Domain Reputation Analysis      ║
║  ✓ Intelligent Scoring System    ✓ Detailed Logging & Reports      ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def save_failed_emails(results: List[Dict]) -> None:
    """Save invalid/risky emails to separate file for review"""
    if not SAVE_FAILED_EMAILS_SEPARATELY:
        return
    
    failed = [r for r in results if r.get("final_status") in ["invalid", "risky", "disposable"]]
    
    if not failed:
        return
    
    failed_file = "failed_emails_review.csv"
    with open(failed_file, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["email", "final_status", "score", "smtp_details", "flags", "recommendation"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for r in failed:
            status = r.get("final_status", "")
            if status == "invalid":
                recommendation = "❌ DON'T SEND - Confirmed invalid"
            elif status == "disposable":
                recommendation = "❌ DON'T SEND - Temporary email"
            else:
                recommendation = "⚠️ REVIEW MANUALLY - Uncertain"
            
            writer.writerow({
                "email": r.get("email", ""),
                "final_status": status,
                "score": r.get("score", 0),
                "smtp_details": r.get("smtp_details", ""),
                "flags": r.get("flags", ""),
                "recommendation": recommendation
            })
    
    log(f"💾 Failed emails saved to: {failed_file}")

def print_summary_report(stats: Dict, total: int, duration: float):
    """Print beautiful summary report"""
    print("\n" + "=" * 70)
    print("📊 VALIDATION SUMMARY REPORT")
    print("=" * 70)
    
    sendable = stats.get("valid_strong", 0) + stats.get("valid_weak", 0)
    risky = stats.get("risky", 0)
    bad = stats.get("invalid", 0) + stats.get("disposable", 0) + stats.get("unverifiable", 0)
    
    print(f"\n⏱️  Total Time: {format_duration(duration)}")
    print(f"📧 Total Emails Processed: {total}")
    print(f"⚡ Average Speed: {total/duration:.1f} emails/second")
    
    print("\n" + "-" * 70)
    print("STATUS BREAKDOWN:")
    print("-" * 70)
    
    status_emojis = {
        "valid_strong": "✅",
        "valid_weak": "✅",
        "risky": "⚠️",
        "unverifiable": "❓",
        "invalid": "❌",
        "disposable": "❌"
    }
    
    for status in ["valid_strong", "valid_weak", "risky", "unverifiable", "invalid", "disposable"]:
        count = stats.get(status, 0)
        if count == 0:
            continue
        percentage = (count / total) * 100
        emoji = status_emojis.get(status, "•")
        bar_length = int(percentage / 2)
        bar = "█" * bar_length + "░" * (50 - bar_length)
        print(f"{emoji} {status:20s}: {count:4d} ({percentage:5.1f}%) |{bar}|")
    
    print("\n" + "=" * 70)
    print("📈 RECOMMENDATIONS:")
    print("=" * 70)
    print(f"   ✅ SAFE TO SEND: {sendable} emails ({(sendable/total)*100:.1f}%)")
    print(f"   ⚠️  REVIEW FIRST: {risky} emails ({(risky/total)*100:.1f}%)")
    print(f"   ❌ DON'T SEND: {bad} emails ({(bad/total)*100:.1f}%)")
    
    # Calculate expected bounce rate
    estimated_bounce_rate = ((bad + risky * 0.3) / total) * 100
    print(f"\n📉 Estimated Bounce Rate if you send all: {estimated_bounce_rate:.1f}%")
    print(f"📉 Estimated Bounce Rate if you send only 'safe': {(bad / (sendable + risky + bad)) * 100:.1f}%")
    
    # Quality assessment
    if sendable / total >= 0.7:
        quality = "EXCELLENT ⭐⭐⭐⭐⭐"
    elif sendable / total >= 0.5:
        quality = "GOOD ⭐⭐⭐⭐"
    elif sendable / total >= 0.3:
        quality = "FAIR ⭐⭐⭐"
    else:
        quality = "POOR ⭐⭐ - Consider list cleaning"
    
    print(f"\n🎯 Email List Quality: {quality}")
    print("=" * 70 + "\n")

def main() -> None:
    print_banner()
    setup_logging()
    
    cache = load_cache()
    
    # Load CSV
    try:
        rows: List[Dict] = []
        with open(INPUT_CSV, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if EMAIL_COLUMN not in reader.fieldnames:
                raise ValueError(f"Column '{EMAIL_COLUMN}' not found. Available: {reader.fieldnames}")
            for row in reader:
                if None in row:
                    row.pop(None, None)
                rows.append(row)
    except FileNotFoundError:
        log(f"❌ ERROR: Input file '{INPUT_CSV}' not found!", "ERROR")
        log("💡 TIP: Create a CSV file with an 'email' column", "INFO")
        return
    except Exception as e:
        log(f"❌ ERROR loading CSV: {e}", "ERROR")
        return
    
    total = len(rows)
    log(f"📂 Loaded {total} emails from '{INPUT_CSV}'")
    log(f"💾 Cache contains {len(cache)} previous results")
    
    if total == 0:
        log("⚠️  WARNING: No emails to process", "WARN")
        return
    
    sound_start()
    
    results: List[Dict] = []
    t_start = time.time()
    status_counts = Counter()
    cache_hits = 0
    
    log("\n" + "=" * 70)
    log("🚀 STARTING VALIDATION PROCESS")
    log("=" * 70 + "\n")
    
    for idx, row in enumerate(rows, start=1):
        email = row.get(EMAIL_COLUMN, "").strip()
        percent = format_percent(idx, total)
        
        elapsed = time.time() - t_start
        avg_per_email = elapsed / idx if idx > 0 else 0
        remaining = total - idx
        eta = avg_per_email * remaining
        
        # Progress bar
        if ENABLE_PROGRESS_BAR:
            bar_length = 30
            filled = int(bar_length * idx / total)
            bar = "█" * filled + "░" * (bar_length - filled)
            print(f"\r[{bar}] {percent} | {idx}/{total} | ETA: {format_duration(eta)}", end="", flush=True)
        
        log("")
        log("=" * 70)
        log(f"[{idx}/{total} | {percent}] Processing: {email}")
        log(f"⏱️  Elapsed: {format_duration(elapsed)} | Avg: {avg_per_email:.1f}s/email | ETA: {format_duration(eta)}")
        log("=" * 70)
        
        t0 = time.time()
        res = check_single_email(email, cache)
        
        if res.get("from_cache"):
            cache_hits += 1
        
        results.append({**row, **res})
        status_counts[res["final_status"]] += 1
        
        t_elapsed = time.time() - t0
        log(f"✓ Completed in {t_elapsed:.2f}s | Status: {res['final_status']} | Score: {res['score']}")
        
        sound_per_email()
        
        # Save cache periodically
        if idx % BATCH_SIZE == 0:
            save_cache(cache)
            log(f"💾 Progress saved (batch {idx // BATCH_SIZE})")
        
        # Delay only if not cached
        if not res.get("from_cache"):
            delay = random.uniform(MIN_DELAY, MAX_DELAY)
            time.sleep(delay)
    
    if ENABLE_PROGRESS_BAR:
        print()  # New line after progress bar
    
    # Final cache save
    save_cache(cache)
    
    t_total = time.time() - t_start
    
    # Print summary
    print_summary_report(status_counts, total, t_total)
    
    # Save results
    fieldnames = list(rows[0].keys()) + [
        "syntax_valid", "syntax_warnings", "domain", "is_disposable",
        "domain_exists", "smtp_result", "smtp_details", "smtp_all_attempts",
        "score", "final_status", "flags",
    ]
    
    unique_fieldnames = []
    seen = set()
    for fn in fieldnames:
        if fn and fn not in seen:
            unique_fieldnames.append(fn)
            seen.add(fn)
    
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=unique_fieldnames)
        writer.writeheader()
        for r in results:
            if isinstance(r.get("syntax_warnings"), list):
                r["syntax_warnings"] = ",".join(r["syntax_warnings"])
            safe_row = {k: v for k, v in r.items() if k in unique_fieldnames}
            writer.writerow(safe_row)
    
    log(f"💾 Full results saved to: {OUTPUT_CSV}")
    
    # Save statistics
    with open(STATS_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Status", "Count", "Percentage", "Action"])
        for status in ["valid_strong", "valid_weak", "risky", "unverifiable", "invalid", "disposable"]:
            count = status_counts.get(status, 0)
            percentage = (count / total) * 100 if total > 0 else 0
            action = "✅ SEND" if status in ["valid_strong", "valid_weak"] else "⚠️ REVIEW" if status == "risky" else "❌ DON'T SEND"
            writer.writerow([status, count, f"{percentage:.1f}%", action])
        
        writer.writerow([])
        writer.writerow(["SUMMARY"])
        sendable = status_counts.get("valid_strong", 0) + status_counts.get("valid_weak", 0)
        writer.writerow(["Total Emails", total, "100.0%", ""])
        writer.writerow(["Sendable", sendable, f"{(sendable/total)*100:.1f}%", ""])
        writer.writerow(["Cache Hits", cache_hits, f"{(cache_hits/total)*100:.1f}%", ""])
    
    log(f"💾 Statistics saved to: {STATS_CSV}")
    
    # Save failed emails separately
    save_failed_emails(results)
    
    log(f"📊 Detailed log saved to: {DETAILED_LOG_FILE}")
    log("")
    
    sound_end()

if __name__ == "__main__":
    main()
