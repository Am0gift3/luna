#!/usr/bin/env python3
"""
Secure Kali API Server v4.2 - NO SHELL INJECTION
================================================

Security:
- NO shell=True
- Whitelist + argument validation for all tools
- API-key auth, per-session + global rate limits
- Encrypted output with deterministic HMAC (survives restart)
- Path-traversal prevention + sensitive-file blacklist
- Privileged tool execution ONLY via sudo NOPASSWD (whitelisted tools)
- Multi-source CVE aggregation: NVD, IBM X-Force, CIRCL, Exploit-DB
- Anti-poisoning output filter with integrity validation
"""
import argparse, asyncio, base64, hashlib, hmac, json, logging, os
import re, secrets, shlex, shutil, signal, sys, time, unicodedata, ipaddress
from pathlib import Path
from typing import ClassVar, Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from functools import lru_cache

from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, Field, validator
import uvicorn

from dotenv import load_dotenv
load_dotenv()

# ============================================================================
# CONFIG
# ============================================================================

class Config:
    HOST = os.getenv("SECURE_SERVER_HOST", "127.0.0.1")
    PORT = int(os.getenv("SECURE_SERVER_PORT", "22163"))
    API_KEY = os.getenv("PENTEST_API_KEY", "")
    HMAC_SECRET = os.getenv("PENTEST_HMAC_SECRET", "")

    MAX_REQUESTS_PER_SECOND = float(os.getenv("MAX_REQUESTS_PER_SECOND", "5"))
    MAX_BURST = int(os.getenv("MAX_BURST_REQUESTS", "10"))
    GLOBAL_MAX_RPS = float(os.getenv("GLOBAL_MAX_RPS", "20"))
    GLOBAL_MAX_BURST = int(os.getenv("GLOBAL_MAX_BURST", "40"))
    MAX_CONCURRENT_EXECUTIONS = int(os.getenv("MAX_CONCURRENT_EXECUTIONS", "4"))
    COMMAND_TIMEOUT = int(os.getenv("COMMAND_TIMEOUT", "600"))
    MAX_OUTPUT_SIZE_MB = int(os.getenv("MAX_OUTPUT_SIZE_MB", "10"))
    SESSION_TIMEOUT_HOURS = int(os.getenv("SESSION_TIMEOUT_HOURS", "24"))
    ENCRYPTION_ENABLED = os.getenv("ENCRYPTION_ENABLED", "true").lower() == "true"
    SUDO_ENABLED = os.getenv("SUDO_ENABLED", "true").lower() == "true"
    DATABASE_PATH = os.getenv("DATABASE_PATH", "knowledge.db")
    ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1,::1").split(",")

    # [v4.2 FIX] Missing API keys — added
    NVD_API_KEY = os.getenv("NVD_API_KEY", "")
    IBM_XFORCE_API_KEY = os.getenv("IBM_XFORCE_API_KEY", "")
    IBM_XFORCE_API_PASSWORD = os.getenv("IBM_XFORCE_API_PASSWORD", "")
    VULNERS_API_KEY = os.getenv("VULNERS_API_KEY", "")
    WPSCAN_API_TOKEN = os.getenv("WPSCAN_API_TOKEN", "")
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

    @classmethod
    def get_hmac_secret(cls) -> bytes:
        if cls.HMAC_SECRET:
            return cls.HMAC_SECRET.encode()
        if cls.API_KEY:
            return cls.API_KEY.encode()
        return b"dev-insecure-hmac-secret-CHANGE-ME"

    @classmethod
    def validate(cls) -> bool:
        if not cls.API_KEY:
            print("WARNING: PENTEST_API_KEY not set - auth disabled!")
            return False
        return True


# Tools that MUST be run as root / CAP_NET_RAW (via sudo NOPASSWD)
PRIVILEGED_TOOLS = frozenset({
    "masscan", "aircrack-ng", "airodump-ng",
    "airmon-ng", "wifite", "responder",
})


# ============================================================================
# HELPERS
# ============================================================================

def safe_split(s: str) -> List[str]:
    """shlex.split with HTTP 400 on malformed input."""
    if not s or not s.strip():
        return []
    try:
        return shlex.split(s)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid argument syntax: {e}")


# ============================================================================
# SECURITY UTILITIES
# ============================================================================

class SecureCrypto:
    """Per-session encryption. HMAC key is deterministic (survives restart)."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        master = self._derive(session_id)
        self.cipher = Fernet(base64.urlsafe_b64encode(master))
        self.hmac_key = hashlib.sha256(master + b"::hmac").digest()

    def _derive(self, seed: str) -> bytes:
        key = Config.get_hmac_secret() + b"::" + seed.encode()
        for _ in range(50_000):
            key = hashlib.sha256(key).digest()
        return key

    def encrypt_output(self, data: str, tool: str, target: str) -> str:
        meta = {
            "tool": tool, "target": target,
            "timestamp": datetime.utcnow().isoformat(),
            "session": self.session_id,
            "hmac": self._hmac(data),
            "size_bytes": len(data),
        }
        return self.cipher.encrypt(json.dumps({"metadata": meta, "data": data}).encode()).decode()

    def decrypt_output(self, encrypted: str) -> Tuple[Optional[str], bool]:
        try:
            obj = json.loads(self.cipher.decrypt(encrypted.encode()).decode())
            if not hmac.compare_digest(self._hmac(obj["data"]), obj["metadata"]["hmac"]):
                return None, False
            return obj["data"], True
        except Exception:
            return None, False

    def _hmac(self, data: str) -> str:
        return hmac.new(self.hmac_key, data.encode(), hashlib.sha256).hexdigest()


class CommandValidator:
    """Per-tool whitelist + argument validation."""

    ALLOWED_COMMANDS = {
        "nmap":            {"max_args": 20, "forbidden_flags": ["--interactive","--unprivileged","--script","--script-args","-oA","-oN","-oX","-oG","-oS"], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'},
        "gobuster":        {"max_args": 15, "forbidden_flags": ["-o","--output"], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'},
        "dirb":            {"max_args": 10, "forbidden_flags": [], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'},
        "ffuf":            {"max_args": 15, "forbidden_flags": ["-o","--output"], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'},
        "nikto":           {"max_args": 10, "forbidden_flags": [], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'},
        "sqlmap":          {"max_args": 25, "forbidden_flags": ["--os-shell","--os-pwn","--sql-shell"], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'},
        "hydra":           {"max_args": 20, "forbidden_flags": [], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'},
        "john":            {"max_args": 15, "forbidden_flags": [], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'},
        "wpscan":          {"max_args": 15, "forbidden_flags": [], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'},
        "enum4linux":      {"max_args": 10, "forbidden_flags": [], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'},
        "curl":            {"max_args": 15, "forbidden_flags": ["-o","--output","-O","--remote-name"], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'},
        "aircrack-ng":     {"max_args": 10, "forbidden_flags": [], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'},
        "airodump-ng":     {"max_args": 10, "forbidden_flags": [], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'},
        "wifite":          {"max_args": 10, "forbidden_flags": [], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'},
        "airmon-ng":       {"max_args": 5,  "forbidden_flags": [], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'},
        "nc":              {"max_args": 10, "forbidden_flags": ["-e","--exec","-c"], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'},
        "cat":             {"max_args": 5,  "forbidden_flags": [], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'},
        "head":            {"max_args": 5,  "forbidden_flags": [], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'},
        "tail":            {"max_args": 5,  "forbidden_flags": [], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'},
        "amass":           {"max_args": 10, "forbidden_flags": ["-o","--output","-config"], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'},
        "subfinder":       {"max_args": 10, "forbidden_flags": ["-o","--output"], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'},
        "nuclei":          {"max_args": 20, "forbidden_flags": ["-o","--output","-interactsh"], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'},
        "masscan":         {"max_args": 15, "forbidden_flags": ["-o","--output","--output-format"], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'},
        "wfuzz":           {"max_args": 15, "forbidden_flags": ["-o","--output"], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'},
        "hashcat":         {"max_args": 15, "forbidden_flags": ["-o","--outfile","--potfile-path","--session","--restore"], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'},
        "searchsploit":    {"max_args": 10, "forbidden_flags": ["-o","--output","--json"], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'},
        "smbclient":       {"max_args": 10, "forbidden_flags": ["-c","--command","-O","--option","-d","--debuglevel"], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'},
        "snmpwalk":        {"max_args": 15, "forbidden_flags": [], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'},
        "ldapsearch":      {"max_args": 20, "forbidden_flags": [], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'},
        "responder":       {"max_args": 10, "forbidden_flags": ["-w","--wpad","-F","--force-wpad"], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'},
        "bloodhound-python":{"max_args":15, "forbidden_flags": [], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'},
        "whatweb":         {"max_args": 15, "forbidden_flags": ["-o","--output","-a","--aggression"], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'},
        "cewl":            {"max_args": 15, "forbidden_flags": ["-o","--output"], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'},
        "medusa":          {"max_args": 25, "forbidden_flags": ["-O","--output","-d","--debug"], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'},
        "dnsrecon":        {"max_args": 15, "forbidden_flags": ["-c","--csv","-j","--json","-x","--xml"], "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'},
    }

    DANGEROUS_PATTERNS = [
        r'[;&|`$]', r'\$\{.*\}', r'\\x[0-9a-f]{2}', r'%[0-9a-f]{2}',
        r'\.\./', r'base64\s+-d', r'curl\s+[^|]+\|\s*(?:sh|bash)',
        r'wget\s+[^|]+\|\s*(?:sh|bash)', r'/dev/tcp/',
        r'python[0-9.]*\s+-c', r'perl\s+-e', r'ruby\s+-e',
    ]

    @classmethod
    def validate_target(cls, target: str) -> Tuple[bool, str]:
        if not target or len(target) > 255:
            return False, "Invalid target length"
        target = unicodedata.normalize('NFKC', target.strip())
        for pat in cls.DANGEROUS_PATTERNS:
            if re.search(pat, target, re.IGNORECASE):
                return False, "Dangerous pattern detected"
        try:
            ipaddress.ip_address(target)
            return True, target
        except ValueError:
            pass
        if re.match(r'^[a-z0-9][a-z0-9\.-]+\.[a-z]{2,}$', target, re.IGNORECASE):
            return True, target
        return False, "Invalid target format"

    @classmethod
    def validate_command_args(cls, tool: str, args: List[str]) -> Tuple[bool, str, List[str]]:
        if tool not in cls.ALLOWED_COMMANDS:
            return False, f"Tool '{tool}' not whitelisted", []
        cfg = cls.ALLOWED_COMMANDS[tool]
        if len(args) > cfg["max_args"]:
            return False, f"Too many args (max {cfg['max_args']})", []
        for arg in args:
            for forbidden in cfg["forbidden_flags"]:
                if arg.startswith(forbidden):
                    return False, f"Forbidden flag: {forbidden}", []
        sanitized = []
        for arg in args:
            for pat in cls.DANGEROUS_PATTERNS:
                if re.search(pat, arg, re.IGNORECASE):
                    return False, f"Dangerous pattern in arg: {arg[:50]}", []
            if not re.match(cfg["allowed_pattern"], arg):
                if not (arg.startswith('/') or arg.startswith('./') or '.' in arg):
                    return False, f"Invalid chars: {arg[:50]}", []
            sanitized.append(arg)
        return True, "", sanitized


class AntiPoisoningFilter:
    # [v4.2 FIX] restored `fake_success` and `carriage_return`
    POISON_PATTERNS = [
        ("ansi_escape", r'\x1b\[[0-9;]*[a-zA-Z]', "medium"),
        ("null_byte", r'\x00', "critical"),
        ("backspace_override", r'.\x08', "medium"),
        ("injection_script", r'<script|javascript:|onload=', "high"),
        ("fake_success", r'(?i)success.*?but.*?not', "medium"),
        ("eval_call", r'eval\(|exec\(|system\(', "critical"),
        ("data_uri", r'data:[a-z]+/[a-z]+;base64,', "high"),
        ("carriage_return", r'\r[^\n]', "low"),
        ("unprintable", r'[\x00-\x08\x0b\x0c\x0e-\x1f]', "medium"),
    ]

    @classmethod
    def filter_output(cls, output: str, skip_binary: bool = False) -> Tuple[str, List[Dict]]:
        warnings = []
        if skip_binary:
            return output, warnings
        filtered = output
        for name, pat, sev in cls.POISON_PATTERNS:
            matches = re.findall(pat, filtered, re.IGNORECASE)
            if matches:
                warnings.append({"name": name, "severity": sev, "count": len(matches)})
                filtered = re.sub(pat, f'[{name}_removed]', filtered)
        filtered = filtered.replace('\x00', '')
        return filtered, warnings

    # [v4.2 FIX] restored the removed method
    @classmethod
    def validate_output_integrity(cls, output: str) -> Tuple[bool, List[str]]:
        """Check if output appears legitimate (sanity heuristics)."""
        issues: List[str] = []

        # Unrealistic success counts
        if "found" in output.lower() or "success" in output.lower():
            matches = re.findall(r'(\d+)\s*(?:found|success)', output.lower())
            total = sum(int(m) for m in matches if m.isdigit())
            if total > 10000:
                issues.append(f"Unusually high success count: {total}")

        # Oversized output
        limit = Config.MAX_OUTPUT_SIZE_MB * 1024 * 1024
        if len(output) > limit:
            issues.append(f"Output size exceeds {Config.MAX_OUTPUT_SIZE_MB}MB")

        # Suspicious binary bytes in text stream
        if any(ord(c) < 32 and c not in '\n\r\t' for c in output[:1000]):
            issues.append("Binary data detected in output")

        return len(issues) == 0, issues


class RateLimiter:
    def __init__(self, rate: float = 5.0, burst: int = 10):
        self.rate, self.burst = rate, burst
        self.tokens, self.last_refill = burst, time.time()
        self.lock = asyncio.Lock()

    async def acquire(self) -> bool:
        async with self.lock:
            now = time.time()
            self.tokens = min(self.burst, self.tokens + (now - self.last_refill) * self.rate)
            self.last_refill = now
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False

    # [v4.2 FIX] restored helper
    async def wait_and_acquire(self) -> None:
        """Block until a token is available."""
        while not await self.acquire():
            await asyncio.sleep(0.1)


# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class NmapRequest(BaseModel):
    target: str
    scan_type: str = "-sV"
    ports: Optional[str] = None
    additional_args: str = ""

    @validator('target')
    def _t(cls, v):
        ok, msg = CommandValidator.validate_target(v)
        if not ok: raise ValueError(msg)
        return v

    @validator('ports')
    def _p(cls, v):
        if v and not re.match(r'^[\d,-]+$', v):
            raise ValueError("Ports must be digits/commas/hyphens")
        return v


class GobusterRequest(BaseModel):
    url: str
    mode: str = "dir"
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    additional_args: str = ""
    
    @validator('url')
    def _u(cls, v):
        v = v.strip()
        # 👇 Auto-add http:// if missing
        if not v.startswith(('http://', 'https://')):
            v = 'http://' + v
        if ' ' in v:
            raise ValueError("URL cannot contain spaces")
        return v

    @validator('url')
    def _u(cls, v):
        if not v.startswith(('http://','https://')) or ' ' in v:
            raise ValueError("URL must start with http(s):// and have no spaces")
        return v

    @validator('wordlist')
    def _w(cls, v):
        p = Path(v)
        if not p.exists(): raise ValueError(f"Wordlist not found: {v}")
        if p.stat().st_size > 100*1024*1024: raise ValueError("Wordlist too large (>100MB)")
        return v


class SqlmapRequest(BaseModel):
    url: str
    data: Optional[str] = None
    additional_args: str = ""

    @validator('url')
    def _u(cls, v):
        v = v.strip()
        if not v.startswith(('http://','https://')): v = 'http://' + v
        return v

    @validator('url')
    def _u(cls, v):
        if not v.startswith(('http://','https://')): raise ValueError("Invalid URL")
        return v


class HydraRequest(BaseModel):
    target: str
    service: str
    username: Optional[str] = None
    username_file: Optional[str] = None
    password: Optional[str] = None
    password_file: Optional[str] = None
    additional_args: str = ""

    @validator('target')
    def _t(cls, v):
        ok, msg = CommandValidator.validate_target(v)
        if not ok: raise ValueError(msg)
        return v

    @validator('service')
    def _s(cls, v):
        if v not in ["ssh","ftp","http-get","http-post","https-get","https-post","smb","rdp","mysql","postgresql"]:
            raise ValueError("Invalid service")
        return v

    @validator('username_file','password_file')
    def _f(cls, v):
        if v:
            p = Path(v)
            if not p.exists(): raise ValueError(f"File not found: {v}")
            if p.stat().st_size > 50*1024*1024: raise ValueError("File too large (>50MB)")
        return v


class DirbRequest(BaseModel):
    url: str
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    additional_args: str = ""

    @validator('url')
    def _u(cls, v):
        if not v.startswith(('http://','https://')): raise ValueError("Invalid URL")
        return v


class FfufRequest(BaseModel):
    url: str
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    match_code: str = "200,204,301,302,307,401,403,405"
    filter_size: str = ""
    additional_args: str = ""

    @validator('url')
    def _u(cls, v):
        if not v.startswith(('http://','https://')): raise ValueError("Invalid URL")
        if "FUZZ" not in v: raise ValueError("URL must contain 'FUZZ'")
        return v


class NiktoRequest(BaseModel):
    target: str
    additional_args: str = ""

    @validator('target')
    def _t(cls, v):
        ok, msg = CommandValidator.validate_target(v)
        if not ok: raise ValueError(msg)
        return v


class WpscanRequest(BaseModel):
    url: str
    additional_args: str = ""

    @validator('url')
    def _u(cls, v):
        if not v.startswith(('http://','https://')): raise ValueError("Invalid URL")
        return v

    @validator('url')
    def _u(cls, v):
        v = v.strip()
        if not v.startswith(('http://','https://')): v = 'http://' + v
        return v

class CurlRequest(BaseModel):
    url: str
    method: str = "GET"
    headers: Dict[str, str] = {}
    data: str = ""

    @validator('url')
    def _u(cls, v):
        v = v.strip()
        if not v.startswith(('http://','https://')): v = 'http://' + v
        return v

    @validator('url')
    def _u(cls, v):
        if not v.startswith(('http://','https://')): raise ValueError("Invalid URL")
        return v

    @validator('method')
    def _m(cls, v):
        if v.upper() not in ["GET","POST","PUT","DELETE","HEAD","OPTIONS","PATCH"]:
            raise ValueError("Invalid method")
        return v.upper()

    @validator('headers')
    def _h(cls, v):
        for k, val in v.items():
            if not re.match(r'^[a-zA-Z0-9\-_]+$', k):
                raise ValueError(f"Invalid header name: {k}")
            if any(c in val for c in ('\r','\n','\x00')):
                raise ValueError(f"Header value has CRLF/NUL: {k}")
        return v


class ReadFileRequest(BaseModel):
    path: str
    max_lines: int = 1000
    command: str = "cat"

    SENSITIVE_PREFIXES: ClassVar[Tuple[str, ...]] = (
        "/etc/shadow", "/etc/gshadow", "/etc/sudoers",
        "/etc/ssh/ssh_host_", "/etc/ssl/private/", "/root/",
    )

    @validator('path')
    def _p(cls, v):
        if '..' in v or not v.startswith('/'):
            raise ValueError("Absolute path required (no '..')")
        resolved = str(Path(v).resolve())
        for prefix in cls.SENSITIVE_PREFIXES:
            if resolved.startswith(prefix):
                raise ValueError(f"File not readable: {v}")
        safe_dirs = ['/tmp','/var/log','/etc','/usr/share']
        if not any(resolved.startswith(sd) for sd in safe_dirs):
            raise ValueError(f"Path must be under: {', '.join(safe_dirs)}")
        if not Path(v).exists():
            raise ValueError(f"File not found: {v}")
        return v

    @validator('max_lines')
    def _m(cls, v):
        if v < 1 or v > 10000: raise ValueError("max_lines must be 1..10000")
        return v


class JohnRequest(BaseModel):
    hash_file: str
    wordlist: str = "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt"
    format_type: str = ""
    additional_args: str = ""

    @validator('hash_file')
    def _h(cls, v):
        p = Path(v)
        if not p.exists(): raise ValueError(f"Hash file not found: {v}")
        if p.stat().st_size > 10*1024*1024: raise ValueError("Hash file too large")
        return v


class NetcatRequest(BaseModel):
    host: str
    port: int

    @validator('host')
    def _h(cls, v):
        ok, msg = CommandValidator.validate_target(v)
        if not ok: raise ValueError(msg)
        return v

    @validator('port')
    def _p(cls, v):
        if v < 1 or v > 65535: raise ValueError("Invalid port")
        return v


class Aircrack_ngRequest(BaseModel):
    output_file: str
    wordlist: str = "/usr/share/wordlists/rockyou.txt"
    additional_args: str = ""

    @validator('output_file')
    def _o(cls, v):
        p = Path(v)
        if not p.exists(): raise ValueError(f"Capture file not found: {v}")
        if p.stat().st_size > 500*1024*1024: raise ValueError("Capture file too large (>500MB)")
        if not v.endswith(('.cap','.pcap','.ivs')):
            raise ValueError("Capture must end with .cap, .pcap, or .ivs")
        return v

    @validator('wordlist')
    def _w(cls, v):
        p = Path(v)
        if not p.exists(): raise ValueError(f"Wordlist not found: {v}")
        if p.stat().st_size > 100*1024*1024: raise ValueError("Wordlist too large")
        return v


class AmassRequest(BaseModel):
    target: str
    additional_args: str = ""

    @validator('target')
    def _t(cls, v):
        ok, msg = CommandValidator.validate_target(v)
        if not ok: raise ValueError(msg)
        return v


class SubfinderRequest(BaseModel):
    target: str
    additional_args: str = ""

    @validator('target')
    def _t(cls, v):
        ok, msg = CommandValidator.validate_target(v)
        if not ok: raise ValueError(msg)
        return v


class NucleiRequest(BaseModel):
    target: str
    templates: Optional[str] = None
    severity: Optional[str] = None
    additional_args: str = ""

    @validator('target')
    def _t(cls, v):
        if not v.startswith(('http://','https://')) and not re.match(r'^[0-9.]+$', v):
            raise ValueError("Target must be URL or IP")
        return v

    @validator('severity')
    def _s(cls, v):
        if v and v not in ["low","medium","high","critical"]:
            raise ValueError("Invalid severity")
        return v


class MasscanRequest(BaseModel):
    target: str
    ports: str = "1-65535"
    rate: int = 1000
    additional_args: str = ""

    @validator('target')
    def _t(cls, v):
        if '/' in v:
            try:
                ipaddress.ip_network(v, strict=False)
                return v
            except ValueError:
                raise ValueError("Invalid CIDR")
        ok, msg = CommandValidator.validate_target(v)
        if not ok: raise ValueError(msg)
        return v

    @validator('ports')
    def _p(cls, v):
        if not re.match(r'^[\d,-]+$', v): raise ValueError("Invalid ports")
        return v

    @validator('rate')
    def _r(cls, v):
        if v < 1 or v > 100000: raise ValueError("rate 1..100000")
        return v


class WfuzzRequest(BaseModel):
    url: str
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    payload: str = "FUZZ"
    filter_code: str = ""
    additional_args: str = ""

    @validator('url')
    def _u(cls, v):
        if not v.startswith(('http://','https://')) or "FUZZ" not in v:
            raise ValueError("URL must be http(s) and contain FUZZ")
        return v

    @validator('wordlist')
    def _w(cls, v):
        p = Path(v)
        if not p.exists(): raise ValueError(f"Wordlist not found: {v}")
        if p.stat().st_size > 100*1024*1024: raise ValueError("Wordlist too large")
        return v


class AirodumpNgRequest(BaseModel):
    interface: str
    bssid: Optional[str] = None
    channel: Optional[int] = None
    output_file: str = "/tmp/airodump_output"
    additional_args: str = ""

    @validator('interface')
    def _i(cls, v):
        if not re.match(r'^[a-zA-Z0-9_]+$', v): raise ValueError("Invalid interface")
        return v

    @validator('channel')
    def _c(cls, v):
        if v is not None and (v < 1 or v > 165): raise ValueError("Channel 1..165")
        return v

    @validator('output_file')
    def _o(cls, v):
        if not str(Path(v).resolve()).startswith('/tmp'):
            raise ValueError("Output must be in /tmp")
        if not v.endswith('.cap'): v += '.cap'
        return v


class WifiteRequest(BaseModel):
    target_bssid: Optional[str] = None
    target_essid: Optional[str] = None
    interface: str = "wlan0mon"
    attack_type: str = "wpa"
    additional_args: str = ""

    @validator('target_bssid')
    def _b(cls, v):
        if v and not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', v):
            raise ValueError("Invalid BSSID")
        return v

    @validator('attack_type')
    def _a(cls, v):
        if v not in ["wpa","wps","all"]: raise ValueError("Invalid attack_type")
        return v


class AirmonNgRequest(BaseModel):
    action: str
    interface: str = "wlan0"

    @validator('action')
    def _a(cls, v):
        if v not in ["start","stop","check"]: raise ValueError("Invalid action")
        return v

    @validator('interface')
    def _i(cls, v):
        if not re.match(r'^[a-zA-Z0-9_]+$', v): raise ValueError("Invalid interface")
        return v


class Enum4linuxRequest(BaseModel):
    target: str
    additional_args: str = "-a"

    @validator('target')
    def _t(cls, v):
        ok, msg = CommandValidator.validate_target(v)
        if not ok: raise ValueError(msg)
        return v


class HashcatRequest(BaseModel):
    hash_file: str
    wordlist: str = "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt"
    hash_type: str = "0"
    additional_args: str = ""

    @validator('hash_file')
    def _h(cls, v):
        p = Path(v)
        if not p.exists(): raise ValueError(f"Hash file not found: {v}")
        if p.stat().st_size > 10*1024*1024: raise ValueError("Hash file too large")
        return v

    @validator('wordlist')
    def _w(cls, v):
        p = Path(v)
        if not p.exists(): raise ValueError(f"Wordlist not found: {v}")
        if p.stat().st_size > 100*1024*1024: raise ValueError("Wordlist too large")
        return v


class SearchsploitRequest(BaseModel):
    term: str
    category: Optional[str] = None
    exact: bool = False
    additional_args: str = ""

    @validator('term')
    def _t(cls, v):
        if not v or len(v) < 2: raise ValueError("Term must be >=2 chars")
        if not re.match(r'^[a-zA-Z0-9\s\-\._]+$', v):
            raise ValueError("Invalid characters in term")
        return v

    @validator('category')
    def _c(cls, v):
        if v and v not in ["remote","local","dos","webapps","hardware","multiple"]:
            raise ValueError("Invalid category")
        return v


class CveSearchRequest(BaseModel):
    keyword: str = ""
    cve_id: Optional[str] = None
    cvss_min: Optional[float] = None
    cvss_max: Optional[float] = None
    cpe: Optional[str] = None

    @validator('cve_id')
    def _c(cls, v):
        if v and not re.match(r'^CVE-\d{4}-\d{4,}$', v, re.IGNORECASE):
            raise ValueError("Invalid CVE ID")
        return v

    @validator('cvss_min','cvss_max')
    def _cv(cls, v):
        if v is not None and (v < 0 or v > 10): raise ValueError("CVSS 0..10")
        return v


class SmbclientRequest(BaseModel):
    host: str
    share: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    additional_args: str = ""

    @validator('host')
    def _h(cls, v):
        ok, msg = CommandValidator.validate_target(v)
        if not ok: raise ValueError(msg)
        return v


class SnmpwalkRequest(BaseModel):
    target: str
    community: str = "public"
    version: str = "2c"
    oid: str = "1.3.6.1.2.1.1"
    additional_args: str = ""

    @validator('target')
    def _t(cls, v):
        ok, msg = CommandValidator.validate_target(v)
        if not ok: raise ValueError(msg)
        return v

    @validator('version')
    def _v(cls, v):
        if v not in ["1","2c","3"]: raise ValueError("Version must be 1, 2c, or 3")
        return v


class LdapsearchRequest(BaseModel):
    host: str
    port: int = 389
    base_dn: str = ""
    filter: str = "(objectClass=*)"
    attributes: str = ""
    bind_dn: str = ""
    bind_password: str = ""
    additional_args: str = ""

    @validator('host')
    def _h(cls, v):
        ok, msg = CommandValidator.validate_target(v)
        if not ok: raise ValueError(msg)
        return v

    @validator('port')
    def _p(cls, v):
        if v < 1 or v > 65535: raise ValueError("Invalid port")
        return v


class ResponderRequest(BaseModel):
    interface: str = "eth0"
    additional_args: str = ""

    @validator('interface')
    def _i(cls, v):
        if not re.match(r'^[a-zA-Z0-9_]+$', v): raise ValueError("Invalid interface")
        return v


class BloodhoundRequest(BaseModel):
    domain: str
    username: str
    password: str
    nameserver: Optional[str] = None
    collection_method: str = "all"
    additional_args: str = ""

    @validator('domain')
    def _d(cls, v):
        if not re.match(r'^[a-z0-9\.\-]+$', v, re.IGNORECASE): raise ValueError("Invalid domain")
        return v

    @validator('collection_method')
    def _c(cls, v):
        if v not in ["all","session","trusts","acl","objectprops","group","localadmin","rdp","dcom","psremote"]:
            raise ValueError("Invalid collection_method")
        return v


class WhatwebRequest(BaseModel):
    target: str
    additional_args: str = ""

    @validator('target')
    def _t(cls, v):
        if not v.startswith(('http://','https://')): raise ValueError("URL required")
        return v


class CewlRequest(BaseModel):
    target: str
    depth: int = 2
    min_word_length: int = 3
    additional_args: str = ""

    @validator('target')
    def _t(cls, v):
        if not v.startswith(('http://','https://')): raise ValueError("URL required")
        return v

    @validator('depth')
    def _d(cls, v):
        if v < 1 or v > 10: raise ValueError("Depth 1..10")
        return v


class MedusaRequest(BaseModel):
    host: str
    service: str
    username: str = ""
    username_file: str = ""
    password: str = ""
    password_file: str = ""
    additional_args: str = ""

    @validator('host')
    def _h(cls, v):
        ok, msg = CommandValidator.validate_target(v)
        if not ok: raise ValueError(msg)
        return v

    @validator('service')
    def _s(cls, v):
        if v not in ["ssh","ftp","http","https","smb","rdp","mysql","postgresql","telnet","vnc"]:
            raise ValueError("Invalid service")
        return v


class DnsreconRequest(BaseModel):
    target: str
    type: str = "std"
    additional_args: str = ""

    @validator('target')
    def _t(cls, v):
        ok, msg = CommandValidator.validate_target(v)
        if not ok:
            if not re.match(r'^[a-z0-9][a-z0-9\.-]+\.[a-z]{2,}$', v, re.IGNORECASE):
                raise ValueError("Invalid target")
        return v

    @validator('type')
    def _ty(cls, v):
        if v not in ["std","brt","axfr","srv","zonewalk"]:
            raise ValueError("Invalid type")
        return v


class SessionInitRequest(BaseModel):
    session_id: Optional[str] = None
    output_dir: Optional[str] = None

    @validator('output_dir')
    def _o(cls, v):
        if v:
            if '..' in v or not v.startswith('/'):
                raise ValueError("output_dir must be absolute (no '..')")
        return v


# ============================================================================
# SECURE COMMAND EXECUTOR
# ============================================================================

class SecureCommandExecutor:
    def __init__(self):
        self.active_processes: Dict[int, asyncio.subprocess.Process] = {}
        self.output_limit = Config.MAX_OUTPUT_SIZE_MB * 1024 * 1024
        self._sem = asyncio.Semaphore(Config.MAX_CONCURRENT_EXECUTIONS)

    async def execute(self, command_parts: List[str], timeout: Optional[int] = None,
                      cwd: Optional[Path] = None, env: Optional[Dict] = None) -> Dict[str, Any]:
        if not command_parts:
            return {"success": False, "stdout": "", "stderr": "Empty command",
                    "return_code": -1, "timed_out": False,
                    "warnings": [], "integrity_issues": []}

        timeout = timeout or Config.COMMAND_TIMEOUT
        tool = command_parts[0]

        ok, err, sanitized = CommandValidator.validate_command_args(tool, command_parts[1:])
        if not ok:
            return {"success": False, "stdout": "", "stderr": f"Validation failed: {err}",
                    "return_code": -1, "timed_out": False,
                    "warnings": [], "integrity_issues": []}

        safe_command = [tool] + sanitized

        # Privileged tools → sudo -n -- <cmd>
        if tool in PRIVILEGED_TOOLS and Config.SUDO_ENABLED:
            if not shutil.which("sudo"):
                return {"success": False, "stdout": "",
                        "stderr": "sudo not found but tool requires privileges",
                        "return_code": -1, "timed_out": False,
                        "warnings": [], "integrity_issues": []}
            safe_command = ["sudo", "-n", "--"] + safe_command

        safe_env = os.environ.copy()
        if env: safe_env.update(env)
        for var in ('BASH_ENV','ENV','LD_PRELOAD','LD_LIBRARY_PATH','LD_DEBUG',
                    'NODE_OPTIONS','PERL5OPT','PYTHONPATH'):
            safe_env.pop(var, None)

        # Global concurrency gate
        try:
            await asyncio.wait_for(self._sem.acquire(), timeout=60)
        except asyncio.TimeoutError:
            return {"success": False, "stdout": "", "stderr": "Server busy (queue full)",
                    "return_code": -1, "timed_out": False,
                    "warnings": [], "integrity_issues": []}

        try:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *safe_command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(cwd) if cwd else None,
                    env=safe_env,
                    limit=self.output_limit,
                )
            except FileNotFoundError:
                return {"success": False, "stdout": "",
                        "stderr": f"Binary not found: {safe_command[0]}",
                        "return_code": -1, "timed_out": False,
                        "warnings": [], "integrity_issues": []}
            except PermissionError as e:
                return {"success": False, "stdout": "",
                        "stderr": f"Permission denied: {e}",
                        "return_code": -1, "timed_out": False,
                        "warnings": [], "integrity_issues": []}

            self.active_processes[proc.pid] = proc
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    proc.kill()
                return {"success": False, "stdout": "",
                        "stderr": f"Timed out after {timeout}s", "return_code": -1,
                        "timed_out": True, "warnings": [], "integrity_issues": []}
            finally:
                self.active_processes.pop(proc.pid, None)

            out = stdout.decode('utf-8', errors='replace')
            err = stderr.decode('utf-8', errors='replace')
            out, w1 = AntiPoisoningFilter.filter_output(out)
            err, w2 = AntiPoisoningFilter.filter_output(err)

            # [v4.2 FIX] integrity check restored
            is_clean, issues = AntiPoisoningFilter.validate_output_integrity(out + err)

            return {"success": proc.returncode == 0, "stdout": out, "stderr": err,
                    "return_code": proc.returncode, "timed_out": False,
                    "warnings": w1 + w2,
                    "integrity_issues": issues if not is_clean else []}
        finally:
            self._sem.release()

    async def kill_all(self):
        for p in list(self.active_processes.values()):
            try: p.terminate()
            except Exception: pass
        self.active_processes.clear()


# ============================================================================
# SESSION MANAGER
# ============================================================================

class SessionManager:
    def __init__(self):
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.rate_limiters: Dict[str, RateLimiter] = {}
        self._lock = asyncio.Lock()

    async def create_session(self, session_id: Optional[str] = None) -> str:
        async with self._lock:
            if not session_id:
                session_id = secrets.token_urlsafe(32)
            if session_id not in self.sessions:
                self.sessions[session_id] = {
                    "created_at": datetime.utcnow(),
                    "crypto": SecureCrypto(session_id) if Config.ENCRYPTION_ENABLED else None,
                    "output_dir": None,
                    "last_activity": datetime.utcnow(),
                    "tool_history": [],
                }
            if session_id not in self.rate_limiters:
                self.rate_limiters[session_id] = RateLimiter(Config.MAX_REQUESTS_PER_SECOND, Config.MAX_BURST)
            return session_id

    def get_session(self, session_id: str) -> Optional[Dict]:
        s = self.sessions.get(session_id)
        if s: s["last_activity"] = datetime.utcnow()
        return s

    def set_output_dir(self, session_id: str, output_dir: Path):
        if session_id in self.sessions:
            self.sessions[session_id]["output_dir"] = output_dir
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "raw_outputs").mkdir(exist_ok=True)
            (output_dir / "encrypted").mkdir(exist_ok=True)

    async def check_rate_limit(self, session_id: str) -> bool:
        lim = self.rate_limiters.get(session_id)
        if not lim:
            lim = RateLimiter(Config.MAX_REQUESTS_PER_SECOND, Config.MAX_BURST)
            self.rate_limiters[session_id] = lim
        return await lim.acquire()

    def add_to_history(self, session_id: str, tool: str, cmd: str, success: bool):
        s = self.sessions.get(session_id)
        if s:
            s["tool_history"].append({
                "tool": tool, "command": cmd[:200],
                "success": success, "timestamp": datetime.utcnow().isoformat(),
            })
            if len(s["tool_history"]) > 100:
                s["tool_history"] = s["tool_history"][-100:]

    def cleanup_old_sessions(self):
        cutoff = datetime.utcnow() - timedelta(hours=Config.SESSION_TIMEOUT_HOURS)
        for sid in [k for k,v in self.sessions.items() if v["last_activity"] < cutoff]:
            del self.sessions[sid]; self.rate_limiters.pop(sid, None)
        if len(self.sessions) > 100:
            oldest = sorted(self.sessions.items(), key=lambda x: x[1]["last_activity"])[:-100]
            for sid, _ in oldest:
                del self.sessions[sid]; self.rate_limiters.pop(sid, None)


# ============================================================================
# LIFESPAN + APP
# ============================================================================

executor = SecureCommandExecutor()
session_manager = SessionManager()
global_limiter = RateLimiter(Config.GLOBAL_MAX_RPS, Config.GLOBAL_MAX_BURST)
security = HTTPBearer(auto_error=False)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s",
                    stream=sys.stderr)
logger = logging.getLogger(__name__)


async def check_sudo_setup():
    if not Config.SUDO_ENABLED:
        logger.info("SUDO_ENABLED=false — privileged tools rely on setcap instead")
        return
    if not shutil.which("sudo"):
        logger.warning("sudo not installed — privileged tools will fail")
        return
    try:
        proc = await asyncio.create_subprocess_exec(
            "sudo", "-n", "--", "true",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, err = await proc.communicate()
        if proc.returncode != 0:
            logger.warning(f"sudo NOPASSWD not configured: {err.decode()[:120]}")
        else:
            logger.info("sudo NOPASSWD OK for privileged tools")
    except Exception as e:
        logger.warning(f"sudo check failed: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting secure pentest API...")
    await check_sudo_setup()
    yield
    logger.info("Shutting down...")
    await executor.kill_all()


app = FastAPI(
    title="Secure Pentest API",
    description="Secure API for penetration testing — NO SHELL INJECTION",
    version="4.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=Config.ALLOWED_HOSTS)


# ============================================================================
# AUTH
# ============================================================================

async def verify_auth(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    if not Config.API_KEY:
        return "no-auth"
    if not credentials:
        raise HTTPException(401, "Missing API key. Use 'Authorization: Bearer <key>'")
    if credentials.credentials != Config.API_KEY:
        raise HTTPException(403, "Invalid API key")
    return credentials.credentials


async def get_session_id(request: Request) -> str:
    if not await global_limiter.acquire():
        raise HTTPException(429, f"Global rate limit: max {Config.GLOBAL_MAX_RPS}/s")

    sid = request.headers.get("X-Session-ID")
    if not sid:
        sid = await session_manager.create_session()
    elif not session_manager.get_session(sid):
        sid = await session_manager.create_session(sid)

    if not await session_manager.check_rate_limit(sid):
        raise HTTPException(429, f"Session rate limit: max {Config.MAX_REQUESTS_PER_SECOND}/s")
    return sid


# ============================================================================
# HEALTH / SESSION
# ============================================================================

@app.get("/health")
async def health(auth: str = Depends(verify_auth)):
    return {
        "status": "healthy", "version": "4.2.0", "secure_mode": True,
        "shell_execution": False,
        "encryption_enabled": Config.ENCRYPTION_ENABLED,
        "sudo_enabled": Config.SUDO_ENABLED,
        "active_sessions": len(session_manager.sessions),
        "privileged_tools": sorted(PRIVILEGED_TOOLS),
        "rate_limit": {"per_session": Config.MAX_REQUESTS_PER_SECOND,
                       "global": Config.GLOBAL_MAX_RPS},
        # [v4.2] surface which API keys are present
        "api_keys_configured": {
            "nvd": bool(Config.NVD_API_KEY),
            "xforce": bool(Config.IBM_XFORCE_API_KEY and Config.IBM_XFORCE_API_PASSWORD),
            "vulners": bool(Config.VULNERS_API_KEY),
            "wpscan": bool(Config.WPSCAN_API_TOKEN),
            "shodan": bool(Config.SHODAN_API_KEY),
            "github": bool(Config.GITHUB_TOKEN),
        },
    }


@app.get("/api/session/info")
async def session_info(session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    s = session_manager.get_session(session_id)
    if not s: raise HTTPException(404, "Session not found")
    return {"session_id": session_id,
            "created_at": s["created_at"].isoformat(),
            "last_activity": s["last_activity"].isoformat(),
            "output_dir": str(s.get("output_dir")) if s.get("output_dir") else None,
            "encryption_enabled": Config.ENCRYPTION_ENABLED,
            "tool_count": len(s.get("tool_history", []))}


@app.post("/api/session/init")
async def init_session(request: SessionInitRequest, auth: str = Depends(verify_auth)):
    sid = request.session_id or None
    if sid and not session_manager.get_session(sid):
        sid = await session_manager.create_session(sid)
    elif not sid:
        sid = await session_manager.create_session()
    if request.output_dir:
        p = Path(request.output_dir)
        if p.parent.exists():
            session_manager.set_output_dir(sid, p)
    return {"session_id": sid, "status": "ok",
            "encryption_enabled": Config.ENCRYPTION_ENABLED}


@app.post("/api/session/cleanup")
async def cleanup(auth: str = Depends(verify_auth)):
    before = len(session_manager.sessions)
    session_manager.cleanup_old_sessions()
    return {"status": "ok", "before": before, "after": len(session_manager.sessions)}


# ============================================================================
# OUTPUT HELPERS
# ============================================================================

# [v4.2 FIX] guarded write — disk errors can no longer 500 the request
def _save_output(session_id: str, tool: str, target: str, result: Dict):
    s = session_manager.get_session(session_id)
    if not s or not s.get("output_dir"):
        return
    try:
        out_dir = s["output_dir"]
        ts = int(time.time())
        text = result.get("stdout", "") + result.get("stderr", "")
        (out_dir / "raw_outputs" / f"{tool}_{ts}.txt").write_text(text)
        if Config.ENCRYPTION_ENABLED and s.get("crypto"):
            enc = s["crypto"].encrypt_output(text, tool, target)
            (out_dir / "encrypted" / f"{tool}_{ts}.enc").write_text(enc)
    except Exception as e:
        logger.warning(f"_save_output failed for {tool}: {e}")


# ============================================================================
# TOOL ENDPOINTS
# ============================================================================

@app.post("/api/tools/nmap")
async def nmap_scan(request: NmapRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["nmap"] + safe_split(request.scan_type)
    if request.ports: cmd += ["-p", request.ports]
    if request.additional_args: cmd += safe_split(request.additional_args)
    cmd.append(request.target)
    logger.info(f"[{session_id[:8]}] nmap: {' '.join(cmd)}")
    res = await executor.execute(cmd, timeout=600)
    _save_output(session_id, "nmap", request.target, res)
    session_manager.add_to_history(session_id, "nmap", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/gobuster")
async def gobuster_scan(request: GobusterRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["gobuster", request.mode, "-u", request.url, "-w", request.wordlist]
    if request.additional_args: cmd += safe_split(request.additional_args)
    res = await executor.execute(cmd, timeout=600)
    _save_output(session_id, "gobuster", request.url, res)
    session_manager.add_to_history(session_id, "gobuster", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/dirb")
async def dirb_scan(request: DirbRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["dirb", request.url, request.wordlist]
    if request.additional_args: cmd += safe_split(request.additional_args)
    res = await executor.execute(cmd, timeout=600)
    _save_output(session_id, "dirb", request.url, res)
    session_manager.add_to_history(session_id, "dirb", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/ffuf")
async def ffuf_scan(request: FfufRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["ffuf", "-u", request.url, "-w", request.wordlist, "-mc", request.match_code]
    if request.filter_size: cmd += ["-fs", request.filter_size]
    if request.additional_args: cmd += safe_split(request.additional_args)
    res = await executor.execute(cmd, timeout=600)
    _save_output(session_id, "ffuf", request.url, res)
    session_manager.add_to_history(session_id, "ffuf", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/nikto")
async def nikto_scan(request: NiktoRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["nikto", "-h", request.target]
    if request.additional_args: cmd += safe_split(request.additional_args)
    res = await executor.execute(cmd, timeout=600)
    _save_output(session_id, "nikto", request.target, res)
    session_manager.add_to_history(session_id, "nikto", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/sqlmap")
async def sqlmap_scan(request: SqlmapRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["sqlmap", "-u", request.url, "--batch"]
    if request.data: cmd += ["--data", request.data]
    if request.additional_args: cmd += safe_split(request.additional_args)
    res = await executor.execute(cmd, timeout=900)
    _save_output(session_id, "sqlmap", request.url, res)
    session_manager.add_to_history(session_id, "sqlmap", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/hydra")
async def hydra_attack(request: HydraRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["hydra", "-t", "4"]
    if request.username: cmd += ["-l", request.username]
    elif request.username_file: cmd += ["-L", request.username_file]
    if request.password: cmd += ["-p", request.password]
    elif request.password_file: cmd += ["-P", request.password_file]
    cmd += [request.target, request.service]
    if request.additional_args: cmd += safe_split(request.additional_args)
    res = await executor.execute(cmd, timeout=1800)
    _save_output(session_id, "hydra", request.target, res)
    session_manager.add_to_history(session_id, "hydra", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/john")
async def john_crack(request: JohnRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["john"]
    if request.format_type: cmd += [f"--format={request.format_type}"]
    if request.wordlist: cmd += [f"--wordlist={request.wordlist}"]
    if request.additional_args: cmd += safe_split(request.additional_args)
    cmd.append(request.hash_file)
    res = await executor.execute(cmd, timeout=3600)
    _save_output(session_id, "john", request.hash_file, res)
    session_manager.add_to_history(session_id, "john", " ".join(cmd), res["success"])
    return res


# [v4.2 FIX] wpscan now actually uses the API token
@app.post("/api/tools/wpscan")
async def wpscan_analyze(request: WpscanRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["wpscan", "--url", request.url]
    if Config.WPSCAN_API_TOKEN:
        cmd += ["--api-token", Config.WPSCAN_API_TOKEN]
    if request.additional_args:
        cmd += safe_split(request.additional_args)
    res = await executor.execute(cmd, timeout=600)
    _save_output(session_id, "wpscan", request.url, res)
    session_manager.add_to_history(session_id, "wpscan", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/enum4linux")
async def enum4linux_scan(request: Enum4linuxRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["enum4linux"]
    if request.additional_args: cmd += safe_split(request.additional_args)
    cmd.append(request.target)
    res = await executor.execute(cmd, timeout=300)
    _save_output(session_id, "enum4linux", request.target, res)
    session_manager.add_to_history(session_id, "enum4linux", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/curl")
async def curl_request(request: CurlRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["curl", "-X", request.method, "-s", "-i"]
    for k, v in request.headers.items():
        cmd += ["-H", f"{k}: {v}"]
    if request.data: cmd += ["-d", request.data]
    cmd.append(request.url)
    res = await executor.execute(cmd, timeout=120)
    _save_output(session_id, "curl", request.url, res)
    return res


@app.post("/api/tools/netcat")
async def netcat_check(request: NetcatRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["nc", "-vz", request.host, str(request.port)]
    return await executor.execute(cmd, timeout=30)


@app.post("/api/tools/aircrack-ng")
async def aircrack_ng(request: Aircrack_ngRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["aircrack-ng", request.wordlist, request.output_file]
    if request.additional_args: cmd += safe_split(request.additional_args)
    res = await executor.execute(cmd, timeout=600)
    _save_output(session_id, "aircrack-ng", request.output_file, res)
    session_manager.add_to_history(session_id, "aircrack-ng", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/read_file")
async def read_file_secure(request: ReadFileRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    path = Path(request.path)
    size = path.stat().st_size
    try:
        if request.command == "head":
            with open(path, encoding='utf-8', errors='replace') as f:
                content = ''.join([next(f) for _ in range(request.max_lines)])
        elif request.command == "tail":
            with open(path, encoding='utf-8', errors='replace') as f:
                content = ''.join(f.readlines()[-request.max_lines:])
        else:
            with open(path, encoding='utf-8', errors='replace') as f:
                content = f.read()
            if len(content) > 10*1024*1024:
                content = content[:10*1024*1024] + "\n[TRUNCATED]"
        filtered, warnings = AntiPoisoningFilter.filter_output(content)
        return {"success": True, "content": filtered, "path": str(path),
                "size_bytes": size, "warnings": warnings}
    except UnicodeDecodeError:
        with open(path, 'rb') as f:
            binary = f.read(1024)
        return {"success": True, "content": f"[BINARY] {binary.hex()}",
                "path": str(path), "size_bytes": size, "is_binary": True}
    except Exception as e:
        return {"success": False, "error": str(e), "path": str(path)}


@app.post("/api/tools/amass")
async def amass_enum(request: AmassRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["amass", "enum", "-d", request.target]
    if request.additional_args: cmd += safe_split(request.additional_args)
    res = await executor.execute(cmd, timeout=600)
    _save_output(session_id, "amass", request.target, res)
    session_manager.add_to_history(session_id, "amass", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/subfinder")
async def subfinder_enum(request: SubfinderRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["subfinder", "-d", request.target]
    if request.additional_args: cmd += safe_split(request.additional_args)
    res = await executor.execute(cmd, timeout=300)
    _save_output(session_id, "subfinder", request.target, res)
    session_manager.add_to_history(session_id, "subfinder", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/nuclei")
async def nuclei_scan(request: NucleiRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["nuclei", "-target", request.target, "-silent"]
    if request.templates: cmd += ["-templates", request.templates]
    if request.severity: cmd += ["-severity", request.severity]
    if request.additional_args: cmd += safe_split(request.additional_args)
    res = await executor.execute(cmd, timeout=600)
    _save_output(session_id, "nuclei", request.target, res)
    session_manager.add_to_history(session_id, "nuclei", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/masscan")
async def masscan_scan(request: MasscanRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["masscan", request.target,
           "-p", request.ports,
           "--rate", str(request.rate)]
    if request.additional_args: cmd += safe_split(request.additional_args)
    logger.info(f"[{session_id[:8]}] masscan: {' '.join(cmd)}")
    res = await executor.execute(cmd, timeout=600)

    if not res["success"]:
        errlow = res["stderr"].lower()
        if "permission" in errlow or "sudo:" in errlow or "cap_net_raw" in errlow:
            raise HTTPException(
                status_code=503,
                detail=("masscan needs root or CAP_NET_RAW. Either add to "
                        "/etc/sudoers.d/pentest-api OR run: "
                        "sudo setcap cap_net_raw,cap_net_admin+eip $(which masscan)")
            )
    _save_output(session_id, "masscan", request.target, res)
    session_manager.add_to_history(session_id, "masscan", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/wfuzz")
async def wfuzz_scan(request: WfuzzRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["wfuzz", "-w", request.wordlist,
           "--hc", request.filter_code if request.filter_code else "404",
           request.url]
    if request.additional_args: cmd += safe_split(request.additional_args)
    res = await executor.execute(cmd, timeout=600)
    _save_output(session_id, "wfuzz", request.url, res)
    session_manager.add_to_history(session_id, "wfuzz", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/airodump-ng")
async def airodump_ng(request: AirodumpNgRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["airodump-ng", request.interface]
    if request.bssid: cmd += ["--bssid", request.bssid]
    if request.channel: cmd += ["-c", str(request.channel)]
    if request.output_file: cmd += ["-w", request.output_file]
    if request.additional_args: cmd += safe_split(request.additional_args)
    res = await executor.execute(cmd, timeout=600)
    _save_output(session_id, "airodump-ng", request.interface, res)
    session_manager.add_to_history(session_id, "airodump-ng", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/wifite")
async def wifite_attack(request: WifiteRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["wifite", "-i", request.interface, "-all"]
    if request.target_bssid: cmd += ["-b", request.target_bssid]
    if request.target_essid: cmd += ["-e", request.target_essid]
    if request.attack_type == "wpa": cmd.append("--wpa")
    elif request.attack_type == "wps": cmd.append("--wps")
    if request.additional_args: cmd += safe_split(request.additional_args)
    res = await executor.execute(cmd, timeout=1800)
    _save_output(session_id, "wifite", request.interface, res)
    session_manager.add_to_history(session_id, "wifite", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/airmon-ng")
async def airmon_ng(request: AirmonNgRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["airmon-ng", request.action, request.interface]
    res = await executor.execute(cmd, timeout=30)
    _save_output(session_id, "airmon-ng", request.interface, res)
    session_manager.add_to_history(session_id, "airmon-ng", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/hashcat")
async def hashcat_crack(request: HashcatRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["hashcat", "-m", request.hash_type, "-a", "0",
           request.hash_file, request.wordlist, "--force"]
    if request.additional_args: cmd += safe_split(request.additional_args)
    res = await executor.execute(cmd, timeout=3600)
    _save_output(session_id, "hashcat", request.hash_file, res)
    session_manager.add_to_history(session_id, "hashcat", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/smbclient")
async def smbclient_enum(request: SmbclientRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    if request.share:
        cmd = ["smbclient", f"//{request.host}/{request.share}", "-N"]
    else:
        cmd = ["smbclient", "-L", request.host]
    if request.username: cmd += ["-U", request.username]
    if request.password: cmd += ["-P", request.password]
    if request.additional_args: cmd += safe_split(request.additional_args)
    res = await executor.execute(cmd, timeout=120)
    _save_output(session_id, "smbclient", request.host, res)
    session_manager.add_to_history(session_id, "smbclient", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/snmpwalk")
async def snmpwalk_scan(request: SnmpwalkRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["snmpwalk", "-v", request.version, "-c", request.community,
           request.target, request.oid]
    if request.additional_args: cmd += safe_split(request.additional_args)
    res = await executor.execute(cmd, timeout=120)
    _save_output(session_id, "snmpwalk", request.target, res)
    session_manager.add_to_history(session_id, "snmpwalk", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/ldapsearch")
async def ldapsearch_query(request: LdapsearchRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["ldapsearch", "-x", "-H", f"ldap://{request.host}:{request.port}"]
    if request.base_dn: cmd += ["-b", request.base_dn]
    if request.filter: cmd += ["-s", "sub", request.filter]
    if request.attributes: cmd.append(request.attributes)
    if request.bind_dn:
        cmd += ["-D", request.bind_dn]
        if request.bind_password: cmd += ["-w", request.bind_password]
    if request.additional_args: cmd += safe_split(request.additional_args)
    res = await executor.execute(cmd, timeout=120)
    _save_output(session_id, "ldapsearch", request.host, res)
    session_manager.add_to_history(session_id, "ldapsearch", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/responder")
async def responder_capture(request: ResponderRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["responder", "-I", request.interface, "--basic", "--lm"]
    if request.additional_args: cmd += safe_split(request.additional_args)
    res = await executor.execute(cmd, timeout=300)
    _save_output(session_id, "responder", request.interface, res)
    session_manager.add_to_history(session_id, "responder", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/bloodhound")
async def bloodhound_collect(request: BloodhoundRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["bloodhound-python", "-d", request.domain, "-u", request.username,
           "-p", request.password, "-c", request.collection_method, "--zip"]
    if request.nameserver: cmd += ["-ns", request.nameserver]
    if request.additional_args: cmd += safe_split(request.additional_args)
    res = await executor.execute(cmd, timeout=600)
    _save_output(session_id, "bloodhound", request.domain, res)
    session_manager.add_to_history(session_id, "bloodhound", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/whatweb")
async def whatweb_identify(request: WhatwebRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["whatweb", request.target]
    if request.additional_args: cmd += safe_split(request.additional_args)
    res = await executor.execute(cmd, timeout=120)
    _save_output(session_id, "whatweb", request.target, res)
    session_manager.add_to_history(session_id, "whatweb", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/cewl")
async def cewl_generate(request: CewlRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["cewl", request.target, "-d", str(request.depth), "-m", str(request.min_word_length)]
    if request.additional_args: cmd += safe_split(request.additional_args)
    res = await executor.execute(cmd, timeout=300)
    _save_output(session_id, "cewl", request.target, res)
    session_manager.add_to_history(session_id, "cewl", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/medusa")
async def medusa_bruteforce(request: MedusaRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["medusa", "-h", request.host, "-s", request.service]
    if request.username: cmd += ["-u", request.username]
    elif request.username_file: cmd += ["-U", request.username_file]
    if request.password: cmd += ["-p", request.password]
    elif request.password_file: cmd += ["-P", request.password_file]
    if request.additional_args: cmd += safe_split(request.additional_args)
    res = await executor.execute(cmd, timeout=1800)
    _save_output(session_id, "medusa", request.host, res)
    session_manager.add_to_history(session_id, "medusa", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/dnsrecon")
async def dnsrecon_enum(request: DnsreconRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["dnsrecon", "-d", request.target, "-t", request.type]
    if request.additional_args: cmd += safe_split(request.additional_args)
    res = await executor.execute(cmd, timeout=300)
    _save_output(session_id, "dnsrecon", request.target, res)
    session_manager.add_to_history(session_id, "dnsrecon", " ".join(cmd), res["success"])
    return res


@app.post("/api/tools/searchsploit")
async def searchsploit_search(request: SearchsploitRequest, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    cmd = ["searchsploit", "--color"]
    if request.category: cmd += ["-c", request.category]
    if request.exact: cmd.append("-e")
    if request.additional_args: cmd += safe_split(request.additional_args)
    cmd.append(request.term)
    res = await executor.execute(cmd, timeout=60)
    _save_output(session_id, "searchsploit", request.term, res)
    session_manager.add_to_history(session_id, "searchsploit", " ".join(cmd), res["success"])
    return res


# ============================================================================
# GENERIC COMMAND (whitelisted only)
# ============================================================================

@app.post("/api/command")
async def generic_command(request: Request, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    data = await request.json()
    command = data.get("command", "")
    if not command: raise HTTPException(400, "Command required")
    try:
        parts = shlex.split(command)
    except ValueError as e:
        raise HTTPException(400, f"Invalid command syntax: {e}")
    if not parts: raise HTTPException(400, "Empty command")
    tool = parts[0]
    if tool not in CommandValidator.ALLOWED_COMMANDS:
        raise HTTPException(403, f"Tool '{tool}' not whitelisted")
    logger.warning(f"[{session_id[:8]}] GENERIC: {' '.join(parts)}")
    res = await executor.execute(parts, timeout=300)
    _save_output(session_id, "generic", tool, res)
    return res


# ============================================================================
# DECRYPT
# ============================================================================

@app.post("/api/decrypt")
async def decrypt_output(request: Request, session_id: str = Depends(get_session_id), auth: str = Depends(verify_auth)):
    data = await request.json()
    enc = data.get("encrypted_data", "")
    if not Config.ENCRYPTION_ENABLED:
        raise HTTPException(400, "Encryption disabled")
    s = session_manager.get_session(session_id)
    if not s or not s.get("crypto"):
        raise HTTPException(400, "No crypto for this session")
    dec, ok = s["crypto"].decrypt_output(enc)
    if not ok:
        raise HTTPException(400, "Integrity check failed")
    return {"success": True, "data": dec}


# ============================================================================
# CVE — MULTI-SOURCE
# ============================================================================

async def _fetch_nvd(request: CveSearchRequest) -> List[Dict]:
    def _sync():
        import requests
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"resultsPerPage": 20}
        headers = {}
        if Config.NVD_API_KEY:
            headers["apiKey"] = Config.NVD_API_KEY
        if request.cve_id:
            params["cveId"] = request.cve_id
        elif request.keyword:
            params["keywordSearch"] = request.keyword
        elif request.cpe:
            params["cpeName"] = request.cpe
        else:
            return []
        try:
            r = requests.get(url, params=params, headers=headers, timeout=30)
            if r.status_code != 200: return []
            return r.json().get("vulnerabilities", [])
        except Exception:
            return []
    try:
        return await asyncio.wait_for(asyncio.to_thread(_sync), timeout=35)
    except Exception:
        return []


async def _fetch_xforce(request: CveSearchRequest) -> List[Dict]:
    if not (Config.IBM_XFORCE_API_KEY and Config.IBM_XFORCE_API_PASSWORD): return []
    query = request.cve_id or request.keyword
    if not query: return []

    def _sync():
        import requests
        from requests.auth import HTTPBasicAuth
        try:
            r = requests.get(
                "https://api.xforce.ibmcloud.com/vulnerabilities",
                params={"q": query},
                auth=HTTPBasicAuth(Config.IBM_XFORCE_API_KEY, Config.IBM_XFORCE_API_PASSWORD),
                timeout=30,
            )
            if r.status_code != 200: return []
            return r.json().get("rows", [])
        except Exception:
            return []
    try:
        return await asyncio.wait_for(asyncio.to_thread(_sync), timeout=35)
    except Exception:
        return []


async def _fetch_circl(request: CveSearchRequest) -> List[Dict]:
    def _sync():
        import requests
        try:
            if request.cve_id:
                r = requests.get(f"https://cve.circl.lu/api/cve/{request.cve_id}", timeout=30)
                return [r.json()] if r.status_code == 200 and r.json() else []
            if request.keyword:
                r = requests.get(f"https://cve.circl.lu/api/search/{request.keyword}", timeout=30)
                if r.status_code != 200: return []
                return r.json().get("data", [])
        except Exception:
            return []
        return []
    try:
        return await asyncio.wait_for(asyncio.to_thread(_sync), timeout=35)
    except Exception:
        return []


async def _fetch_exploitdb(request: CveSearchRequest) -> List[Dict]:
    query = request.cve_id or request.keyword
    if not query: return []

    def _sync():
        import requests
        try:
            r = requests.get(
                "https://www.exploit-db.com/search",
                params={"q": query},
                headers={"X-Requested-With": "XMLHttpRequest"},
                timeout=30,
            )
            if r.status_code != 200: return []
            return r.json().get("data", [])
        except Exception:
            return []
    try:
        return await asyncio.wait_for(asyncio.to_thread(_sync), timeout=35)
    except Exception:
        return []


@app.post("/api/cve/search")
async def search_cve_enhanced(request: CveSearchRequest,
                               session_id: str = Depends(get_session_id),
                               auth: str = Depends(verify_auth)):
    nvd, xf, circl, edb = await asyncio.gather(
        _fetch_nvd(request), _fetch_xforce(request),
        _fetch_circl(request), _fetch_exploitdb(request),
        return_exceptions=True,
    )
    if isinstance(nvd, Exception): nvd = []
    if isinstance(xf, Exception): xf = []
    if isinstance(circl, Exception): circl = []
    if isinstance(edb, Exception): edb = []

    merged: Dict[str, Dict] = {}

    for item in nvd:
        try:
            cve = item["cve"]; cid = cve["id"]
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en": desc = d["value"][:300]; break
            metrics = cve.get("metrics", {}); score = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics:
                    score = metrics[key][0].get("cvssData", {}).get("baseScore"); break
            merged[cid] = {
                "id": cid, "description": desc, "cvss_score": score,
                "published": cve.get("published", ""),
                "references": [r["url"] for r in cve.get("references", [])[:3]],
                "sources": ["nvd"], "exploits": [],
            }
        except Exception:
            continue

    for item in circl:
        try:
            cid = item.get("id") or item.get("cve")
            if not cid: continue
            if cid not in merged:
                merged[cid] = {
                    "id": cid,
                    "description": (item.get("summary") or "")[:300],
                    "cvss_score": item.get("cvss"),
                    "published": item.get("Published", ""),
                    "references": item.get("references", [])[:3],
                    "sources": [], "exploits": [],
                }
            if "circl" not in merged[cid]["sources"]:
                merged[cid]["sources"].append("circl")
        except Exception:
            continue

    for item in xf:
        try:
            cid = item.get("stdcode") or item.get("cve") or item.get("cve_id")
            if not cid: continue
            if cid not in merged:
                merged[cid] = {
                    "id": cid,
                    "description": (item.get("description") or "")[:300],
                    "cvss_score": item.get("risk_score"),
                    "published": item.get("published", ""),
                    "references": [], "sources": [], "exploits": [],
                }
            if "xforce" not in merged[cid]["sources"]:
                merged[cid]["sources"].append("xforce")
            merged[cid]["xforce_risk"] = item.get("risk_score")
            merged[cid]["xforce_ti"] = item.get("ti")
        except Exception:
            continue

    for item in edb:
        try:
            cid = item.get("cve") or ""
            if not cid: continue
            edb_entry = {
                "id": item.get("id"),
                "description": (item.get("description") or "")[:200],
                "date": item.get("date_published", ""),
                "url": f"https://www.exploit-db.com/exploits/{item.get('id')}",
            }
            if cid not in merged:
                merged[cid] = {
                    "id": cid, "description": "", "cvss_score": None,
                    "published": "", "references": [], "sources": [], "exploits": [],
                }
            merged[cid]["exploits"].append(edb_entry)
            if "exploit-db" not in merged[cid]["sources"]:
                merged[cid]["sources"].append("exploit-db")
        except Exception:
            continue

    results = list(merged.values())
    if request.cvss_min is not None:
        results = [c for c in results if c.get("cvss_score") is not None and c["cvss_score"] >= request.cvss_min]
    if request.cvss_max is not None:
        results = [c for c in results if c.get("cvss_score") is not None and c["cvss_score"] <= request.cvss_max]
    results.sort(key=lambda c: c.get("cvss_score") or 0, reverse=True)

    session_manager.add_to_history(
        session_id, "cve_search",
        f"{request.cve_id or request.keyword or request.cpe}", True,
    )
    return {
        "cves": results[:50],
        "count": len(results),
        "sources_used": {
            "nvd": len(nvd), "xforce": len(xf),
            "circl": len(circl), "exploit-db": len(edb),
        },
    }


# ============================================================================
# MAIN
# ============================================================================

def parse_args():
    p = argparse.ArgumentParser(description="Secure Pentest API Server")
    p.add_argument("--host", default=Config.HOST)
    p.add_argument("--port", type=int, default=Config.PORT)
    p.add_argument("--reload", action="store_true")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    Config.validate()
    print("=" * 70)
    print("SECURE PENTEST API SERVER v4.2")
    print("=" * 70)
    print(f"Host: {args.host}:{args.port}")
    print(f"Shell: DISABLED")
    print(f"Encryption: {'ON' if Config.ENCRYPTION_ENABLED else 'OFF'}")
    print(f"Sudo (privileged tools): {'ON' if Config.SUDO_ENABLED else 'OFF'}")
    print(f"Rate limit: {Config.MAX_REQUESTS_PER_SECOND}/s per session, "
          f"{Config.GLOBAL_MAX_RPS}/s global")
    print(f"Auth: {'ON' if Config.API_KEY else 'OFF (WARNING)'}")
    print(f"Privileged tools: {', '.join(sorted(PRIVILEGED_TOOLS))}")
    print(f"WPSCAN token: {'SET' if Config.WPSCAN_API_TOKEN else 'not set'}")
    print(f"NVD key:      {'SET' if Config.NVD_API_KEY else 'not set'}")
    print(f"X-Force key:  {'SET' if Config.IBM_XFORCE_API_KEY else 'not set'}")
    print("=" * 70)
    uvicorn.run(app, host=args.host, port=args.port, reload=args.reload, log_level="info")
