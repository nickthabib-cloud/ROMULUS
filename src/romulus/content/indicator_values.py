"""Kind-specific canonicalization for analyst indicators; no inferred types."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qsl, unquote, urlsplit

import idna

KINDS = frozenset({
    'program_name', 'ip', 'cidr', 'domain', 'ja3', 'ja4', 'hassh',
    'md5', 'sha1', 'sha256', 'url', 'x509_sha1', 'x509_sha256',
})
MAX_VALUE_CHARS = 16384
_DIGEST_LENGTHS = {'md5': 32, 'sha1': 40, 'sha256': 64,
                   'x509_sha1': 40, 'x509_sha256': 64, 'ja3': 32, 'hassh': 32}
_SECRET_KEY = re.compile(
    r'(?:^|[^a-z0-9])(?:password|passwd|pwd|secret|client[_-]?secret|access[_-]?token|'
    r'refresh[_-]?token|auth[_-]?token|api[_-]?key|authorization|credentials?|token|'
    r'signature|x-amz-signature|x-amz-credential|sig)(?:$|[^a-z0-9])', re.IGNORECASE,
)
_SECRET_ASSIGNMENT = re.compile(
    r'(?:password|passwd|pwd|secret|token|api[_-]?key|authorization|credential)\s*[:=]', re.IGNORECASE,
)
_SECRET_LITERAL = re.compile(r'(?:\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\beyJ[a-zA-Z0-9_-]+\.'
                             r'[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b|\b(?:ghp_|sk-)[a-zA-Z0-9]{20,})')
_URI_USERINFO = re.compile(r'://[^/?#\s]*@')


def _safe_text(value: str, *, limit: int = MAX_VALUE_CHARS) -> str:
    """Validate text without ever putting untrusted text into an exception."""
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError('invalid text type or field size')
    if any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value):
        raise ValueError('control character in field')
    if any(0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ValueError('invalid Unicode in field')
    if _SECRET_ASSIGNMENT.search(value) or _SECRET_LITERAL.search(value) or _URI_USERINFO.search(value):
        raise ValueError('credential-like content refused')
    return value


def _domain(value: str) -> str:
    name = value.removesuffix('.')
    if not name or len(name) > 253 or name.endswith('.'):
        raise ValueError('invalid domain')
    try:
        name = idna.encode(name.lower(), uts46=True, std3_rules=True).decode('ascii')
    except idna.IDNAError:
        raise ValueError('invalid domain') from None
    if len(name) > 253 or any(not label or len(label) > 63 for label in name.split('.')):
        raise ValueError('invalid domain')
    return name


def normalize_url(value: str) -> str:
    """Normalize only the scheme, authority host and default port of an exact URL."""
    _safe_text(value)
    if not value or any(c.isspace() for c in value) or '\\' in value:
        raise ValueError('invalid URL')
    decoded = unquote(value)
    _safe_text(decoded)
    try:
        parts = urlsplit(value)
        if not parts.scheme or not parts.netloc or not parts.hostname:
            raise ValueError('absolute URL required')
        if parts.username is not None or parts.password is not None or '@' in parts.netloc:
            raise ValueError('URL user information refused')
        if '%' in parts.hostname:
            raise ValueError('invalid URL host')
        try:
            address = ipaddress.ip_address(parts.hostname)
        except ValueError:
            host = _domain(parts.hostname)
        else:
            host = '[' + str(address) + ']' if address.version == 6 else str(address)
        port = parts.port
        if parts.netloc.endswith(':'):
            raise ValueError('invalid URL port')
        scheme = parts.scheme.lower()
        if port is not None and port != {'http': 80, 'https': 443, 'ftp': 21}.get(scheme):
            host += ':' + str(port)
        for key, _ in parse_qsl(parts.query, keep_blank_values=True):
            if _SECRET_KEY.search(key):
                raise ValueError('credential-like URL query refused')
        if parts.fragment:
            for key, _ in parse_qsl(parts.fragment, keep_blank_values=True):
                if _SECRET_KEY.search(key):
                    raise ValueError('credential-like URL fragment refused')
        # urlunsplit loses an empty '?' or '#'; preserve the original suffix byte-for-byte.
        suffix = value[value.index('://') + 3:]
        cut = min((suffix.find(c) for c in '/?#' if c in suffix), default=len(suffix))
        return scheme + '://' + host + suffix[cut:]
    except (ValueError, UnicodeError):
        raise ValueError('invalid or credential-bearing URL') from None


def normalize_value(kind: str, value: str) -> str:
    """Return a canonical validated value or raise a diagnostic without the value."""
    if not isinstance(kind, str) or kind not in KINDS:
        raise ValueError('unsupported or missing indicator kind')
    _safe_text(value)
    if kind == 'url':
        return normalize_url(value)
    value = value.strip()
    if not value:
        raise ValueError('empty indicator value')
    if kind in {'ip', 'cidr'}:
        if '%' in value:
            raise ValueError('scoped addresses are unsupported')
        try:
            return str(ipaddress.ip_address(value) if kind == 'ip' else ipaddress.ip_network(value, strict=False))
        except ValueError:
            raise ValueError('invalid address or network') from None
    if kind == 'domain':
        return _domain(value)
    if kind == 'program_name':
        if value in {'.', '..'} or len(value) > 255 or any(c in value for c in '/\\:<>"|?*'):
            raise ValueError('invalid program basename')
        return value.lower()
    if kind == 'ja4':
        if not re.fullmatch(r'[tqu][a-z0-9]{9}_[a-f0-9]{12}_[a-f0-9]{12}', value.lower()):
            raise ValueError('invalid JA4 fingerprint')
        return value.lower()
    if ':' in value:
        if not re.fullmatch(r'[a-fA-F0-9]{2}(?::[a-fA-F0-9]{2})+', value):
            raise ValueError('invalid digest separators')
        value = value.replace(':', '')
    if len(value) != _DIGEST_LENGTHS[kind] or not re.fullmatch(r'[a-fA-F0-9]+', value):
        raise ValueError('invalid fingerprint length or encoding')
    return value.lower()
