"""QRSig: signed QR codes. See SPEC.md."""
from .format import INVALID, UNSIGNED, UNVERIFIABLE, VERIFIED, Key, KeysUnavailable, Result, parse, sign, verify

__version__ = "0.1.0"
__all__ = ["INVALID", "UNSIGNED", "UNVERIFIABLE", "VERIFIED", "Key", "KeysUnavailable", "Result",
           "parse", "sign", "verify"]
