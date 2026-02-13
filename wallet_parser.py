#!/usr/bin/env python3
"""Parser maison pour wallet.dat (Berkeley DB) sans bsddb3/pywallet/bitcoin core."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import struct
import subprocess
from pathlib import Path
from typing import Any


BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class ParseError(Exception):
    pass


def read_compact_size(buf: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(buf):
        raise ParseError("compactSize hors limite")
    first = buf[pos]
    pos += 1
    if first < 253:
        return first, pos
    if first == 253:
        if pos + 2 > len(buf):
            raise ParseError("compactSize u16 tronqué")
        return struct.unpack_from("<H", buf, pos)[0], pos + 2
    if first == 254:
        if pos + 4 > len(buf):
            raise ParseError("compactSize u32 tronqué")
        return struct.unpack_from("<I", buf, pos)[0], pos + 4
    if pos + 8 > len(buf):
        raise ParseError("compactSize u64 tronqué")
    return struct.unpack_from("<Q", buf, pos)[0], pos + 8


def read_var_bytes(buf: bytes, pos: int) -> tuple[bytes, int]:
    ln, pos = read_compact_size(buf, pos)
    end = pos + ln
    if end > len(buf):
        raise ParseError("var bytes tronqué")
    return buf[pos:end], end


def parse_db_pages(raw: bytes) -> list[bytes]:
    if len(raw) < 512:
        return []
    # Page size Berkeley DB (meta page offset 20, little-endian en pratique pour wallet.dat)
    page_size = struct.unpack_from("<I", raw, 20)[0]
    if page_size < 512 or page_size > 65536:
        # fallback robuste
        page_size = 4096
    blobs: list[bytes] = []
    for pg_start in range(0, len(raw), page_size):
        page = raw[pg_start : pg_start + page_size]
        if len(page) < 32:
            continue
        page_type = page[25]
        # 5=btree leaf, 13=hash page; on tente les deux
        if page_type not in (5, 13):
            continue
        n_entries = struct.unpack_from("<H", page, 20)[0]
        if n_entries <= 0 or n_entries > 400:
            continue
        offsets: list[int] = []
        for i in range(n_entries):
            off = struct.unpack_from("<H", page, 26 + i * 2)[0]
            if 0 < off < page_size - 3:
                offsets.append(off)
        offsets = sorted(set(offsets))
        for off in offsets:
            # Heuristiques: variantes de layout item BDB
            candidates = []
            if off + 2 < page_size:
                l1 = struct.unpack_from("<H", page, off)[0]
                if 0 < l1 <= page_size - off - 2:
                    candidates.append(page[off + 2 : off + 2 + l1])
            if off + 3 < page_size:
                l2 = struct.unpack_from("<H", page, off + 1)[0]
                if 0 < l2 <= page_size - off - 3:
                    candidates.append(page[off + 3 : off + 3 + l2])
            for c in candidates:
                if len(c) >= 2:
                    blobs.append(c)
    return blobs


def decode_key_record(key_blob: bytes, value_blob: bytes) -> dict[str, Any] | None:
    try:
        pos = 0
        key_type_raw, pos = read_var_bytes(key_blob, pos)
        key_type = key_type_raw.decode("ascii", errors="strict")
    except Exception:
        return None

    rec: dict[str, Any] = {"type": key_type, "raw_key_hex": key_blob.hex(), "raw_value_hex": value_blob.hex()}
    try:
        if key_type == "mkey":
            if pos + 4 > len(key_blob):
                return None
            rec["mkey_id"] = struct.unpack_from("<I", key_blob, pos)[0]

            vpos = 0
            crypted, vpos = read_var_bytes(value_blob, vpos)
            salt, vpos = read_var_bytes(value_blob, vpos)
            if vpos + 8 > len(value_blob):
                raise ParseError("mkey tronqué")
            deriv_method = struct.unpack_from("<I", value_blob, vpos)[0]
            vpos += 4
            iterations = struct.unpack_from("<I", value_blob, vpos)[0]
            vpos += 4
            other, _ = read_var_bytes(value_blob, vpos)

            rec.update(
                {
                    "crypted_key": crypted.hex(),
                    "salt": salt.hex(),
                    "derivation_method": deriv_method,
                    "derive_iterations": iterations,
                    "other_derivation_params": other.hex(),
                }
            )
            return rec

        if key_type == "ckey":
            pubkey, _ = read_var_bytes(key_blob, pos)
            rec["pubkey"] = pubkey.hex()
            rec["crypted_secret"] = value_blob.hex()
            return rec

        if key_type == "key":
            pubkey, _ = read_var_bytes(key_blob, pos)
            rec["pubkey"] = pubkey.hex()
            rec["secret"] = value_blob.hex()
            return rec

        if key_type in {"name", "purpose"}:
            k, _ = read_var_bytes(key_blob, pos)
            rec["key"] = k.hex()
            rec["text"] = value_blob.decode("utf-8", errors="replace")
            return rec

        # Enregistrement reconnu mais pas décodé en détail
        if key_type in {"tx", "wkey", "hdseed", "version", "minversion", "defaultkey"}:
            return rec

    except Exception:
        return None

    return None


def bytes_to_key_sha512_aes(passphrase: str, salt: bytes, iterations: int) -> tuple[bytes, bytes]:
    data = passphrase.encode("utf-8") + salt
    h = hashlib.sha512(data).digest()
    for _ in range(max(1, iterations) - 1):
        h = hashlib.sha512(h).digest()
    return h[:32], h[32:48]


def aes256_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cmd = [
        "openssl",
        "enc",
        "-d",
        "-aes-256-cbc",
        "-nopad",
        "-K",
        key.hex(),
        "-iv",
        iv.hex(),
    ]
    proc = subprocess.run(cmd, input=ciphertext, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if proc.returncode != 0:
        raise ParseError(f"openssl a échoué: {proc.stderr.decode(errors='ignore').strip()}")
    return proc.stdout


def strip_pkcs7_padding(data: bytes) -> bytes:
    if not data:
        return data
    pad = data[-1]
    if pad == 0 or pad > 16 or pad > len(data):
        return data
    if data[-pad:] != bytes([pad]) * pad:
        return data
    return data[:-pad]


def normalize_secret32(data: bytes) -> bytes:
    if len(data) == 32:
        return data
    unpadded = strip_pkcs7_padding(data)
    if len(unpadded) == 32:
        return unpadded
    raise ParseError(f"secret déchiffré de taille inattendue: {len(data)}")


def decrypt_master_key(mkey_rec: dict[str, Any], passphrase: str) -> bytes:
    salt = bytes.fromhex(mkey_rec["salt"])
    crypted = bytes.fromhex(mkey_rec["crypted_key"])
    iterations = int(mkey_rec["derive_iterations"])
    key, iv = bytes_to_key_sha512_aes(passphrase, salt, iterations)
    return normalize_secret32(aes256_cbc_decrypt(crypted, key, iv))


def try_decrypt_ckey(master_key: bytes, ckey_rec: dict[str, Any]) -> bytes:
    pub = bytes.fromhex(ckey_rec["pubkey"])
    iv = hashlib.sha256(hashlib.sha256(pub).digest()).digest()[:16]
    crypted = bytes.fromhex(ckey_rec["crypted_secret"])
    return normalize_secret32(aes256_cbc_decrypt(crypted, master_key[:32], iv))


def b58encode(data: bytes) -> str:
    num = int.from_bytes(data, "big")
    encoded = ""
    while num > 0:
        num, rem = divmod(num, 58)
        encoded = BASE58_ALPHABET[rem] + encoded
    prefix = "1" * (len(data) - len(data.lstrip(b"\x00")))
    return prefix + (encoded or "")


def b58check(version: bytes, payload: bytes) -> str:
    raw = version + payload
    checksum = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    return b58encode(raw + checksum)


def pubkey_to_p2pkh_address(pubkey: bytes, testnet: bool = False) -> str:
    sha = hashlib.sha256(pubkey).digest()
    ripe = hashlib.new("ripemd160", sha).digest()
    version = b"\x6f" if testnet else b"\x00"
    return b58check(version, ripe)


def private_key_to_wif(secret32: bytes, compressed: bool, testnet: bool = False) -> str:
    version = b"\xef" if testnet else b"\x80"
    payload = secret32 + (b"\x01" if compressed else b"")
    return b58check(version, payload)


def parse_wallet(path: Path, passphrase: str | None = None) -> dict[str, Any]:
    raw = path.read_bytes()
    blobs = parse_db_pages(raw)

    records: list[dict[str, Any]] = []
    for i in range(0, len(blobs) - 1, 2):
        rec = decode_key_record(blobs[i], blobs[i + 1])
        if rec:
            records.append(rec)

    # Déduplication simple
    uniq: list[dict[str, Any]] = []
    seen = set()
    for r in records:
        sig = (r.get("type"), r.get("raw_key_hex"), r.get("raw_value_hex"))
        if sig in seen:
            continue
        seen.add(sig)
        uniq.append(r)

    out: dict[str, Any] = {
        "wallet_path": str(path),
        "records_count": len(uniq),
        "records": uniq,
        "decryption": {"attempted": False, "success": False, "details": ""},
    }

    mkeys = [r for r in uniq if r.get("type") == "mkey"]
    ckeys = [r for r in uniq if r.get("type") == "ckey"]

    if mkeys and ckeys:
        out["decryption"]["attempted"] = True
        if not passphrase:
            passphrase = getpass.getpass("walletpassphrase: ")
        try:
            master = decrypt_master_key(mkeys[0], passphrase)
            dec = []
            for c in ckeys:
                try:
                    secret = try_decrypt_ckey(master, c)
                    pubkey = bytes.fromhex(c["pubkey"])
                    if len(secret) != 32 or len(pubkey) not in (33, 65):
                        continue
                    compressed = len(pubkey) == 33
                    dec.append(
                        {
                            "pubkey": c["pubkey"],
                            "crypted_secret": c["crypted_secret"],
                            "decrypted_crypted_secret": secret.hex(),
                            "address_p2pkh": pubkey_to_p2pkh_address(pubkey),
                            "private_key_hex": secret.hex(),
                            "private_key_wif": private_key_to_wif(secret, compressed=compressed),
                            "compressed": compressed,
                        }
                    )
                except Exception:
                    continue
            if dec:
                out["decryption"].update({"success": True, "details": "ckey déchiffrées", "master_key_hex": master.hex()})
                out["decrypted_keys"] = dec
            else:
                out["decryption"]["details"] = "master key ok, mais aucune ckey validée"
        except Exception as exc:
            out["decryption"]["details"] = f"échec déchiffrement: {exc}"

    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Parser maison wallet.dat sans bsddb3/pywallet/bitcoin libs, avec option walletpassphrase et sortie JSON.",
    )
    parser.add_argument("wallet", type=Path, help="Chemin vers wallet.dat")
    parser.add_argument("--walletpassphrase", help="Passphrase wallet chiffré (sinon demande interactive)")
    parser.add_argument("--out", type=Path, help="Chemin du JSON de sortie")
    args = parser.parse_args()

    result = parse_wallet(args.wallet, passphrase=args.walletpassphrase)
    rendered = json.dumps(result, indent=2, ensure_ascii=False)

    if args.out:
        args.out.write_text(rendered + "\n", encoding="utf-8")
        print(f"JSON écrit: {args.out}")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
