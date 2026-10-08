#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AESCrypt3 - Sichere Datei- und Text-Verschlüsselung
Optimierte Version mit hoher I/O-Performance, Krypto-Agilität und RAM-Zeroizing.
"""

import os
import sys
import secrets
import struct
import tempfile
import base64
import ctypes
import errno
from pathlib import Path
from typing import Optional, Callable, Tuple, Union

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag

# --- Konfiguration & Konstanten ---

CHUNK_SIZE = 1024 * 1024  # 1 MB Standard-Chunk-Größe

# Legacy-V2 Formatspezifikation
MAGIC = b"AESCRYPT2"
FORMAT_VERSION = 2

# V3 Formatspezifikation
MAGIC_V3 = b"AESCRYPT3"
FORMAT_VERSION_V3 = 1

APP_VERSION = "1.3.2_test"

SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16

NAME_LEN_SIZE = 4
MAX_NAME_LEN = 1024

V3_CHUNK_SIZE_SIZE = 4
V3_FILE_SIZE_SIZE = 8
V3_CHUNK_COUNT_SIZE = 8
V3_RECORD_HEADER_SIZE = 8 + 4 + 4  # Index (Q), PlainLen (I), CipherLen (I)
MAX_V3_CHUNK_SIZE = 64 * 1024 * 1024
MAX_V3_CHUNK_COUNT = 0xFFFFFFFF

# Default KDF Parameter
SCRYPT_N = 2**16
SCRYPT_R = 8
SCRYPT_P = 1

# KDF Sicherheitsgrenzen gegen DoS
SCRYPT_MAX_N = 2**17
SCRYPT_MAX_R = 16
SCRYPT_MAX_P = 4
SCRYPT_MAX_MEMORY_BYTES = 128 * 1024 * 1024  # Max. 128 MB RAM für Key Derivation

# System-Lookup für atomares Rename (einmalig beim Laden gecacht)
_RENAMEAT2_FUNC = None
if sys.platform.startswith("linux"):
    try:
        _libc = ctypes.CDLL(None, use_errno=True)
        _RENAMEAT2_FUNC = getattr(_libc, "renameat2")
        _RENAMEAT2_FUNC.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        _RENAMEAT2_FUNC.restype = ctypes.c_int
    except (AttributeError, OSError):
        _RENAMEAT2_FUNC = None


# --- Hilfsfunktionen für Speicher & Sicherheit ---

def zeroize(buf: bytearray) -> None:
    """Überschreibt sensitives Schlüsselmaterial im Arbeitsspeicher mit Nullen."""
    if isinstance(buf, bytearray):
        buf[:] = b"\x00" * len(buf)


def derive_key(
    password: str,
    salt: bytes,
    n: int = SCRYPT_N,
    r: int = SCRYPT_R,
    p: int = SCRYPT_P,
) -> bytearray:
    """Leitet mittels Scrypt einen 256-Bit-Schlüssel als veränderbaren bytearray ab."""
    if not isinstance(password, str):
        raise TypeError("Passwort muss ein String sein.")
    if not password:
        raise ValueError("Passwort darf nicht leer sein.")
    if len(salt) != SALT_SIZE:
        raise ValueError("Ungültige Salt-Länge.")

    if not isinstance(n, int) or n <= 1 or n > SCRYPT_MAX_N or (n & (n - 1)):
        raise ValueError("Ungültige Scrypt-Konfiguration (N).")
    if not isinstance(r, int) or not 1 <= r <= SCRYPT_MAX_R:
        raise ValueError("Ungültige Scrypt-Konfiguration (r).")
    if not isinstance(p, int) or not 1 <= p <= SCRYPT_MAX_P:
        raise ValueError("Ungültige Scrypt-Konfiguration (p).")

    estimated_memory = 128 * n * r + 256 * r * p + 256 * r
    if estimated_memory > SCRYPT_MAX_MEMORY_BYTES:
        raise ValueError("Scrypt-Konfiguration überschreitet das Speicherlimit.")

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=n,
        r=r,
        p=p,
    )
    return bytearray(kdf.derive(password.encode("utf-8")))


# --- V2 Legacy Format Support ---

def build_header(salt: bytes, nonce: bytes) -> bytes:
    if len(salt) != SALT_SIZE:
        raise ValueError("Ungültige Salt-Länge.")
    if len(nonce) != NONCE_SIZE:
        raise ValueError("Ungültige Nonce-Länge.")
    return MAGIC + bytes([FORMAT_VERSION]) + salt + nonce


def read_header(fin) -> Tuple[bytes, bytes, bytes]:
    magic = fin.read(len(MAGIC))
    if magic != MAGIC:
        raise ValueError("Ungültiges Dateiformat.")

    version = fin.read(1)
    if len(version) != 1 or version[0] != FORMAT_VERSION:
        raise ValueError("Nicht unterstützte Dateiformat-Version.")

    salt = fin.read(SALT_SIZE)
    nonce = fin.read(NONCE_SIZE)

    if len(salt) != SALT_SIZE or len(nonce) != NONCE_SIZE:
        raise ValueError("Datei-Header ist unvollständig.")

    header = MAGIC + version + salt + nonce
    return salt, nonce, header


# --- V3 Format Funktionen (mit Krypto-Agilität & Batch-I/O) ---

def build_v3_header(
    salt: bytes,
    base_nonce: bytes,
    file_size: int,
    data_chunk_count: int,
    scrypt_n: int = SCRYPT_N,
    scrypt_r: int = SCRYPT_R,
    scrypt_p: int = SCRYPT_P,
) -> bytes:
    """Erstellt den V3 Header inkl. eingebetteter Scrypt-Parameter für Zukunftsfähigkeit."""
    if len(salt) != SALT_SIZE:
        raise ValueError("Ungültige Salt-Länge.")
    if len(base_nonce) != NONCE_SIZE:
        raise ValueError("Ungültige Nonce-Länge.")
    if not 0 <= file_size <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("Datei ist zu groß für das AESCRYPT3-Format.")
    if not 0 <= data_chunk_count <= MAX_V3_CHUNK_COUNT:
        raise ValueError("Zu viele Chunks.")

    scrypt_params = struct.pack(">III", scrypt_n, scrypt_r, scrypt_p)

    return (
        MAGIC_V3
        + bytes([FORMAT_VERSION_V3])
        + scrypt_params
        + salt
        + base_nonce
        + struct.pack(">I", CHUNK_SIZE)
        + struct.pack(">Q", file_size)
        + struct.pack(">Q", data_chunk_count)
    )


def read_v3_header(fin) -> Tuple[bytes, bytes, int, int, int, bytes, int, int, int]:
    """Liest und validiert den V3 Header inklusive KDF-Parametern."""
    magic = fin.read(len(MAGIC_V3))
    if magic != MAGIC_V3:
        raise ValueError("Ungültiges oder nicht unterstütztes AESCRYPT3-Format.")

    version = fin.read(1)
    if len(version) != 1 or version[0] != FORMAT_VERSION_V3:
        raise ValueError("Nicht unterstützte AESCRYPT3-Version.")

    scrypt_raw = fin.read(12)
    if len(scrypt_raw) != 12:
        raise ValueError("AESCRYPT3-Header unvollständig (Scrypt-Parameter).")
    scrypt_n, scrypt_r, scrypt_p = struct.unpack(">III", scrypt_raw)

    salt = fin.read(SALT_SIZE)
    base_nonce = fin.read(NONCE_SIZE)
    chunk_size_raw = fin.read(V3_CHUNK_SIZE_SIZE)
    file_size_raw = fin.read(V3_FILE_SIZE_SIZE)
    chunk_count_raw = fin.read(V3_CHUNK_COUNT_SIZE)

    if (
        len(salt) != SALT_SIZE
        or len(base_nonce) != NONCE_SIZE
        or len(chunk_size_raw) != V3_CHUNK_SIZE_SIZE
        or len(file_size_raw) != V3_FILE_SIZE_SIZE
        or len(chunk_count_raw) != V3_CHUNK_COUNT_SIZE
    ):
        raise ValueError("AESCRYPT3-Header unvollständig.")

    chunk_size = struct.unpack(">I", chunk_size_raw)[0]
    file_size = struct.unpack(">Q", file_size_raw)[0]
    data_chunk_count = struct.unpack(">Q", chunk_count_raw)[0]

    if chunk_size == 0 or chunk_size > MAX_V3_CHUNK_SIZE:
        raise ValueError("Ungültige AESCRYPT3-Chunk-Größe.")

    expected_count = (file_size + chunk_size - 1) // chunk_size if file_size else 0
    if expected_count > MAX_V3_CHUNK_COUNT:
        raise ValueError("AESCRYPT3-Datei enthält zu viele Chunks.")
    if data_chunk_count != expected_count:
        raise ValueError("Ungültige AESCRYPT3-Chunk-Anzahl.")

    header = (
        MAGIC_V3
        + version
        + scrypt_raw
        + salt
        + base_nonce
        + chunk_size_raw
        + file_size_raw
        + chunk_count_raw
    )

    return (
        salt,
        base_nonce,
        chunk_size,
        file_size,
        data_chunk_count,
        header,
        scrypt_n,
        scrypt_r,
        scrypt_p,
    )


def build_v3_nonce(base_nonce: bytes, chunk_index: int) -> bytes:
    if len(base_nonce) != NONCE_SIZE:
        raise ValueError("Ungültige Base-Nonce-Länge.")
    if not 0 <= chunk_index <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("Chunk-Index liegt außerhalb des gültigen Bereichs.")

    nonce_int = int.from_bytes(base_nonce, byteorder="big") ^ chunk_index
    return nonce_int.to_bytes(NONCE_SIZE, byteorder="big")


def build_v3_aad(header: bytes, chunk_index: int, plaintext_size: int) -> bytes:
    if not 0 <= chunk_index <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("Chunk-Index liegt außerhalb des gültigen Bereichs.")
    if not 0 <= plaintext_size <= 0xFFFFFFFF:
        raise ValueError("Klartextgröße liegt außerhalb des gültigen Bereichs.")

    return header + struct.pack(">QI", chunk_index, plaintext_size)


def encrypt_v3_chunk(
    aes_key: bytearray,
    base_nonce: bytes,
    header: bytes,
    chunk_index: int,
    plaintext: bytes,
) -> Tuple[bytes, bytes]:
    nonce = build_v3_nonce(base_nonce, chunk_index)
    cipher = Cipher(algorithms.AES(bytes(aes_key)), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(
        build_v3_aad(header, chunk_index, len(plaintext))
    )
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, encryptor.tag


def decrypt_v3_chunk(
    aes_key: bytearray,
    base_nonce: bytes,
    header: bytes,
    chunk_index: int,
    plaintext_size: int,
    ciphertext: bytes,
    tag: bytes,
) -> bytes:
    if len(ciphertext) != plaintext_size:
        raise ValueError("Ungültige Chunk-Größe.")
    if len(tag) != TAG_SIZE:
        raise ValueError("Authentifizierungs-Tag fehlt oder ist ungültig.")

    nonce = build_v3_nonce(base_nonce, chunk_index)
    cipher = Cipher(algorithms.AES(bytes(aes_key)), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(
        build_v3_aad(header, chunk_index, plaintext_size)
    )
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidTag:
        raise ValueError("Falsches Passwort oder beschädigter AESCRYPT3-Chunk.")

    if len(plaintext) != plaintext_size:
        raise ValueError("Entschlüsselter Chunk hat eine ungültige Größe.")
    return plaintext


def write_v3_chunk(
    fout,
    aes_key: bytearray,
    base_nonce: bytes,
    header: bytes,
    chunk_index: int,
    plaintext: bytes,
) -> None:
    """Schreibt einen V3 Chunk mit optimiertem Single-I/O-Systemcall."""
    ciphertext, tag = encrypt_v3_chunk(
        aes_key, base_nonce, header, chunk_index, plaintext
    )
    chunk_header = struct.pack(">QII", chunk_index, len(plaintext), len(ciphertext))
    fout.write(chunk_header + ciphertext + tag)


def read_v3_chunk(fin, max_chunk_size: int) -> Optional[Tuple[int, int, bytes, bytes]]:
    record_header = fin.read(V3_RECORD_HEADER_SIZE)
    if not record_header:
        return None

    if len(record_header) < V3_RECORD_HEADER_SIZE:
        raise ValueError("AESCRYPT3-Chunk-Header ist unvollständig.")

    chunk_index, plain_size, cipher_size = struct.unpack(">QII", record_header)

    if plain_size != cipher_size:
        raise ValueError("AESCRYPT3-Nutzdaten-Länge stimmt nicht mit Chiffretext-Länge überein.")

    if plain_size > max_chunk_size:
        raise ValueError("AESCRYPT3-Chunk überschreitet maximale erlaubte Größe.")

    ciphertext = fin.read(cipher_size)
    tag = fin.read(TAG_SIZE)

    if len(ciphertext) != cipher_size or len(tag) != TAG_SIZE:
        raise ValueError("AESCRYPT3-Chunk ist unvollständig.")

    return chunk_index, plain_size, ciphertext, tag


# --- Dateisystem-Sicherheit ---

def _try_atomic_noreplace_rename(
    tmp_path: Union[str, Path], output_path: Union[str, Path]
) -> bool:
    """Versucht ein atomares Ersetzen ohne Überschreiben bestehender Dateien."""
    tmp_path = Path(tmp_path)
    output_path = Path(output_path)

    if sys.platform.startswith("linux"):
        if _RENAMEAT2_FUNC is None:
            return False

        result = _RENAMEAT2_FUNC(
            -100, os.fsencode(tmp_path), -100, os.fsencode(output_path), 1
        )  # AT_FDCWD = -100, RENAME_NOREPLACE = 1
        if result == 0:
            return True

        error_code = ctypes.get_errno()
        if error_code == errno.EEXIST:
            raise FileExistsError(error_code, os.strerror(error_code), str(output_path))
        unsupported = {
            errno.ENOSYS,
            errno.EINVAL,
            errno.EXDEV,
            getattr(errno, "EOPNOTSUPP", errno.EINVAL),
            getattr(errno, "ENOTSUP", errno.EINVAL),
        }
        if error_code in unsupported:
            return False
        raise OSError(error_code, os.strerror(error_code), str(output_path))

    if os.name == "nt":
        try:
            os.rename(tmp_path, output_path)
            return True
        except FileExistsError:
            raise
        except OSError:
            return False

    return False


def install_temp_no_overwrite(
    tmp_path: Union[str, Path], output_path: Union[str, Path]
) -> None:
    """Überführt eine temporäre Datei sicher an ihr Ziel und schützt vor Race Conditions."""
    tmp_path = Path(tmp_path)
    output_path = Path(output_path)

    tmp_stat = tmp_path.stat()
    installed_identity = (tmp_stat.st_dev, tmp_stat.st_ino)

    try:
        os.link(tmp_path, output_path)
    except FileExistsError:
        raise FileExistsError(f"Zieldatei existiert bereits: {output_path}")
    except OSError:
        try:
            if _try_atomic_noreplace_rename(tmp_path, output_path):
                return
        except FileExistsError:
            raise FileExistsError(f"Zieldatei existiert bereits: {output_path}")

        out_fd = None
        created_identity = None
        try:
            out_fd = os.open(
                output_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            out_stat = os.fstat(out_fd)
            created_identity = (out_stat.st_dev, out_stat.st_ino)
            installed_identity = created_identity

            with os.fdopen(out_fd, "wb") as fout:
                out_fd = None
                with tmp_path.open("rb") as fin:
                    while True:
                        block = fin.read(CHUNK_SIZE)
                        if not block:
                            break
                        fout.write(block)
                fout.flush()
                os.fsync(fout.fileno())
        except FileExistsError:
            raise FileExistsError(f"Zieldatei existiert bereits: {output_path}")
        except OSError as e:
            if out_fd is not None:
                try:
                    os.close(out_fd)
                except OSError:
                    pass
            cleanup_note = ""
            if created_identity is not None:
                try:
                    current = output_path.stat()
                    if (current.st_dev, current.st_ino) == created_identity:
                        output_path.unlink()
                except FileNotFoundError:
                    pass
                except OSError as cleanup_error:
                    cleanup_note = f" Die unvollständige Zieldatei konnte nicht entfernt werden: {cleanup_error}"
            raise OSError(
                f"Zieldatei konnte nicht sicher installiert werden: {e}.{cleanup_note}"
            )

    try:
        tmp_path.unlink()
    except OSError as e:
        rollback_note = ""
        if installed_identity is not None:
            try:
                current = output_path.stat()
                if (current.st_dev, current.st_ino) == installed_identity:
                    output_path.unlink()
                else:
                    rollback_note = " Das Ziel wurde inzwischen verändert; es blieb unangetastet."
            except FileNotFoundError:
                pass
            except OSError as rollback_error:
                rollback_note = f" Das Ziel konnte nicht zurückgerollt werden: {rollback_error}"
        raise OSError(
            f"Temporäre Datei konnte nicht entfernt werden: {e}.{rollback_note}"
        )


# --- Text-Verschlüsselung / Entschlüsselung ---

def encrypt_text(text: str, password: str) -> str:
    """Verschlüsselt einen String in ein Base64-kodiertes Format."""
    if not isinstance(text, str):
        raise TypeError("Text muss ein String sein.")

    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    aes_key = derive_key(password, salt)

    try:
        header = build_header(salt, nonce)
        plaintext_bytes = text.encode("utf-8")

        cipher = Cipher(algorithms.AES(bytes(aes_key)), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(header)

        ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
        tag = encryptor.tag

        payload = header + ciphertext + tag
        return base64.b64encode(payload).decode("utf-8")
    finally:
        zeroize(aes_key)


def decrypt_text(encoded_payload: str, password: str) -> str:
    """Entschlüsselt einen Base64-kodierten Chiffretext-String."""
    try:
        payload = base64.b64decode(encoded_payload.encode("utf-8"), validate=True)
    except Exception:
        raise ValueError("Ungültiges Base64-Format.")

    header_size = len(MAGIC) + 1 + SALT_SIZE + NONCE_SIZE
    minimum_size = header_size + TAG_SIZE

    if len(payload) < minimum_size:
        raise ValueError("Daten zu kurz oder beschädigt.")

    if payload[: len(MAGIC)] != MAGIC:
        raise ValueError("Ungültiges oder nicht unterstütztes Format.")
    if payload[len(MAGIC)] != FORMAT_VERSION:
        raise ValueError("Nicht unterstützte Dateiformat-Version.")

    header = payload[:header_size]
    salt = header[len(MAGIC) + 1 : len(MAGIC) + 1 + SALT_SIZE]
    nonce = header[len(MAGIC) + 1 + SALT_SIZE :]

    tag = payload[-TAG_SIZE:]
    ciphertext = payload[header_size:-TAG_SIZE]

    aes_key = derive_key(password, salt)

    try:
        cipher = Cipher(algorithms.AES(bytes(aes_key)), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(header)

        plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext_bytes.decode("utf-8")
    except InvalidTag:
        raise ValueError("Falsches Passwort oder beschädigte Daten.")
    finally:
        zeroize(aes_key)


# --- Datei-Verschlüsselung / Entschlüsselung ---

def encrypt_file(
    input_path: Union[str, Path],
    output_path: Union[str, Path],
    password: str,
    progress_cb: Optional[Callable[[int, int], Optional[bool]]] = None,
) -> Path:
    """Verschlüsselt eine Datei im modernen AESCRYPT3-Format."""
    in_path = Path(input_path).resolve()
    out_path = Path(output_path).resolve()

    if in_path == out_path:
        raise ValueError("Quelle und Ziel dürfen nicht identisch sein.")

    file_size = in_path.stat().st_size
    data_chunk_count = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE if file_size else 0

    salt = secrets.token_bytes(SALT_SIZE)
    base_nonce = secrets.token_bytes(NONCE_SIZE)
    aes_key = derive_key(password, salt)

    orig_name = in_path.name.encode("utf-8")
    if len(orig_name) == 0 or len(orig_name) > MAX_NAME_LEN:
        raise ValueError("Dateiname zu lang oder leer.")

    metadata = struct.pack(">I", len(orig_name)) + orig_name
    header = build_v3_header(salt, base_nonce, file_size, data_chunk_count)

    out_dir = out_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    tmp_fd, tmp_path_str = tempfile.mkstemp(
        dir=out_dir, prefix=".aescrypto-", suffix=".tmp"
    )
    tmp_path = Path(tmp_path_str)

    try:
        with in_path.open("rb") as fin:
            with os.fdopen(tmp_fd, "wb") as fout:
                tmp_fd = None
                fout.write(header)

                # Chunk 0: Verschlüsselte Dateimetadaten
                write_v3_chunk(fout, aes_key, base_nonce, header, 0, metadata)

                bytes_read = 0
                for index in range(1, data_chunk_count + 1):
                    expected = min(CHUNK_SIZE, file_size - bytes_read)
                    chunk = fin.read(expected)
                    if len(chunk) != expected:
                        raise ValueError(
                            "Quelldatei konnte während der Verschlüsselung nicht vollständig gelesen werden."
                        )

                    write_v3_chunk(fout, aes_key, base_nonce, header, index, chunk)

                    bytes_read += len(chunk)
                    if progress_cb:
                        should_stop = progress_cb(bytes_read, file_size)
                        if should_stop is False:
                            raise InterruptedError("Verarbeitung vom Benutzer gestoppt.")

                if bytes_read != file_size:
                    raise ValueError("Dateigröße hat sich während der Verschlüsselung geändert.")

                if fin.read(1):
                    raise ValueError("Quelldatei ist während der Verschlüsselung gewachsen.")

                fout.flush()
                os.fsync(fout.fileno())

        install_temp_no_overwrite(tmp_path, out_path)
        tmp_path = None
        return out_path

    except Exception:
        if tmp_fd is not None:
            try:
                os.close(tmp_fd)
            except OSError:
                pass
        if tmp_path and tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
        raise
    finally:
        zeroize(aes_key)


def decrypt_file_v3(
    input_path: Union[str, Path],
    output_path: Union[str, Path],
    password: str,
    progress_cb: Optional[Callable[[int, int], Optional[bool]]] = None,
) -> Path:
    """Entschlüsselt eine AESCRYPT3-Datei."""
    in_path = Path(input_path).resolve()
    out_path = Path(output_path).resolve()

    if in_path == out_path:
        raise ValueError("Quelle und Ziel dürfen nicht identisch sein.")

    fsize = in_path.stat().st_size
    tmp_path = None

    with in_path.open("rb") as fin:
        (
            salt,
            base_nonce,
            chunk_size,
            file_size,
            data_chunk_count,
            header,
            scrypt_n,
            scrypt_r,
            scrypt_p,
        ) = read_v3_header(fin)

        if chunk_size != CHUNK_SIZE:
            if chunk_size <= 0 or chunk_size > MAX_V3_CHUNK_SIZE:
                raise ValueError("Ungültige AESCRYPT3-Chunk-Größe.")

        minimum_size = len(header) + V3_RECORD_HEADER_SIZE + TAG_SIZE
        if fsize < minimum_size:
            raise ValueError("AESCRYPT3-Datei zu klein oder beschädigt.")

        aes_key = derive_key(password, salt, n=scrypt_n, r=scrypt_r, p=scrypt_p)

        out_dir = out_path.parent
        out_dir.mkdir(parents=True, exist_ok=True)
        tmp_fd, tmp_path_str = tempfile.mkstemp(
            dir=out_dir, prefix=".aescrypto-", suffix=".tmp"
        )
        tmp_path = Path(tmp_path_str)

        try:
            with os.fdopen(tmp_fd, "wb") as fout:
                tmp_fd = None
                first = read_v3_chunk(
                    fin, max_chunk_size=NAME_LEN_SIZE + MAX_NAME_LEN
                )
                if first is None:
                    raise ValueError("AESCRYPT3-Datei enthält keine Metadaten.")

                index, plain_size, ciphertext, tag = first
                if index != 0:
                    raise ValueError("AESCRYPT3-Datei beginnt nicht mit Metadaten.")

                metadata = decrypt_v3_chunk(
                    aes_key, base_nonce, header, index, plain_size, ciphertext, tag
                )

                if len(metadata) < NAME_LEN_SIZE:
                    raise ValueError("AESCRYPT3-Dateiname fehlt.")

                name_len = struct.unpack(">I", metadata[:NAME_LEN_SIZE])[0]
                if name_len == 0 or name_len > MAX_NAME_LEN:
                    raise ValueError("Ungültiges Dateiformat: ungültiger Dateiname.")
                if len(metadata) != NAME_LEN_SIZE + name_len:
                    raise ValueError("AESCRYPT3-Metadaten sind ungültig.")

                try:
                    name_bytes = metadata[NAME_LEN_SIZE:]
                    name_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    raise ValueError("Ungültiger Dateiname.")

                expected_total_data = file_size
                bytes_written = 0

                for expected_index in range(1, data_chunk_count + 1):
                    record = read_v3_chunk(fin, max_chunk_size=chunk_size)
                    if record is None:
                        raise ValueError("AESCRYPT3-Datei ist unvollständig.")

                    index, plain_size, ciphertext, tag = record
                    if index != expected_index:
                        raise ValueError(
                            "AESCRYPT3-Chunk-Reihenfolge oder Chunk-Anzahl ist ungültig."
                        )

                    expected_size = min(
                        chunk_size, expected_total_data - bytes_written
                    )
                    if plain_size != expected_size:
                        raise ValueError("AESCRYPT3-Chunk hat eine unerwartete Größe.")

                    plaintext = decrypt_v3_chunk(
                        aes_key, base_nonce, header, index, plain_size, ciphertext, tag
                    )

                    fout.write(plaintext)
                    bytes_written += len(plaintext)

                    if progress_cb:
                        should_stop = progress_cb(bytes_written, file_size)
                        if should_stop is False:
                            raise InterruptedError("Verarbeitung vom Benutzer gestoppt.")

                if bytes_written != file_size:
                    raise ValueError(
                        "AESCRYPT3-Dateigröße stimmt nicht mit dem Header überein."
                    )

                trailing = fin.read(1)
                if trailing:
                    raise ValueError(
                        "AESCRYPT3-Datei enthält unerwartete zusätzliche Daten."
                    )

                fout.flush()
                os.fsync(fout.fileno())

            install_temp_no_overwrite(tmp_path, out_path)
            tmp_path = None
            return out_path

        except Exception:
            if tmp_path and tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass
            raise
        finally:
            zeroize(aes_key)


def decrypt_file_v2(
    input_path: Union[str, Path],
    output_path: Union[str, Path],
    password: str,
    progress_cb: Optional[Callable[[int, int], Optional[bool]]] = None,
) -> Path:
    """Entschlüsselt eine ältere AESCRYPT2 (V2) Datei zur Abwärtskompatibilität."""
    in_path = Path(input_path).resolve()
    out_path = Path(output_path).resolve()

    if in_path == out_path:
        raise ValueError("Quelle und Ziel dürfen nicht identisch sein.")

    fsize = in_path.stat().st_size
    header_size = len(MAGIC) + 1 + SALT_SIZE + NONCE_SIZE
    minimum_size = header_size + NAME_LEN_SIZE + 1 + TAG_SIZE
    if fsize < minimum_size:
        raise ValueError("Datei zu klein oder beschädigt.")

    tmp_path = None
    tmp_fd = None
    aes_key = None
    try:
        with in_path.open("rb") as fin:
            salt, nonce, header = read_header(fin)

            fin.seek(fsize - TAG_SIZE)
            tag = fin.read(TAG_SIZE)
            if len(tag) != TAG_SIZE:
                raise ValueError("Authentifizierungs-Tag fehlt.")

            ciphertext_size = fsize - len(header) - TAG_SIZE
            if ciphertext_size < NAME_LEN_SIZE + 1:
                raise ValueError("Ungültige Dateistruktur.")

            out_dir = out_path.parent
            out_dir.mkdir(parents=True, exist_ok=True)
            tmp_fd, tmp_path_str = tempfile.mkstemp(
                dir=out_dir, prefix=".aescrypto-", suffix=".tmp"
            )
            tmp_path = Path(tmp_path_str)

            aes_key = derive_key(password, salt)
            cipher = Cipher(algorithms.AES(bytes(aes_key)), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()
            decryptor.authenticate_additional_data(header)

            prefix = bytearray()
            name_end = None
            processed = 0
            fin.seek(len(header))

            with os.fdopen(tmp_fd, "wb") as fout:
                tmp_fd = None

                def consume_plaintext(data: bytes) -> None:
                    nonlocal name_end
                    if not data:
                        return
                    if name_end is not None:
                        fout.write(data)
                        return

                    prefix.extend(data)
                    if len(prefix) < NAME_LEN_SIZE:
                        return

                    name_len = struct.unpack(">I", prefix[:NAME_LEN_SIZE])[0]
                    if name_len == 0 or name_len > MAX_NAME_LEN:
                        raise ValueError("Ungültiges Dateiformat: ungültiger Dateiname.")

                    expected_end = NAME_LEN_SIZE + name_len
                    if len(prefix) < expected_end:
                        return

                    try:
                        bytes(prefix[NAME_LEN_SIZE:expected_end]).decode("utf
