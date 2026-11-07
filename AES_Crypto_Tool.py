#!/usr/bin/env python3
"""AES Crypto Tool – Einzeldatei mit PySide6-GUI, Kryptografie-Engine und CLI.

Die vorhandene AESCRYPT2/AESCRYPT3-Engine bleibt in dieser Datei enthalten.
Ohne Argumente startet die GUI; mit Argumenten wird die CLI ausgeführt.
"""
#!/usr/bin/env python3

import os
import hashlib
import sys
import secrets
import struct
import threading
import argparse
import multiprocessing
import getpass
import tempfile
import base64
import ctypes
import errno


try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
    from PIL import Image, ImageDraw

    GUI_AVAILABLE = True

except ImportError:
    GUI_AVAILABLE = False


# Tray ist optional. Fehlt pystray, bleibt die normale GUI trotzdem verfügbar.
PYSTRAY_AVAILABLE = False
if GUI_AVAILABLE and not sys.platform.startswith("linux"):
    try:
        import pystray
        from pystray import MenuItem as item
        PYSTRAY_AVAILABLE = True
    except ImportError:
        PYSTRAY_AVAILABLE = False


try:
    from tkinterdnd2 import TkinterDnD, DND_FILES

    DND_AVAILABLE = True

except Exception:
    DND_AVAILABLE = False


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag


# ============================================================
# Konfiguration
# ============================================================

CHUNK_SIZE = 1024 * 1024

# AESCRYPT2 bleibt als Legacy-Format für bestehende Dateien erhalten.
MAGIC = b"AESCRYPT2"
FORMAT_VERSION = 3

# Neues chunk-basiertes Dateiformat.
MAGIC_V3 = b"AESCRYPT3"
FORMAT_VERSION_V3 = 1

# Version 2 des AESCRYPT3-Headers: KDF-Parameter liegen im Header.
FORMAT_VERSION_V3_KDF = 2

APP_VERSION = "1.5.0"

SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16

NAME_LEN_SIZE = 4
MAX_NAME_LEN = 1024

# AESCRYPT3 Header-Felder
V3_CHUNK_SIZE_SIZE = 4
V3_FILE_SIZE_SIZE = 8
V3_CHUNK_COUNT_SIZE = 8
V3_KDF_PARAM_SIZE = 4          # je Feld in v2: N, r, p als >I
V3_RECORD_HEADER_SIZE = 8 + 4 + 4
MAX_V3_CHUNK_SIZE = 64 * 1024 * 1024
MAX_V3_CHUNK_COUNT = 0xFFFFFFFF

# Scrypt ist speicherhart und erschwert Offline-Passwortangriffe.
# Diese Werte dienen als Default für NEU geschriebene Dateien und als
# Fallback für alte v1-Dateien, die keine Parameter im Header tragen.
SCRYPT_N = 2**16
SCRYPT_R = 8
SCRYPT_P = 1

# Harte Obergrenzen schützen vor versehentlich überhöhten Parametern.
# Sie gelten sowohl für die Default-Konfiguration als auch für Werte,
# die aus einer Datei gelesen werden (Schutz vor DoS über Header-Manipulation).
# Die aktuellen Werte benötigen ungefähr 64 MiB Arbeitsspeicher.
SCRYPT_MAX_N = 2**17
SCRYPT_MAX_R = 16
SCRYPT_MAX_P = 4
SCRYPT_MAX_MEMORY_BYTES = 128 * 1024 * 1024


# ============================================================
# Kryptographie (Grundlagen)
# ============================================================

def _validate_scrypt_params(n, r, p):
    """Prüft Scrypt-Parameter gegen Typ, Form und Ressourcen-Obergrenzen.

    Wird sowohl für die feste Konfiguration als auch für Werte verwendet,
    die aus einem Datei-Header gelesen wurden. Die Ressourcenschätzung
    verhindert, dass ein manipulierter Header exzessiven Speicher anfordert.
    """
    if (not isinstance(n, int) or n <= 1 or
            n > SCRYPT_MAX_N or n & (n - 1)):
        raise ValueError("Ungültige Scrypt-Konfiguration (N).")
    if (not isinstance(r, int) or
            not 1 <= r <= SCRYPT_MAX_R):
        raise ValueError("Ungültige Scrypt-Konfiguration (r).")
    if (not isinstance(p, int) or
            not 1 <= p <= SCRYPT_MAX_P):
        raise ValueError("Ungültige Scrypt-Konfiguration (p).")

    # Konservative Speicherabschätzung; vor dem Start der teuren KDF prüfen.
    estimated_memory = 128 * n * r + 256 * r * p + 256 * r
    if estimated_memory > SCRYPT_MAX_MEMORY_BYTES:
        raise ValueError("Scrypt-Konfiguration überschreitet das Speicherlimit.")


def derive_key(password: str, salt: bytes, n=None, r=None, p=None) -> bytes:
    if not isinstance(password, str):
        raise TypeError("Passwort muss ein String sein.")
    if not password:
        raise ValueError("Passwort darf nicht leer sein.")
    if len(salt) != SALT_SIZE:
        raise ValueError("Ungültige Salt-Länge.")

    # Ohne explizite Parameter gelten die festen Programm-Defaults.
    # Alte v1-Dateien rufen derive_key() ohne Parameter auf und erhalten
    # dadurch exakt das bisherige Verhalten.
    if n is None:
        n = SCRYPT_N
    if r is None:
        r = SCRYPT_R
    if p is None:
        p = SCRYPT_P

    _validate_scrypt_params(n, r, p)

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=n,
        r=r,
        p=p,
    )
    return kdf.derive(password.encode("utf-8"))


def build_header(salt: bytes, nonce: bytes) -> bytes:
    """AESCRYPT2-Header. Wird auch für die Textfunktion verwendet."""
    if len(salt) != SALT_SIZE:
        raise ValueError("Ungültige Salt-Länge.")
    if len(nonce) != NONCE_SIZE:
        raise ValueError("Ungültige Nonce-Länge.")

    return (
        MAGIC
        + bytes([FORMAT_VERSION])
        + salt
        + nonce
    )


def read_header(fin):
    """AESCRYPT2-Header lesen."""
    magic = fin.read(len(MAGIC))
    if magic != MAGIC:
        raise ValueError("Ungültiges oder nicht unterstütztes Dateiformat.")

    version = fin.read(1)
    if len(version) != 1 or version[0] != FORMAT_VERSION:
        raise ValueError("Nicht unterstützte Dateiformat-Version.")

    salt = fin.read(SALT_SIZE)
    if len(salt) != SALT_SIZE:
        raise ValueError("Header unvollständig.")

    nonce = fin.read(NONCE_SIZE)
    if len(nonce) != NONCE_SIZE:
        raise ValueError("Header unvollständig.")

    header = MAGIC + version + salt + nonce
    return salt, nonce, header


def build_v3_header(salt: bytes, base_nonce: bytes, file_size: int,
                    data_chunk_count: int, n=None, r=None, p=None) -> bytes:
    """AESCRYPT3-Hader der aktuellen Version (v2).

    Enthält Größe, erwartete Chunk-Anzahl und die verwendeten
    Scrypt-Parameter, damit Trunkierung/Entfernung von Chunks erkannt wird
    und die Schlüsselableitung nicht mehr an feste Programmkonstanten
    gebunden ist. Die Parameter sind in den AAD eingebunden und damit
    nicht unbemerkt manipulierbar.
    """
    if len(salt) != SALT_SIZE:
        raise ValueError("Ungültige Salt-Länge.")
    if len(base_nonce) != NONCE_SIZE:
        raise ValueError("Ungültige Nonce-Länge.")
    if not 0 <= file_size <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("Datei ist zu groß für das AESCRYPT3-Format.")
    if not 0 <= data_chunk_count <= MAX_V3_CHUNK_COUNT:
        raise ValueError("Zu viele Chunks.")

    if n is None:
        n = SCRYPT_N
    if r is None:
        r = SCRYPT_R
    if p is None:
        p = SCRYPT_P

    _validate_scrypt_params(n, r, p)

    return (
        MAGIC_V3
        + bytes([FORMAT_VERSION_V3_KDF])
        + salt
        + base_nonce
        + struct.pack(">I", CHUNK_SIZE)
        + struct.pack(">Q", file_size)
        + struct.pack(">Q", data_chunk_count)
        + struct.pack(">I", n)
        + struct.pack(">I", r)
        + struct.pack(">I", p)
    )


def read_v3_header(fin):
    """Liest den AESCRYPT3-Header und liefert auch die Scrypt-Parameter.

    Unterstützt sowohl v1-Dateien (ohne Parameter im Header; feste
    Programm-Defaults) als auch v2-Dateien (Parameter im Header).
    Rückgabe:
        salt, base_nonce, chunk_size, file_size, data_chunk_count,
        scrypt_params, header
    wobei scrypt_params ein Dict mit den Schlüsseln "n", "r", "p" ist.
    """
    magic = fin.read(len(MAGIC_V3))
    if magic != MAGIC_V3:
        raise ValueError("Ungültiges oder nicht unterstütztes AESCRYPT3-Format.")

    version = fin.read(1)
    if len(version) != 1:
        raise ValueError("AESCRYPT3-Header unvollständig.")
    version_number = version[0]
    if version_number not in (FORMAT_VERSION_V3, FORMAT_VERSION_V3_KDF):
        raise ValueError("Nicht unterstützte AESCRYPT3-Version.")

    salt = fin.read(SALT_SIZE)
    base_nonce = fin.read(NONCE_SIZE)
    chunk_size_raw = fin.read(V3_CHUNK_SIZE_SIZE)
    file_size_raw = fin.read(V3_FILE_SIZE_SIZE)
    chunk_count_raw = fin.read(V3_CHUNK_COUNT_SIZE)

    if (len(salt) != SALT_SIZE or len(base_nonce) != NONCE_SIZE or
            len(chunk_size_raw) != V3_CHUNK_SIZE_SIZE or
            len(file_size_raw) != V3_FILE_SIZE_SIZE or
            len(chunk_count_raw) != V3_CHUNK_COUNT_SIZE):
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
        + salt
        + base_nonce
        + chunk_size_raw
        + file_size_raw
        + chunk_count_raw
    )

    if version_number == FORMAT_VERSION_V3_KDF:
        kdf_raw = fin.read(3 * V3_KDF_PARAM_SIZE)
        if len(kdf_raw) != 3 * V3_KDF_PARAM_SIZE:
            raise ValueError("AESCRYPT3-Header unvollständig (KDF-Parameter).")
        n, r, p = struct.unpack(">III", kdf_raw)
        # Werte stammen aus einer Datei und sind nicht vertrauenswürdig.
        _validate_scrypt_params(n, r, p)
        header = header + kdf_raw
        scrypt_params = {"n": n, "r": r, "p": p}
    else:
        # v1: Parameter waren nicht im Header; es galten die damaligen
        # festen Programmkonstanten. Für Abwärtskompatibilität die
        # aktuellen Defaults verwenden.
        scrypt_params = {"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P}

    return (
        salt,
        base_nonce,
        chunk_size,
        file_size,
        data_chunk_count,
        scrypt_params,
        header,
    )


def build_v3_nonce(base_nonce: bytes, chunk_index: int) -> bytes:
    if len(base_nonce) != NONCE_SIZE:
        raise ValueError("Ungültige Nonce-Länge.")
    if not 0 <= chunk_index <= MAX_V3_CHUNK_COUNT:
        raise ValueError("Zu viele Chunks für AES-GCM-Nonce.")
    return base_nonce[:8] + chunk_index.to_bytes(4, "big")


def build_v3_aad(header: bytes, chunk_index: int, plaintext_size: int) -> bytes:
    if not 0 <= chunk_index <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("Ungültiger Chunk-Index.")
    if not 0 <= plaintext_size <= 0xFFFFFFFF:
        raise ValueError("Chunk ist zu groß.")
    return header + struct.pack(">Q", chunk_index) + struct.pack(">I", plaintext_size)


def encrypt_v3_chunk(aes_key: bytes, base_nonce: bytes, header: bytes, chunk_index: int, plaintext: bytes):
    nonce = build_v3_nonce(base_nonce, chunk_index)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(
        build_v3_aad(header, chunk_index, len(plaintext))
    )
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, encryptor.tag


def decrypt_v3_chunk(aes_key: bytes, base_nonce: bytes, header: bytes, chunk_index: int, plaintext_size: int, ciphertext: bytes, tag: bytes):
    if len(ciphertext) != plaintext_size:
        raise ValueError("Ungültige Chunk-Größe.")
    if len(tag) != TAG_SIZE:
        raise ValueError("Authentifizierungs-Tag fehlt oder ist ungültig.")

    nonce = build_v3_nonce(base_nonce, chunk_index)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
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


def write_v3_chunk(fout, aes_key, base_nonce, header, chunk_index, plaintext):
    ciphertext, tag = encrypt_v3_chunk(
        aes_key, base_nonce, header, chunk_index, plaintext
    )
    fout.write(struct.pack(">Q", chunk_index))
    fout.write(struct.pack(">I", len(plaintext)))
    fout.write(struct.pack(">I", len(ciphertext)))
    fout.write(ciphertext)
    fout.write(tag)


def read_v3_chunk(fin, max_chunk_size=MAX_V3_CHUNK_SIZE):
    """Liest einen AESCRYPT3-Chunk erst nach Prüfung seiner Größenangaben.

    max_chunk_size wird vom Aufrufer anhand des Headers bzw. des Chunk-Typs
    begrenzt. So bleiben gültige AESCRYPT3-Dateien mit größeren, im Format
    erlaubten Chunks kompatibel, ohne unbeschränktes Einlesen zuzulassen.
    """
    record_header = fin.read(V3_RECORD_HEADER_SIZE)
    if not record_header:
        return None
    if len(record_header) != V3_RECORD_HEADER_SIZE:
        raise ValueError("AESCRYPT3-Chunk-Header ist unvollständig.")

    chunk_index, plaintext_size, ciphertext_size = struct.unpack(
        ">QII", record_header
    )

    # Beide Größen sind nicht vertrauenswürdig: vor fin.read() begrenzen.
    if (plaintext_size > max_chunk_size or
            ciphertext_size > max_chunk_size or
            ciphertext_size != plaintext_size):
        raise ValueError("Ungültige AESCRYPT3-Chunk-Größe.")

    ciphertext = fin.read(ciphertext_size)
    if len(ciphertext) != ciphertext_size:
        raise ValueError("AESCRYPT3-Datei ist unvollständig.")

    tag = fin.read(TAG_SIZE)
    if len(tag) != TAG_SIZE:
        raise ValueError("AESCRYPT3-Authentifizierungs-Tag fehlt.")

    return chunk_index, plaintext_size, ciphertext, tag


def _try_atomic_noreplace_rename(tmp_path, output_path):
    """Versucht eine atomare Umbenennung ohne Überschreiben.

    Unter Linux wird renameat2(RENAME_NOREPLACE) verwendet. Unter Windows
    garantiert os.rename(), dass ein vorhandenes Ziel nicht ersetzt wird.
    False bedeutet, dass die Plattform/das Dateisystem diesen Weg nicht
    unterstützt; dann darf der Aufrufer einen sicheren Fallback versuchen.
    """
    if sys.platform.startswith("linux"):
        try:
            renameat2 = getattr(ctypes.CDLL(None, use_errno=True), "renameat2")
        except (AttributeError, OSError):
            return False

        renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p,
                              ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            -100, os.fsencode(tmp_path), -100, os.fsencode(output_path), 1
        )  # AT_FDCWD, RENAME_NOREPLACE
        if result == 0:
            return True

        error_code = ctypes.get_errno()
        if error_code == errno.EEXIST:
            raise FileExistsError(error_code, os.strerror(error_code), output_path)
        unsupported = {
            errno.ENOSYS, errno.EINVAL, errno.EXDEV,
            getattr(errno, "EOPNOTSUPP", errno.EINVAL),
            getattr(errno, "ENOTSUP", errno.EINVAL),
        }
        if error_code in unsupported:
            return False
        raise OSError(error_code, os.strerror(error_code), output_path)

    if os.name == "nt":
        try:
            os.rename(tmp_path, output_path)
            return True
        except FileExistsError:
            raise
        except OSError:
            return False

    return False


def install_temp_no_overwrite(tmp_path, output_path):
    """Installiert eine temporäre Datei, ohne ein vorhandenes Ziel zu überschreiben.

    Bevorzugt einen atomaren Hardlink. Wenn das nicht möglich ist, wird eine
    atomare Umbenennung ohne Überschreiben versucht (Linux/Windows). Nur wenn
    beides nicht verfügbar ist, wird das Ziel exklusiv angelegt und kopiert.
    Dieser letzte Fallback ist während des Kopierens sichtbar; bei normalen
    Laufzeitfehlern wird eine von uns angelegte Teildatei entfernt.
    """
    tmp_stat = os.stat(tmp_path)
    installed_identity = (tmp_stat.st_dev, tmp_stat.st_ino)

    try:
        os.link(tmp_path, output_path)
    except FileExistsError:
        raise FileExistsError(f"Zieldatei existiert bereits: {output_path}")
    except OSError:
        # Rename verschiebt die temporäre Datei atomar und exklusiv, wo
        # die Plattform das unterstützt. Bei Erfolg existiert tmp_path nicht mehr.
        try:
            if _try_atomic_noreplace_rename(tmp_path, output_path):
                return
        except FileExistsError:
            raise FileExistsError(f"Zieldatei existiert bereits: {output_path}")

        # Letzter, kompatibler Fallback für andere Plattformen/Dateisysteme.
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
                with open(tmp_path, "rb") as fin:
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
                    current = os.stat(output_path)
                    if (current.st_dev, current.st_ino) == created_identity:
                        os.unlink(output_path)
                except FileNotFoundError:
                    pass
                except OSError as cleanup_error:
                    cleanup_note = (
                        f" Die unvollständige Zieldatei konnte nicht entfernt werden: "
                        f"{cleanup_error}"
                    )
            raise OSError(
                f"Zieldatei konnte nicht sicher installiert werden: {e}.{cleanup_note}"
            )

    try:
        os.unlink(tmp_path)
    except OSError as e:
        rollback_note = ""
        if installed_identity is not None:
            try:
                current = os.stat(output_path)
                if (current.st_dev, current.st_ino) == installed_identity:
                    os.unlink(output_path)
                else:
                    rollback_note = " Das Ziel wurde inzwischen verändert; es blieb unangetastet."
            except FileNotFoundError:
                pass
            except OSError as rollback_error:
                rollback_note = f" Das Ziel konnte nicht zurückgerollt werden: {rollback_error}"
        raise OSError(
            f"Temporäre Datei konnte nicht entfernt werden: {e}.{rollback_note}"
        )


# ============================================================
# Text-Verschlüsselung
# ============================================================


def encrypt_text(text: str, password: str) -> str:
    if not isinstance(text, str):
        raise TypeError("Text muss ein String sein.")

    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    aes_key = derive_key(password, salt)

    header = build_header(salt, nonce)
    plaintext_bytes = text.encode("utf-8")

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(header)

    ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
    tag = encryptor.tag

    payload = header + ciphertext + tag
    return base64.b64encode(payload).decode("utf-8")


def decrypt_text(encoded_payload: str, password: str) -> str:
    try:
        payload = base64.b64decode(encoded_payload.encode("utf-8"), validate=True)
    except Exception:
        raise ValueError("Ungültiges Base64-Format.")

    header_size = len(MAGIC) + 1 + SALT_SIZE + NONCE_SIZE
    minimum_size = header_size + TAG_SIZE

    if len(payload) < minimum_size:
        raise ValueError("Daten zu kurz oder beschädigt.")

    # Vor der Schlüsselableitung das erwartete Format explizit prüfen.
    if payload[:len(MAGIC)] != MAGIC:
        raise ValueError("Ungültiges oder nicht unterstütztes Dateiformat.")
    if payload[len(MAGIC)] != FORMAT_VERSION:
        raise ValueError("Nicht unterstützte Dateiformat-Version.")

    header = payload[:header_size]
    salt = header[len(MAGIC) + 1 : len(MAGIC) + 1 + SALT_SIZE]
    nonce = header[len(MAGIC) + 1 + SALT_SIZE :]

    tag = payload[-TAG_SIZE:]
    ciphertext = payload[header_size:-TAG_SIZE]

    aes_key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(header)

    try:
        plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidTag:
        raise ValueError("Falsches Passwort oder beschädigte Daten.")

    return plaintext_bytes.decode("utf-8")


# ============================================================
# Datei-Verschlüsselung & Entschlüsselung
# ============================================================

def _sha256_file(path):
    """Berechnet SHA-256 blockweise, ohne die Datei vollständig in den RAM zu laden."""
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while True:
            block = stream.read(CHUNK_SIZE)
            if not block:
                break
            digest.update(block)
    return digest.digest()


def _copy_source_snapshot(input_path, snapshot_fd):
    """Kopiert die Quelle in den exklusiv angelegten Snapshot-Dateideskriptor."""
    digest = hashlib.sha256()
    with open(input_path, "rb") as source, os.fdopen(snapshot_fd, "wb") as snapshot:
        while True:
            block = source.read(CHUNK_SIZE)
            if not block:
                break
            snapshot.write(block)
            digest.update(block)
        snapshot.flush()
        os.fsync(snapshot.fileno())
    return digest.digest()


def encrypt_file(input_path, output_path, password, progress_cb=None):
    """Verschlüsselt eine stabile Momentaufnahme als AESCRYPT3.

    Die Quelle wird vor der Verschlüsselung in eine temporäre Snapshot-Datei
    kopiert. SHA-256-Prüfungen vor und nach der Verschlüsselung erkennen
    Änderungen der Quelldatei während des Vorgangs. Das Verfahren verwendet
    ausschließlich portable Python-Dateioperationen für Windows und Linux.
    """
    input_path = os.path.abspath(input_path)
    output_path = os.path.abspath(output_path)

    if os.path.normcase(input_path) == os.path.normcase(output_path):
        raise ValueError("Quelle und Ziel dürfen nicht identisch sein.")

    out_dir = os.path.dirname(output_path) or "."
    os.makedirs(out_dir, exist_ok=True)

    snapshot_fd, snapshot_path = tempfile.mkstemp(
        dir=out_dir, prefix=".aescrypto-snapshot-", suffix=".tmp"
    )
    tmp_fd = None
    tmp_path = None

    try:
        # Erst eine private Momentaufnahme erzeugen. Änderungen der Quelle
        # während des Kopierens werden durch den anschließenden Hashvergleich
        # erkannt, sofern sie nicht exakt auf denselben Dateiinhalt zurücklaufen.
        snapshot_fd_for_copy = snapshot_fd
        snapshot_fd = None  # _copy_source_snapshot schließt den Deskriptor auch bei Fehlern.
        snapshot_digest = _copy_source_snapshot(input_path, snapshot_fd_for_copy)
        file_size = os.path.getsize(snapshot_path)
        if _sha256_file(input_path) != snapshot_digest:
            raise ValueError(
                "Quelldatei wurde während der Momentaufnahme verändert; "
                "Verschlüsselung abgebrochen."
            )

        data_chunk_count = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE if file_size else 0
        if data_chunk_count > MAX_V3_CHUNK_COUNT:
            raise ValueError("Quelldatei ist für das AESCRYPT3-Format zu groß.")

        salt = secrets.token_bytes(SALT_SIZE)
        base_nonce = secrets.token_bytes(NONCE_SIZE)
        aes_key = derive_key(password, salt)

        # Den ursprünglichen Namen in den verschlüsselten Metadaten behalten,
        # obwohl die Nutzdaten aus der temporären Momentaufnahme gelesen werden.
        orig_name = os.path.basename(input_path).encode("utf-8")
        if len(orig_name) == 0 or len(orig_name) > MAX_NAME_LEN:
            raise ValueError("Dateiname zu lang oder leer.")

        metadata = struct.pack(">I", len(orig_name)) + orig_name
        header = build_v3_header(salt, base_nonce, file_size, data_chunk_count)

        tmp_fd, tmp_path = tempfile.mkstemp(
            dir=out_dir, prefix=".aescrypto-", suffix=".tmp"
        )

        with open(snapshot_path, "rb") as fin:
            with os.fdopen(tmp_fd, "wb") as fout:
                tmp_fd = None
                fout.write(header)
                write_v3_chunk(fout, aes_key, base_nonce, header, 0, metadata)

                bytes_read = 0
                for index in range(1, data_chunk_count + 1):
                    expected = min(CHUNK_SIZE, file_size - bytes_read)
                    chunk = fin.read(expected)
                    if len(chunk) != expected:
                        raise ValueError("Interne Momentaufnahme ist unvollständig.")
                    write_v3_chunk(fout, aes_key, base_nonce, header, index, chunk)
                    bytes_read += len(chunk)
                    if progress_cb:
                        should_stop = progress_cb(bytes_read, file_size)
                        if should_stop is False:
                            raise InterruptedError("Verarbeitung vom Benutzer gestoppt.")

                if bytes_read != file_size or fin.read(1):
                    raise ValueError("Interne Momentaufnahme hat eine unerwartete Größe.")

                fout.flush()
                os.fsync(fout.fileno())

        # Prüft auch Änderungen, die während der eigentlichen Verschlüsselung
        # an der Originalquelle vorgenommen wurden. Vor erfolgreicher Prüfung
        # wird die Ausgabedatei nicht unter ihrem endgültigen Namen veröffentlicht.
        if _sha256_file(input_path) != snapshot_digest:
            raise ValueError(
                "Quelldatei wurde während der Verschlüsselung verändert; "
                "Ausgabe wird verworfen."
            )

        install_temp_no_overwrite(tmp_path, output_path)
        tmp_path = None

    except Exception:
        if tmp_fd is not None:
            try:
                os.close(tmp_fd)
            except OSError:
                pass
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        raise
    finally:
        if snapshot_fd is not None:
            try:
                os.close(snapshot_fd)
            except OSError:
                pass
        try:
            os.unlink(snapshot_path)
        except OSError:
            pass

def decrypt_file_v3(input_path, output_path, password, progress_cb=None):
    input_path = os.path.abspath(input_path)
    output_path = os.path.abspath(output_path)

    if input_path == output_path:
        raise ValueError("Quelle und Ziel dürfen nicht identisch sein.")

    fsize = os.path.getsize(input_path)
    tmp_path = None

    with open(input_path, "rb") as fin:
        (
            salt,
            base_nonce,
            chunk_size,
            file_size,
            data_chunk_count,
            scrypt_params,
            header,
        ) = read_v3_header(fin)

        if chunk_size != CHUNK_SIZE:
            if chunk_size <= 0 or chunk_size > MAX_V3_CHUNK_SIZE:
                raise ValueError("Ungültige AESCRYPT3-Chunk-Größe.")

        minimum_size = len(header) + V3_RECORD_HEADER_SIZE + TAG_SIZE
        if fsize < minimum_size:
            raise ValueError("AESCRYPT3-Datei zu klein oder beschädigt.")

        aes_key = derive_key(
            password,
            salt,
            n=scrypt_params["n"],
            r=scrypt_params["r"],
            p=scrypt_params["p"],
        )

        out_dir = os.path.dirname(output_path) or "."
        os.makedirs(out_dir, exist_ok=True)
        tmp_fd, tmp_path = tempfile.mkstemp(
            dir=out_dir, prefix=".aescrypto-", suffix=".tmp"
        )

        try:
            with os.fdopen(tmp_fd, "wb") as fout:
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
                        raise ValueError("AESCRYPT3-Chunk-Reihenfolge oder Chunk-Anzahl ist ungültig.")

                    expected_size = min(
                        chunk_size,
                        expected_total_data - bytes_written
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
                    raise ValueError("AESCRYPT3-Dateigröße stimmt nicht mit dem Header überein.")

                trailing = fin.read(1)
                if trailing:
                    raise ValueError("AESCRYPT3-Datei enthält unerwartete zusätzliche Daten.")

                fout.flush()
                os.fsync(fout.fileno())

            install_temp_no_overwrite(tmp_path, output_path)
            tmp_path = None
            return output_path

        except Exception:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            raise


def decrypt_file_v2(input_path, output_path, password, progress_cb=None):
    """AESCRYPT2-Legacy-Entschlüsselung mit begrenztem Speicherverbrauch.

    Klartext wird während der GCM-Prüfung ausschließlich in eine temporäre
    Datei geschrieben. Diese wird erst nach erfolgreicher Tag-Prüfung als
    endgültige Ausgabedatei installiert.
    """
    input_path = os.path.abspath(input_path)
    output_path = os.path.abspath(output_path)

    if input_path == output_path:
        raise ValueError("Quelle und Ziel dürfen nicht identisch sein.")

    fsize = os.path.getsize(input_path)
    header_size = len(MAGIC) + 1 + SALT_SIZE + NONCE_SIZE
    minimum_size = header_size + NAME_LEN_SIZE + 1 + TAG_SIZE
    if fsize < minimum_size:
        raise ValueError("Datei zu klein oder beschädigt.")

    tmp_path = None
    tmp_fd = None
    try:
        with open(input_path, "rb") as fin:
            salt, nonce, header = read_header(fin)

            fin.seek(fsize - TAG_SIZE)
            tag = fin.read(TAG_SIZE)
            if len(tag) != TAG_SIZE:
                raise ValueError("Authentifizierungs-Tag fehlt.")

            ciphertext_size = fsize - len(header) - TAG_SIZE
            if ciphertext_size < NAME_LEN_SIZE + 1:
                raise ValueError("Ungültige Dateistruktur.")

            out_dir = os.path.dirname(output_path) or "."
            os.makedirs(out_dir, exist_ok=True)
            tmp_fd, tmp_path = tempfile.mkstemp(
                dir=out_dir, prefix=".aescrypto-", suffix=".tmp"
            )

            aes_key = derive_key(password, salt)
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()
            decryptor.authenticate_additional_data(header)

            # Nur der kurze Dateinamen-Präfix bleibt im RAM. Die Nutzdaten
            # gehen in die temporäre Datei; diese wird vor GCM-finalize nie
            # als gültige Ausgabe sichtbar gemacht.
            prefix = bytearray()
            name_end = None
            processed = 0
            fin.seek(len(header))

            with os.fdopen(tmp_fd, "wb") as fout:
                tmp_fd = None

                def consume_plaintext(data):
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
                        bytes(prefix[NAME_LEN_SIZE:expected_end]).decode("utf-8")
                    except UnicodeDecodeError:
                        raise ValueError("Ungültiger Dateiname.")

                    name_end = expected_end
                    fout.write(prefix[name_end:])
                    prefix.clear()

                remaining = ciphertext_size
                while remaining:
                    chunk = fin.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise ValueError("Verschlüsselte Datei ist unvollständig.")
                    consume_plaintext(decryptor.update(chunk))
                    processed += len(chunk)
                    remaining -= len(chunk)
                    if progress_cb:
                        should_stop = progress_cb(processed, ciphertext_size)
                        if should_stop is False:
                            raise InterruptedError("Verarbeitung vom Benutzer gestoppt.")

                # finalize() prüft den GCM-Tag. Bis dieser Aufruf erfolgreich
                # war, bleibt die temporäre Datei unveröffentlicht.
                try:
                    consume_plaintext(decryptor.finalize())
                except InvalidTag:
                    raise ValueError("Falsches Passwort oder beschädigte Datei.")

                if name_end is None:
                    raise ValueError("Verschlüsselte Datei enthält keinen vollständigen Dateinamen.")

                fout.flush()
                os.fsync(fout.fileno())

        install_temp_no_overwrite(tmp_path, output_path)
        tmp_path = None
        return output_path

    except Exception:
        if tmp_fd is not None:
            try:
                os.close(tmp_fd)
            except OSError:
                pass
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        raise


def decrypt_file(input_path, output_path, password, progress_cb=None):
    """Automatische Format-Erkennung; AESCRYPT2 bleibt abwärtskompatibel."""
    input_path = os.path.abspath(input_path)
    with open(input_path, "rb") as fin:
        magic = fin.read(len(MAGIC_V3))

    if magic == MAGIC_V3:
        return decrypt_file_v3(input_path, output_path, password, progress_cb)

    if magic == MAGIC:
        return decrypt_file_v2(input_path, output_path, password, progress_cb)

    raise ValueError("Ungültiges oder nicht unterstütztes Dateiformat.")


def get_original_filename(enc_path, password):
    enc_path = os.path.abspath(enc_path)
    with open(enc_path, "rb") as fin:
        magic = fin.read(len(MAGIC_V3))

    if magic == MAGIC_V3:
        with open(enc_path, "rb") as fin:
            (
                salt,
                base_nonce,
                chunk_size,
                file_size,
                data_chunk_count,
                scrypt_params,
                header,
            ) = read_v3_header(fin)
            aes_key = derive_key(
                password,
                salt,
                n=scrypt_params["n"],
                r=scrypt_params["r"],
                p=scrypt_params["p"],
            )
            record = read_v3_chunk(
                fin, max_chunk_size=NAME_LEN_SIZE + MAX_NAME_LEN
            )
            if record is None:
                raise ValueError("AESCRYPT3-Datei enthält keine Metadaten.")
            index, plain_size, ciphertext, tag = record
            if index != 0:
                raise ValueError("AESCRYPT3-Metadaten fehlen.")
            metadata = decrypt_v3_chunk(
                aes_key, base_nonce, header, index, plain_size, ciphertext, tag
            )
            if len(metadata) < NAME_LEN_SIZE:
                raise ValueError("Verschlüsselte Datei enthält keinen gültigen Dateinamen.")
            name_len = struct.unpack(">I", metadata[:NAME_LEN_SIZE])[0]
            if name_len == 0 or name_len > MAX_NAME_LEN or len(metadata) != NAME_LEN_SIZE + name_len:
                raise ValueError("Ungültiges Dateiformat: ungültiger Dateiname.")
            try:
                return metadata[NAME_LEN_SIZE:].decode("utf-8")
            except UnicodeDecodeError:
                raise ValueError("Ungültiger Dateiname.")

    if magic == MAGIC:
        fsize = os.path.getsize(enc_path)
        header_size = len(MAGIC) + 1 + SALT_SIZE + NONCE_SIZE
        if fsize < header_size + NAME_LEN_SIZE + 1 + TAG_SIZE:
            raise ValueError("Datei zu klein oder beschädigt.")

        with open(enc_path, "rb") as fin:
            salt, nonce, header = read_header(fin)
            fin.seek(fsize - TAG_SIZE)
            tag = fin.read(TAG_SIZE)
            if len(tag) != TAG_SIZE:
                raise ValueError("Authentifizierungs-Tag fehlt.")

            ciphertext_size = fsize - len(header) - TAG_SIZE
            aes_key = derive_key(password, salt)
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()
            decryptor.authenticate_additional_data(header)
            fin.seek(len(header))

            # Nur die für den Dateinamen nötigen Bytes werden behalten.
            # Die gesamte Datei wird trotzdem verarbeitet, damit GCM den
            # Authentifizierungs-Tag zuverlässig prüfen kann.
            prefix = bytearray()
            expected_prefix_size = NAME_LEN_SIZE

            def collect_name_prefix(data):
                nonlocal expected_prefix_size
                offset = 0
                while offset < len(data) and len(prefix) < expected_prefix_size:
                    needed = expected_prefix_size - len(prefix)
                    take = min(needed, len(data) - offset)
                    prefix.extend(data[offset:offset + take])
                    offset += take

                    if len(prefix) == NAME_LEN_SIZE and expected_prefix_size == NAME_LEN_SIZE:
                        name_len = struct.unpack(">I", prefix)[0]
                        if name_len == 0 or name_len > MAX_NAME_LEN:
                            raise ValueError("Ungültiges Dateiformat: ungültiger Dateiname.")
                        expected_prefix_size = NAME_LEN_SIZE + name_len

            remaining = ciphertext_size
            while remaining:
                chunk = fin.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    raise ValueError("Verschlüsselte Datei ist unvollständig.")
                collect_name_prefix(decryptor.update(chunk))
                remaining -= len(chunk)

            try:
                collect_name_prefix(decryptor.finalize())
            except InvalidTag:
                raise ValueError("Falsches Passwort oder beschädigte Datei.")

            if len(prefix) != expected_prefix_size:
                raise ValueError("Verschlüsselte Datei enthält keinen vollständigen Dateinamen.")
            try:
                return bytes(prefix[NAME_LEN_SIZE:]).decode("utf-8")
            except UnicodeDecodeError:
                raise ValueError("Ungültiger Dateiname.")

    raise ValueError("Ungültiges oder nicht unterstütztes Dateiformat.")


def _file_identity(filepath):
    """Liefert eine konservative Identität der Datei bzw. des Verzeichniseintrags."""
    st = os.lstat(filepath)
    return (
        st.st_dev,
        st.st_ino,
        st.st_mode,
        st.st_size,
        st.st_mtime_ns,
        st.st_ctime_ns,
    )


def delete_original_file(filepath, expected_identity=None):
    """Löscht das Original nur, wenn es noch dem erfassten Dateiobjekt entspricht.

    Der Identitätsvergleich verhindert insbesondere, dass ein zwischenzeitlich
    am selben Pfad eingesetzter anderer Dateieintrag versehentlich gelöscht wird.
    Portable Pfadoperationen können das kleine Zeitfenster zwischen lstat und
    remove nicht auf allen Betriebssystemen atomar schließen.
    """
    try:
        current_identity = _file_identity(filepath)
    except FileNotFoundError:
        if expected_identity is not None:
            raise RuntimeError("Original fehlt inzwischen; Löschen abgebrochen.")
        return

    if expected_identity is not None and current_identity != expected_identity:
        raise RuntimeError(
            "Quelldatei wurde seit Beginn der Verarbeitung ersetzt oder verändert; "
            "Löschen des Originals aus Sicherheitsgründen abgebrochen."
        )

    try:
        os.remove(filepath)
    except OSError as e:
        raise RuntimeError(f"Datei konnte nicht entfernt werden: {e}")


def collect_files(paths):
    files = []
    for p in paths:
        if not p:
            continue
        p = os.path.abspath(p)
        if os.path.islink(p):
            continue
        if os.path.isfile(p):
            files.append(p)
        elif os.path.isdir(p):
            for root, dirs, fnames in os.walk(p, followlinks=False):
                dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
                for fn in fnames:
                    fp = os.path.join(root, fn)
                    if not os.path.islink(fp):
                        files.append(os.path.abspath(fp))
    seen = set()
    result = []
    for f in files:
        if f not in seen:
            seen.add(f)
            result.append(f)
    return result


def make_encrypt_output_path(fpath, encrypt_filename=False):
    fpath = os.path.abspath(fpath)
    if encrypt_filename:
        directory = os.path.dirname(fpath) or "."
        while True:
            random_name = secrets.token_hex(32) + ".enc"
            candidate = os.path.join(directory, random_name)
            if not os.path.lexists(candidate):
                return candidate

    out_path = fpath + ".enc"
    if not os.path.exists(out_path):
        return out_path

    base, ext = os.path.splitext(fpath)
    counter = 1
    while True:
        candidate = f"{base}_conflict{counter}{ext}.enc"
        if not os.path.exists(candidate):
            return candidate
        counter += 1


def make_decrypt_output_path(fpath, password):
    fpath = os.path.abspath(fpath)
    orig_name = get_original_filename(fpath, password)
    # Beide üblichen Pfadtrenner unabhängig vom aktuellen Betriebssystem
    # behandeln, damit fremde/alte Dateien keinen Pfad aus dem Metadatum
    # in das Ausgabeverzeichnis einschleusen können.
    orig_name = orig_name.replace("\\", "/")
    orig_name = os.path.basename(orig_name)
    if not orig_name or orig_name in (".", "..") or "\x00" in orig_name:
        raise ValueError("Ungültiger Original-Dateiname.")

    directory = os.path.dirname(fpath)
    out_path = os.path.join(directory, orig_name)
    if not os.path.exists(out_path):
        return out_path

    name, ext = os.path.splitext(orig_name)
    counter = 1
    while True:
        candidate = os.path.join(directory, f"{name}_restored{counter}{ext}")
        if not os.path.exists(candidate):
            return candidate
        counter += 1


def process_single(fpath, password, delete_original, encrypt_filename=False, progress_cb=None):
    mode = "decrypt" if fpath.lower().endswith(".enc") else "encrypt"
    try:
        # Identität vor jeder Verarbeitung erfassen, damit beim optionalen
        # Löschen kein inzwischen ausgetauschter Pfadeintrag entfernt wird.
        source_identity = _file_identity(fpath) if delete_original else None

        if mode == "encrypt":
            out_path = make_encrypt_output_path(fpath, encrypt_filename)
            encrypt_file(fpath, out_path, password, progress_cb=progress_cb)
        else:
            out_path = make_decrypt_output_path(fpath, password)
            decrypt_file(fpath, out_path, password, progress_cb=progress_cb)

        if delete_original:
            try:
                delete_original_file(fpath, expected_identity=source_identity)
            except Exception:
                return False, f"{os.path.basename(fpath)}: {mode} erfolgreich, Original konnte nicht entfernt werden."

        return True, f"{os.path.basename(fpath)} ({mode})"
    except InterruptedError:
        return False, f"{os.path.basename(fpath)}: Verarbeitung gestoppt."
    except InvalidTag:
        # Authentifizierung fehlgeschlagen: falsches Passwort oder beschädigte Datei.
        # Als reguläres Ergebnis zurückgeben, damit der GUI-Worker abschließen kann.
        return False, f"{os.path.basename(fpath)}: Falsches Passwort oder beschädigte Datei."
    except Exception as exc:
        # Auch unerwartete Datei-/Krypto-Fehler dürfen den Worker nicht vorzeitig
        # beenden, sonst wird _processing_finished() nicht aufgerufen und die GUI
        # bleibt im Zustand „Wird vorbereitet" bzw. der Button bleibt gesperrt.
        detail = str(exc).strip() or exc.__class__.__name__
        return False, f"{os.path.basename(fpath)}: {detail}"


# ============================================================
# Tray Icon
# ============================================================

def create_shield_icon(size=64):
    img = Image.new(
        "RGBA",
        (
            size,
            size,
        ),
        (
            0,
            0,
            0,
            0,
        ),
    )

    d = ImageDraw.Draw(img)

    def i(v):
        return int(round(v))

    m = size * 0.1

    shield = [
        (
            m,
            m * 1.2,
        ),
        (
            size - m,
            m * 1.2,
        ),
        (
            size - m * 0.7,
            size * 0.38,
        ),
        (
            size / 2,
            size - m * 1.4,
        ),
        (
            m * 0.7,
            size * 0.38,
        ),
    ]

    d.polygon(
        [
            (
                i(x),
                i(y),
            )
            for x, y in shield
        ],
        fill="#0B132B",
        outline="#1C2541",
        width=max(1, i(size * 0.025)),
    )

    im = m * 1.5

    inner = [
        (
            m + im * 0.8,
            m * 1.2 + im * 0.8,
        ),
        (
            size - m - im * 0.8,
            m * 1.2 + im * 0.8,
        ),
        (
            size - m * 0.7 - im * 0.5,
            size * 0.38 + im * 0.4,
        ),
        (
            size / 2,
            size - m * 1.4 - im * 1.1,
        ),
        (
            m * 0.7 + im * 0.5,
            size * 0.38 + im * 0.4,
        ),
    ]

    d.polygon(
        [
            (
                i(x),
                i(y),
            )
            for x, y in inner
        ],
        fill="#3A506B",
    )

    lw = size * 0.26
    lh = size * 0.20

    lx = size / 2 - lw / 2
    ly = size * 0.44

    d.rectangle(
        [
            i(lx),
            i(ly),
            i(lx + lw),
            i(ly + lh),
        ],
        fill="#E0E0E0",
    )

    sr = size * 0.07

    d.arc(
        [
            i(lx + lw * 0.25),
            i(ly - sr * 1.8),
            i(lx + lw * 0.75),
            i(ly),
        ],
        start=180,
        end=0,
        fill="#E0E0E0",
        width=max(
            1,
            i(size * 0.06),
        ),
    )

    kh = size * 0.02

    d.ellipse(
        [
            i(size / 2 - kh),
            i(ly + lh * 0.3),
            i(size / 2 + kh),
            i(ly + lh * 0.3 + kh * 2),
        ],
        fill="#0B132B",
    )

    keyhole = [
        (
            size / 2 - kh * 0.9,
            ly + lh * 0.5,
        ),
        (
            size / 2 + kh * 0.9,
            ly + lh * 0.5,
        ),
        (
            size / 2,
            ly + lh * 0.8,
        ),
    ]

    d.polygon(
        [
            (
                i(x),
                i(y),
            )
            for x, y in keyhole
        ],
        fill="#0B132B",
    )

    return img


# ============================================================
# Grafische Benutzeroberfläche (GUI)
# ============================================================

if GUI_AVAILABLE:

    class AESCryptoApp:

        def __init__(self, root):
            self.root = root
            self.root.title(f"AES Crypto Tool v{APP_VERSION}")
            self.root.geometry("700x580")
            # GUI-Fenster unter Windows und Linux dauerhaft im Vordergrund halten.
            self.root.attributes("-topmost", True)

            # Tray-Status
            self.tray_icon = None
            self.tray_thread = None
            self.exiting = False

            # Fenster-Icon
            try:
                if sys.platform.startswith("win"):
                    icon_path = os.path.join(
                        os.path.dirname(os.path.abspath(__file__)),
                        "aescrypto.ico",
                    )
                    if os.path.isfile(icon_path):
                        self.root.iconbitmap(icon_path)
                    else:
                        self.window_icon = create_shield_icon(64)
                        self.root.iconphoto(False, self.window_icon)
                else:
                    self.window_icon = create_shield_icon(64)
                    self.root.iconphoto(False, self.window_icon)
            except Exception:
                self.window_icon = None

            # Schließen-Button:
            # Unter Linux wird die Anwendung normal beendet.
            # Auf anderen Systemen bleibt das bisherige Tray-Verhalten erhalten.
            if sys.platform.startswith("linux"):
                self.root.protocol("WM_DELETE_WINDOW", self.exit_application)
            else:
                self.root.protocol("WM_DELETE_WINDOW", self.hide_to_tray)

            # Notebook (Tabs) erstellen
            self.notebook = ttk.Notebook(self.root)
            self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

            # Reiter 1: Datei-Verschlüsselung mit Drag-and-Drop
            self.tab_files = ttk.Frame(self.notebook)
            self.notebook.add(self.tab_files, text="Dateien / Ordner")
            self.setup_files_tab()

            # Reiter 2: Text-Verschlüsselung
            self.tab_text = ttk.Frame(self.notebook)
            self.notebook.add(self.tab_text, text="Text Verschlüsselung")
            self.setup_text_tab()

            # Tray nur starten, wenn pystray verfügbar ist.
            if PYSTRAY_AVAILABLE:
                self.start_tray()

        # ====================================================
        # Tray
        # ====================================================

        def start_tray(self):
            # Unter Linux niemals einen Tray starten.
            if not GUI_AVAILABLE or not PYSTRAY_AVAILABLE:
                return

            try:
                icon_path = os.path.join(
                    os.path.dirname(os.path.abspath(__file__)),
                    "aescrypto.ico",
                )
                icon_image = Image.open(icon_path).convert("RGBA")

                menu = pystray.Menu(
                    item(
                        f"AES Crypto Tool v{APP_VERSION}",
                        self.tray_show,
                        default=True,
                    ),
                    pystray.Menu.SEPARATOR,
                    item(
                        "Anzeigen",
                        self.tray_show,
                    ),
                    item(
                        "Beenden",
                        self.tray_exit,
                    ),
                )

                self.tray_icon = pystray.Icon(
                    "AESCryptoTool",
                    icon_image,
                    f"AES Crypto Tool v{APP_VERSION}",
                    menu,
                )

                self.tray_thread = threading.Thread(
                    target=self._run_tray,
                    name="AESCryptoTray",
                    daemon=True,
                )
                self.tray_thread.start()

            except Exception as e:
                self.tray_icon = None
                self.tray_thread = None
                try:
                    print(f"Tray konnte nicht gestartet werden: {e}", file=sys.stderr)
                except Exception:
                    pass

        def _run_tray(self):
            try:
                self.tray_icon.run()
            except Exception as e:
                try:
                    print(f"Tray-Fehler: {e}", file=sys.stderr)
                except Exception:
                    pass

        def tray_show(self, icon=None, menu_item=None):
            try:
                self.root.after(0, self._show_window)
            except Exception:
                pass

        def _show_window(self):
            if self.exiting:
                return

            try:
                self.root.deiconify()
                self.root.lift()
                # Den Vordergrund-Status auch nach dem Wiederherstellen beibehalten.
                self.root.attributes("-topmost", True)
                self.root.focus_force()
            except Exception:
                pass

        def hide_to_tray(self):
            # Unter Linux gibt es kein Tray.
            if sys.platform.startswith("linux"):
                self.exit_application()
                return

            if self.exiting:
                return

            try:
                self.root.withdraw()
            except Exception:
                pass

        def tray_exit(self, icon=None, menu_item=None):
            try:
                self.root.after(0, self.exit_application)
            except Exception:
                self.exit_application()

        def exit_application(self):
            if self.exiting:
                return

            self.exiting = True

            try:
                if self.tray_icon is not None:
                    self.tray_icon.stop()
            except Exception:
                pass

            try:
                self.root.destroy()
            except Exception:
                pass

        # ====================================================
        # Dateien / Ordner
        # ====================================================

        def setup_files_tab(self):
            info_label = ttk.Label(self.tab_files, text="Wähle Dateien/Ordner aus oder ziehe sie per Drag & Drop hierher:", padding=10)
            info_label.pack(anchor="w", pady=(0, 2))

            btn_frame = ttk.Frame(self.tab_files, padding=(10, 4))
            btn_frame.pack(fill="x")

            ttk.Button(btn_frame, text="Dateien hinzufügen", command=self.add_files).pack(side="left", padx=5)
            ttk.Button(btn_frame, text="Ordner hinzufügen", command=self.add_folder).pack(side="left", padx=5)
            ttk.Button(btn_frame, text="Liste leeren", command=self.clear_list).pack(side="left", padx=5)

            # Listbox für Dateipfade
            # Kompakt halten, damit Einstellungen, Fortschritt und
            # der Button "Verarbeitung starten" bei der normalen Fenstergröße
            # immer sichtbar bleiben. Die Liste selbst bleibt scrollbar.
            list_frame = ttk.Frame(self.tab_files, padding=(10, 4), height=190)
            list_frame.pack(fill="x", expand=False)
            list_frame.pack_propagate(False)

            self.file_listbox = tk.Listbox(list_frame, selectmode=tk.EXTENDED)
            self.file_listbox.pack(side="left", fill="both", expand=True)

            scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.file_listbox.yview)
            scrollbar.pack(side="right", fill="y")
            self.file_listbox.config(yscrollcommand=scrollbar.set)

            # Drag & Drop Bindung aktivieren, falls verfügbar
            if DND_AVAILABLE:
                try:
                    self.file_listbox.drop_target_register(DND_FILES)
                    self.file_listbox.dnd_bind('<<Drop>>', self.on_drop)
                except Exception:
                    pass

            # Passwort & Optionen
            opt_frame = ttk.LabelFrame(self.tab_files, text="Einstellungen", padding=10)
            opt_frame.pack(fill="x", padx=10, pady=5)

            ttk.Label(opt_frame, text="Passwort:").pack(side="left", padx=5)
            self.file_pwd_entry = ttk.Entry(opt_frame, show="*", width=20)
            self.file_pwd_entry.pack(side="left", padx=5)

            # Passwort anzeigen Checkbutton (Dateien-Tab)
            self.file_show_pwd_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(
                opt_frame,
                text="Anzeigen",
                variable=self.file_show_pwd_var,
                command=self.toggle_file_password_visibility
            ).pack(side="left", padx=5)

            self.del_orig_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(opt_frame, text="Original löschen", variable=self.del_orig_var).pack(side="left", padx=10)

            self.enc_name_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(opt_frame, text="Dateinamen tarnen", variable=self.enc_name_var).pack(side="left", padx=10)

            # Start-Button bewusst VOR der Fortschrittsanzeige platzieren,
            # damit er bei der normalen Fenstergröße immer vollständig sichtbar bleibt.
            self.processing_button = ttk.Button(
                self.tab_files,
                text="Verarbeitung starten",
                command=self.start_processing,
            )
            self.processing_button.pack(pady=(2, 6))

            # Fortschrittsanzeige
            progress_frame = ttk.LabelFrame(
                self.tab_files,
                text="Fortschritt",
                padding=10,
            )
            progress_frame.pack(fill="x", padx=10, pady=(0, 6))

            self.progress_status_var = tk.StringVar(value="Bereit")
            ttk.Label(
                progress_frame,
                textvariable=self.progress_status_var,
            ).pack(anchor="w", pady=(0, 5))

            self.progress_file_var = tk.StringVar(value="Keine Verarbeitung aktiv")
            ttk.Label(
                progress_frame,
                textvariable=self.progress_file_var,
            ).pack(anchor="w", pady=(0, 5))

            self.progress_bar = ttk.Progressbar(
                progress_frame,
                orient="horizontal",
                mode="determinate",
                maximum=100,
                value=0,
            )
            self.progress_bar.pack(fill="x", expand=True)

            self.progress_percent_var = tk.StringVar(value="0 %")
            ttk.Label(
                progress_frame,
                textvariable=self.progress_percent_var,
                anchor="e",
            ).pack(fill="x", pady=(3, 0))

            self.processing = False
            self.stop_event = threading.Event()

        def toggle_file_password_visibility(self):
            if self.file_show_pwd_var.get():
                self.file_pwd_entry.config(show="")
            else:
                self.file_pwd_entry.config(show="*")

        def on_drop(self, event):
            files = self.root.tk.splitlist(event.data)
            collected = collect_files(files)
            for f in collected:
                if f not in self.file_listbox.get(0, tk.END):
                    self.file_listbox.insert(tk.END, f)

        def add_files(self):
            files = filedialog.askopenfilenames(
                title="Dateien auswählen",
                filetypes=[
                    ("Alle Dateien", "*"),
                    ("Verschlüsselte Dateien", "*.enc"),
                ],
            )
            for f in files:
                if f not in self.file_listbox.get(0, tk.END):
                    self.file_listbox.insert(tk.END, f)

        def add_folder(self):
            folder = filedialog.askdirectory(title="Ordner auswählen")
            if folder:
                collected = collect_files([folder])
                for f in collected:
                    if f not in self.file_listbox.get(0, tk.END):
                        self.file_listbox.insert(tk.END, f)

        def clear_list(self):
            self.file_listbox.delete(0, tk.END)

        def start_processing(self):
            # Derselbe Button dient während eines laufenden Jobs zum Stoppen.
            if self.processing:
                self.stop_processing()
                return

            pwd = self.file_pwd_entry.get()
            paths = list(self.file_listbox.get(0, tk.END))

            if not pwd:
                messagebox.showerror("Fehler", "Bitte gib ein Passwort ein.")
                return
            if not paths:
                messagebox.showerror("Fehler", "Keine Dateien ausgewählt.")
                return

            self.processing = True
            self.stop_event.clear()
            self.processing_button.config(text="Verarbeitung stoppen", state="normal")
            self.progress_bar["value"] = 0
            self.progress_percent_var.set("0 %")
            self.progress_status_var.set(f"0 / {len(paths)} Dateien verarbeitet")
            self.progress_file_var.set("Vorbereitung ...")

            delete_original = self.del_orig_var.get()
            encrypt_filename = self.enc_name_var.get()

            worker = threading.Thread(
                target=self._process_files_worker,
                args=(paths, pwd, delete_original, encrypt_filename),
                name="AESCryptoFileWorker",
                daemon=True,
            )
            worker.start()

        def _process_files_worker(self, paths, password, delete_original, encrypt_filename):
            success_count = 0
            error_msgs = []
            total_files = len(paths)

            for file_index, path in enumerate(paths, start=1):
                if self.stop_event.is_set():
                    break

                def progress_cb(processed, total, p=path, idx=file_index):
                    if self.stop_event.is_set():
                        return False

                    percent = (processed / total * 100) if total else 100
                    try:
                        self.root.after(
                            0,
                            self._update_progress,
                            idx,
                            total_files,
                            p,
                            percent,
                        )
                    except Exception:
                        pass

                success, msg = process_single(
                    path,
                    password,
                    delete_original,
                    encrypt_filename,
                    progress_cb=progress_cb,
                )
                if success:
                    success_count += 1
                else:
                    error_msgs.append(msg)

                # Einen fehlgeschlagenen Einzelvorgang nicht als 100 %
                # darstellen. Bei Erfolg ist der Vorgang bereits durch
                # den letzten Fortschritts-Callback bei 100 % angekommen;
                # bei kleinen/0-Byte-Dateien wird hier 100 % gesetzt.
                if self.stop_event.is_set():
                    break

                if success:
                    try:
                        self.root.after(
                            0,
                            self._update_progress,
                            file_index,
                            total_files,
                            path,
                            100,
                        )
                    except Exception:
                        pass

            cancelled = self.stop_event.is_set()
            try:
                self.root.after(
                    0,
                    self._processing_finished,
                    success_count,
                    error_msgs,
                    cancelled,
                )
            except Exception:
                pass

        def _update_progress(self, file_index, total_files, path, percent):
            """GUI-sicheres Aktualisieren der Fortschrittsanzeige."""
            percent = max(0.0, min(100.0, float(percent)))
            self.progress_bar["value"] = percent
            self.progress_percent_var.set(f"{percent:.0f} %")
            self.progress_status_var.set(
                f"{file_index} / {total_files} Dateien – aktuelle Datei"
            )
            self.progress_file_var.set(os.path.basename(path))

        def stop_processing(self):
            if not self.processing:
                return

            self.stop_event.set()
            self.processing_button.config(state="disabled")
            self.progress_status_var.set("Stop wird ausgeführt ...")
            self.progress_file_var.set("Aktuelle Datei wird sauber abgebrochen ...")

        def _processing_finished(self, success_count, error_msgs, cancelled=False):
            self.processing = False
            self.progress_bar["value"] = 0
            self.progress_percent_var.set("0 %")
            self.progress_status_var.set("Bereit")
            self.progress_file_var.set("Keine Verarbeitung aktiv")
            try:
                self.processing_button.config(text="Verarbeitung starten", state="normal")
            except Exception:
                pass

            if cancelled:
                messagebox.showinfo(
                    "Verarbeitung gestoppt",
                    f"Erfolgreich abgeschlossen: {success_count}\n"
                    "Die laufende Verarbeitung wurde gestoppt.",
                )
            elif error_msgs:
                messagebox.showwarning(
                    "Fertig mit Hinweisen",
                    f"Erfolgreich: {success_count}\nFehler:\n"
                    + "\n".join(error_msgs),
                )
            else:
                messagebox.showinfo(
                    "Erfolg",
                    f"Alle {success_count} Elemente wurden erfolgreich verarbeitet!",
                )

        # ====================================================
        # Text-Verschlüsselung
        # ====================================================

        def setup_text_tab(self):
            pwd_frame = ttk.LabelFrame(self.tab_text, text="Passwort", padding=10)
            pwd_frame.pack(fill="x", padx=10, pady=10)

            ttk.Label(pwd_frame, text="Passwort:").pack(side="left", padx=5)
            self.text_pwd_entry = ttk.Entry(pwd_frame, show="*", width=25)
            self.text_pwd_entry.pack(side="left", padx=5, fill="x", expand=True)

            # Passwort anzeigen Checkbutton (Text-Tab)
            self.text_show_pwd_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(
                pwd_frame,
                text="Anzeigen",
                variable=self.text_show_pwd_var,
                command=self.toggle_text_password_visibility
            ).pack(side="left", padx=5)

            io_frame = ttk.Frame(self.tab_text)
            io_frame.pack(fill="both", expand=True, padx=10, pady=5)

            left_pane = ttk.Frame(io_frame)
            left_pane.pack(side="left", fill="both", expand=True, padx=5)
            ttk.Label(left_pane, text="Eingabetext (Klartext oder Ciphertext):").pack(anchor="w")
            self.input_text_area = scrolledtext.ScrolledText(left_pane, height=10, width=30)
            self.input_text_area.pack(fill="both", expand=True, pady=5)

            btn_pane = ttk.Frame(io_frame)
            btn_pane.pack(side="left", fill="y", padx=5, pady=20)

            ttk.Button(btn_pane, text="Ver-/Entschlüsseln", command=self.on_process_text).pack(fill="x", pady=5)

            right_pane = ttk.Frame(io_frame)
            right_pane.pack(side="left", fill="both", expand=True, padx=5)
            ttk.Label(right_pane, text="Ergebnis:").pack(anchor="w")
            self.output_text_area = scrolledtext.ScrolledText(right_pane, height=10, width=30)
            self.output_text_area.pack(fill="both", expand=True, pady=5)

            # Untere Steuerungsleiste (Kopieren & Felder leeren)
            action_frame = ttk.Frame(self.tab_text)
            action_frame.pack(fill="x", padx=10, pady=10)

            ttk.Button(action_frame, text="Ergebnis in Zwischenablage kopieren", command=self.copy_to_clipboard).pack(side="left", fill="x", expand=True, padx=(0, 5))
            ttk.Button(action_frame, text="Felder leeren", command=self.clear_text_fields).pack(side="right", padx=(5, 0))

        def toggle_text_password_visibility(self):
            if self.text_show_pwd_var.get():
                self.text_pwd_entry.config(show="")
            else:
                self.text_pwd_entry.config(show="*")

        def on_process_text(self):
            pwd = self.text_pwd_entry.get()
            text = self.input_text_area.get("1.0", "end-1c")
            if not pwd:
                messagebox.showerror("Fehler", "Bitte gib ein Passwort ein.")
                return
            if not text:
                messagebox.showerror("Fehler", "Bitte gib einen Text ein.")
                return

            # AESCRYPT2-Textdaten sind Base64-kodiert und beginnen nach
            # dem Decodieren mit dem AESCRYPT2-Magic. Nur dann wird
            # automatisch entschlüsselt; alles andere wird als Klartext
            # behandelt und verschlüsselt.
            try:
                payload = base64.b64decode(text.encode("utf-8"), validate=True)
                is_ciphertext = payload.startswith(MAGIC)
            except Exception:
                is_ciphertext = False

            if is_ciphertext:
                try:
                    result = decrypt_text(text, pwd)
                    self.output_text_area.delete("1.0", tk.END)
                    self.output_text_area.insert("1.0", result)
                except Exception as e:
                    messagebox.showerror("Fehler bei der Entschlüsselung", str(e))
            else:
                try:
                    result = encrypt_text(text, pwd)
                    self.output_text_area.delete("1.0", tk.END)
                    self.output_text_area.insert("1.0", result)
                except Exception as e:
                    messagebox.showerror("Fehler bei der Verschlüsselung", str(e))

        def copy_to_clipboard(self):
            result_text = self.output_text_area.get("1.0", tk.END).strip()
            if result_text:
                self.root.clipboard_clear()
                self.root.clipboard_append(result_text)
                messagebox.showinfo("Erfolg", "Ergebnis wurde in die Zwischenablage kopiert.")
            else:
                messagebox.showwarning("Warnung", "Kein Text zum Kopieren vorhanden.")

        def clear_text_fields(self):
            self.text_pwd_entry.delete(0, tk.END)
            self.input_text_area.delete("1.0", tk.END)
            self.output_text_area.delete("1.0", tk.END)


# ============================================================
# Main Entry Point (CLI & GUI Support)
# ============================================================

def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="aescrypto-cli",
        description="AES Datei- und Text-Verschlüsselungstool",
    )
    parser.add_argument("paths", nargs="*", help="Dateien oder Ordner für die Verarbeitung")
    parser.add_argument("-t", "--text", help="Text der ver- oder entschlüsselt werden soll")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Entschlüsseln Modus (für Text)")
    parser.add_argument("--delete", action="store_true", help="Originaldatei nach Verarbeitung löschen")
    parser.add_argument("--enc-name", action="store_true", help="Dateinamen tarnen")
    parser.add_argument("--version", action="version", version=f"AES Crypto Tool {APP_VERSION}")
    return parser


def _stdin_is_interactive():
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except Exception:
        return False


def read_cli_password():
    if _stdin_is_interactive():
        return getpass.getpass("Passwort: ")
    if sys.stdin is None:
        raise RuntimeError("Kein Passwort verfügbar (keine Konsoleneingabe möglich).")
    line = sys.stdin.readline()
    if not line:
        raise RuntimeError("Kein Passwort über stdin erhalten.")
    return line.rstrip("\r\n")


def run_cli(argv=None):
    """Reiner CLI-Einstiegspunkt für aes_cli.py (Konsolen-Build).
    Startet niemals die GUI und liefert einen Exit-Code zurück."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if not args.paths and args.text is None:
        parser.print_help()
        return 2

    try:
        password = read_cli_password()
    except Exception as e:
        print(f"Fehler: {e}", file=sys.stderr)
        return 1

    if not password:
        print("Fehler: Passwort darf nicht leer sein.", file=sys.stderr)
        return 1

    if args.text is not None:
        try:
            if args.decrypt:
                result = decrypt_text(args.text, password)
            else:
                result = encrypt_text(args.text, password)
        except Exception as e:
            print(f"Fehler: {e}", file=sys.stderr)
            return 1
        print(result)
        return 0

    files = collect_files(args.paths)
    if not files:
        print("Fehler: Keine passenden Dateien gefunden.", file=sys.stderr)
        return 1

    failed = 0
    for f in files:
        success, msg = process_single(f, password, args.delete, args.enc_name)
        if success:
            print(msg)
        else:
            failed += 1
            print(msg, file=sys.stderr)

    return 1 if failed else 0


def run_gui():
    """GUI-Einstiegspunkt für den --windowed Build."""
    if not GUI_AVAILABLE:
        return 1
    root = TkinterDnD.Tk() if DND_AVAILABLE else tk.Tk()
    AESCryptoApp(root)
    root.mainloop()
    return 0


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if argv:
        return run_cli(argv)
    return run_gui()

# CLI-Aufrufe benötigen PySide6 nicht. Die GUI-Abhängigkeit wird nur geladen,
# wenn das Script ohne Kommandozeilenargumente gestartet wird.
if __name__ == "__main__" and len(sys.argv) > 1:
    multiprocessing.freeze_support()
    raise SystemExit(run_cli(sys.argv[1:]))

import os
import sys
import base64
from pathlib import Path
from dataclasses import dataclass
from typing import List

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QAction, QFont
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QFrame, QLabel, QPushButton,
    QVBoxLayout, QHBoxLayout, QGridLayout, QLineEdit, QTextEdit, QFileDialog,
    QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox, QProgressBar,
    QMessageBox, QStackedWidget, QListWidget, QListWidgetItem, QSplitter,
    QAbstractItemView
)
import sys as _sys
crypto = _sys.modules[__name__]  # Engine-Funktionen liegen in dieser Einzeldatei.

APP_TITLE = f"AES Crypto Tool  v{crypto.APP_VERSION}"
STYLE = """
QWidget { font-family: 'Segoe UI', 'Noto Sans', sans-serif; font-size: 10pt; color:#17264a; }
QMainWindow { background:#f4f7ff; }
QFrame#sidebar { background:#102c58; border-radius:14px; }
QLabel#brand { color:white; font-size:17pt; font-weight:700; }
QLabel#brandSub { color:#d5e3ff; }
QPushButton#nav { text-align:left; color:#eef4ff; background:transparent; border:0; padding:13px 16px; border-radius:9px; font-size:11pt; }
QPushButton#nav:checked, QPushButton#nav:hover { background:#2475ed; }
QFrame#panel { background:white; border:1px solid #d6e1fb; border-radius:12px; }
QLabel#heading { font-size:23pt; font-weight:750; color:#102653; }
QLabel#section { font-size:13pt; font-weight:700; }
QLabel#detect { background:#e7f2ff; color:#124d9c; border:1px solid #b9d5ff; border-radius:9px; padding:11px; font-weight:600; }
QLabel#detectGood { background:#e8f8ef; color:#14683c; border:1px solid #a8e2c0; border-radius:9px; padding:11px; font-weight:600; }
QPushButton { background:#1769df; color:white; border:0; border-radius:9px; padding:10px 15px; font-weight:650; }
QPushButton:hover { background:#0d58c4; }
QPushButton:disabled { background:#cbd6e9; color:#71809b; }
QPushButton#secondary { background:#fff; color:#1769df; border:1px solid #8eb5ff; }
QLineEdit, QTextEdit, QTableWidget { background:#fff; border:1px solid #cbd8f2; border-radius:8px; padding:8px; selection-background-color:#cfe1ff; }
QHeaderView::section { background:#edf2fc; padding:8px; border:0; font-weight:700; }
QCheckBox { spacing:8px; }
QProgressBar { background:#e5ebf7; border:0; border-radius:7px; height:14px; text-align:center; }
QProgressBar::chunk { background:#20a66a; border-radius:7px; }
QTextEdit#result { background:#f0fbf4; border:1px solid #a9dfbd; }
"""


def is_encrypted_file(path: str) -> bool:
    with open(path, 'rb') as f:
        magic = f.read(max(len(crypto.MAGIC), len(crypto.MAGIC_V3)))
    return magic.startswith(crypto.MAGIC) or magic.startswith(crypto.MAGIC_V3)


def detect_text(value: str) -> bool:
    """True only for a structurally plausible supported AESCRYPT2 text payload."""
    try:
        raw = base64.b64decode(value.encode('utf-8'), validate=True)
        header_len = len(crypto.MAGIC) + 1 + crypto.SALT_SIZE + crypto.NONCE_SIZE
        return (len(raw) >= header_len + crypto.TAG_SIZE
                and raw.startswith(crypto.MAGIC)
                and raw[len(crypto.MAGIC)] == crypto.FORMAT_VERSION)
    except Exception:
        return False


@dataclass
class Job:
    path: str
    encrypted: bool


class FileWorker(QThread):
    progress = Signal(int, int, str)
    item_done = Signal(str, bool, str)
    finished_all = Signal(int, int, bool)

    def __init__(self, jobs: List[Job], password: str, delete_original: bool, mask_names: bool):
        super().__init__()
        self.jobs, self.password = jobs, password
        self.delete_original, self.mask_names = delete_original, mask_names
        self.cancel_requested = False

    def cancel(self):
        self.cancel_requested = True

    def run(self):
        ok = fail = 0
        total = len(self.jobs)
        for index, job in enumerate(self.jobs):
            if self.cancel_requested:
                break
            try:
                identity = crypto._file_identity(job.path) if self.delete_original else None
                if job.encrypted:
                    out = crypto.make_decrypt_output_path(job.path, self.password)
                    crypto.decrypt_file(job.path, out, self.password)
                    mode = 'entschlüsselt'
                else:
                    out = crypto.make_encrypt_output_path(job.path, self.mask_names)
                    crypto.encrypt_file(job.path, out, self.password)
                    mode = 'verschlüsselt'
                if self.delete_original:
                    crypto.delete_original_file(job.path, expected_identity=identity)
                ok += 1
                msg = f'{Path(job.path).name} → {Path(out).name} ({mode})'
                self.item_done.emit(job.path, True, msg)
            except Exception as exc:
                fail += 1
                self.item_done.emit(job.path, False, f'{Path(job.path).name}: {exc}')
            self.progress.emit(index + 1, total, Path(job.path).name)
        self.finished_all.emit(ok, fail, self.cancel_requested)


class DropTable(QTableWidget):
    paths_dropped = Signal(list)
    def __init__(self):
        super().__init__(0, 4)
        self.setHorizontalHeaderLabels(['Name', 'Typ', 'Größe', 'Automatische Erkennung'])
        self.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        for c in (1,2,3): self.horizontalHeader().setSectionResizeMode(c, QHeaderView.ResizeToContents)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setAcceptDrops(True)
        self.setAlternatingRowColors(True)
    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls(): e.acceptProposedAction()
        else: e.ignore()
    def dropEvent(self, e):
        paths = [u.toLocalFile() for u in e.mimeData().urls() if u.isLocalFile()]
        self.paths_dropped.emit(paths); e.acceptProposedAction()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE); self.resize(1240, 850); self.setMinimumSize(980, 700)
        self.paths: List[str] = []; self.worker = None
        root = QWidget(); self.setCentralWidget(root)
        outer = QHBoxLayout(root); outer.setContentsMargins(12,12,12,12); outer.setSpacing(12)
        side = QFrame(); side.setObjectName('sidebar'); side.setFixedWidth(218)
        sl = QVBoxLayout(side); sl.setContentsMargins(15,22,15,18)
        logo = QLabel('🛡  AES Crypto Tool'); logo.setObjectName('brand'); sl.addWidget(logo)
        sub = QLabel('Sicher. Einfach. Plattformunabhängig.'); sub.setObjectName('brandSub'); sl.addWidget(sub); sl.addSpacing(28)
        self.nav_files = QPushButton('▣   Dateien & Ordner'); self.nav_text = QPushButton('▤   Text')
        self.nav_history = QPushButton('◷   Verlauf'); self.nav_settings = QPushButton('⚙   Einstellungen')
        self.nav_files.setObjectName('nav'); self.nav_text.setObjectName('nav')
        for b in (self.nav_files,self.nav_text,self.nav_history,self.nav_settings):
            b.setCheckable(True); sl.addWidget(b)
        self.nav_files.setChecked(True); sl.addStretch(1)
        sl.addWidget(QLabel('●  Bereit'))
        outer.addWidget(side)
        self.stack = QStackedWidget(); outer.addWidget(self.stack,1)
        self.files_page = self.make_files_page(); self.text_page = self.make_text_page()
        self.stack.addWidget(self.files_page); self.stack.addWidget(self.text_page)
        self.nav_files.clicked.connect(lambda: self.switch(0)); self.nav_text.clicked.connect(lambda: self.switch(1))
        self.nav_history.clicked.connect(lambda: QMessageBox.information(self,'Verlauf','Der Verlauf wird in einer späteren Ausbaustufe ergänzt.'))
        self.nav_settings.clicked.connect(lambda: QMessageBox.information(self,'Einstellungen','Keine Sicherheitsstufen-Auswahl. Die vorhandenen Kryptografie-Standards bleiben unverändert.'))

    def switch(self, index):
        self.stack.setCurrentIndex(index); self.nav_files.setChecked(index==0); self.nav_text.setChecked(index==1)

    def panel(self, layout=None):
        f=QFrame(); f.setObjectName('panel')
        if layout is not None: f.setLayout(layout)
        return f

    def make_files_page(self):
        page=QWidget(); v=QVBoxLayout(page); v.setSpacing(12)
        h=QLabel('Dateien oder Ordner sicher verarbeiten'); h.setObjectName('heading'); v.addWidget(h)
        v.addWidget(QLabel('Dateien und ganze Ordner hinzufügen – jede Datei wird einzeln automatisch erkannt.'))
        drop=self.panel(QVBoxLayout()); drop.layout().setContentsMargins(18,15,18,15)
        prompt=QLabel('⬇   Dateien oder Ordner hierher ziehen'); prompt.setAlignment(Qt.AlignCenter); prompt.setStyleSheet('font-size:15pt;font-weight:700;color:#1769df;padding:12px;')
        drop.layout().addWidget(prompt)
        buttons=QHBoxLayout(); self.add_files_btn=QPushButton('Dateien auswählen …'); self.add_folder_btn=QPushButton('Ordner auswählen …'); self.clear_btn=QPushButton('Liste leeren'); self.clear_btn.setObjectName('secondary')
        for b in (self.add_files_btn,self.add_folder_btn,self.clear_btn): buttons.addWidget(b)
        drop.layout().addLayout(buttons); v.addWidget(drop)
        self.table=DropTable(); self.table.paths_dropped.connect(self.add_paths); v.addWidget(self.table,1)
        opts=self.panel(QHBoxLayout()); opts.layout().setContentsMargins(14,10,14,10)
        self.password=QLineEdit(); self.password.setPlaceholderText('Passwort'); self.password.setEchoMode(QLineEdit.Password)
        self.show_pwd=QCheckBox('Anzeigen'); self.show_pwd.toggled.connect(lambda x:self.password.setEchoMode(QLineEdit.Normal if x else QLineEdit.Password))
        self.delete_original=QCheckBox('Originaldateien nach Erfolg löschen'); self.mask_names=QCheckBox('Dateinamen verschleiern')
        opts.layout().addWidget(QLabel('🔑 Passwort')); opts.layout().addWidget(self.password,1); opts.layout().addWidget(self.show_pwd); opts.layout().addWidget(self.delete_original); opts.layout().addWidget(self.mask_names); v.addWidget(opts)
        detect=self.panel(QVBoxLayout()); detect.layout().setContentsMargins(14,10,14,10)
        self.summary=QLabel('Automatische Erkennung: Dateien werden beim Start einzeln geprüft.'); self.summary.setObjectName('detect'); detect.layout().addWidget(self.summary); v.addWidget(detect)
        runrow=QHBoxLayout(); self.run_btn=QPushButton('▶   Erkannte Vorgänge ausführen'); self.cancel_btn=QPushButton('Abbrechen'); self.cancel_btn.setObjectName('secondary'); self.cancel_btn.setEnabled(False)
        runrow.addWidget(self.run_btn,1); runrow.addWidget(self.cancel_btn); v.addLayout(runrow)
        self.progress=QProgressBar(); self.progress.setValue(0); v.addWidget(self.progress)
        self.log=QTextEdit(); self.log.setReadOnly(True); self.log.setMaximumHeight(105); self.log.setPlaceholderText('Verarbeitungsprotokoll …'); v.addWidget(self.log)
        self.add_files_btn.clicked.connect(self.choose_files); self.add_folder_btn.clicked.connect(self.choose_folder); self.clear_btn.clicked.connect(self.clear_files)
        self.run_btn.clicked.connect(self.start_files); self.cancel_btn.clicked.connect(self.cancel_files)
        return page

    def choose_files(self):
        files,_=QFileDialog.getOpenFileNames(self,'Dateien auswählen'); self.add_paths(files)
    def choose_folder(self):
        folder=QFileDialog.getExistingDirectory(self,'Ordner auswählen')
        if folder: self.add_paths([folder])
    def add_paths(self, paths):
        for p in paths:
            p=os.path.abspath(p)
            if os.path.islink(p): continue
            if os.path.isfile(p): candidates=[p]
            elif os.path.isdir(p): candidates=crypto.collect_files([p])
            else: continue
            for f in candidates:
                if f not in self.paths: self.paths.append(f)
        self.refresh_table()
    def refresh_table(self):
        self.table.setRowCount(0)
        for p in self.paths:
            try:
                enc=is_encrypted_file(p); size=os.path.getsize(p)
                row=self.table.rowCount(); self.table.insertRow(row)
                vals=[Path(p).name,'Datei',f'{size/1024/1024:.2f} MB','Verschlüsselt → Entschlüsseln' if enc else 'Klartext → Verschlüsseln']
                for c,val in enumerate(vals): self.table.setItem(row,c,QTableWidgetItem(val))
            except Exception as e: self.log.append(f'{p}: Erkennung fehlgeschlagen: {e}')
        self.summary.setText(f'Automatische Erkennung: {len(self.paths)} Datei(en) – jede Datei wird einzeln geprüft; gemischte Ordner sind möglich.')
    def clear_files(self): self.paths=[]; self.refresh_table(); self.log.clear(); self.progress.setValue(0)
    def start_files(self):
        if not self.paths: QMessageBox.warning(self,'Keine Dateien','Bitte Dateien oder einen Ordner hinzufügen.'); return
        pwd=self.password.text()
        if not pwd: QMessageBox.warning(self,'Passwort fehlt','Bitte ein Passwort eingeben.'); return
        jobs=[]
        for p in self.paths:
            try: jobs.append(Job(p,is_encrypted_file(p)))
            except Exception as e: self.log.append(f'Übersprungen {p}: {e}')
        if not jobs: return
        self.run_btn.setEnabled(False); self.cancel_btn.setEnabled(True); self.progress.setMaximum(len(jobs)); self.progress.setValue(0)
        self.worker=FileWorker(jobs,pwd,self.delete_original.isChecked(),self.mask_names.isChecked())
        self.worker.progress.connect(self.file_progress); self.worker.item_done.connect(self.file_done); self.worker.finished_all.connect(self.file_finished); self.worker.start()
    def file_progress(self,n,total,name): self.progress.setValue(n); self.summary.setText(f'Verarbeitung {n}/{total}: {name}')
    def file_done(self,path,ok,msg): self.log.append(('✓ ' if ok else '✗ ')+msg)
    def file_finished(self,ok,fail,cancelled):
        self.run_btn.setEnabled(True); self.cancel_btn.setEnabled(False); self.password.clear()
        self.summary.setText(f'Abgeschlossen: {ok} erfolgreich, {fail} Fehler'+(' – abgebrochen' if cancelled else ''))
        QMessageBox.information(self,'Verarbeitung abgeschlossen',f'{ok} erfolgreich\n{fail} Fehler'+('\nVorgang abgebrochen.' if cancelled else ''))
        self.refresh_table()
    def cancel_files(self):
        if self.worker: self.worker.cancel(); self.summary.setText('Abbruch vorgemerkt – aktuelle Datei wird beendet.')

    def make_text_page(self):
        page=QWidget(); v=QVBoxLayout(page); v.setSpacing(12)
        h=QLabel('Textverschlüsselung'); h.setObjectName('heading'); v.addWidget(h)
        v.addWidget(QLabel('Text einfügen – AES Crypto Tool erkennt automatisch, ob ver- oder entschlüsselt werden muss.'))
        inp=self.panel(QVBoxLayout()); inp.layout().setContentsMargins(15,12,15,12)
        top=QHBoxLayout(); top.addWidget(QLabel('Eingabetext')); top.addStretch(); self.clear_text_btn=QPushButton('Text löschen'); self.clear_text_btn.setObjectName('secondary'); top.addWidget(self.clear_text_btn); inp.layout().addLayout(top)
        self.input_text=QTextEdit(); self.input_text.setPlaceholderText('Klartext oder AESCRYPT-Text hier einfügen …'); self.input_text.setMinimumHeight(220); inp.layout().addWidget(self.input_text)
        self.text_detect=QLabel('Erkennung: Bitte Text eingeben.'); self.text_detect.setObjectName('detect'); inp.layout().addWidget(self.text_detect); v.addWidget(inp)
        self.text_process=QPushButton('🔐   Text verarbeiten'); v.addWidget(self.text_process,0,Qt.AlignHCenter)
        out=self.panel(QVBoxLayout()); out.layout().setContentsMargins(15,12,15,12)
        top2=QHBoxLayout(); top2.addWidget(QLabel('Ergebnis')); top2.addStretch(); self.copy_btn=QPushButton('In Zwischenablage kopieren'); self.copy_btn.setObjectName('secondary'); top2.addWidget(self.copy_btn); out.layout().addLayout(top2)
        self.output_text=QTextEdit(); self.output_text.setObjectName('result'); self.output_text.setMinimumHeight(220); self.output_text.setReadOnly(True); self.output_text.setPlaceholderText('Das Ergebnis erscheint hier …'); out.layout().addWidget(self.output_text); v.addWidget(out,1)
        self.text_status=QLabel('Bereit'); self.text_status.setObjectName('detectGood'); v.addWidget(self.text_status)
        self.text_pwd=QLineEdit(); self.text_pwd.setPlaceholderText('Passwort'); self.text_pwd.setEchoMode(QLineEdit.Password)
        self.text_show=QCheckBox('Passwort anzeigen'); self.text_show.toggled.connect(lambda x:self.text_pwd.setEchoMode(QLineEdit.Normal if x else QLineEdit.Password))
        pwrow=QHBoxLayout(); pwrow.addWidget(QLabel('Passwort')); pwrow.addWidget(self.text_pwd,1); pwrow.addWidget(self.text_show); v.insertLayout(2,pwrow)
        self.input_text.textChanged.connect(self.update_text_detection); self.text_process.clicked.connect(self.process_text); self.copy_btn.clicked.connect(self.copy_text); self.clear_text_btn.clicked.connect(self.clear_text)
        return page
    def update_text_detection(self):
        value=self.input_text.toPlainText().strip()
        if not value: msg='Erkennung: Bitte Text eingeben.'
        elif detect_text(value): msg='Erkannt: AESCRYPT2-Text – es wird automatisch entschlüsselt.'
        else: msg='Erkannt: Klartext – es wird automatisch verschlüsselt.'
        self.text_detect.setText(msg)
    def process_text(self):
        value=self.input_text.toPlainText(); pwd=self.text_pwd.text()
        if not value.strip() or not pwd: QMessageBox.warning(self,'Eingabe fehlt','Bitte Text und Passwort eingeben.'); return
        try:
            if detect_text(value.strip()): result=crypto.decrypt_text(value.strip(),pwd); mode='entschlüsselt'
            else: result=crypto.encrypt_text(value,pwd); mode='verschlüsselt'
            self.output_text.setPlainText(result); self.text_status.setText(f'Text erfolgreich {mode}.'); self.text_pwd.clear()
        except Exception as e:
            QMessageBox.critical(self,'Verarbeitung fehlgeschlagen',str(e)); self.text_status.setText('Fehler bei der Verarbeitung.')
    def copy_text(self):
        value=self.output_text.toPlainText()
        if value: QApplication.clipboard().setText(value); self.text_status.setText('Ergebnis in die Zwischenablage kopiert.')
    def clear_text(self): self.input_text.clear(); self.output_text.clear(); self.text_pwd.clear(); self.text_status.setText('Bereit')


def gui_main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    app.setStyleSheet(STYLE)
    win = MainWindow()
    win.show()
    return app.exec()

def standalone_main():
    multiprocessing.freeze_support()
    if len(sys.argv) > 1:
        return run_cli(sys.argv[1:])
    try:
        return gui_main()
    except Exception as exc:
        print(f"GUI konnte nicht gestartet werden: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(standalone_main())
