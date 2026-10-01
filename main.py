#!/usr/bin/env python3

import os
import re
import sys
import secrets
import struct
import threading
import queue
import argparse
import multiprocessing
import getpass
import io
import tempfile
import base64

# Linux GUI: Single-Instance-Sperre
if sys.platform.startswith("linux"):
    import fcntl

from urllib.parse import unquote, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
    import pystray
    from pystray import MenuItem as item
    from PIL import Image, ImageDraw

    GUI_AVAILABLE = True

except ImportError:
    GUI_AVAILABLE = False


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

APP_VERSION = "1.2.0"

SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16

NAME_LEN_SIZE = 4
MAX_NAME_LEN = 1024

# AESCRYPT3 Header-Felder
V3_CHUNK_SIZE_SIZE = 4
V3_FILE_SIZE_SIZE = 8
V3_CHUNK_COUNT_SIZE = 8
V3_RECORD_HEADER_SIZE = 8 + 4 + 4
MAX_V3_CHUNK_SIZE = 64 * 1024 * 1024

# Scrypt ist speicherhart und erschwert Offline-Passwortangriffe.
SCRYPT_N = 2**16
SCRYPT_R = 8
SCRYPT_P = 1


# ============================================================
# Kryptographie (Grundlagen)
# ============================================================

def derive_key(password: str, salt: bytes) -> bytes:
    if not isinstance(password, str):
        raise TypeError("Passwort muss ein String sein.")
    if not password:
        raise ValueError("Passwort darf nicht leer sein.")
    if len(salt) != SALT_SIZE:
        raise ValueError("Ungültige Salt-Länge.")

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
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


def build_v3_header(salt: bytes, base_nonce: bytes, file_size: int, data_chunk_count: int) -> bytes:
    """AESCRYPT3 Header. Enthält Größe und erwartete Chunk-Anzahl,
    damit Trunkierung/Entfernung von Chunks erkannt wird."""
    if len(salt) != SALT_SIZE:
        raise ValueError("Ungültige Salt-Länge.")
    if len(base_nonce) != NONCE_SIZE:
        raise ValueError("Ungültige Nonce-Länge.")
    if not 0 <= file_size <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("Datei ist zu groß für das AESCRYPT3-Format.")
    if not 0 <= data_chunk_count <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("Zu viele Chunks.")

    return (
        MAGIC_V3
        + bytes([FORMAT_VERSION_V3])
        + salt
        + base_nonce
        + struct.pack(">I", CHUNK_SIZE)
        + struct.pack(">Q", file_size)
        + struct.pack(">Q", data_chunk_count)
    )


def read_v3_header(fin):
    magic = fin.read(len(MAGIC_V3))
    if magic != MAGIC_V3:
        raise ValueError("Ungültiges oder nicht unterstütztes AESCRYPT3-Format.")

    version = fin.read(1)
    if len(version) != 1 or version[0] != FORMAT_VERSION_V3:
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

    return salt, base_nonce, chunk_size, file_size, data_chunk_count, header


def build_v3_nonce(base_nonce: bytes, chunk_index: int) -> bytes:
    if len(base_nonce) != NONCE_SIZE:
        raise ValueError("Ungültige Nonce-Länge.")
    if not 0 <= chunk_index <= 0xFFFFFFFF:
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


def read_v3_chunk(fin):
    record_header = fin.read(V3_RECORD_HEADER_SIZE)
    if not record_header:
        return None
    if len(record_header) != V3_RECORD_HEADER_SIZE:
        raise ValueError("AESCRYPT3-Chunk-Header ist unvollständig.")

    chunk_index, plaintext_size, ciphertext_size = struct.unpack(
        ">QII", record_header
    )

    if ciphertext_size != plaintext_size:
        raise ValueError("Ungültige AESCRYPT3-Chunk-Größe.")

    ciphertext = fin.read(ciphertext_size)
    if len(ciphertext) != ciphertext_size:
        raise ValueError("AESCRYPT3-Datei ist unvollständig.")

    tag = fin.read(TAG_SIZE)
    if len(tag) != TAG_SIZE:
        raise ValueError("AESCRYPT3-Authentifizierungs-Tag fehlt.")

    return chunk_index, plaintext_size, ciphertext, tag


def install_temp_no_overwrite(tmp_path, output_path):
    try:
        fd = os.open(
            output_path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
        )
    except FileExistsError:
        raise FileExistsError(f"Zieldatei existiert bereits: {output_path}")
    except OSError as e:
        raise OSError(f"Zieldatei konnte nicht sicher angelegt werden: {e}")
    else:
        try:
            os.close(fd)
            os.replace(tmp_path, output_path)
        except OSError as e:
            try:
                os.remove(output_path)
            except OSError:
                pass
            raise OSError(f"Zieldatei konnte nicht installiert werden: {e}")


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
        payload = base64.b64decode(encoded_payload.encode("utf-8"))
    except Exception:
        raise ValueError("Ungültiges Base64-Format.")
    
    header_size = len(MAGIC) + 1 + SALT_SIZE + NONCE_SIZE
    minimum_size = header_size + TAG_SIZE
    
    if len(payload) < minimum_size:
        raise ValueError("Daten zu kurz oder beschädigt.")
        
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

def encrypt_file(input_path, output_path, password, progress_cb=None):
    """Neue Dateien werden ausschließlich als AESCRYPT3 geschrieben."""
    input_path = os.path.abspath(input_path)
    output_path = os.path.abspath(output_path)

    if input_path == output_path:
        raise ValueError("Quelle und Ziel dürfen nicht identisch sein.")

    file_size = os.path.getsize(input_path)
    data_chunk_count = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE if file_size else 0

    salt = secrets.token_bytes(SALT_SIZE)
    base_nonce = secrets.token_bytes(NONCE_SIZE)
    aes_key = derive_key(password, salt)

    orig_name = os.path.basename(input_path).encode("utf-8")
    if len(orig_name) == 0 or len(orig_name) > MAX_NAME_LEN:
        raise ValueError("Dateiname zu lang oder leer.")

    metadata = struct.pack(">I", len(orig_name)) + orig_name
    header = build_v3_header(salt, base_nonce, file_size, data_chunk_count)

    out_dir = os.path.dirname(output_path) or "."
    os.makedirs(out_dir, exist_ok=True)

    tmp_fd, tmp_path = tempfile.mkstemp(
        dir=out_dir, prefix=".aescrypto-", suffix=".tmp"
    )

    try:
        with open(input_path, "rb") as fin, os.fdopen(tmp_fd, "wb") as fout:
            fout.write(header)

            # Chunk 0 enthält ausschließlich die verschlüsselten Dateimetadaten.
            write_v3_chunk(
                fout, aes_key, base_nonce, header, 0, metadata
            )

            bytes_read = 0
            for index in range(1, data_chunk_count + 1):
                expected = min(CHUNK_SIZE, file_size - bytes_read)
                chunk = fin.read(expected)
                if len(chunk) != expected:
                    raise ValueError("Quelldatei konnte während der Verschlüsselung nicht vollständig gelesen werden.")

                write_v3_chunk(
                    fout, aes_key, base_nonce, header, index, chunk
                )

                bytes_read += len(chunk)
                if progress_cb:
                    progress_cb(bytes_read, file_size)

            if bytes_read != file_size:
                raise ValueError("Dateigröße hat sich während der Verschlüsselung geändert.")

            fout.flush()
            os.fsync(fout.fileno())

        install_temp_no_overwrite(tmp_path, output_path)
        tmp_path = None

    except Exception:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        raise


def decrypt_file_v3(input_path, output_path, password, progress_cb=None):
    input_path = os.path.abspath(input_path)
    output_path = os.path.abspath(output_path)

    if input_path == output_path:
        raise ValueError("Quelle und Ziel dürfen nicht identisch sein.")

    fsize = os.path.getsize(input_path)
    tmp_path = None

    with open(input_path, "rb") as fin:
        salt, base_nonce, chunk_size, file_size, data_chunk_count, header = read_v3_header(fin)

        if chunk_size != CHUNK_SIZE:
            # Andere gültige AESCRYPT3-Chunkgrößen dürfen gelesen werden;
            # sie müssen nur innerhalb der Formatgrenzen liegen.
            if chunk_size <= 0 or chunk_size > MAX_V3_CHUNK_SIZE:
                raise ValueError("Ungültige AESCRYPT3-Chunk-Größe.")

        # Ein Minimalcheck verhindert offensichtlich abgeschnittene Dateien.
        minimum_size = len(header) + V3_RECORD_HEADER_SIZE + TAG_SIZE
        if fsize < minimum_size:
            raise ValueError("AESCRYPT3-Datei zu klein oder beschädigt.")

        aes_key = derive_key(password, salt)

        out_dir = os.path.dirname(output_path) or "."
        os.makedirs(out_dir, exist_ok=True)
        tmp_fd, tmp_path = tempfile.mkstemp(
            dir=out_dir, prefix=".aescrypto-", suffix=".tmp"
        )

        try:
            with os.fdopen(tmp_fd, "wb") as fout:
                # Chunk 0: Dateiname/Metadaten. Er muss vor dem ersten Datenchunk
                # vollständig und authentisch sein.
                first = read_v3_chunk(fin)
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
                    record = read_v3_chunk(fin)
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
                        progress_cb(bytes_written, file_size)

                if bytes_written != file_size:
                    raise ValueError("AESCRYPT3-Dateigröße stimmt nicht mit dem Header überein.")

                # Nach dem erwarteten letzten Chunk darf nichts mehr folgen.
                trailing = fin.read(1)
                if trailing:
                    raise ValueError("AESCRYPT3-Datei enthält unerwartete zusätzliche Daten.")

                fout.flush()
                os.fsync(fout.fileno())

            # Erst nach erfolgreicher Authentifizierung und vollständiger
            # Strukturprüfung wird die temporäre Klartextdatei sichtbar installiert.
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
    """AESCRYPT2-Legacy-Entschlüsselung. Alte Dateien bleiben lesbar."""
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

            aes_key = derive_key(password, salt)
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()
            decryptor.authenticate_additional_data(header)

            # Legacy-Dateien werden vollständig in RAM authentifiziert, bevor
            # überhaupt eine Klartext-Ausgabedatei angelegt wird.
            fin.seek(len(header))
            plaintext = bytearray()
            remaining = ciphertext_size
            processed = 0

            while remaining:
                chunk = fin.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    raise ValueError("Verschlüsselte Datei ist unvollständig.")
                plaintext.extend(decryptor.update(chunk))
                processed += len(chunk)
                remaining -= len(chunk)
                if progress_cb:
                    progress_cb(processed, ciphertext_size)

            try:
                plaintext.extend(decryptor.finalize())
            except InvalidTag:
                raise ValueError("Falsches Passwort oder beschädigte Datei.")

            if len(plaintext) < NAME_LEN_SIZE + 1:
                raise ValueError("Verschlüsselte Datei enthält keinen gültigen Dateinamen.")

            name_len = struct.unpack(">I", plaintext[:NAME_LEN_SIZE])[0]
            if name_len == 0 or name_len > MAX_NAME_LEN:
                raise ValueError("Ungültiges Dateiformat: ungültiger Dateiname.")

            name_end = NAME_LEN_SIZE + name_len
            if len(plaintext) < name_end:
                raise ValueError("Verschlüsselte Datei enthält keinen vollständigen Dateinamen.")

            try:
                bytes(plaintext[NAME_LEN_SIZE:name_end]).decode("utf-8")
            except UnicodeDecodeError:
                raise ValueError("Ungültiger Dateiname.")

            out_dir = os.path.dirname(output_path) or "."
            os.makedirs(out_dir, exist_ok=True)
            tmp_fd, tmp_path = tempfile.mkstemp(
                dir=out_dir, prefix=".aescrypto-", suffix=".tmp"
            )

            with os.fdopen(tmp_fd, "wb") as fout:
                fout.write(plaintext[name_end:])
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
            salt, base_nonce, chunk_size, file_size, data_chunk_count, header = read_v3_header(fin)
            aes_key = derive_key(password, salt)
            record = read_v3_chunk(fin)
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
        # Für AESCRYPT2 wird die vollständige Datei authentifiziert, bevor
        # der Dateiname zurückgegeben wird. Das entspricht dem Legacy-Format.
        fsize = os.path.getsize(enc_path)
        header_size = len(MAGIC) + 1 + SALT_SIZE + NONCE_SIZE
        if fsize < header_size + NAME_LEN_SIZE + 1 + TAG_SIZE:
            raise ValueError("Datei zu klein oder beschädigt.")

        with open(enc_path, "rb") as fin:
            salt, nonce, header = read_header(fin)
            fin.seek(fsize - TAG_SIZE)
            tag = fin.read(TAG_SIZE)
            ciphertext_size = fsize - len(header) - TAG_SIZE
            aes_key = derive_key(password, salt)
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()
            decryptor.authenticate_additional_data(header)
            fin.seek(len(header))
            plaintext = bytearray()
            remaining = ciphertext_size
            while remaining:
                chunk = fin.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    raise ValueError("Verschlüsselte Datei ist unvollständig.")
                plaintext.extend(decryptor.update(chunk))
                remaining -= len(chunk)
            try:
                plaintext.extend(decryptor.finalize())
            except InvalidTag:
                raise ValueError("Falsches Passwort oder beschädigte Datei.")

            if len(plaintext) < NAME_LEN_SIZE + 1:
                raise ValueError("Verschlüsselte Datei enthält keinen gültigen Dateinamen.")
            name_len = struct.unpack(">I", plaintext[:NAME_LEN_SIZE])[0]
            if name_len == 0 or name_len > MAX_NAME_LEN or len(plaintext) < NAME_LEN_SIZE + name_len:
                raise ValueError("Ungültiges Dateiformat: ungültiger Dateiname.")
            try:
                return bytes(plaintext[NAME_LEN_SIZE:NAME_LEN_SIZE + name_len]).decode("utf-8")
            except UnicodeDecodeError:
                raise ValueError("Ungültiger Dateiname.")

    raise ValueError("Ungültiges oder nicht unterstütztes Dateiformat.")


def delete_original_file(filepath):
    if not os.path.lexists(filepath):
        return
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
    orig_name = os.path.basename(orig_name)
    if not orig_name:
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


def process_single(fpath, password, delete_original, encrypt_filename=False):
    mode = "decrypt" if fpath.lower().endswith(".enc") else "encrypt"
    try:
        if mode == "encrypt":
            out_path = make_encrypt_output_path(fpath, encrypt_filename)
            encrypt_file(fpath, out_path, password)
        else:
            out_path = make_decrypt_output_path(fpath, password)
            decrypt_file(fpath, out_path, password)

        if delete_original:
            try:
                delete_original_file(fpath)
            except Exception:
                return False, f"{os.path.basename(fpath)}: {mode} erfolgreich, Original konnte nicht entfernt werden."

        return True, f"{os.path.basename(fpath)} ({mode})"
    except Exception as e:
        return False, f"{os.path.basename(fpath)}: {str(e)}"


# ============================================================
# Grafische Benutzeroberfläche (GUI)
# ============================================================

if GUI_AVAILABLE:

    class AESCryptoApp:

        def __init__(self, root):
            self.root = root
            self.root.title(f"AES Crypto Tool v{APP_VERSION}")
            self.root.geometry("700x580")
            
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

        def setup_files_tab(self):
            info_label = ttk.Label(self.tab_files, text="Wähle Dateien/Ordner aus oder ziehe sie per Drag & Drop hierher:", padding=10)
            info_label.pack(anchor="w")

            btn_frame = ttk.Frame(self.tab_files, padding=10)
            btn_frame.pack(fill="x")

            ttk.Button(btn_frame, text="Dateien hinzufügen", command=self.add_files).pack(side="left", padx=5)
            ttk.Button(btn_frame, text="Ordner hinzufügen", command=self.add_folder).pack(side="left", padx=5)
            ttk.Button(btn_frame, text="Liste leeren", command=self.clear_list).pack(side="left", padx=5)

            # Listbox für Dateipfade
            list_frame = ttk.Frame(self.tab_files, padding=10)
            list_frame.pack(fill="both", expand=True)

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
            opt_frame.pack(fill="x", padx=10, pady=10)

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

            # Ausführen-Button
            ttk.Button(self.tab_files, text="Verarbeitung starten", command=self.start_processing).pack(pady=10)

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
            files = filedialog.askopenfilenames(title="Dateien auswählen")
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
            pwd = self.file_pwd_entry.get()
            paths = list(self.file_listbox.get(0, tk.END))

            if not pwd:
                messagebox.showerror("Fehler", "Bitte gib ein Passwort ein.")
                return
            if not paths:
                messagebox.showerror("Fehler", "Keine Dateien ausgewählt.")
                return

            success_count = 0
            error_msgs = []

            for path in paths:
                success, msg = process_single(path, pwd, self.del_orig_var.get(), self.enc_name_var.get())
                if success:
                    success_count += 1
                else:
                    error_msgs.append(msg)

            if error_msgs:
                messagebox.showwarning("Fertig mit Hinweisen", f"Erfolgreich: {success_count}\nFehler:\n" + "\n".join(error_msgs))
            else:
                messagebox.showinfo("Erfolg", f"Alle {success_count} Elemente wurden erfolgreich verarbeitet!")

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

        def on_encrypt_text(self):
            pwd = self.text_pwd_entry.get()
            text = self.input_text_area.get("1.0", tk.END).strip()
            if not pwd:
                messagebox.showerror("Fehler", "Bitte gib ein Passwort ein.")
                return
            if not text:
                messagebox.showerror("Fehler", "Bitte gib einen Text zum Verschlüsseln ein.")
                return
            try:
                encrypted = encrypt_text(text, pwd)
                self.output_text_area.delete("1.0", tk.END)
                self.output_text_area.insert("1.0", encrypted)
            except Exception as e:
                messagebox.showerror("Fehler bei der Verschlüsselung", str(e))

        def on_process_text(self):
            pwd = self.text_pwd_entry.get()
            text = self.input_text_area.get("1.0", tk.END).strip()
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

        def on_decrypt_text(self):
            pwd = self.text_pwd_entry.get()
            text = self.input_text_area.get("1.0", tk.END).strip()
            if not pwd:
                messagebox.showerror("Fehler", "Bitte gib ein Passwort ein.")
                return
            if not text:
                messagebox.showerror("Fehler", "Bitte gib einen Ciphertext ein.")
                return
            try:
                decrypted = decrypt_text(text, pwd)
                self.output_text_area.delete("1.0", tk.END)
                self.output_text_area.insert("1.0", decrypted)
            except Exception as e:
                messagebox.showerror("Fehler bei der Entschlüsselung", str(e))

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


if __name__ == "__main__":
    multiprocessing.freeze_support()
    raise SystemExit(main())
