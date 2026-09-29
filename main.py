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

MAGIC = b"AESCRYPT2"
FORMAT_VERSION = 3

SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16

NAME_LEN_SIZE = 4
MAX_NAME_LEN = 1024

# Scrypt ist speicherhart und erschwert Offline-Passwortangriffe.
SCRYPT_N = 2**16
SCRYPT_R = 8
SCRYPT_P = 1


# ============================================================
# Kryptographie
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

    if len(salt) != SALT_SIZE:
        raise ValueError("Ungültige Salt-Länge.")

    if len(nonce) != NONCE_SIZE:
        raise ValueError("Ungültige Nonce-Länge.")

    # Der Dateiname steht NICHT im Klartext im Header.
    # Er wird als erster Teil der GCM-Nutzdaten verschlüsselt.
    return (
        MAGIC
        + bytes([FORMAT_VERSION])
        + salt
        + nonce
    )


def read_header(fin):

    magic = fin.read(len(MAGIC))

    if magic != MAGIC:
        raise ValueError(
            "Ungültiges oder nicht unterstütztes Dateiformat."
        )

    version = fin.read(1)

    if len(version) != 1 or version[0] != FORMAT_VERSION:
        raise ValueError(
            "Nicht unterstützte Dateiformat-Version."
        )

    salt = fin.read(SALT_SIZE)

    if len(salt) != SALT_SIZE:
        raise ValueError(
            "Header unvollständig."
        )

    nonce = fin.read(NONCE_SIZE)

    if len(nonce) != NONCE_SIZE:
        raise ValueError(
            "Header unvollständig."
        )

    header = (
        MAGIC
        + version
        + salt
        + nonce
    )

    return salt, nonce, header


def install_temp_no_overwrite(tmp_path, output_path):
    """
    Installiert eine fertige Datei atomar, ohne ein vorhandenes
    Ziel zu überschreiben.

    WICHTIG (Bugfix):
    Die ursprüngliche Implementierung nutzte os.link() (Hardlink),
    um die temporäre Datei "an die Zielposition zu klonen".
    Hardlinks werden jedoch von vielen Dateisystemen, die auf
    externen Datenträgern (USB-Sticks, SD-Karten etc.) verwendet
    werden - allen voran FAT32 und exFAT - NICHT unterstützt.
    os.link() schlug dort mit einem OSError fehl, obwohl die
    Ver-/Entschlüsselung selbst bereits erfolgreich und vollständig
    abgeschlossen war. Die fertige Datei wurde dadurch verworfen.

    Die neue Implementierung verwendet stattdessen:

      1. os.open(..., O_CREAT | O_EXCL)
         -> atomares, exklusives Anlegen der Zieldatei
            (auf so gut wie jedem Dateisystem unterstützt,
             inkl. FAT32/exFAT/NTFS/ext4/...).
            Existiert die Datei bereits, schlägt dies mit
            FileExistsError fehl - Race-Conditions werden
            damit weiterhin sicher verhindert.

      2. os.replace(tmp_path, output_path)
         -> überschreibt die (leere) reservierte Datei mit dem
            fertigen Inhalt. Da sich tmp_path und output_path im
            selben Verzeichnis (und damit auf demselben
            Dateisystem) befinden, ist dies atomar und
            funktioniert plattform- und dateisystemübergreifend.
    """

    try:

        fd = os.open(
            output_path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
        )

    except FileExistsError:

        raise FileExistsError(
            f"Zieldatei existiert bereits: {output_path}"
        )

    except OSError as e:

        raise OSError(
            f"Zieldatei konnte nicht sicher angelegt werden: {e}"
        )

    else:

        try:

            os.close(fd)

            os.replace(
                tmp_path,
                output_path,
            )

        except OSError as e:

            # Reservierte (leere) Zieldatei wieder entfernen,
            # damit kein Datei-Müll zurückbleibt.
            try:
                os.remove(output_path)
            except OSError:
                pass

            raise OSError(
                f"Zieldatei konnte nicht installiert werden: {e}"
            )


# ============================================================
# Verschlüsselung
# ============================================================

def encrypt_file(
    input_path,
    output_path,
    password,
    progress_cb=None,
):

    input_path = os.path.abspath(
        input_path
    )

    output_path = os.path.abspath(
        output_path
    )

    if input_path == output_path:

        raise ValueError(
            "Quelle und Ziel dürfen nicht identisch sein."
        )

    salt = secrets.token_bytes(
        SALT_SIZE
    )

    nonce = secrets.token_bytes(
        NONCE_SIZE
    )

    aes_key = derive_key(
        password,
        salt,
    )

    orig_name = os.path.basename(
        input_path
    ).encode("utf-8")

    if len(orig_name) > MAX_NAME_LEN:

        raise ValueError(
            "Dateiname zu lang."
        )

    header = build_header(
        salt,
        nonce,
    )

    # Der Dateiname wird weiterhin verschlüsselt
    # innerhalb der Datei gespeichert.
    encrypted_metadata = (
        struct.pack(
            ">I",
            len(orig_name),
        )
        + orig_name
    )

    file_size = os.path.getsize(
        input_path
    )

    bytes_read = 0

    out_dir = (
        os.path.dirname(output_path)
        or "."
    )

    os.makedirs(
        out_dir,
        exist_ok=True,
    )

    tmp_fd, tmp_path = tempfile.mkstemp(
        dir=out_dir,
        prefix=".aescrypto-",
        suffix=".tmp",
    )

    try:

        with open(
            input_path,
            "rb",
        ) as fin, os.fdopen(
            tmp_fd,
            "wb",
        ) as fout:

            fout.write(
                header
            )

            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(nonce),
            )

            encryptor = cipher.encryptor()

            encryptor.authenticate_additional_data(
                header
            )

            encrypted_metadata = encryptor.update(
                encrypted_metadata
            )

            if encrypted_metadata:

                fout.write(
                    encrypted_metadata
                )

            while True:

                chunk = fin.read(
                    CHUNK_SIZE
                )

                if not chunk:
                    break

                encrypted = encryptor.update(
                    chunk
                )

                if encrypted:

                    fout.write(
                        encrypted
                    )

                bytes_read += len(
                    chunk
                )

                if progress_cb:

                    progress_cb(
                        bytes_read,
                        file_size,
                    )

            final_data = encryptor.finalize()

            if final_data:

                fout.write(
                    final_data
                )

            tag = encryptor.tag

            if len(tag) != TAG_SIZE:

                raise ValueError(
                    "Ungültige GCM-Tag-Länge."
                )

            fout.write(
                tag
            )

            fout.flush()

            os.fsync(
                fout.fileno()
            )

        install_temp_no_overwrite(
            tmp_path,
            output_path,
        )

        tmp_path = None

    except Exception:

        if tmp_path:

            try:
                os.unlink(
                    tmp_path
                )
            except OSError:
                pass

        raise


# ============================================================
# Entschlüsselung
# ============================================================

def decrypt_file(
    input_path,
    output_path,
    password,
    progress_cb=None,
):

    input_path = os.path.abspath(
        input_path
    )

    output_path = os.path.abspath(
        output_path
    )

    if input_path == output_path:

        raise ValueError(
            "Quelle und Ziel dürfen nicht identisch sein."
        )

    fsize = os.path.getsize(
        input_path
    )

    header_size = (
        len(MAGIC)
        + 1
        + SALT_SIZE
        + NONCE_SIZE
    )

    minimum_size = (
        header_size
        + NAME_LEN_SIZE
        + 1
        + TAG_SIZE
    )

    if fsize < minimum_size:

        raise ValueError(
            "Datei zu klein oder beschädigt."
        )

    tmp_path = None

    try:

        with open(
            input_path,
            "rb",
        ) as fin:

            (
                salt,
                nonce,
                header,
            ) = read_header(fin)

            header_size = len(
                header
            )

            if fsize < (
                header_size
                + NAME_LEN_SIZE
                + 1
                + TAG_SIZE
            ):

                raise ValueError(
                    "Ungültige Dateistruktur."
                )

            fin.seek(
                fsize - TAG_SIZE
            )

            tag = fin.read(
                TAG_SIZE
            )

            if len(tag) != TAG_SIZE:

                raise ValueError(
                    "Authentifizierungs-Tag fehlt."
                )

            ciphertext_size = (
                fsize
                - header_size
                - TAG_SIZE
            )

            if ciphertext_size < (
                NAME_LEN_SIZE + 1
            ):

                raise ValueError(
                    "Ungültige Dateistruktur."
                )

            aes_key = derive_key(
                password,
                salt,
            )

            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(
                    nonce,
                    tag,
                ),
            )

            decryptor = cipher.decryptor()

            decryptor.authenticate_additional_data(
                header
            )

            out_dir = (
                os.path.dirname(output_path)
                or "."
            )

            os.makedirs(
                out_dir,
                exist_ok=True,
            )

            tmp_fd, tmp_path = tempfile.mkstemp(
                dir=out_dir,
                prefix=".aescrypto-",
                suffix=".tmp",
            )

            bytes_read = 0
            metadata = bytearray()
            metadata_done = False
            name_len = None
            name_bytes = None

            with os.fdopen(
                tmp_fd,
                "wb",
            ) as fout:

                fin.seek(
                    header_size
                )

                while (
                    bytes_read
                    < ciphertext_size
                ):

                    to_read = min(
                        CHUNK_SIZE,
                        ciphertext_size
                        - bytes_read,
                    )

                    ct_chunk = fin.read(
                        to_read
                    )

                    if len(ct_chunk) != to_read:

                        raise ValueError(
                            "Verschlüsselte Datei ist unvollständig."
                        )

                    plaintext = decryptor.update(
                        ct_chunk
                    )

                    if plaintext:

                        if not metadata_done:

                            metadata.extend(
                                plaintext
                            )

                            if (
                                name_len is None
                                and len(metadata)
                                >= NAME_LEN_SIZE
                            ):

                                name_len = struct.unpack(
                                    ">I",
                                    metadata[
                                        :NAME_LEN_SIZE
                                    ],
                                )[0]

                                if (
                                    name_len == 0
                                    or name_len > MAX_NAME_LEN
                                ):

                                    raise ValueError(
                                        "Ungültiges Dateiformat: "
                                        "ungültiger Dateiname."
                                    )

                            if (
                                name_len is not None
                                and len(metadata)
                                >= (
                                    NAME_LEN_SIZE
                                    + name_len
                                )
                            ):

                                name_bytes = bytes(
                                    metadata[
                                        NAME_LEN_SIZE:
                                        NAME_LEN_SIZE
                                        + name_len
                                    ]
                                )

                                try:

                                    name_bytes.decode(
                                        "utf-8"
                                    )

                                except UnicodeDecodeError:

                                    raise ValueError(
                                        "Ungültiger Dateiname."
                                    )

                                metadata_done = True

                                remaining = metadata[
                                    NAME_LEN_SIZE
                                    + name_len:
                                ]

                                if remaining:

                                    fout.write(
                                        remaining
                                    )

                                metadata.clear()

                        else:

                            fout.write(
                                plaintext
                            )

                    bytes_read += len(
                        ct_chunk
                    )

                    if progress_cb:

                        data_done = max(
                            0,
                            bytes_read
                            - NAME_LEN_SIZE
                            - (
                                name_len
                                if name_len is not None
                                else 0
                            ),
                        )

                        data_total = max(
                            1,
                            ciphertext_size
                            - NAME_LEN_SIZE
                            - (
                                name_len
                                if name_len is not None
                                else 0
                            ),
                        )

                        progress_cb(
                            min(
                                data_done,
                                data_total,
                            ),
                            data_total,
                        )

                # ------------------------------------------------
                # Sicherheitskritisch:
                #
                # Erst finalize() bestätigt die GCM-Authentizität.
                # ------------------------------------------------

                final_plaintext = (
                    decryptor.finalize()
                )

                if final_plaintext:

                    if not metadata_done:

                        metadata.extend(
                            final_plaintext
                        )

                        if (
                            name_len is None
                            and len(metadata)
                            >= NAME_LEN_SIZE
                        ):

                            name_len = struct.unpack(
                                ">I",
                                metadata[
                                    :NAME_LEN_SIZE
                                ],
                            )[0]

                            if (
                                name_len == 0
                                or name_len > MAX_NAME_LEN
                            ):

                                raise ValueError(
                                    "Ungültiges Dateiformat: "
                                    "ungültiger Dateiname."
                                )

                        if (
                            name_len is not None
                            and len(metadata)
                            >= (
                                NAME_LEN_SIZE
                                + name_len
                            )
                        ):

                            name_bytes = bytes(
                                metadata[
                                    NAME_LEN_SIZE:
                                    NAME_LEN_SIZE
                                    + name_len
                                ]
                            )

                            try:

                                name_bytes.decode(
                                    "utf-8"
                                )

                            except UnicodeDecodeError:

                                raise ValueError(
                                    "Ungültiger Dateiname."
                                )

                            metadata_done = True

                            remaining = metadata[
                                NAME_LEN_SIZE
                                + name_len:
                            ]

                            if remaining:

                                fout.write(
                                    remaining
                                )

                            metadata.clear()

                    else:

                        fout.write(
                            final_plaintext
                        )

                if not metadata_done:

                    raise ValueError(
                        "Verschlüsselte Datei enthält "
                        "keinen gültigen Dateinamen."
                    )

                fout.flush()

                os.fsync(
                    fout.fileno()
                )

            # Erst jetzt ist die Entschlüsselung authentifiziert.
            install_temp_no_overwrite(
                tmp_path,
                output_path,
            )

            tmp_path = None

            return output_path

    except InvalidTag:

        raise ValueError(
            "Falsches Passwort oder beschädigte Datei."
        )

    finally:

        if tmp_path:

            try:

                os.unlink(
                    tmp_path
                )

            except OSError:
                pass


def get_original_filename(
    enc_path,
    password,
):

    enc_path = os.path.abspath(
        enc_path
    )

    fsize = os.path.getsize(
        enc_path
    )

    header_size = (
        len(MAGIC)
        + 1
        + SALT_SIZE
        + NONCE_SIZE
    )

    if fsize < (
        header_size
        + NAME_LEN_SIZE
        + 1
        + TAG_SIZE
    ):

        raise ValueError(
            "Datei zu klein oder beschädigt."
        )

    with open(
        enc_path,
        "rb",
    ) as fin:

        (
            salt,
            nonce,
            header,
        ) = read_header(fin)

        fin.seek(
            fsize - TAG_SIZE
        )

        tag = fin.read(
            TAG_SIZE
        )

        ciphertext_size = (
            fsize
            - len(header)
            - TAG_SIZE
        )

        if ciphertext_size < (
            NAME_LEN_SIZE + 1
        ):

            raise ValueError(
                "Ungültige Dateistruktur."
            )

        aes_key = derive_key(
            password,
            salt,
        )

        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(
                nonce,
                tag,
            ),
        )

        decryptor = cipher.decryptor()

        decryptor.authenticate_additional_data(
            header
        )

        fin.seek(
            len(header)
        )

        metadata = bytearray()

        while len(metadata) < NAME_LEN_SIZE:

            remaining_ciphertext = (
                ciphertext_size
                - len(metadata)
            )

            if remaining_ciphertext <= 0:

                raise ValueError(
                    "Verschlüsselte Datei enthält "
                    "keinen gültigen Dateinamen."
                )

            chunk = fin.read(
                min(
                    CHUNK_SIZE,
                    remaining_ciphertext,
                )
            )

            if not chunk:

                raise ValueError(
                    "Verschlüsselte Datei enthält "
                    "keinen gültigen Dateinamen."
                )

            metadata.extend(
                decryptor.update(
                    chunk
                )
            )

        name_len = struct.unpack(
            ">I",
            metadata[
                :NAME_LEN_SIZE
            ],
        )[0]

        if (
            name_len == 0
            or name_len > MAX_NAME_LEN
        ):

            raise ValueError(
                "Ungültiges Dateiformat: "
                "ungültiger Dateiname."
            )

        needed = (
            NAME_LEN_SIZE
            + name_len
        )

        while len(metadata) < needed:

            consumed = len(metadata)

            remaining_ciphertext = (
                ciphertext_size
                - consumed
            )

            if remaining_ciphertext <= 0:

                raise ValueError(
                    "Verschlüsselte Datei enthält "
                    "keinen vollständigen Dateinamen."
                )

            chunk = fin.read(
                min(
                    CHUNK_SIZE,
                    remaining_ciphertext,
                )
            )

            if not chunk:

                raise ValueError(
                    "Verschlüsselte Datei enthält "
                    "keinen vollständigen Dateinamen."
                )

            metadata.extend(
                decryptor.update(
                    chunk
                )
            )

        # Die komplette Datei muss durch den Decryptor laufen,
        # damit der GCM-Tag geprüft werden kann.
        consumed = len(metadata)

        while consumed < ciphertext_size:

            remaining = (
                ciphertext_size
                - consumed
            )

            read_size = min(
                CHUNK_SIZE,
                remaining,
            )

            chunk = fin.read(
                read_size
            )

            if len(chunk) != read_size:

                raise ValueError(
                    "Verschlüsselte Datei ist unvollständig."
                )

            decryptor.update(
                chunk
            )

            consumed += len(
                chunk
            )

        decryptor.finalize()

        name_bytes = bytes(
            metadata[
                NAME_LEN_SIZE:
                NAME_LEN_SIZE
                + name_len
            ]
        )

        try:

            return name_bytes.decode(
                "utf-8"
            )

        except UnicodeDecodeError:

            raise ValueError(
                "Ungültiger Dateiname."
            )


# ============================================================
# Originaldatei löschen
# ============================================================

def delete_original_file(filepath):

    if not os.path.lexists(filepath):
        return

    try:

        os.remove(
            filepath
        )

    except OSError as e:

        raise RuntimeError(
            f"Datei konnte nicht entfernt werden: {e}"
        )


# ============================================================
# Dateien sammeln
# ============================================================

def collect_files(paths):

    files = []

    for p in paths:

        if not p:
            continue

        p = os.path.abspath(
            p
        )

        if os.path.islink(p):
            continue

        if os.path.isfile(p):

            files.append(
                p
            )

        elif os.path.isdir(p):

            for root, dirs, fnames in os.walk(
                p,
                followlinks=False,
            ):

                dirs[:] = [
                    d
                    for d in dirs
                    if not os.path.islink(
                        os.path.join(
                            root,
                            d,
                        )
                    )
                ]

                for fn in fnames:

                    fp = os.path.join(
                        root,
                        fn,
                    )

                    if not os.path.islink(
                        fp
                    ):

                        files.append(
                            os.path.abspath(
                                fp
                            )
                        )

    seen = set()
    result = []

    for f in files:

        if f not in seen:

            seen.add(
                f
            )

            result.append(
                f
            )

    return result


# ============================================================
# Ausgabe-Pfade
# ============================================================

def make_encrypt_output_path(
    fpath,
    encrypt_filename=False,
):

    fpath = os.path.abspath(
        fpath
    )

    # --------------------------------------------------------
    # NEU:
    #
    # Wenn aktiviert, bekommt die verschlüsselte Datei einen
    # zufälligen Dateinamen.
    #
    # Beispiel:
    #
    # Rechnung_2026.pdf
    #
    # wird zu:
    #
    # 8f9b4d7a1e3c...c21a.enc
    #
    # Der eigentliche Original-Dateiname ist weiterhin
    # verschlüsselt in den GCM-Nutzdaten enthalten.
    # --------------------------------------------------------

    if encrypt_filename:

        directory = os.path.dirname(
            fpath
        ) or "."

        while True:

            random_name = (
                secrets.token_hex(
                    32
                )
                + ".enc"
            )

            candidate = os.path.join(
                directory,
                random_name,
            )

            # Erste Kollisionsprüfung.
            if not os.path.lexists(
                candidate
            ):

                return candidate

    # --------------------------------------------------------
    # Bisheriges Verhalten
    # --------------------------------------------------------

    out_path = (
        fpath
        + ".enc"
    )

    if not os.path.exists(
        out_path
    ):

        return out_path

    base, ext = os.path.splitext(
        fpath
    )

    counter = 1

    while True:

        candidate = (
            f"{base}_conflict"
            f"{counter}"
            f"{ext}.enc"
        )

        if not os.path.exists(
            candidate
        ):

            return candidate

        counter += 1


def make_decrypt_output_path(
    fpath,
    password,
):

    fpath = os.path.abspath(
        fpath
    )

    orig_name = get_original_filename(
        fpath,
        password,
    )

    # Nur ein Dateiname, niemals ein Pfad
    # aus dem Header.
    orig_name = os.path.basename(
        orig_name
    )

    if not orig_name:

        raise ValueError(
            "Ungültiger Original-Dateiname."
        )

    directory = os.path.dirname(
        fpath
    )

    out_path = os.path.join(
        directory,
        orig_name,
    )

    # --------------------------------------------------------
    # Kollisionsprüfung
    # --------------------------------------------------------

    if not os.path.exists(
        out_path
    ):

        return out_path

    name, ext = os.path.splitext(
        orig_name
    )

    counter = 1

    while True:

        candidate = os.path.join(
            directory,
            f"{name}_restored"
            f"{counter}"
            f"{ext}",
        )

        if not os.path.exists(
            candidate
        ):

            return candidate

        counter += 1


# ============================================================
# Einzelverarbeitung
# ============================================================

def process_single(
    fpath,
    password,
    delete_original,
    encrypt_filename=False,
):

    mode = (
        "decrypt"
        if fpath.lower().endswith(
            ".enc"
        )
        else "encrypt"
    )

    try:

        if mode == "encrypt":

            out_path = (
                make_encrypt_output_path(
                    fpath,
                    encrypt_filename,
                )
            )

            encrypt_file(
                fpath,
                out_path,
                password,
            )

        else:

            out_path = (
                make_decrypt_output_path(
                    fpath,
                    password,
                )
            )

            decrypt_file(
                fpath,
                out_path,
                password,
            )

        # Original NUR nach erfolgreicher
        # Kryptografie löschen.
        if delete_original:

            try:

                delete_original_file(
                    fpath
                )

            except Exception:

                return (
                    False,
                    f"{os.path.basename(fpath)}: "
                    f"{mode} erfolgreich, "
                    f"Original konnte nicht entfernt werden.",
                )

        return (
            True,
            f"{os.path.basename(fpath)} "
            f"({mode})",
        )

    except Exception as e:

        return (
            False,
            f"{os.path.basename(fpath)}: {e}",
        )


def _cli_process_single(
    fpath,
    password,
    delete_original,
    encrypt_filename,
):

    ok, msg = process_single(
        fpath,
        password,
        delete_original,
        encrypt_filename,
    )

    return (
        f"OK: {msg}"
        if ok
        else f"FEHLER: {msg}"
    )


# ============================================================
# CLI
# ============================================================

def run_cli():

    parser = argparse.ArgumentParser(
        description=(
            "AES Crypto CLI - "
            "Ver-/Entschlüsselung"
        )
    )

    parser.add_argument(
        "-f",
        "--files",
        nargs="+",
        default=[],
        help="Dateien",
    )

    parser.add_argument(
        "-d",
        "--dirs",
        nargs="+",
        default=[],
        help="Ordner",
    )

    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=min(
            4,
            multiprocessing.cpu_count() or 1,
        ),
        help="Parallele Worker",
    )

    parser.add_argument(
        "--keep-original",
        action="store_true",
        help="Original nicht löschen",
    )

    parser.add_argument(
        "--encrypt-filename",
        action="store_true",
        help=(
            "Beim Verschlüsseln einen zufälligen "
            "Dateinamen für die .enc-Datei verwenden"
        ),
    )

    args = parser.parse_args()

    if not args.files and not args.dirs:

        parser.error(
            "Mindestens --files oder --dirs angeben."
        )

    if args.workers < 1:

        parser.error(
            "--workers muss mindestens 1 sein."
        )

    try:

        password = getpass.getpass(
            "Passwort eingeben: "
        )

    except KeyboardInterrupt:

        print(
            "\nAbbruch durch Benutzer."
        )

        sys.exit(1)

    if not password:

        print(
            "Leeres Passwort nicht erlaubt."
        )

        sys.exit(1)

    all_files = collect_files(
        args.files
        + args.dirs
    )

    if not all_files:

        print(
            "Keine verarbeitbaren Dateien gefunden."
        )

        sys.exit(1)

    print(
        f"{len(all_files)} Datei(en) gefunden."
    )

    successful = 0
    failed = 0

    with ThreadPoolExecutor(
        max_workers=args.workers
    ) as executor:

        futures = {
            executor.submit(
                _cli_process_single,
                f,
                password,
                not args.keep_original,
                args.encrypt_filename,
            ): f
            for f in all_files
        }

        for future in as_completed(
            futures
        ):

            result = future.result()

            print(
                result
            )

            if result.startswith(
                "OK:"
            ):

                successful += 1

            else:

                failed += 1

    print()

    print(
        f"Fertig: {successful} erfolgreich, "
        f"{failed} Fehler."
    )

    sys.exit(
        1
        if failed
        else 0
    )


# ============================================================
# Tray Icon
# ============================================================

def create_shield_icon(
    size=32,
):

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

    d = ImageDraw.Draw(
        img
    )

    def i(v):

        return int(
            round(v)
        )

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
        width=1,
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
# GUI
# ============================================================

class CryptoGUI:

    DROP_IDLE_BG = None
    DROP_HOVER_BG = "#D6F5D6"

    def __init__(
        self,
        root,
        initial_paths=None,
    ):

        self.root = root

        self.root.title(
            "AES Crypto"
        )

        self.root.geometry(
            "560x510"
        )

        self.root.minsize(
            520,
            470,
        )

        self.queue = queue.Queue()

        self.worker_running = False

        # Passwort nur für die Laufzeit der GUI-Instanz
        # intern im Arbeitsspeicher halten.
        self._session_password = None

        self.selected_paths = []

        self.tray = None

        self.closing = False

        self.dnd_active = False

        self.app_icon = create_shield_icon(
            32
        )

        buf = io.BytesIO()

        self.app_icon.save(
            buf,
            format="PNG",
        )

        self.tk_icon = tk.PhotoImage(
            data=buf.getvalue()
        )

        self.root.iconphoto(
            True,
            self.tk_icon,
        )

        self._build_ui()

        self._setup_dnd()

        self._setup_tray()

        self._center_window()

        self.root.after(
            100,
            self._process_queue,
        )

        self.root.bind_all(
            "<Control-q>",
            lambda e: self._request_exit(),
        )

        self.root.bind_all(
            "<Control-Q>",
            lambda e: self._request_exit(),
        )

        self._update_listbox()

        if initial_paths:

            self._add_paths(
                initial_paths
            )

    # --------------------------------------------------------
    # UI
    # --------------------------------------------------------

    def _build_ui(self):

        main = ttk.Frame(
            self.root,
            padding="10",
        )

        main.pack(
            fill=tk.BOTH,
            expand=True,
        )

        sel_frame = ttk.Frame(
            main
        )

        sel_frame.pack(
            fill=tk.X,
            pady=(0, 4),
        )

        ttk.Button(
            sel_frame,
            text="Datei(en)",
            command=self._add_files,
        ).pack(
            side=tk.LEFT,
            padx=2,
        )

        ttk.Button(
            sel_frame,
            text="Ordner",
            command=self._add_folder,
        ).pack(
            side=tk.LEFT,
            padx=2,
        )

        ttk.Button(
            sel_frame,
            text="Leeren",
            command=self._clear_selection,
        ).pack(
            side=tk.LEFT,
            padx=2,
        )

        self.info_var = tk.StringVar(
            value="Keine Auswahl"
        )

        ttk.Label(
            main,
            textvariable=self.info_var,
            font=(
                "TkDefaultFont",
                8,
                "bold",
            ),
        ).pack(
            anchor=tk.W,
            pady=(0, 2),
        )

        self.drop_hint_var = tk.StringVar(
            value=(
                "Dateien & Ordner hierher ziehen "
                "(Drag & Drop)"
            )
        )

        self.drop_frame = ttk.LabelFrame(
            main,
            padding=4,
            text="Auswahl",
        )

        self.drop_frame.pack(
            fill=tk.BOTH,
            expand=True,
            pady=(0, 6),
        )

        ttk.Label(
            self.drop_frame,
            textvariable=self.drop_hint_var,
            font=(
                "TkDefaultFont",
                8,
            ),
        ).pack(
            anchor=tk.W,
            padx=2,
            pady=(0, 2),
        )

        self.listbox = scrolledtext.ScrolledText(
            self.drop_frame,
            height=7,
            state=tk.DISABLED,
            font=(
                "TkFixedFont",
                8,
            ),
            relief=tk.FLAT,
            borderwidth=0,
        )

        self.listbox.pack(
            fill=tk.BOTH,
            expand=True,
        )

        self.DROP_IDLE_BG = (
            self.listbox.cget(
                "background"
            )
        )

        pw_frame = ttk.Frame(
            main
        )

        pw_frame.pack(
            fill=tk.X,
            pady=(0, 4),
        )

        ttk.Label(
            pw_frame,
            text="Passwort:",
        ).pack(
            side=tk.LEFT
        )

        self.pass_var = tk.StringVar()

        self.pass_entry = ttk.Entry(
            pw_frame,
            textvariable=self.pass_var,
            show="*",
            width=36,
        )

        self.pass_entry.pack(
            side=tk.LEFT,
            padx=4,
        )

        self.show_pw = tk.BooleanVar()

        ttk.Checkbutton(
            pw_frame,
            text="Zeigen",
            variable=self.show_pw,
            command=self._toggle_pw,
        ).pack(
            side=tk.LEFT
        )

        # ----------------------------------------------------
        # Original löschen
        # ----------------------------------------------------

        self.delete_original = tk.BooleanVar(
            value=True
        )

        ttk.Checkbutton(
            main,
            text=(
                "Original nach erfolgreicher Verarbeitung löschen"
            ),
            variable=self.delete_original,
        ).pack(
            anchor=tk.W,
            pady=(0, 3),
        )

        # ----------------------------------------------------
        # Dateiname verschlüsseln / verschleiern
        # ----------------------------------------------------

        self.encrypt_filename = tk.BooleanVar(
            value=False
        )

        ttk.Checkbutton(
            main,
            text=(
                "Dateiname verschlüsseln "
                "(zufälligen Dateinamen für .enc verwenden)"
            ),
            variable=self.encrypt_filename,
        ).pack(
            anchor=tk.W,
            pady=(0, 6),
        )

        self.action_btn = ttk.Button(
            main,
            text="Ver-/Entschlüsseln",
            command=self._run_batch,
        )

        self.action_btn.pack(
            pady=(0, 4),
        )

        self.progress = ttk.Progressbar(
            main,
            orient=tk.HORIZONTAL,
            mode="determinate",
        )

        self.progress.pack(
            fill=tk.X,
            pady=(0, 3),
        )

        self.status_var = tk.StringVar(
            value="Bereit"
        )

        ttk.Label(
            main,
            textvariable=self.status_var,
            foreground="gray",
            font=(
                "TkDefaultFont",
                8,
            ),
        ).pack(
            anchor=tk.W
        )

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self._on_close,
        )

    # --------------------------------------------------------
    # Drag & Drop
    # --------------------------------------------------------

    def _setup_dnd(self):

        if (
            not DND_AVAILABLE
            or not hasattr(
                self.root,
                "drop_target_register",
            )
        ):

            self.drop_hint_var.set(
                "Drag & Drop inaktiv"
            )

            return

        targets = (
            self.listbox,
            self.drop_frame,
            self.root,
        )

        registered = False

        for w in targets:

            try:

                w.drop_target_register(
                    DND_FILES
                )

                w.dnd_bind(
                    "<<DropEnter>>",
                    self._on_drag_enter,
                )

                w.dnd_bind(
                    "<<DropLeave>>",
                    self._on_drag_leave,
                )

                w.dnd_bind(
                    "<<Drop>>",
                    self._on_drop,
                )

                registered = True

            except Exception:
                continue

        self.dnd_active = registered

        if not registered:

            self.drop_hint_var.set(
                "Drag & Drop konnte nicht initialisiert werden"
            )

    def _on_drag_enter(
        self,
        event,
    ):

        if self.worker_running:

            self.drop_hint_var.set(
                "Verarbeitung läuft"
            )

        else:

            self.drop_hint_var.set(
                "Loslassen zum Hinzufügen ..."
            )

            try:

                self.listbox.config(
                    background=self.DROP_HOVER_BG
                )

            except Exception:
                pass

        return getattr(
            event,
            "action",
            None,
        )

    def _on_drag_leave(
        self,
        event=None,
    ):

        self.drop_hint_var.set(
            "Dateien & Ordner hierher ziehen "
            "(Drag & Drop)"
        )

        try:

            self.listbox.config(
                background=self.DROP_IDLE_BG
            )

        except Exception:
            pass

        return getattr(
            event,
            "action",
            None,
        )

    def _on_drop(
        self,
        event,
    ):

        self._on_drag_leave()

        if self.worker_running:

            self.status_var.set(
                "Verarbeitung läuft."
            )

            return getattr(
                event,
                "action",
                None,
            )

        paths = self._parse_drop_data(
            getattr(
                event,
                "data",
                "",
            )
        )

        if not paths:

            self.status_var.set(
                "Keine gültigen Pfade."
            )

            return getattr(
                event,
                "action",
                None,
            )

        added, skipped = self._add_paths(
            paths
        )

        if added and skipped:

            self.status_var.set(
                f"{added} hinzugefügt, "
                f"{skipped} übersprungen"
            )

        elif added:

            self.status_var.set(
                f"{added} Pfad(e) hinzugefügt"
            )

        else:

            self.status_var.set(
                "Nichts hinzugefügt"
            )

        return getattr(
            event,
            "action",
            None,
        )

    # --------------------------------------------------------
    # Pfade
    # --------------------------------------------------------

    def _parse_drop_data(
        self,
        data,
    ):

        if isinstance(
            data,
            (list, tuple),
        ):

            candidates = [
                [
                    str(p)
                    for p in data
                ]
            ]

        else:

            raw = str(
                data or ""
            ).strip()

            if not raw:

                return []

            candidates = [
                split_tcl_droplist(
                    raw
                )
            ]

            try:

                candidates.append(
                    list(
                        self.root.tk.splitlist(
                            raw
                        )
                    )
                )

            except Exception:
                pass

            candidates.append(
                [
                    raw
                ]
            )

        best = []
        best_hits = -1

        for cand in candidates:

            norm = [
                normalize_dropped_path(
                    c
                )
                for c in cand
            ]

            norm = [
                n
                for n in norm
                if n
            ]

            hits = sum(
                1
                for n in norm
                if os.path.exists(
                    n
                )
            )

            if norm and hits == len(norm):

                return norm

            if hits > best_hits:

                best = norm
                best_hits = hits

        return best

    def _add_paths(
        self,
        paths,
    ):

        added = 0
        skipped = 0

        for raw in paths:

            p = normalize_dropped_path(
                raw
            )

            if not p:

                skipped += 1
                continue

            p = os.path.abspath(
                p
            )

            if (
                not os.path.exists(p)
                or p in self.selected_paths
            ):

                skipped += 1
                continue

            self.selected_paths.append(
                p
            )

            added += 1

        if added:

            self._update_listbox()

        return (
            added,
            skipped,
        )

    # --------------------------------------------------------
    # Tray
    # --------------------------------------------------------

    def _setup_tray(
        self,
    ):

        if not GUI_AVAILABLE:
            return

        if sys.platform.startswith(
            "linux"
        ):
            return

        try:

            menu = pystray.Menu(
                item(
                    "Zeigen",
                    self._show_from_tray,
                    default=True,
                ),
                item(
                    "Beenden",
                    self._request_exit,
                ),
            )

            self.tray = pystray.Icon(
                "AES Crypto",
                self.app_icon,
                "AES Crypto",
                menu=menu,
            )

            self.tray.run_detached()

        except Exception as e:

            self.tray = None

            try:

                self.status_var.set(
                    f"Tray nicht verfügbar: {e}"
                )

            except Exception:
                pass

    def _on_close(
        self,
    ):

        if self.closing:
            return

        # Fenster schließen = in den Tray.
        if self.tray is not None:

            try:

                self.root.withdraw()

                return

            except tk.TclError:
                pass

        self._request_exit()

    def _request_exit(
        self,
        icon=None,
        menu_item=None,
    ):

        if self.closing:
            return

        self.closing = True

        try:

            self.root.after(
                0,
                self._shutdown,
            )

        except (
            tk.TclError,
            RuntimeError,
        ):

            self._stop_tray()

    def _shutdown(
        self,
    ):

        self.closing = True

        self._session_password = None

        self.pass_var.set(
            ""
        )

        self._stop_tray()

        try:

            self.root.quit()

        except tk.TclError:
            pass

        try:

            self.root.destroy()

        except tk.TclError:
            pass

    def _stop_tray(
        self,
    ):

        tray = self.tray

        if tray is None:
            return

        self.tray = None

        try:

            tray.stop()

        except Exception:
            pass

    def _show_from_tray(
        self,
        icon=None,
        menu_item=None,
    ):

        if self.closing:
            return

        def show_window():

            if self.closing:
                return

            try:

                self.root.deiconify()
                self.root.lift()
                self.root.focus_force()

                if sys.platform == "win32":

                    try:

                        self.root.attributes(
                            "-topmost",
                            True,
                        )

                        self.root.after(
                            150,
                            lambda: (
                                self.root.attributes(
                                    "-topmost",
                                    False,
                                )
                                if not self.closing
                                else None
                            ),
                        )

                    except tk.TclError:
                        pass

            except tk.TclError:
                pass

        try:

            self.root.after(
                0,
                show_window,
            )

        except (
            tk.TclError,
            RuntimeError,
        ):

            pass

    # --------------------------------------------------------
    # UI Hilfsfunktionen
    # --------------------------------------------------------

    def _center_window(
        self,
    ):

        self.root.update_idletasks()

        w = self.root.winfo_width()
        h = self.root.winfo_height()

        x = (
            self.root.winfo_screenwidth()
            // 2
            - w // 2
        )

        y = (
            self.root.winfo_screenheight()
            // 2
            - h // 2
        )

        self.root.geometry(
            f"+{x}+{y}"
        )

    def _toggle_pw(
        self,
    ):

        self.pass_entry.config(
            show=(
                ""
                if self.show_pw.get()
                else "*"
            )
        )

    def _update_listbox(
        self,
    ):

        self.listbox.config(
            state=tk.NORMAL
        )

        self.listbox.delete(
            "1.0",
            tk.END,
        )

        if not self.selected_paths:

            hint = (
                "(leer)"
                if not self.dnd_active
                else "(leer) – Dateien/Ordner hierher ziehen"
            )

            self.listbox.insert(
                tk.END,
                hint,
            )

        else:

            for p in self.selected_paths:

                prefix = (
                    "Ordner "
                    if os.path.isdir(p)
                    else "Datei "
                )

                self.listbox.insert(
                    tk.END,
                    prefix
                    + p
                    + "\n",
                )

        self.listbox.config(
            state=tk.DISABLED
        )

        self.listbox.see(
            tk.END
        )

        total_files = 0
        total_size = 0

        for p in self.selected_paths:

            if os.path.isfile(
                p
            ):

                total_files += 1

                try:

                    total_size += os.path.getsize(
                        p
                    )

                except OSError:
                    pass

            elif os.path.isdir(
                p
            ):

                for root, dirs, files in os.walk(
                    p,
                    followlinks=False,
                ):

                    dirs[:] = [
                        d
                        for d in dirs
                        if not os.path.islink(
                            os.path.join(
                                root,
                                d,
                            )
                        )
                    ]

                    for f in files:

                        fp = os.path.join(
                            root,
                            f,
                        )

                        if os.path.islink(
                            fp
                        ):
                            continue

                        total_files += 1

                        try:

                            total_size += (
                                os.path.getsize(
                                    fp
                                )
                            )

                        except OSError:
                            pass

        self.info_var.set(
            f"{len(self.selected_paths)} "
            f"Eintrag/Einträge | "
            f"{total_files} Datei(en) | "
            f"{self._format_size(total_size)}"
        )

    def _format_size(
        self,
        b,
    ):

        for u in (
            "B",
            "KB",
            "MB",
            "GB",
            "TB",
        ):

            if b < 1024:

                return (
                    f"{b:.1f} {u}"
                )

            b /= 1024

        return (
            f"{b:.1f} PB"
        )

    def _add_files(
        self,
    ):

        paths = filedialog.askopenfilenames(
            title="Datei(en) auswählen",
            filetypes=[
                (
                    "Alle Dateien",
                    "*",
                ),
                (
                    "Verschlüsselte Dateien",
                    "*.enc",
                ),
            ],
        )

        if paths:

            self._add_paths(
                paths
            )

    def _add_folder(
        self,
    ):

        path = filedialog.askdirectory(
            title="Ordner auswählen"
        )

        if path:

            self._add_paths(
                [
                    path
                ]
            )

    def _clear_selection(
        self,
    ):

        self.selected_paths.clear()

        self._update_listbox()

        self.status_var.set(
            "Auswahl geleert"
        )

    # --------------------------------------------------------
    # Batch
    # --------------------------------------------------------

    def _run_batch(
        self,
    ):

        if self.worker_running:
            return

        if not self.selected_paths:

            messagebox.showwarning(
                "Hinweis",
                "Bitte Dateien/Ordner auswählen "
                "oder per Drag & Drop ablegen.",
            )

            return

        entered_password = (
            self.pass_var.get()
        )

        if entered_password:

            self._session_password = (
                entered_password
            )

        password = (
            self._session_password
        )

        if not password:

            messagebox.showwarning(
                "Hinweis",
                "Passwort darf nicht leer sein.",
            )

            return

        self.pass_var.set(
            ""
        )

        self.worker_running = True

        self.action_btn.config(
            state=tk.DISABLED
        )

        self.progress[
            "value"
        ] = 0

        self.status_var.set(
            "Sammle Dateien..."
        )

        selected_snapshot = list(
            self.selected_paths
        )

        delete_original = (
            self.delete_original.get()
        )

        encrypt_filename = (
            self.encrypt_filename.get()
        )

        def worker():

            try:

                files = collect_files(
                    selected_snapshot
                )

                if not files:

                    self.queue.put(
                        (
                            "error",
                            "Keine verarbeitbaren Dateien gefunden.",
                        )
                    )

                    return

                valid_files = []
                total_bytes = 0

                for f in files:

                    try:

                        sz = os.path.getsize(
                            f
                        )

                        total_bytes += sz

                        valid_files.append(
                            (
                                f,
                                sz,
                            )
                        )

                    except OSError:
                        continue

                if not valid_files:

                    self.queue.put(
                        (
                            "error",
                            "Keine lesbaren Dateien gefunden.",
                        )
                    )

                    return

                processed_bytes = 0
                errors = []
                success_count = 0

                for (
                    fpath,
                    fsize,
                ) in valid_files:

                    if self.closing:
                        return

                    mode = (
                        "decrypt"
                        if fpath.lower().endswith(
                            ".enc"
                        )
                        else "encrypt"
                    )

                    self.queue.put(
                        (
                            "status",
                            f"{os.path.basename(fpath)} "
                            f"({mode})",
                        )
                    )

                    current_out = None
                    output_existed_before = False

                    try:

                        if mode == "encrypt":

                            out_path = (
                                make_encrypt_output_path(
                                    fpath,
                                    encrypt_filename,
                                )
                            )

                        else:

                            out_path = (
                                make_decrypt_output_path(
                                    fpath,
                                    password,
                                )
                            )

                        output_existed_before = (
                            os.path.lexists(
                                out_path
                            )
                        )

                        current_out = out_path

                        def file_progress(
                            cur,
                            tot,
                            base=processed_bytes,
                        ):

                            if total_bytes <= 0:

                                pct = 0

                            else:

                                pct = int(
                                    (
                                        base
                                        + cur
                                    )
                                    / total_bytes
                                    * 100
                                )

                            self.queue.put(
                                (
                                    "progress",
                                    min(
                                        100,
                                        max(
                                            0,
                                            pct,
                                        ),
                                    ),
                                )
                            )

                        if mode == "encrypt":

                            encrypt_file(
                                fpath,
                                out_path,
                                password,
                                file_progress,
                            )

                        else:

                            decrypt_file(
                                fpath,
                                out_path,
                                password,
                                file_progress,
                            )

                        # ------------------------------------------------
                        # Nur nach vollständig erfolgreicher
                        # Kryptografie löschen.
                        # ------------------------------------------------

                        if delete_original:

                            try:

                                delete_original_file(
                                    fpath
                                )

                            except Exception as delete_error:

                                errors.append(
                                    f"{fpath}: Verarbeitung "
                                    f"erfolgreich, Original konnte "
                                    f"nicht entfernt werden: "
                                    f"{delete_error}"
                                )

                        processed_bytes += (
                            fsize
                        )

                        success_count += 1

                        self.queue.put(
                            (
                                "progress",
                                min(
                                    100,
                                    int(
                                        processed_bytes
                                        / total_bytes
                                        * 100
                                    ),
                                ),
                            )
                        )

                    except Exception as e:

                        errors.append(
                            f"{fpath}: {e}"
                        )

                        # ------------------------------------------------
                        # Sicherheitsregel:
                        #
                        # Bei Fehler bleibt das Original erhalten.
                        #
                        # Nur ein Ziel, das während dieses
                        # Verarbeitungsschrittes entstanden ist,
                        # darf entfernt werden.
                        # ------------------------------------------------

                        if (
                            current_out
                            and not output_existed_before
                            and os.path.exists(
                                current_out
                            )
                        ):

                            try:

                                os.remove(
                                    current_out
                                )

                            except OSError:
                                pass

                msg = (
                    f"{success_count}/"
                    f"{len(valid_files)} "
                    f"erfolgreich verarbeitet."
                )

                if errors:

                    msg += (
                        "\n\n"
                        f"{len(errors)} "
                        f"Hinweis(e)/Fehler:\n"
                        + "\n".join(
                            errors[:4]
                        )
                    )

                    if len(errors) > 4:

                        msg += (
                            "\n... +"
                            f"{len(errors) - 4}"
                            " weitere."
                        )

                    self.queue.put(
                        (
                            "warning",
                            msg,
                        )
                    )

                else:

                    self.queue.put(
                        (
                            "success",
                            msg,
                        )
                    )

            except Exception as e:

                self.queue.put(
                    (
                        "error",
                        f"Unerwarteter Fehler: {e}",
                    )
                )

        threading.Thread(
            target=worker,
            daemon=True,
        ).start()

    # --------------------------------------------------------
    # Queue
    # --------------------------------------------------------

    def _process_queue(
        self,
    ):

        if self.closing:
            return

        try:

            while True:

                msg_type, msg = (
                    self.queue.get_nowait()
                )

                if msg_type == "progress":

                    self.progress[
                        "value"
                    ] = msg

                elif msg_type == "status":

                    self.status_var.set(
                        msg
                    )

                elif msg_type == "success":

                    self.status_var.set(
                        "Fertig"
                    )

                    messagebox.showinfo(
                        "Erfolg",
                        msg,
                    )

                    self._reset_ui()

                elif msg_type == "warning":

                    self.status_var.set(
                        "Fertig mit Hinweisen"
                    )

                    messagebox.showwarning(
                        "Hinweis",
                        msg,
                    )

                    self._reset_ui()

                elif msg_type == "error":

                    self.status_var.set(
                        "Fehler"
                    )

                    messagebox.showerror(
                        "Fehler",
                        msg,
                    )

                    self._reset_ui()

        except queue.Empty:
            pass

        try:

            self.root.after(
                100,
                self._process_queue,
            )

        except tk.TclError:
            pass

    def _reset_ui(
        self,
    ):

        if self.closing:
            return

        self.worker_running = False

        self.action_btn.config(
            state=tk.NORMAL
        )

        self.progress[
            "value"
        ] = 0

        self.status_var.set(
            "Bereit"
        )

        self._update_listbox()


# ============================================================
# Drop Path Parsing
# ============================================================

def normalize_dropped_path(
    raw,
):

    if raw is None:
        return ""

    p = str(
        raw
    ).strip().strip(
        "\r\n"
    )

    if not p:
        return ""

    if (
        len(p) >= 2
        and p[0] == "{"
        and p[-1] == "}"
    ):

        p = p[1:-1]

    if (
        len(p) >= 2
        and p[0] == '"'
        and p[-1] == '"'
    ):

        p = p[1:-1]

    if p.lower().startswith(
        "file://"
    ):

        parsed = urlparse(
            p
        )

        path = unquote(
            parsed.path
        )

        if (
            parsed.netloc
            and parsed.netloc.lower()
            not in (
                "localhost",
                "",
            )
        ):

            path = (
                f"//{parsed.netloc}"
                f"{path}"
            )

        if (
            os.name == "nt"
            and re.match(
                r"^/[A-Za-z]:",
                path,
            )
        ):

            path = path[1:]

        p = path

    return (
        os.path.normpath(
            p
        )
        if p
        else ""
    )


def split_tcl_droplist(
    data,
):

    items = []
    buf = []
    in_brace = False

    for ch in data:

        if (
            ch == "{"
            and not in_brace
            and not buf
        ):

            in_brace = True

        elif (
            ch == "}"
            and in_brace
        ):

            in_brace = False

            items.append(
                "".join(
                    buf
                )
            )

            buf = []

        elif (
            ch in " \t\r\n"
            and not in_brace
        ):

            if buf:

                items.append(
                    "".join(
                        buf
                    )
                )

                buf = []

        else:

            buf.append(
                ch
            )

    if buf:

        items.append(
            "".join(
                buf
            )
        )

    return [
        i
        for i in items
        if i
    ]


# ============================================================
# Root
# ============================================================

def create_root():

    global DND_AVAILABLE

    if DND_AVAILABLE:

        try:

            return TkinterDnD.Tk()

        except Exception as e:

            print(
                f"Drag&Drop-Backend nicht ladbar: {e}"
            )

            DND_AVAILABLE = False

    return tk.Tk()


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":

    multiprocessing.freeze_support()

    cli_args = sys.argv[1:]

    preload_paths = []

    # --------------------------------------------------------
    # Dateien direkt angeben:
    #
    # python aescrypto.py datei1 datei2
    #
    # -> GUI mit vorausgewählten Dateien
    #
    # CLI mit Optionen:
    #
    # python aescrypto.py -f datei
    # --------------------------------------------------------

    if cli_args:

        if all(
            (
                not a.startswith("-")
                and os.path.exists(a)
            )
            for a in cli_args
        ):

            preload_paths = [
                os.path.abspath(
                    a
                )
                for a in cli_args
            ]

        else:

            run_cli()

            sys.exit(0)

    if not GUI_AVAILABLE:

        print(
            "GUI-Abhängigkeiten fehlen."
        )

        print(
            "Installiere:"
        )

        print(
            "pip install pystray Pillow "
            "cryptography tkinterdnd2"
        )

        sys.exit(1)

    # --------------------------------------------------------
    # Windows DPI
    # --------------------------------------------------------

    if sys.platform == "win32":

        try:

            from ctypes import windll

            windll.shcore.SetProcessDpiAwareness(
                1
            )

        except Exception:
            pass

    # --------------------------------------------------------
    # Linux: nur eine GUI-Instanz gleichzeitig
    # --------------------------------------------------------

    _instance_lock_file = None

    if sys.platform.startswith(
        "linux"
    ):

        _runtime_dir = os.environ.get(
            "XDG_RUNTIME_DIR"
        )

        if (
            _runtime_dir
            and os.path.isdir(
                _runtime_dir
            )
        ):

            lock_dir = _runtime_dir

        else:

            lock_dir = tempfile.gettempdir()

        lock_path = os.path.join(
            lock_dir,
            "aescrypto-gui.lock",
        )

        try:

            _instance_lock_file = open(
                lock_path,
                "w",
            )

            fcntl.flock(
                _instance_lock_file.fileno(),
                fcntl.LOCK_EX
                | fcntl.LOCK_NB,
            )

        except (
            OSError,
            IOError,
        ):

            try:

                if (
                    _instance_lock_file
                    is not None
                ):

                    _instance_lock_file.close()

            except Exception:
                pass

            print(
                "AES Crypto läuft bereits."
            )

            sys.exit(0)

    root = create_root()

    app = CryptoGUI(
        root,
        initial_paths=preload_paths,
    )

    root.mainloop()
