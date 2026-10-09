<img width="926" height="682" alt="grafik" src="https://github.com/user-attachments/assets/49eaab4a-d9a6-48ed-885d-3a1bd295174c" />

### Dateiaufbau AES Crypto Tool v1.4.0

Alle Größen in Bytes. > = Big-Endian. Der Magic-String ist die Primärdiskriminante: decryptfile() liest die ersten 9 Bytes und verzweigt danach.

Überblick: alle drei Formate

| Format | Magic | Header-Version | Krypto |
|---|---|---|---|
| AESCRYPT2 (legacy) | AESCRYPT2 (9 B) | 3 | AES-256-GCM, ein Tag am Dateiende |
| AESCRYPT3 v1 (alt) | AESCRYPT3 (9 B) | 1 | AES-256-GCM, chunkweise, feste Scrypt-Parameter |
| AESCRYPT3 v2 (neu) | AESCRYPT3 (9 B) | 2 | AES-256-GCM, chunkweise, Scrypt-Parameter im Header |

AESCRYPT3 v2 — vollständiger Aufbau

| # | Feld | Größe | Typ | Beschreibung |
|---|---|---|---|---|
| 1 | Magic | 9 | bytes | b"AESCRYPT3" |
| 2 | Version | 1 | u8 | 2 — FORMATVERSIONV3KDF |
| 3 | Salt | 16 | bytes | secrets.tokenbytes(16), pro Datei zufällig |
| 4 | Base-Nonce | 12 | bytes | secrets.tokenbytes(12), pro Datei zufällig |
| 5 | Chunk-Größe | 4 | u32 >I | CHUNKSIZE = 1 048 576 |
| 6 | Dateigröße | 8 | u64 >Q | Klartext-Nutzdatengröße (ohne Metadaten) |
| 7 | Chunk-Anzahl | 8 | u64 >Q | Anzahl der Nutzdaten-Chunks (ohne Metadaten-Chunk) |
| 8 | Scrypt N | 4 | u32 >I | SCRYPTN = 65536 (2¹⁶) |
| 9 | Scrypt r | 4 | u32 >I | SCRYPTR = 8 |
| 10 | Scrypt p | 4 | u32 >I | SCRYPTP = 1 |
| | Header gesamt | 70 | | Bytes 1–10 bilden zusammen den AAD für jeden Chunk |

Chunk-Records (ab Byte 70)

| # | Feld | Größe | Typ | Beschreibung |
|---|---|---|---|---|
| 1 | Chunk-Index | 8 | u64 >Q | 0 = Metadaten, 1..N = Nutzdaten in Reihenfolge |
| 2 | Klartext-Länge | 4 | u32 >I | Länge des Chunks vor Verschlüsselung |
| 3 | Ciphertext-Länge | 4 | u32 >I | muss == Klartext-Länge sein; sonst Abbruch vor read() |
| 4 | Ciphertext | variabel | bytes | Länge = Feld 3 |
| 5 | GCM-Tag | 16 | bytes | Authentifizierung des Chunks |
| | Record-Header gesamt | 16 | | Felder 1–3; vor fin.read() validiert |

Metadaten-Chunk (Index 0, immer der erste)

| # | Feld | Größe | Typ | Beschreibung |
|---|---|---|---|---|
| 1 | Namenslänge | 4 | u32 >I | Länge des UTF-8-Namens |
| 2 | Dateiname | variabel | UTF-8 | Originalname, 1 ≤ len ≤ 1024 |
| | Klartext gesamt | = Namenslänge + 4 | | Max 1028 B (== NAMELENSIZE + MAXNAMELEN) |

Nutzdaten-Chunks (Index 1…N)

| Eigenschaft | Wert |
|---|---|
| Chunk-Größe | CHUNKSIZE = 1 MiB, außer der letzte |
| Letzter Chunk | filesize − (N−1)·CHUNKSIZE, ggf. kleiner |
| Bei filesize == 0 | keine Nutzdaten-Chunks, chunkcount == 0 |
| Chunk-Anzahl (Nutzdaten) | ceil(filesize / CHUNKSIZE) |

AAD-Konstruktion pro Chunk

| Bestandteil | Größe | Quelle |
|---|---|---|
| Header (Felder 1–10) | 70 | byteidentisch wie geschrieben |
| Chunk-Index | 8 | >Q |
| Klartext-Länge | 4 | >I |
| AAD gesamt | 82 | alles in authenticateadditionaldata() |

Der AAD bindet Header und KDF-Parameter und Index und Länge. Eine Manipulation an Feldern 5–10 oder eine Chunk-Vertauschung bricht den GCM-Tag.

Nonce-Ableitung pro Chunk

| Bestandteil | Größe | Quelle |
|---|---|---|
| Base-Nonce-Präfix | 8 | erste 8 B aus Header-Feld 4 |
| Chunk-Index | 4 | >I, chunkindex.tobytes(4, "big") |
| Nonce gesamt | 12 | basenonce[:8] + index |

AESCRYPT3 v1 (alt) — Unterschied zu v2

| Aspekt | v1 | v2 |
|---|---|---|
| Header-Version | 1 | 2 |
| Header-Größe | 58 B | 70 B |
| Scrypt N/r/p im Header | nein | ja (Felder 8–10) |
| KDF-Parameter beim Lesen | feste SCRYPTN/R/P-Konstanten | aus Header, gegen MAX* validiert |
| AAD-Größe | 58 (Header) + 12 = 70 | 70 (Header) + 12 = 82 |
| Rest (Chunks, Metadaten) | identisch | identisch |

Der Decoder liest die 12 KDF-Bytes nur bei Version 2 — bei v1 wird der Header nach Feld 7 beendet und bleibt bei 58 Bytes. Das ist der Kompatibilitätspunkt.

AESCRYPT2 (Legacy) — klassischer Aufbau

| # | Feld | Größe | Typ | Beschreibung |
|---|---|---|---|---|
| 1 | Magic | 9 | bytes | b"AESCRYPT2" |
| 2 | Version | 1 | u8 | 3 — FORMATVERSION |
| 3 | Salt | 16 | bytes | zufällig |
| 4 | Nonce | 12 | bytes | zufällig, einmalig für die ganze Datei |
| | Header gesamt | 38 | | Felder 1–4 bilden den AAD |
| 5 | Ciphertext | variabel | bytes | Gesamte Nutzdaten in einem GCM-Stream |
| 6 | GCM-Tag | 16 | bytes | am Dateiende; Position = fsize − 16 |

Kein Chunking: ciphertextsize = fsize − 38 − 16. Der Klartext der Datei beginnt mit dem Metadaten-Präfix [u32 Namenslänge][UTF-8 Name]; die Namenslänge wird erst nach Begin der GCM-Entschlüsselung ausgewertet, aber der Tag wird über die ganze Datei geprüft.

Textverschlüsselung — Base64-Payload

| # | Feld | Größe (roh) | Typ | Beschreibung |
|---|---|---|---|---|
| 1 | Header | 38 | bytes | identisch zum AESCRYPT2-Header (Felder 1–4 oben) |
| 2 | Ciphertext | variabel | bytes | UTF-8 des Klartexts, verschlüsselt |
| 3 | GCM-Tag | 16 | bytes | am Ende des Roh-Payloads |
| | Roh-Payload | = 38 + len(text) + 16 | | wird als Ganzes Base64-kodiert ausgegeben |
| | Ausgabe | Base64(string) | ASCII | Standardalphabet mit Padding |

Erkennung beim Ver-/Entschlüsseln: Base64-dekodieren → wenn Ergebnis mit AESCRYPT2 beginnt, wird entschlüsselt, sonst verschlüsselt.

Kompatibilitätsmatrix (Format × Operation)

| Format | verschlüsseln (schreiben) | entschlüsseln (lesen) |
|---|---|---|
| AESCRYPT3 v2 | ja (aktueller Pfad) | ja |
| AESCRYPT3 v1 | nein (nie erzeugt) | ja (Legacy-Pfad) |
| AESCRYPT2 | nein (nie erzeugt) | ja (Legacy-Pfad) |
| Text (AESCRYPT2-Format) | ja | ja |

Konstanten-Referenz

| Konstante | Wert |
|---|---|
| CHUNKSIZE | 1 048 576 (1 MiB) |
| SALTSIZE | 16 |
| NONCESIZE | 12 |
| TAGSIZE | 16 |
| NAMELENSIZE | 4 |
| MAXNAMELEN | 1024 |
| V3RECORDHEADERSIZE | 16 |
| MAXV3CHUNKSIZE | 67 108 864 (64 MiB) |
| MAXV3CHUNKCOUNT | 0xFFFFFFFF |
| SCRYPTN | 2¹⁶ |
| SCRYPTR | 8 |
| SCRYPTP | 1 |
| SCRYPTMAXN | 2¹⁷ |
| SCRYPTMAXR | 16 |
| SCRYPTMAXP | 4 |
| SCRYPTMAXMEMORY_BYTES | 134 217 728 (128 MiB) |

Eine Randnotiz zur Verifikation: Die Tabellen sind aus dem Quellcode abgeleitet, den du gepostet hast — die Byte-Zahlen habe ich addiert (z.B. 9+1+16+12+4+8+8+4+4+4 = 70 für den v2-Header), nicht gemessen. Wenn du einen Byte-Level-Beweis willst, liest du den Header einer erzeugten .enc mit hexdump -C und vergleichst die ersten 70 Bytes gegen Tabelle 1 — das bestätigt Magic, Version, Chunk-Größe und die KDF-Parameter in einem Blick.
