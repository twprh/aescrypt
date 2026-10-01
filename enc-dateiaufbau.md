Dateiaufbaus als tabellarische Übersicht:

---

### 1. AESCRYPT3-Format (Aktueller Standard)

Das moderne Format teilt die Datei in einen festen Header und sequenzielle Chunks (Blöcke) auf.

| Komponente | Größe | Datentyp / Format | Beschreibung |
| --- | --- | --- | --- |
| **`MAGIC_V3`** | 9 Bytes | `bytes` (`b"AESCRYPT3"`) | Identifiziert das Dateiformat |
| **`VERSION`** | 1 Byte | `int` (`1`) | Versionsnummer des Formats |
| **`SALT`** | 16 Bytes | `bytes` | Zufallswert für die Schlüsselableitung (Scrypt) |
| **`BASE_NONCE`** | 12 Bytes | `bytes` | Basis-Nonce für AES-GCM |
| **`CHUNK_SIZE`** | 4 Bytes | Big-Endian Unsigned Int (`>I`) | Größe der einzelnen Chunks (Standard: 1 MB) |
| **`FILE_SIZE`** | 8 Bytes | Big-Endian Unsigned Long (`>Q`) | Exakte Dateigröße der Originaldatei |
| **`CHUNK_COUNT`** | 8 Bytes | Big-Endian Unsigned Long (`>Q`) | Gesamtzahl der erwarteten Daten-Chunks |

---

#### Struktur der Chunks ab dem Header:

Jeder Chunk (inklusive **Chunk 0** für Metadaten) ist nach diesem Schema aufgebaut:

| Teil | Größe | Beschreibung |
| --- | --- | --- |
| **Chunk Index** | 8 Bytes (`>Q`) | Laufende Nummer des Chunks (0 = Metadaten, 1+ = Dateidaten) |
| **Plaintext Size** | 4 Bytes (`>I`) | Größe der unverschlüsselten Daten im Chunk |
| **Ciphertext Size** | 4 Bytes (`>I`) | Größe der verschlüsselten Daten (entspricht meist der Plaintext Size) |
| **Ciphertext** | Variabel | Die eigentlichen verschlüsselten Daten |
| **Auth Tag** | 16 Bytes | AES-GCM Authentifizierungs-Tag zur Integritätsprüfung |

> **Besonderheit Chunk 0:** Der entschlüsselte Inhalt von Chunk 0 enthält den Original-Dateinamen:
> * *Länge des Namens* (4 Bytes) + *Name als UTF-8-String* (variabel).
> 
> 

---

### 2. AESCRYPT2-Format (Legacy / Abwärtskompatibilität)

Das ältere Format speichert alle Daten in einem Block mit einem Auth-Tag am Ende.

| Komponente | Größe | Beschreibung |
| --- | --- | --- |
| **`MAGIC`** | 9 Bytes | Identifiziert das Format (`b"AESCRYPT2"`) |
| **`VERSION`** | 1 Byte | Versionsnummer (`3`) |
| **`SALT`** | 16 Bytes | Zufallswert für Scrypt |
| **`NONCE`** | 12 Bytes | Nonce für AES-GCM |
| **`Ciphertext`** | Variabel | Verschlüsselter Inhalt (enthält am Anfang den Dateinamen + Längenpräfix, danach die eigentlichen Datei-Daten) |
| **`Auth Tag`** | 16 Bytes | Befindet sich am **Ende** der Datei zur Integritätsprüfung |
