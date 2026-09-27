Hier ist eine detaillierte technische Beschreibung des Dateiformats (`.enc`), basierend auf der Struktur, die im bereitgestellten Skript definiert ist.

---

## 🏗️ Aufbau einer `.enc`-Datei

Eine `.enc`-Datei ist modular aufgebaut und gliedert sich in drei Hauptbereiche: den **Header** (Dateikopf), die **verschlüsselten Nutzdaten (Payload)** inklusive Metadaten und das **Authentifizierungs-Tag** am Ende der Datei.

### 1. Header (Dateikopf)

Der Header enthält alle notwendigen Informationen, die für die Entschlüsselung (außer dem Passwort selbst) erforderlich sind. Er hat eine feste Länge und wird im Klartext am Anfang der Datei gespeichert.

* **Magic Bytes (`MAGIC`):**
* *Größe:* 9 Bytes
* *Wert:* `b"AESCRYPT2"`
* *Zweck:* Dient als Erkennungsmerkmal, um das Dateiformat eindeutig zu identifizieren.


* **Format-Version (`FORMAT_VERSION`):**
* *Größe:* 1 Byte
* *Wert:* `3` (Integer)
* *Zweck:* Gibt die Versionsnummer des Dateiformats an, um Abwärtskompatibilität oder Fehler bei Änderungen zu steuern.


* **Salt (`SALT_SIZE`):**
* *Größe:* 16 Bytes (zufällig generiert)
* *Zweck:* Wird zusammen mit dem Benutzerpasswort an die schlüsselableitende Funktion (`Scrypt`) übergeben, um Rainbow-Table-Angriffe abzuwehren.


* **Nonce / Initialization Vector (`NONCE_SIZE`):**
* *Größe:* 12 Bytes (zufällig generiert)
* *Zweck:* Einmaliger Initialisierungsvektor für den AES-GCM-Modus, der sicherstellt, dass identische Klartexte bei gleicher Verschlüsselung zu unterschiedlichem Chiffrat führen.



---

### 2. Verschlüsselte Nutzdaten & Metadaten (Payload)

Der gesamte Inhalt nach dem Header – einschließlich des ursprünglichen Dateinamens – wird mittels **AES-256 im GCM-Modus** (Galois/Counter Mode) verschlüsselt.

Zudem wird der Header als *Additional Authenticated Data (AAD)* in den GCM-Modus eingebunden, sodass Manipulationen am Header sofort auffallen.

* **Länge des Dateinamens (`NAME_LEN_SIZE`):**
* *Größe:* 4 Bytes (Big-Endian-Integer, `>I`)
* *Zweck:* Gibt an, wie lang der nachfolgende Dateiname in Bytes ist (maximal erlaubt: 1024 Bytes).


* **Originaler Dateiname (`orig_name`):**
* *Größe:* Variabel (entspricht der im vorherigen Schritt definierten Länge)
* *Zweck:* Speichert den ursprünglichen Namen der Datei im *verschlüsselten* Zustand, sodass er im Dateisystem von außen nicht im Klartext sichtbar ist.


* **Eigentliche Dateidaten:**
* *Größe:* Variabel (wird in Chunks zu je $1\,\text{MB}$ verarbeitet)
* *Zweck:* Der eigentliche Inhalt der Quelldatei.



---

### 3. Authentifizierungs-Tag (Footer)

Am absoluten Ende der Datei befindet sich das kryptografische Prüfsiegel.

* **GCM Tag (`TAG_SIZE`):**
* *Größe:* 16 Bytes
* *Zweck:* Garantiert die Integrität und Authentizität der gesamten Nachricht (Header, Metadaten und Nutzdaten). Stimmt das Tag beim Entschlüsseln (nach Passworteingabe) nicht überein, wird der Vorgang sofort abgebrochen (Schutz vor Datenmanipulation und falschem Passwort).



---

## 📊 Zusammenfassung der Byte-Struktur

| Bereich | Feld | Größe in Bytes | Beschreibung |
| --- | --- | --- | --- |
| **Header** | Magic Bytes | 9 | `AESCRYPT2` |
|  | Version | 1 | Version `3` |
|  | Salt | 16 | Zufälliger Wert für Scrypt |
|  | Nonce | 12 | Initialisierungsvektor für AES-GCM |
| **Payload** *(Verschlüsselt)* | Name-Länge | 4 | Länge des Dateinamens |
|  | Dateiname | Variabel | UTF-8 kodierter Originalname |
|  | Dateidaten | Variabel | Dateiinhalt in $1\,\text{MB}$-Blöcken |
| **Footer** | GCM Tag | 16 | Authentifizierungs-Prüfsumme |
