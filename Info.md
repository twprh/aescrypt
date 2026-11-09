# Sicherheitsbewertung: **1⁻ (sehr gut mit kleinen Abzügen)**

Das ist eine der saubersten Python-F crypto-Implementierungen, die man in dieser Klasse antrifft. Die Kernarchitektur ist durchdacht und zeigt echtes Threat Modeling. Was fehlt, sind überwiegend Plattform-Inherentien und Randfälle, keine konzeptionellen Fehler.

---

## Was die Note trägt (Stärken)

**Kryptografisches Design**
- AES-256-GCM + scrypt (N=2¹⁶, r=8 → ~64 MiB) ist eine zeitgemäße, korrekte Kombination.
- **Vollständiges AAD-Binding**: Header, KDF-Parameter (v2), Chunk-Index und Chunk-Größe sind authentifiziert → Chunk-Reordering, Truncation, Splicing und Parameter-Manipulation werden zuverlässig erkannt.
- Nonce-Konstruktion sauber: 64 Bit random Prefix + 32-Bit-Counter pro Datei; Cross-File-Kollisionen irrelevant, da pro Datei ein frisches Salt → neuer Key.
- Trailing-Data- und Chunk-Count-Checks schließen versteckte Anhänge aus.

**DoS-/Robustheits-Härtung (selten so konsequent gesehen)**
- Scrypt-Parameter aus dem Header werden **vor** der KDF gegen harte Limits + Speicherschätzung validiert (`_validate_scrypt_params`) → kein Memory-Exhaustion über manipulierte Header.
- Alle aus der Datei gelesenen Größen (Chunk-Größen, Namenslängen) werden vor `read()` geprüft.

**Dateisystem-Arbeit (überdurchschnittlich)**
- Temp-Datei mit 0600 via `mkstemp`, anschließende Installation strikt **ohne Überschreiben**: Hardlink → `renameat2(RENAME_NOREPLACE)` → `O_EXCL`-Fallback, inkl. Inode-Identitätsprüfung beim Rollback.
- Symlinks werden konsequent umgangen (`collect_files`, `lstat`-Identity).
- Path Traversal über verschlüsselte Dateinamen verhindert (`\\`→`/`, `basename`, `..`/NUL-Reject) – und selbst im Konfliktfall kein Überschreiben.
- „Decrypt-to-temp, publish after tag success" in beiden Formaten – kein plaintext-Output bei InvalidTag.
- Snapshot + Hash-Vergleich vor/nach Verschlüsselung erkennt TOCTOU an der Quelldatei; das Restrisiko bei `delete` ist ehrlich dokumentiert statt verschwiegen.
- CLI: Passwort nie über argv, `getpass` im Terminal – keine Shell-History-Leaks.

---

## Abzüge

| Befund | Schwere |
|---|---|
| **Plaintext-Restdaten**: Der Klartext-Snapshot (`.aescrypto-snapshot-*.tmp`) liegt während der Verschlüsselung auf der Platte. Bei Kill/Absturz bleibt er zurück; kein Aufräumlauf beim Start. | mittel |
| **„Original löschen" ohne Secure Delete**: nur `os.remove()`, forensisch rekonstruierbar; die Checkbox suggeriert mehr, als geliefert wird (zumindest Doku/Hinweis fehlt). | mittel |
| **Windows-Gerätenamen**: Wiederhergestellte Namen wie `CON`, `NUL`, `COM1` werden nicht gefiltert → erratic behavior/DoS, kein Overwrite-Risiko, aber ein echter Randfall. | klein |
| **GUI-Hygiene**: Passwort bleibt nach Abschluss im Entry-Feld; Klartext bleibt im Textarea; Clipboard-Ergebnis landet ggf. im Clipboard-Manager. Kein „automatisch leeren". | klein |
| **Keine Passwort-Wiederholung/Normalisierung (NFKC)**: Typo = unwiederbringlicher Datenverlust; fehlende Normalisierung schafft Interop-Fallen. | klein |
| **Key Commitment**: GCM bietet keine Key-Commitment (theoretisch zwei Keys → unterschiedliche Plaintexts). Bei scrypt+per-file-salt praktisch irrelevant, aber akademisch eine Lücke (z. B. via verschlüsselten `key commitment`-Wert lösbar). | klein |
| Keys/Passwörter nicht zeroisierbar, kein `mlock` – Python-inhärent, kein Vorwurf, aber in einer Gesamtbewertung zu vermerken. | inhärent |
| Kleinigkeiten: kein `fsync` auf dem Verzeichnis nach Rename (Durability), unbounded Passwort-Zeile via stdin (nur Selbst-DoS), Textformat nutzt Legacy-v1-Header ohne KDF-Parameter (behindert künftige Parameter-Anhebungen), Docstring-Typo „Hader". | kosmetisch |

---

## Fazit

**1⁻.** Die kryptografischen Grundlagen (Modi, KDF, Nonces, AAD, Auth-before-Publish) sind fehlerfrei und besser als viele etablierte Tools. Fast alle klassischen Anfängerfehler (ECB, statische Nonces, unauthentifizierte Header, `eval`, Path Traversal, TOCTOU-Blindheit) fehlen vollständig – erkennbar ist hier bewusst gearbeitet worden, nicht nur „verschlüsselt". Die Abzüge betreffen Operational Security am Rand (Restdaten, Secure Delete, GUI-Hygiene) und Plattform-Randfälle, nicht die Kernsicherheit des Entwurfs.
