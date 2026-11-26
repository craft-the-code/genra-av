# Security policy

## Reporting a vulnerability in Genra AV

Please report privately through GitHub: **Security → Report a vulnerability** on this repository.
Do not open a public issue for a vulnerability. We aim to answer within 7 days.

In scope: the engine and parsers (a file that crashes or hangs the scanner, or gets past a rule it
should match), the desktop app, the update and rule-pack signing chain, and the backend in `backend/`.

## Reporting malware Genra missed, or a file it flags wrongly

Use the in-app **"báo nhầm" / report** button, or open an issue with the file's **SHA-256** and what
you expected. **Never attach live malware** to an issue or pull request. If we need the sample, we will
ask for it through the app's sample upload, which sends only the extracted macro code.

## Supported versions

Only the latest release receives fixes.
