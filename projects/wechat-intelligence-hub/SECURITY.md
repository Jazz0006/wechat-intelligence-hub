# Security and Privacy

WeChat Intelligence Hub processes private local chat data. Treat every real input and generated report as sensitive.

## Never Commit

- WeChat databases, keys, tokens, cookies, session material, or reader state
- Real contact lists, WeChat IDs, group names, avatars, or relationship maps
- Raw or summarized chat transcripts
- Generated reports, screenshots, media attachments, logs, or local SQLite databases
- `.env` files, `config/profile.local.json`, and machine-specific configuration

The repository `.gitignore` excludes the standard local paths, but it is not a substitute for reviewing the staged diff before every commit.
Do not publish by manually zipping the working directory: ignored local files can still be copied into an archive. Build releases from Git-tracked files only.

## Reporting A Vulnerability

Do not open a public issue containing chat samples, credentials, database fragments, local paths with personal identifiers, or screenshots of real conversations. Reproduce the problem with the fake sample data first.

## Operating Boundary

The project is read-only by design. It must not send messages, add contacts, transfer files, make payments, or mutate WeChat data. Third-party local readers can break after a WeChat upgrade; run the compatibility check before relying on a fresh report.

## HTML Reports

Install the pinned sanitizer using `bash scripts/setup_html.sh`; Markdown commands do not need it. The bundle renderers disable raw HTML, apply an nh3 allowlist and add a hash-based CSP. No embedded images or automatic remote fetches are allowed. Only known local report links are routed internally; HTTP(S) sources open on an explicit click. Missing sanitizer or unexpected script structure stops HTML generation.

Existing HTML files are not repaired automatically. Regenerate them using the upgraded engine before opening or sharing. This is not a guarantee about third-party Markdown viewers, browser extensions or the contents of external links.
