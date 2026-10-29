# Security and privacy

Please do not open a public issue containing chat messages, contact details, local paths, API keys, cookies, access tokens, invoices, client briefs, or other personal and commercial data.

Before reporting a bug, reproduce it with the bundled fictional samples whenever possible. If a private report is required, contact the maintainer through a private channel and share the minimum evidence needed.

## Report Rendering

Chat text, Markdown, filenames and links are untrusted data, not agent instructions. Both report-bundle renderers disable raw HTML in Pandoc, sanitize converted fragments with an explicit nh3 allowlist, and restrict application scripts with a hash-based Content Security Policy. External images and automatic network requests are disabled. Known report links become local navigation; unknown file links are disabled. HTTP(S) source links remain manual navigation and are not endorsements of the destination.

HTML generation fails closed if nh3 is missing. Run `bash scripts/setup_html.sh` inside the actual Hub engine to install it in a private virtual environment; Pandoc is also required. This hardening does not retroactively change existing HTML files. Regenerate old reports from trusted local Markdown with the upgraded renderer before opening or sharing them. Other viewers of exported Markdown enforce their own rendering policies.

The Reader and Intelligence Hub are read-only with respect to WeChat: they do not send messages or automate replies. The separate experimental `rion-wechat-access` helper is not read-only: after explicit review and confirmation it can invoke an external local provider with macOS administrator authorization, which may restart WeChat, debug its process and re-sign a shadow copy. Installation and daily reports never invoke acquisition. No provider is bundled or downloaded by the installer/helper; when first access is explicitly requested, Codex may prepare a pinned, reviewed provider separately. Acquisition compatibility on a fresh machine is not yet verified. See [the authorization and recovery boundaries](skills/wechat-cli/references/experimental-access.md). Users remain responsible for local data access, backups, applicable platform rules, and legal compliance.

Never commit:

- real WeChat IDs or chatroom IDs;
- exported chats, contact lists, databases, screenshots, or generated reports;
- `config/profile.local.json` or equivalent personal profiles;
- secrets, tokens, passwords, cookies, private keys, or paid client materials.
