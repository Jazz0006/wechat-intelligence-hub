"""Conversation identity carried by reader provenance, without storing credentials."""


def source_chat_id(source_file: str) -> str:
    prefix = "wechat-cli:timeline:"
    return source_file[len(prefix):].strip() if source_file.startswith(prefix) else ""


def conversation_key(chat: str, source_file: str) -> tuple[str, str]:
    # Keep the display name for compatibility with imported records. Distinct
    # reader identities must never be collapsed just because names match.
    return chat, source_chat_id(source_file)
