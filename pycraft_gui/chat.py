"""Render Minecraft chat JSON into plain text for the chat log.

The old client logged ``chat_packet.json_data`` verbatim, so the log showed
raw JSON like ``{"translate": "chat.type.text", "with": [...]}``. Servers
send chat as JSON text components (see https://wiki.vg/Chat): a message is
``{"text": ...}`` with an optional ``"extra"`` list, or a ``"translate"``
key with ``"with"`` arguments. This module turns those into the line a
player would see in-game.

Unknown shapes degrade to the closest readable text rather than raising:
a chat line the renderer cannot understand should still appear in the
log, not crash the network thread.
"""

import json
import re

_SECTION_CODE_RE = re.compile(r"\u00a7[0-9a-fk-or]")

# translate keys the client knows how to phrase. Anything else falls back
# to joining the "with" arguments with spaces.
_TRANSLATIONS = {
    "chat.type.text": "<{0}> {1}",
    "chat.type.announcement": "[{0}] {1}",
    "chat.type.emote": "* {0} {1}",
}


def _render_component(component):
    if isinstance(component, str):
        return component
    if isinstance(component, (int, float, bool)):
        return str(component)
    if not isinstance(component, dict):
        return ""
    if "text" in component:
        text = str(component["text"])
    elif "translate" in component:
        text = _render_translate(component)
    else:
        text = ""
    for extra in component.get("extra", []):
        text += _render_component(extra)
    return text


def _render_translate(component):
    key = component.get("translate", "")
    args = [_render_component(arg) for arg in component.get("with", [])]
    template = _TRANSLATIONS.get(key)
    if template is not None:
        try:
            return template.format(*args)
        except (IndexError, KeyError):
            pass
    # Unknown translate key: show the arguments; the key itself is not
    # something a player can read.
    return " ".join(args)


def render_chat_json(json_data):
    """Render one raw chat JSON string as plain text.

    Returns ``""`` for empty input; never raises on malformed JSON.
    """
    if not json_data:
        return ""
    try:
        parsed = json.loads(json_data)
    except (ValueError, TypeError):
        # Not JSON at all — show it as-is rather than dropping the line.
        return _SECTION_CODE_RE.sub("", str(json_data))
    text = _render_component(parsed)
    return _SECTION_CODE_RE.sub("", text)
