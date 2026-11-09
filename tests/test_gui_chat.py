import json

from pycraft_gui.chat import render_chat_json


def test_plain_text_component():
    assert render_chat_json(json.dumps({"text": "Hello"})) == "Hello"


def test_text_with_extras():
    assert render_chat_json(json.dumps({
        "text": "Hello ", "extra": [{"text": "world"}, "!"],
    })) == "Hello world!"


def test_player_chat_translate():
    # What a real server sends for "<Steve> hi".
    assert render_chat_json(json.dumps({
        "translate": "chat.type.text",
        "with": ["Steve", "hi"],
    })) == "<Steve> hi"


def test_announcement_translate():
    assert render_chat_json(json.dumps({
        "translate": "chat.type.announcement",
        "with": ["Server", "Restarting soon"],
    })) == "[Server] Restarting soon"


def test_unknown_translate_key_falls_back_to_arguments():
    assert render_chat_json(json.dumps({
        "translate": "some.future.key",
        "with": ["a", "b"],
    })) == "a b"


def test_section_codes_are_stripped():
    assert render_chat_json(json.dumps({"text": "\u00a7aGreen \u00a7ltext"})) == "Green text"


def test_non_json_is_shown_as_is():
    assert render_chat_json("just a string") == "just a string"


def test_empty_and_malformed_input_do_not_raise():
    assert render_chat_json("") == ""
    assert render_chat_json("{not json") == "{not json"
    assert render_chat_json(None) == ""
