"""多格式日志 reader 单元测试。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from log_redaction.readers import (
    JsonLinesReader,
    SyslogReader,
    TextReader,
    get_reader,
)


class TestTextReader:
    def test_parse_line(self):
        reader = TextReader()
        line = "2026-06-15 10:00:00 INFO user login phone: 13812345678"
        entry = reader.parse_line(line, 1)
        assert entry.line_number == 1
        assert entry.raw == line
        assert entry.message == line
        assert entry.fields == {}

    def test_format_entry(self):
        reader = TextReader()
        entry = reader.parse_line("hello world", 1)
        formatted = reader.format_entry(entry, "hello *****")
        assert formatted == "hello *****"


class TestJsonLinesReader:
    def test_parse_json_line(self):
        reader = JsonLinesReader(message_field="message")
        obj = {
            "timestamp": "2026-06-15T10:00:00",
            "level": "INFO",
            "message": "User login: zhangsan phone 13812345678",
        }
        line = json.dumps(obj, ensure_ascii=False)
        entry = reader.parse_line(line, 1)
        assert entry.line_number == 1
        assert entry.fields == obj
        assert entry.message == "User login: zhangsan phone 13812345678"

    def test_parse_custom_field(self):
        reader = JsonLinesReader(message_field="log")
        obj = {"time": "2026-06-15", "log": "email: test@example.com"}
        line = json.dumps(obj)
        entry = reader.parse_line(line, 1)
        assert entry.message == "email: test@example.com"

    def test_format_entry(self):
        reader = JsonLinesReader(message_field="message")
        obj = {
            "timestamp": "2026-06-15T10:00:00",
            "level": "INFO",
            "message": "phone 13812345678",
        }
        line = json.dumps(obj, ensure_ascii=False)
        entry = reader.parse_line(line, 1)
        formatted = reader.format_entry(entry, "phone 138****5678")
        parsed = json.loads(formatted)
        assert parsed["timestamp"] == "2026-06-15T10:00:00"
        assert parsed["level"] == "INFO"
        assert parsed["message"] == "phone 138****5678"

    def test_parse_invalid_json(self):
        reader = JsonLinesReader()
        line = "not a json line"
        entry = reader.parse_line(line, 1)
        assert entry.fields.get("_parse_error") is True
        assert entry.message == line

    def test_message_field_not_found(self):
        reader = JsonLinesReader(message_field="msg")
        obj = {"level": "INFO"}
        line = json.dumps(obj)
        entry = reader.parse_line(line, 1)
        assert entry.message == ""


class TestSyslogReader:
    def test_parse_rfc5424(self):
        reader = SyslogReader()
        line = '<134>1 2026-06-15T10:00:00.000Z myhost myapp 1234 - [meta sequenceId="1"] User login phone 13812345678'
        entry = reader.parse_line(line, 1)
        assert entry.fields["format"] == "rfc5424"
        assert entry.fields["priority"] == "134"
        assert entry.fields["version"] == "1"
        assert entry.fields["timestamp"] == "2026-06-15T10:00:00.000Z"
        assert entry.fields["hostname"] == "myhost"
        assert entry.fields["appname"] == "myapp"
        assert entry.fields["procid"] == "1234"
        assert entry.fields["msgid"] == "-"
        assert "phone 13812345678" in entry.message

    def test_parse_rfc3164(self):
        reader = SyslogReader()
        line = '<134>Jun 15 10:00:00 myhost myapp[1234]: User login phone 13812345678'
        entry = reader.parse_line(line, 1)
        assert entry.fields["format"] == "rfc3164"
        assert entry.fields["priority"] == "134"
        assert entry.fields["timestamp"] == "Jun 15 10:00:00"
        assert entry.fields["hostname"] == "myhost"
        assert "phone 13812345678" in entry.message

    def test_format_rfc5424(self):
        reader = SyslogReader()
        line = '<134>1 2026-06-15T10:00:00.000Z myhost myapp 1234 - - User login phone 13812345678'
        entry = reader.parse_line(line, 1)
        formatted = reader.format_entry(entry, "User login phone 138****5678")
        assert formatted.startswith("<134>1")
        assert "2026-06-15T10:00:00.000Z" in formatted
        assert "myhost myapp 1234 - -" in formatted
        assert "138****5678" in formatted

    def test_format_rfc3164(self):
        reader = SyslogReader()
        line = '<134>Jun 15 10:00:00 myhost myapp: phone 13812345678'
        entry = reader.parse_line(line, 1)
        formatted = reader.format_entry(entry, "phone 138****5678")
        assert formatted.startswith("<134>Jun 15 10:00:00")
        assert "myhost myapp: phone 138****5678" in formatted

    def test_parse_invalid_syslog(self):
        reader = SyslogReader()
        line = "not a syslog line"
        entry = reader.parse_line(line, 1)
        assert entry.fields.get("_parse_error") is True
        assert entry.message == line


class TestGetReader:
    def test_get_text_reader(self):
        reader = get_reader("text")
        assert isinstance(reader, TextReader)
        reader = get_reader("plain")
        assert isinstance(reader, TextReader)
        reader = get_reader("txt")
        assert isinstance(reader, TextReader)

    def test_get_json_reader(self):
        reader = get_reader("json")
        assert isinstance(reader, JsonLinesReader)
        reader = get_reader("jsonl")
        assert isinstance(reader, JsonLinesReader)
        reader = get_reader("ndjson")
        assert isinstance(reader, JsonLinesReader)

    def test_get_syslog_reader(self):
        reader = get_reader("syslog")
        assert isinstance(reader, SyslogReader)
        reader = get_reader("rfc5424")
        assert isinstance(reader, SyslogReader)
        reader = get_reader("rfc3164")
        assert isinstance(reader, SyslogReader)

    def test_get_reader_invalid_format(self):
        with pytest.raises(ValueError, match="不支持的日志格式"):
            get_reader("invalid")

    def test_json_reader_custom_field(self):
        reader = get_reader("json", json_message_field="custom_msg")
        assert isinstance(reader, JsonLinesReader)
        assert reader.message_field == "custom_msg"
