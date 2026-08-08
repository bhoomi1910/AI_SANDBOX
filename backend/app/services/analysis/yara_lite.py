"""Pure-Python YARA-subset engine ("yara-lite").

Full `yara-python` cannot build on Python 3.14 (requires libyara), so this module
implements a documented subset of YARA for deterministic rule matching:

Supported strings:
  - double-quoted literal      $a = "VirtualAllocEx"  (modifiers: nocase, wide, ascii, fullword)
  - regex (Python re)          $b = /downloadstring/i
  - hex with ?? wildcards      $c = { 4D 5A ?? ?? 00 }

Supported conditions:
  - any of them | all of them | N of them
  - boolean expressions over $identifiers with and / or / not and parentheses

Meta fields: description, author, severity, mitre, tags.
Rules are loaded from backend/rules/*.yar.
"""
from __future__ import annotations

import re
from pathlib import Path

RULES_DIR = Path(__file__).resolve().parents[3] / "rules"  # backend/rules


class RuleParseError(Exception):
    pass


class _Rule:
    def __init__(self, name: str, meta: dict, strings: list, condition: list):
        self.name = name
        self.meta = meta
        self.strings = strings  # list of (identifier, matcher)
        self.condition = condition  # tokenized condition

    @property
    def severity(self) -> str:
        return str(self.meta.get("severity", "medium")).lower()

    def description(self) -> str:
        return str(self.meta.get("description", "")).strip('"')

    def author(self) -> str:
        return str(self.meta.get("author", "Sandbox Rules")).strip('"')

    def tags(self) -> list[str]:
        raw = str(self.meta.get("tags", "")).strip('"')
        return [t.strip() for t in raw.split(",") if t.strip()]

    def mitre(self) -> str | None:
        v = self.meta.get("mitre")
        return str(v).strip('"') if v else None


def load_rules(directory: Path = RULES_DIR) -> list[_Rule]:
    rules = []
    for yar in sorted(directory.glob("*.yar")):
        rules.extend(parse_rules(yar.read_text(encoding="utf-8", errors="replace")))
    return rules


def parse_rules(source: str) -> list[_Rule]:
    rules = []
    for block in re.finditer(r"rule\s+(\w+)\s*\{", source):
        name = block.group(1)
        start = block.end()
        end = _find_rule_end(source, start)
        body = source[start:end]
        meta = _parse_meta(body)
        strings, ident_map = _parse_strings(body)
        cond_tokens = _tokenize_condition(_extract_condition(body))
        rules.append(_Rule(name, meta, strings, cond_tokens))
    return rules


def _find_rule_end(source: str, start: int) -> int:
    depth = 1
    i = start
    while i < len(source) and depth:
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
        i += 1
    return i - 1


def _parse_meta(body: str) -> dict:
    meta = {}
    m = re.search(r"meta:\s*(.*?)(?:strings:|condition:|$)", body, re.DOTALL)
    if not m:
        return meta
    for key, value in re.findall(r"(\w+)\s*=\s*(\"[^\"]*\"|'[^']*'|\d+)", m.group(1)):
        meta[key] = value.strip("\"'")
    return meta


def _parse_strings(body: str) -> tuple[list, dict]:
    strings: list = []
    ident_map: dict[str, object] = {}
    m = re.search(r"strings:\s*(.*?)(?:condition:|$)", body, re.DOTALL)
    if not m:
        return strings, ident_map
    for line in m.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        match = re.match(r"\$(\w+)\s*=\s*(.+)", line)
        if not match:
            continue
        ident, spec = match.group(1), match.group(2).rstrip()
        if spec.startswith('"'):
            strings.append((ident, _literal_matcher(spec)))
        elif spec.startswith("/"):
            strings.append((ident, _regex_matcher(spec)))
        elif spec.startswith("{"):
            strings.append((ident, _hex_matcher(spec)))
        ident_map[ident] = True
    return strings, ident_map


def _literal_matcher(spec: str) -> callable:
    parts = spec.split()
    literal = parts[0].strip('"')
    flags = {p for p in parts[1:] if p in ("nocase", "wide", "ascii", "fullword")}
    payloads = [literal.encode("ascii", "ignore")]
    if "wide" in flags:
        payloads.append(literal.encode("utf-16-le"))

    def matcher(data: bytes) -> bool:
        for payload in payloads:
            for m in re.finditer(re.escape(payload), data):
                if "fullword" in flags and not _word_boundary(data, m.start(), len(payload)):
                    continue
                return True
        return False

    return matcher


def _regex_matcher(spec: str) -> callable:
    end = spec.rfind("/")
    pattern = spec[1:end]
    mods = spec[end + 1 :]
    flags = re.IGNORECASE if "i" in mods else 0
    try:
        rx = re.compile(pattern.encode("ascii"), flags)
        return lambda data: bool(rx.search(data))
    except re.error:
        rx = re.compile(pattern, flags)
        return lambda data: bool(rx.search(data.decode("latin-1", "ignore")))


def _hex_matcher(spec: str) -> callable:
    tokens = re.findall(r"[0-9a-fA-F]{2}|\?\?", spec)
    pattern = b""
    parts = []
    for t in tokens:
        if t == "??":
            parts.append(b".")
        else:
            parts.append(re.escape(bytes.fromhex(t)))
    rx = re.compile(b"".join(parts))
    return lambda data: bool(rx.search(data))


def _word_boundary(data: bytes, start: int, length: int) -> bool:
    before = data[start - 1] if start > 0 else 0
    after = data[start + length] if start + length < len(data) else 0
    return not (_is_alnum(before) or _is_alnum(after))


def _is_alnum(b: int) -> bool:
    return 48 <= b <= 57 or 65 <= b <= 90 or 97 <= b <= 122 or b == 95


def _extract_condition(body: str) -> str:
    m = re.search(r"condition:\s*(.*)$", body, re.DOTALL)
    return m.group(1) if m else "any of them"


def _tokenize_condition(cond: str) -> list:
    return re.findall(r"any of them|all of them|not|\band\b|\bor\b|\(|\)|\.\w+|\$\w+|\d+\s+of them|\d+|\w+", cond.lower())


def match_file(rules: list[_Rule], data: bytes) -> list[dict]:
    hits = []
    for rule in rules:
        matched = {ident for ident, matcher in rule.strings if matcher(data)}
        if _eval_condition(rule.condition, matched, len(rule.strings)):
            hits.append({
                "rule": rule.name,
                "description": rule.description(),
                "severity": rule.severity,
                "tags": rule.tags(),
                "author": rule.author(),
                "mitre": rule.mitre(),
                "matchedStrings": sorted(matched),
            })
    return hits


def _eval_condition(tokens: list, matched: set[str], total: int) -> bool:
    pos = 0

    def parse_expr() -> bool:
        nonlocal pos
        left = parse_term()
        while pos < len(tokens) and tokens[pos] in ("and", "or"):
            op = tokens[pos]
            pos += 1
            right = parse_term()
            left = (left and right) if op == "and" else (left or right)
        return left

    def parse_term() -> bool:
        nonlocal pos
        if pos >= len(tokens):
            return False
        if tokens[pos] == "not":
            pos += 1
            return not parse_term()
        if tokens[pos] == "(":
            pos += 1
            val = parse_expr()
            if pos < len(tokens) and tokens[pos] == ")":
                pos += 1
            return val
        tok = tokens[pos]
        if tok == "any of them":
            pos += 1
            return len(matched) >= 1
        if tok == "all of them":
            pos += 1
            return total > 0 and len(matched) == total
        if tok.endswith("of them"):
            n = int(tok.split()[0])
            pos += 1
            return len(matched) >= n
        if tok.startswith("$"):
            pos += 1
            return tok in matched
        pos += 1
        return True

    return parse_expr()


def get_rules() -> list[_Rule]:
    if not hasattr(get_rules, "_cache"):
        get_rules._cache = load_rules()
    return get_rules._cache
