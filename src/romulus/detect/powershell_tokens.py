"""A nonexecuting PowerShell lexer and conservative call-shape reader.

This is not the PowerShell grammar or a runtime. It separates comments and literal data from commands,
member calls and constant call targets. Unknown/dynamic syntax is never evaluated. All text is scanned;
state lives only for the current bounded telemetry record, never for the hunt.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    escaped: bool = False


@dataclass
class Script:
    commands: set[str] = field(default_factory=set)
    definitions: set[str] = field(default_factory=set)
    members: set[str] = field(default_factory=set)
    static_calls: set[tuple[str, str]] = field(default_factory=set)
    arguments: dict[str, list[tuple[str, ...]]] = field(default_factory=dict)
    literals: set[str] = field(default_factory=set)
    variables: set[str] = field(default_factory=set)
    obfuscation: set[str] = field(default_factory=set)
    dynamic_invocation: bool = False
    partial: bool = False


def _expression_end(text: str, start: int) -> int:
    """Find the closing parenthesis of an expandable-string subexpression, respecting literal data."""
    i, depth, quote, comment = start, 1, "", 0
    while i < len(text):
        if text[i] == "`" and i + 1 < len(text):
            i += 2
            continue
        if comment:
            if text.startswith("<#", i):
                comment, i = comment + 1, i + 2
            elif text.startswith("#>", i):
                comment, i = comment - 1, i + 2
            else:
                i += 1
            continue
        if quote:
            if text[i] == quote:
                if i + 1 < len(text) and text[i+1] == quote:
                    i += 2
                    continue
                quote = ""
        elif text.startswith("<#", i):
            comment, i = 1, i + 2
            continue
        elif text[i] == "#":
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
            continue
        elif text[i] in "'\"":
            quote = text[i]
        elif text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if not depth:
                return i
        i += 1
    return len(text)


def lex(text: str, *, csharp: bool = False) -> tuple[list[Token], bool]:
    """Tokenize strings, here-strings, comments, variables, operators and escaped bare words."""
    tokens, i, partial = [], 0, False
    while i < len(text):
        c = text[i]
        if csharp and text.startswith("//", i):
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
        elif csharp and text.startswith("/*", i):
            end = text.find("*/", i + 2)
            partial |= end < 0
            i = len(text) if end < 0 else end + 2
        elif text.startswith("`\r\n", i) or text.startswith("`\n", i):
            i += 3 if text.startswith("`\r\n", i) else 2
        elif c in " \t\r":
            i += 1
        elif text.startswith("<#", i):
            depth, i = 1, i + 2
            while i < len(text) and depth:
                if text.startswith("<#", i):
                    depth, i = depth + 1, i + 2
                elif text.startswith("#>", i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
            partial |= bool(depth)
        elif c == "#":
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
        elif c == "@" and i + 2 < len(text) and text[i+1] in "'\"" and text[i+2] in "\r\n":
            quote, start = text[i+1], i + 2
            end = re.search(r"(?m)^" + re.escape(quote) + "@", text[start:])
            if end is None:
                tokens.append(Token("data", text[start:]))
                partial, i = True, len(text)
            else:
                body = text[start:start+end.start()]
                j = 0
                if quote == '"':
                    while j < len(body):
                        if body[j] == "`":
                            j += 2
                        elif body.startswith("$(", j):
                            stop = _expression_end(body, j + 2)
                            tokens.append(Token("expression", body[j+2:stop]))
                            partial |= stop == len(body)
                            j = stop + 1
                        else:
                            j += 1
                tokens.append(Token("data" if quote == '"' and "$" in body else "string", body))
                i = start + end.end()
        elif c in "'\"":
            quote, i, value, dynamic = c, i + 1, [], False
            closed = False
            while i < len(text):
                if quote == '"' and text.startswith("$(", i):
                    end = _expression_end(text, i + 2)
                    tokens.append(Token("expression", text[i+2:end]))
                    partial |= end == len(text)
                    dynamic, i = True, min(len(text), end + 1)
                elif text[i] == quote:
                    if i + 1 < len(text) and text[i+1] == quote:
                        value.append(quote)
                        i += 2
                    else:
                        i, closed = i + 1, True
                        break
                elif quote == '"' and text[i] == "`" and i + 1 < len(text):
                    value.append({"n": "\n", "r": "\r", "t": "\t", "0": "\0"}.get(text[i+1], text[i+1]))
                    i += 2
                else:
                    dynamic |= quote == '"' and text[i] == "$"
                    value.append(text[i])
                    i += 1
            partial |= not closed
            tokens.append(Token("data" if dynamic or not closed else "string", "".join(value)))
        elif c == "$":
            match = re.match(r"\$(?:\{[^}]*\}|[\w?]+(?::(?!:)[\w?]+)?)", text[i:])
            if match:
                tokens.append(Token("variable", match[0].casefold()))
                i += len(match[0])
            else:
                tokens.append(Token("op", c))
                i += 1
        elif text.startswith("::", i):
            tokens.append(Token("op", "::"))
            i += 2
        elif c in "\n;|&(){}[],=+.@":
            tokens.append(Token("op", c))
            i += 1
        else:
            value, escaped = [], False
            member = bool(tokens and tokens[-1].value in {".", "::"})
            while i < len(text) and text[i] not in " \t\r\n;|&(){}[],=+@'\"#$":
                if text[i] == "." and member:
                    break
                if text[i] == "`" and i + 1 < len(text):
                    escaped = True
                    value.append(text[i+1])
                    i += 2
                else:
                    value.append(text[i])
                    i += 1
            tokens.append(Token("word", "".join(value).casefold(), escaped))
    return tokens, partial


def _read_tokens(tokens: list[Token], partial: bool) -> Script:
    result = Script(partial=partial)
    # Fold only adjacent constant string additions. This never executes telemetry or substitutes variables.
    folded, i = [], 0
    while i < len(tokens):
        token = tokens[i]
        if token.kind == "string":
            value, end = token.value, i + 1
            while end + 1 < len(tokens) and tokens[end].value == "+" and tokens[end+1].kind == "string":
                value += tokens[end+1].value
                end += 2
            if end > i + 1:
                result.obfuscation.add("concatenation")
            folded.append(Token("string", value))
            i = end
        else:
            folded.append(token)
            i += 1
    tokens = folded
    stack = []
    start, called, command, args = True, False, "", []

    def finish():
        if command:
            result.arguments.setdefault(command, []).append(tuple(args))

    for i, token in enumerate(tokens):
        value, previous = token.value, tokens[i-1].value if i else ""
        following = tokens[i+1].value if i + 1 < len(tokens) else ""
        if value in {"(", "[", "{"}:
            stack.append(value)
        elif value in {")", "]", "}"}:
            want = {")": "(", "]": "[", "}": "{"}[value]
            if not stack or stack.pop() != want:
                result.partial = True
        if token.kind == "variable":
            result.variables.add(value)
        if token.kind == "string":
            result.literals.add(value.casefold())
        if value == "-join" and any(t.value.casefold() == "char" for t in tokens[max(0, i-12):i+8]):
            result.obfuscation.add("char-join")
        if value == "-f" and i and tokens[i-1].kind == "string" and re.search(r"\{\d+(?:[^}]*)\}", previous):
            result.obfuscation.add("format-string")
        if token.kind in {"word", "string"} and previous in {".", "::"} and following == "(":
            result.members.add(value.casefold())
            if previous == "::" and i > 2 and tokens[i-2].value == "]":
                j = i - 3
                while j >= 0 and tokens[j].value not in {"[", ";", "\n"}:
                    j -= 1
                if j >= 0 and tokens[j].value == "[":
                    typename = "".join(t.value for t in tokens[j+1:i-2])
                    result.static_calls.add((typename.casefold(), value.casefold()))
        if value in {";", "\n", "|", "{", "}"} and token.kind == "op":
            finish()
            start, called, command, args = True, False, "", []
            continue
        if token.kind == "word" and previous in {"function", "filter"}:
            result.definitions.add(value)
        if value == "&" and token.kind == "op":
            start, called = True, True
            result.dynamic_invocation = True
            continue
        if token.kind == "op" and value in {"=", "("}:
            start = True
            continue
        if token.kind in {"word", "string"} and start:
            # Type literals and cast names are expressions, not command invocations.
            if ((token.kind == "word" or called) and previous not in {"[", ".", "::"}
                    and following not in {"::", ".", "="}):
                command = value.casefold()
                result.commands.add(command)
                if token.escaped:
                    result.obfuscation.add("backtick")
            start, called = False, False
        elif command and token.kind in {"word", "string", "variable"}:
            args.append(value.casefold())
    finish()
    result.partial |= bool(stack)
    return result


def read_script(text: str) -> Script:
    """Read expandable-string code iteratively, without a recursion or executable-evaluation path."""
    result, pending = Script(), [text]
    while pending:
        tokens, partial = lex(pending.pop())
        pending.extend(token.value for token in tokens if token.kind == "expression")
        parsed = _read_tokens([token for token in tokens if token.kind != "expression"], partial)
        for name in ("commands", "definitions", "members", "static_calls", "literals", "variables", "obfuscation"):
            getattr(result, name).update(getattr(parsed, name))
        for command, arguments in parsed.arguments.items():
            result.arguments.setdefault(command, []).extend(arguments)
        result.dynamic_invocation |= parsed.dynamic_invocation
        result.partial |= parsed.partial
    return result
