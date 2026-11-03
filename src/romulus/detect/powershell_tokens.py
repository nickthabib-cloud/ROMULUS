"""A nonexecuting PowerShell lexer and conservative call-shape reader.

This is not the PowerShell grammar or a runtime. It separates comments and literal data from commands,
member calls and constant call targets. Unknown/dynamic syntax is never executed. Work caps are explicit and partial;
state lives only for the current bounded telemetry record, never for the hunt.
"""
from __future__ import annotations

import ntpath
import re
from dataclasses import dataclass, field, replace

MAX_TOKENS = 60_000
MAX_READ_CHARS = 2_097_152
MAX_WORD_CHARS = 65_536
_VARIABLE = re.compile(r"\$[\w?]+(?::(?!:)[\w?]+)?")
_HERE = {quote: re.compile(r"(?m)^" + re.escape(quote) + "@") for quote in "'\""}
_QUOTES = {c: "'" for c in "'\u2018\u2019\u201a\u201b"} | {c: '"' for c in '\"\u201c\u201d\u201e'}
_MODULE_COMMAND_NAME = re.compile(r'[\w.-]+\\[a-z][\w]*-[a-z][\w-]*\Z', re.IGNORECASE | re.ASCII)
_PROGRAM_SUFFIXES = ('.exe', '.com', '.cmd', '.bat', '.ps1', '.msi', '.msp', '.vbs', '.vbe',
                     '.js', '.jse', '.wsf', '.wsh', '.scr', '.cpl')
_SHELL_METHODS = {'wscript.shell': frozenset({'run', 'exec'}),
                  'shell.application': frozenset({'shellexecute'})}


def _path_literal(value):
    return ('\\' in value or '/' in value) and not _MODULE_COMMAND_NAME.fullmatch(value)


def _program_target(value):
    return _path_literal(value) or value.casefold().endswith(_PROGRAM_SUFFIXES)


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    escaped: bool = False
    transforms: frozenset[str] = frozenset()


@dataclass
class Script:
    commands: set[str] = field(default_factory=set)
    definitions: set[str] = field(default_factory=set)
    members: set[str] = field(default_factory=set)
    member_literals: set[tuple[str, str]] = field(default_factory=set)
    static_calls: set[tuple[str, str]] = field(default_factory=set)
    arguments: dict[str, list[tuple[str, ...]]] = field(default_factory=dict)
    literals: set[str] = field(default_factory=set)
    variables: set[str] = field(default_factory=set)
    obfuscation: set[str] = field(default_factory=set)
    dynamic_invocation: bool = False
    obfuscated_execution: bool = False
    evaluates_code: bool = False
    starts_program: bool = False
    reflection_filter: bool = False
    inert_words: set[str] = field(default_factory=set)
    constant_folds: list[tuple] = field(default_factory=list)
    module_binding_data: bool = False
    module_bindings: list[tuple[str, str, str]] = field(default_factory=list)
    partial: bool = False
    limits: set[str] = field(default_factory=set)
    fold_evidence_truncated: bool = False


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
            start = i
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


def lex(text: str, *, csharp: bool = False, limits=None) -> tuple[list[Token], bool]:
    """Tokenize strings, here-strings, comments, variables, operators and escaped bare words."""
    limits = set() if limits is None else limits
    partial = len(text) > MAX_READ_CHARS
    if partial:
        limits.add('MAX_READ_CHARS=2097152')
        text = text[:MAX_READ_CHARS]
    tokens, i, chunks = [], 0, 0
    word_end = -1
    word_parts, word_size, word_index = [], 0, None

    def finish_word():
        nonlocal word_parts, word_size, word_index
        if word_parts:
            old = tokens[word_index]
            tokens[word_index] = Token('word', ''.join(word_parts), old.escaped, old.transforms)
            word_parts, word_size, word_index = [], 0, None

    def append_word(value, escaped=False, transforms=frozenset()):
        nonlocal word_size, word_index, partial
        if not word_parts:
            word_index = len(tokens) - 1
            word_parts.append(tokens[-1].value)
            word_size = len(tokens[-1].value)
        room = max(0, MAX_WORD_CHARS - word_size)
        word_parts.append(value[:room])
        word_size += len(value)
        if word_size > MAX_WORD_CHARS:
            partial = True
            limits.add('MAX_WORD_CHARS=65536')
        old = tokens[word_index]
        tokens[word_index] = Token('word', '', old.escaped or escaped, old.transforms | transforms)

    while i < len(text) and chunks < MAX_TOKENS:
        c = text[i]
        chunks += c not in ' \t\r'
        continuation = (word_end == i and tokens and tokens[-1].kind == 'word'
                        and (c in _QUOTES or c not in " \t\r\n;|&(){}[],=+@$"))
        if not continuation:
            finish_word()
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
            start = i
            depth, i = 1, i + 2
            while i < len(text) and depth:
                if text.startswith("<#", i):
                    depth, i = depth + 1, i + 2
                elif text.startswith("#>", i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
            partial |= bool(depth)
            tokens.append(Token("inert", text[start:i]))
        elif c == "#":
            end = text.find("\n", i)
            tokens.append(Token("inert", text[i:len(text) if end < 0 else end]))
            i = len(text) if end < 0 else end
        elif c == "@" and i + 2 < len(text) and text[i+1] in _QUOTES and text[i+2] in "\r\n":
            quote, start = _QUOTES[text[i+1]], i + 2
            end = _HERE[quote].search(text, start)
            if end is None:
                tokens.append(Token("data", text[start:]))
                partial, i = True, len(text)
            else:
                body = text[start:end.start()]
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
                i = end.end()
        elif c in _QUOTES:
            start = i
            quote, i, value, dynamic = _QUOTES[c], i + 1, [], False
            closed = False
            while i < len(text):
                if quote == '"' and text.startswith("$(", i):
                    end = _expression_end(text, i + 2)
                    tokens.append(Token("expression", text[i+2:end]))
                    partial |= end == len(text)
                    dynamic, i = True, min(len(text), end + 1)
                elif _QUOTES.get(text[i]) == quote:
                    if i + 1 < len(text) and _QUOTES.get(text[i+1]) == quote:
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
            value = "".join(value)
            if word_end == start and tokens and tokens[-1].kind == "word" and not dynamic and closed:
                append_word(value.casefold(), transforms={'embedded-quotes'})
                word_end = i
            else:
                finish_word()
                tokens.append(Token("data" if dynamic or not closed else "string", value))
        elif c == "$":
            if text.startswith('${', i):
                end = text.find('}', i + 2)
                if end < 0:
                    partial = True
                    limits.add('unclosed_braced_variable')
                    i = len(text)
                else:
                    tokens.append(Token('variable', text[i:end + 1].casefold()))
                    i = end + 1
            elif (match := _VARIABLE.match(text, i)):
                tokens.append(Token("variable", match[0].casefold()))
                i += len(match[0])
            else:
                tokens.append(Token("op", c))
                i += 1
        elif text.startswith(("::", "&&"), i):
            tokens.append(Token("op", text[i:i+2]))
            i += 2
        elif c in "\n;|&(){}[],=+.@" and not text.startswith((".\\", "./"), i):
            tokens.append(Token("op", c))
            i += 1
        else:
            start = i
            value, escaped = [], False
            dot_call = (tokens and tokens[-1].value == '.' and (len(tokens) == 1
                        or tokens[-2].value in {';', '\n', '{', '=', '(', '|'}))
            member = bool(tokens and tokens[-1].value in {".", "::"} and not dot_call
                          and not text.startswith((".\\", "./"), i))
            while i < len(text) and text[i] not in " \t\r\n;|&(){}[],=+@$" and text[i] not in _QUOTES:
                if text[i] == "." and member:
                    break
                if text[i] == "`" and i + 1 < len(text):
                    escaped = True
                    value.append(text[i+1])
                    i += 2
                else:
                    value.append(text[i])
                    i += 1
            value = "".join(value).casefold()
            if value.startswith(("\u2013", "\u2014", "\u2015")):
                value = "-" + value[1:]
            if word_end == start and tokens and tokens[-1].kind == "word":
                append_word(value, escaped, {'backtick'} if escaped else set())
            else:
                if len(value) > MAX_WORD_CHARS:
                    partial = True
                    limits.add('MAX_WORD_CHARS=65536')
                tokens.append(Token("word", value[:MAX_WORD_CHARS], escaped,
                                    frozenset({'backtick'} if escaped else set())))
            word_end = i
    finish_word()
    if i < len(text):
        limits.add('MAX_TOKENS=60000')
    partial |= i < len(text)
    if partial and not limits:
        limits.add('unclosed_literal_or_comment')
    return tokens, partial


def _mark_path_calls(tokens: list[Token]) -> list[Token]:
    """Classify literal path operands before folding can merge a nonpath literal into a path."""
    stack, ends, bad, literals, statements = [], {}, [0], [0], [0]
    for position, item in enumerate(tokens):
        if item.kind == 'op' and item.value == '(':
            stack.append(position)
        elif item.kind == 'op' and item.value == ')' and stack:
            ends[stack.pop()] = position
        root = item.kind == 'variable' and (item.value.startswith('$env:')
                                           or item.value in {'$psscriptroot', '$pscommandpath'})
        literal = item.kind == 'string' and _path_literal(item.value)
        bad.append(bad[-1] + int(not (root or literal or item.kind == 'op' and item.value in {'+', '(', ')'})))
        literals.append(literals[-1] + int(literal))
        statements.append(statements[-1] + int(item.kind == 'op'
                                               and item.value in {';', '\n', '|', '&', '&&', '{', '}'}))
    for begin, end in ends.items():
        if not begin or tokens[begin-1].kind != 'op' or tokens[begin-1].value not in {'&', '.'}:
            continue
        first = begin + 1
        # This is the same nesting ceiling as constant interpretation; no suffix rescans.
        for _ in range(32):
            if first >= end or tokens[first].kind != 'op' or tokens[first].value != '(':
                break
            first += 1
        command_first, command_end = begin + 1, end
        for _ in range(32):
            if command_first >= command_end or ends.get(command_first) != command_end - 1:
                break
            command_first += 1
            command_end -= 1
        # Only a whole path command has a path result. A pipeline, later statement,
        # or operation outside its parentheses may instead return constructed text.
        path_command = (command_first < command_end and tokens[command_first].kind == 'word'
                        and tokens[command_first].value.rsplit('\\', 1)[-1] in {'join-path', 'resolve-path'}
                        and statements[command_end] == statements[command_first])
        if (path_command or first < end and tokens[first].kind == 'variable'
                and bad[end] == bad[begin+1] and literals[end] > literals[begin+1]):
            tokens[begin] = replace(tokens[begin], transforms=tokens[begin].transforms | {'path-call'})
    return tokens


def _read_tokens(tokens: list[Token], partial: bool, constant_budget=None) -> Script:
    from romulus.detect.powershell_constants import OBFUSCATING, fold_constants, variable_name

    result = Script(partial=partial)
    for token in tokens:
        if token.kind == 'variable':
            result.variables.add(token.value)
        if token.kind == 'string':
            result.literals.add(token.value.casefold())
        if token.kind in {'string', 'data', 'inert'}:
            result.inert_words.update(re.findall(r'[a-z][\w-]*', token.value.casefold()))
    tokens, result.constant_folds, limited = fold_constants(_mark_path_calls(tokens), constant_budget, result.limits)
    result.fold_evidence_truncated = 'MAX_FOLD_EVIDENCE=256' in result.limits
    result.limits.discard('MAX_FOLD_EVIDENCE=256')
    result.partial |= limited
    # Match group ends once; overlapping call expressions never rescan the same token suffix.
    group_stack, group_ends, group_starts, constructed_prefix = [], {}, {}, [0]
    lookup_pattern_positions = set()
    for position, item in enumerate(tokens):
        if item.kind == 'word' and item.value in {'gcm', 'get-command', 'gal', 'get-alias'}:
            argument = position + 1 + int(position + 1 < len(tokens) and tokens[position+1].value == '-name')
            for _ in range(32):
                if argument >= len(tokens) or tokens[argument].kind != 'op' or tokens[argument].value != '(':
                    break
                argument += 1
            if argument < len(tokens):
                pattern = tokens[argument].value
                if ('?' in pattern[1:-1] or ('*' in pattern or '?' in pattern)
                        and max(map(len, pattern.replace('?', '*').split('*'))) < 4):
                    lookup_pattern_positions.add(argument)
    for position, item in enumerate(tokens):
        if item.kind == 'op' and item.value in {'(', '['}:
            group_stack.append((item.value, position))
        elif item.kind == 'op' and item.value in {')', ']'} and group_stack:
            opening, begin = group_stack.pop()
            if (opening, item.value) in {('(', ')'), ('[', ']')}:
                group_ends[begin] = position
                group_starts[position] = begin
        constructed = item.value in {'+', '-f', '-join'} or position in lookup_pattern_positions
        constructed_prefix.append(constructed_prefix[-1] + int(constructed))
    stack, contexts = [], []
    start, called, command, args, evaluating = True, False, '', [], False
    type_depth = 0
    pending_switch_depth = None
    switch_bodies = set()
    switch_depths = []
    reflection_pattern = False
    invoking_member_target = False
    evaluators = {'iex', 'invoke-expression'}
    shell_receivers = {}
    keywords = {'function', 'filter', 'if', 'elseif', 'else', 'while', 'for', 'foreach', 'switch',
                'param', 'begin', 'process', 'end', 'try', 'catch', 'finally', 'return', 'throw', 'class', 'enum'}

    def command_name(value):
        name = value.casefold()
        if ':' in name and name.split(':', 1)[0] in {'global', 'script', 'local', 'private'}:
            name = name.split(':', 1)[1]
        if '\\' in name or '/' in name:
            name = ntpath.basename(name.replace('/', '\\'))
        return name.removesuffix('.ps1')

    def finish():
        if command:
            result.arguments.setdefault(command, []).append(tuple(args))

    def member_literal(position, method):
        end = group_ends.get(position + 1, position + 1)
        argument, current, steps = 0, position + 2, 0
        wanted = int(method == 'getprocaddress')
        while current < end and steps < 64:
            steps += 1
            item = tokens[current]
            if argument == wanted:
                if item.kind == 'string':
                    result.member_literals.add((method, item.value.casefold()))
                return
            if item.kind == 'op' and item.value == ',':
                argument += 1
            elif current in group_ends:
                current = group_ends[current]
            current += 1

    def shell_constructor(begin, end):
        # Exact constructors only. Parenthesis unwrapping shares the bounded expression depth;
        # receivers are block-local lexical facts, never general object/data-flow inference.
        for _ in range(32):
            if begin < end and tokens[begin].value == '(' and group_ends.get(begin) == end - 1:
                begin, end = begin + 1, end - 1
            else:
                break
        if end - begin != 3:
            return ''
        creator, parameter, progid = tokens[begin:end]
        if (creator.kind == 'word' and command_name(creator.value) == 'new-object'
                and parameter.kind == 'word' and len(parameter.value) >= 4
                and '-comobject'.startswith(parameter.value)
                and progid.kind in {'word', 'string'} and progid.value.casefold() in _SHELL_METHODS):
            return progid.value.casefold()
        return ''

    for i, token in enumerate(tokens):
        value, previous = token.value, tokens[i-1].value if i else ""
        following = tokens[i+1].value if i + 1 < len(tokens) else ""
        transforms = token.transforms & OBFUSCATING
        result.obfuscation.update(transforms)
        if token.kind == 'variable' and following in {'+', '-', '++', '--'}:
            shell_receivers.pop(variable_name(value), None)
        if token.kind == 'variable' and following == '=':
            name = variable_name(value)
            shell_receivers.pop(name, None)
            begin = i + 2
            end = group_ends.get(begin, begin + 2) + 1
            if ((not i or previous in {';', '\n', '{'}) and end <= len(tokens)
                    and (end == len(tokens) or tokens[end].value in {';', '\n', '}'})):
                progid = shell_constructor(begin, end)
                if progid:
                    shell_receivers[name] = progid
        if token.kind in {'inert', 'data'}:
            if token.kind == 'data' and called:
                result.starts_program = True
                start, called, invoking_member_target = False, False, False
            if command and token.kind == 'data':
                args.append(value.casefold())
            continue
        if token.kind == 'string':
            result.literals.add(value.casefold())
        if token.kind == 'word' and value == 'switch' and start:
            pending_switch_depth = len(stack)
        if token.kind == "op" and value in {"(", "[", "{"}:
            stack.append(value)
            if value == '{' and pending_switch_depth == len(stack) - 1:
                switch_bodies.add(len(stack))
                switch_depths.append(len(stack))
                pending_switch_depth = None
        elif token.kind == "op" and value in {")", "]", "}"}:
            want = {")": "(", "]": "[", "}": "{"}[value]
            if not stack or stack.pop() != want:
                result.partial = True
                result.limits.add('unbalanced_syntax')
            while switch_depths and switch_depths[-1] > len(stack):
                switch_bodies.discard(switch_depths.pop())
        if token.kind in {'word', 'string'} and len(stack) in switch_bodies:
            # Bare switch labels are patterns; the code inside their action blocks is read normally.
            result.inert_words.add(value.casefold())
            start = False
            continue
        if token.kind == 'word' and value == '-join' and evaluating:
            result.obfuscation.add('char-join')
            result.obfuscated_execution = True
        if token.kind == 'word' and value == '-like' and i + 1 < len(tokens) and tokens[i+1].kind == 'string':
            pattern = tokens[i+1].value.casefold()
            reflection_pattern |= '*' in pattern and pattern.endswith('iutils')
        if (token.kind in {"word", "string"} and i and tokens[i-1].kind == 'op'
                and previous in {".", "::"} and following == "("):
            result.members.add(value.casefold())
            if previous == '.' and value.casefold() in {'run', 'exec', 'shellexecute'} and i >= 2:
                begin = group_starts.get(i - 2)
                progid = shell_constructor(begin, i - 1) if begin is not None else ''
                if tokens[i-2].kind == 'variable':
                    progid = shell_receivers.get(variable_name(tokens[i-2].value), '')
                result.starts_program |= value.casefold() in _SHELL_METHODS.get(progid, ())
            if value.casefold() in {'getmethod', 'getprocaddress'}:
                member_literal(i, value.casefold())
            if value.casefold() == 'invoke' and i >= 3 and tokens[i-3].value in {'.', '::'} and tokens[i-2].kind in {'word', 'string'}:
                result.members.add(tokens[i-2].value.casefold())
            if value.casefold() == 'invokescript':
                result.evaluates_code = True
            if value.casefold() == 'newscriptblock' or invoking_member_target and value.casefold() in {'getcmdlet', 'getcommand'}:
                result.evaluates_code = True
                if invoking_member_target and value.casefold() in {'getcmdlet', 'getcommand'}:
                    result.obfuscation.add('command-lookup')
                    result.obfuscated_execution = True
            invoking_member_target = False
            if previous == "::" and i > 2 and tokens[i-2].kind == "op" and tokens[i-2].value == "]":
                j = i - 3
                lower = max(0, i - 64)
                while j >= lower and not (tokens[j].kind == 'op' and tokens[j].value in {"[", ";", "\n"}):
                    j -= 1
                if j >= lower and tokens[j].kind == 'op' and tokens[j].value == "[":
                    parts = tokens[j+1:i-2]
                    if sum(len(part.value) for part in parts) <= 1024:
                        typename = "".join(t.value for t in parts)
                        result.static_calls.add((typename.casefold(), value.casefold()))
                        result.starts_program |= (typename.casefold() in {'diagnostics.process', 'system.diagnostics.process'}
                                                  and value.casefold() == 'start')
        if value in {";", "\n", "|", "&&", "{", "}"} and token.kind == "op":
            if value in {'{', '}'}:
                shell_receivers.clear()
            finish()
            start, called, command, args = True, False, "", []
            invoking_member_target = False
            continue
        if token.kind == "word" and i and tokens[i-1].kind == 'word' and previous in {"function", "filter"}:
            result.definitions.add(command_name(value))
            start = False
            continue
        member_dot = (value == '.' and i and (tokens[i-1].kind in {'variable', 'word', 'string'}
                                             or previous in {')', ']'}))
        if value in {"&", "."} and token.kind == "op" and not member_dot and (start or value == "&"):
            if value == "&" and previous.endswith('>'):
                continue
            start, called = True, True
            result.dynamic_invocation = True
            invoking_member_target = i + 1 < len(tokens) and (tokens[i+1].kind == 'variable' or following == '(')
            if i + 1 < len(tokens):
                target = tokens[i+1]
                result.starts_program |= (target.kind in {'variable', 'data'}
                                          or target.kind in {'word', 'string'} and _program_target(target.value))
            if following == '(':
                end = group_ends.get(i + 1, i + 1)
                path_call = 'path-call' in tokens[i+1].transforms
                result.starts_program |= path_call
                if not path_call and constructed_prefix[end] > constructed_prefix[i + 2]:
                    result.obfuscation.add('unresolved-constructed-target')
                    result.obfuscated_execution = result.evaluates_code = True
            continue
        if token.kind == 'op' and value == '(':
            member_arguments = i > 1 and tokens[i-1].kind in {'word', 'string'} and tokens[i-2].value in {'.', '::'}
            contexts.append((start, called, command, args, evaluating))
            evaluating = ('path-call' not in token.transforms and (evaluating or called or command in evaluators
                          or (member_arguments and previous.casefold() == 'invokescript')))
            start, called, command, args = not member_arguments, False, '', []
            continue
        if token.kind == 'op' and value == ')':
            finish()
            if contexts:
                start, called, command, args, evaluating = contexts.pop()
                if called:
                    start, called = False, False
                    invoking_member_target = False
            continue
        if token.kind == 'op' and value == '[':
            type_depth += 1
            continue
        if token.kind == 'op' and value == ']':
            type_depth = max(0, type_depth - 1)
            start = False
            continue
        if type_depth:
            continue
        if token.kind == "op" and value == "=":
            start = True
            continue
        if token.kind in {"word", "string"} and start:
            name = command_name(value)
            command_position = ((token.kind == "word" or called) and (called or previous not in {"[", ".", "::"})
                                and following not in {"::", ".", "=", "["})
            if command_position and _program_target(value):
                result.starts_program = True
                shell_receivers.clear()
            if (command_position and name not in keywords
                    and re.fullmatch(r'[a-z_][\w.-]*', name, re.ASCII)):
                command = name
                result.commands.add(command)
                result.evaluates_code |= command in evaluators
                result.obfuscated_execution |= bool(transforms)
                if command != 'new-object':
                    shell_receivers.clear()
            start, called = False, False
        elif command and token.kind in {"word", "string", "variable"}:
            args.append(value.casefold())
            if command in evaluators:
                result.obfuscated_execution |= bool(transforms)
        if evaluating and transforms:
            result.obfuscated_execution = True
    finish()
    result.reflection_filter = reflection_pattern and 'gettypes' in result.members
    result.partial |= bool(stack)
    if stack:
        result.limits.add('unbalanced_syntax')
    return result


def read_script(text: str) -> Script:
    """Read expandable-string code iteratively, without a recursion or executable-evaluation path."""
    result, pending, remaining = Script(), [text], MAX_READ_CHARS
    from romulus.detect.powershell_constants import MAX_STEPS
    constant_budget = [MAX_READ_CHARS, MAX_STEPS]
    while pending and remaining > 0:
        source = pending.pop()
        clipped = len(source) > remaining
        lexical_limits = set()
        tokens, partial = lex(source[:remaining] if clipped else source, limits=lexical_limits)
        remaining -= len(source)
        partial |= clipped
        pending.extend(token.value for token in tokens if token.kind == "expression")
        parsed = _read_tokens([token for token in tokens if token.kind != "expression"], partial, constant_budget)
        result.limits.update(lexical_limits | parsed.limits)
        if clipped:
            result.limits.add('MAX_READ_CHARS=2097152')
        for name in ("commands", "definitions", "members", "member_literals", "static_calls", "literals", "variables", "obfuscation", "inert_words"):
            getattr(result, name).update(getattr(parsed, name))
        for command, arguments in parsed.arguments.items():
            result.arguments.setdefault(command, []).extend(arguments)
        result.dynamic_invocation |= parsed.dynamic_invocation
        result.obfuscated_execution |= parsed.obfuscated_execution
        result.evaluates_code |= parsed.evaluates_code
        result.starts_program |= parsed.starts_program
        result.reflection_filter |= parsed.reflection_filter
        room = max(0, 256 - len(result.constant_folds))
        result.constant_folds.extend(parsed.constant_folds[:room])
        result.fold_evidence_truncated |= len(parsed.constant_folds) > room or parsed.fold_evidence_truncated
        result.partial |= parsed.partial
    result.partial |= bool(pending)
    if pending:
        result.limits.add('MAX_READ_CHARS=2097152')
    return result


def read_event_script(event):
    """Share one bounded reading on the live batch object; the cache is never serialized or hunt-global."""
    text = str(event.get("script.text") or "")
    module_payload = str(event.get('script.module_payload') or '')
    code = event.get('event.code')
    previous = event.__dict__.get("_powershell_reading")
    if previous is None or previous[0] != (code, text, module_payload):
        parsed = _read_module_payload(text) if code == 4103 else read_script(text)
        if code == 800:
            parsed.partial = True
            parsed.limits.add('legacy_pipeline_source_incomplete')
            if module_payload:
                bindings = _read_module_payload(module_payload)
                parsed.commands.update(bindings.commands)
                parsed.module_bindings.extend(bindings.module_bindings)
                parsed.module_binding_data |= bindings.module_binding_data
        previous = ((code, text, module_payload), parsed)
        event.__dict__["_powershell_reading"] = previous
    return previous[1]


_MODULE_COMMAND = re.compile(r'^CommandInvocation\(([\w.\\/-]+)\):\s*"([^"\r\n]*)"\s*$', re.IGNORECASE)
_MODULE_BINDING = re.compile(r'^ParameterBinding\(([\w.\\/-]+)\):\s*name="([^"\r\n]*)";\s*value="(.*)"\s*$', re.IGNORECASE)


def _read_module_payload(text):
    """Module-log bindings are data, never executable PowerShell source.

    Microsoft documents these records as CommandInvocation and ParameterBinding lines.
    Missing source/binding completeness remains partial, including otherwise valid records.
    """
    result = Script(partial=True, limits={'module_invocation_source_incomplete'})
    header = True
    for line in text[:MAX_READ_CHARS].splitlines()[:MAX_TOKENS]:
        if not line.strip():
            continue
        command = _MODULE_COMMAND.fullmatch(line.strip()) if header else None
        header = False
        if command and command[1].casefold() == command[2].casefold():
            name = command[1].casefold()
            result.commands.add(name)
            result.evaluates_code |= name in {'iex', 'invoke-expression'}
        else:
            binding = _MODULE_BINDING.fullmatch(line.strip())
            if binding:
                result.module_binding_data = True
                result.inert_words.update(re.findall(r'[a-z][\w-]*', binding[3].casefold()))
                # Keep serialized bindings as evidence, separate from executable command arguments.
                result.module_bindings.append((binding[1].casefold(), binding[2].casefold(), binding[3]))
            else:
                result.inert_words.update(re.findall(r'[a-z][\w-]*', line.casefold()))
    return result
