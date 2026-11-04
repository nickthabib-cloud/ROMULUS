"""Bounded interpretation of a small, nonexecuting subset of constant PowerShell expressions.

Only literal strings/numbers, exact straight-line assignments and the documented concat,
indexed-format, character-cast and join operations are interpreted. No runtime, imports,
reflection, general member dispatch or telemetry-derived Python formatting is used.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace

MAX_VALUE_CHARS = 65_536
MAX_CONSTANT_WORK = 2_097_152
MAX_STEPS = 180_000
MAX_DEPTH = 32
MAX_ITEMS = 4096
MAX_FOLD_EVIDENCE = 256
OBFUSCATING = frozenset({'concatenation', 'format-string', 'character-cast', 'char-join',
                         'string-join', 'backtick', 'embedded-quotes', 'command-lookup'})
_NUMBER = re.compile(r'(?:0x[0-9a-f]+|[0-9]+)\Z', re.ASCII)
_VARIABLE = re.compile(r'\$[a-z_][\w]*\Z', re.ASCII)
_VARIABLE_MUTATORS = frozenset({'sv', 'set-variable', 'set', 'clv', 'clear-variable', 'rv', 'remove-variable'})


@dataclass(frozen=True)
class Constant:
    value: str | int | tuple
    transforms: frozenset[str] = frozenset()


def variable_name(value):
    return '$' + value[2:-1] if value.startswith('${') and value.endswith('}') else value


class _Unknown(Exception):
    pass


class _Limited(Exception):
    pass


class _Reader:
    def __init__(self, tokens, budget=None, limits=None):
        self.tokens, self.variables = tokens, {}
        self.mutated_arrays = {}
        self.budget = [MAX_CONSTANT_WORK, MAX_STEPS] if budget is None else budget
        self.partial = False
        self.limits = set() if limits is None else limits
        self.furthest = 0

    @property
    def work(self):
        return self.budget[0]

    @work.setter
    def work(self, value):
        self.budget[0] = value

    def limit(self, name):
        if name.startswith('MAX_VALUE_CHARS'):
            # A complete large data value is outside this constant subset, not missing source.
            raise _Unknown
        self.partial = True
        self.limits.add(name)
        raise _Limited

    def value(self, index):
        return self.tokens[index].value if index < len(self.tokens) else ''

    def scan_items(self, values):
        if len(values) > MAX_ITEMS:
            self.limit('MAX_ITEMS=4096')
        if len(values) > self.work:
            self.limit('MAX_CONSTANT_WORK=2097152')
        self.work -= len(values)

    def invalidate_mutator(self, position):
        position += int(self.value(position) == '-name')
        if position < len(self.tokens) and self.tokens[position].kind in {'word', 'string'}:
            name = self.value(position).casefold().lstrip('$')
            if re.fullmatch(r'[a-z_][\w]*', name, re.ASCII):
                self.variables.pop('$' + name, None)
                return
        self.variables.clear()

    def make(self, value, transforms=frozenset()):
        if isinstance(value, tuple):
            self.scan_items(value)
        if isinstance(value, tuple) and not all(isinstance(item, (str, int)) for item in value):
            raise _Unknown
        size = sum(len(str(item)) for item in value) if isinstance(value, tuple) else len(str(value))
        if size > MAX_VALUE_CHARS:
            self.limit('MAX_VALUE_CHARS=65536')
        if size > self.work:
            self.limit('MAX_CONSTANT_WORK=2097152')
        self.work -= size
        return Constant(value, frozenset(transforms))

    def expression(self, index, precedence=0, depth=0, *, call_target=False):
        self.budget[1] -= 1
        self.furthest = max(self.furthest, index)
        if self.budget[1] < 0:
            self.limit('MAX_STEPS=180000')
        if depth > MAX_DEPTH:
            self.limit('MAX_DEPTH=32')
        if index >= len(self.tokens):
            raise _Unknown
        token, value = self.tokens[index], self.value(index)
        if token.kind == 'string':
            left, end = self.make(value, token.transforms), index + 1
        elif token.kind == 'variable' and variable_name(value) in self.variables:
            if self.value(index + 1) in {'[', '.', '::'}:
                # An unresolved index/member expression is not the value of its variable prefix.
                raise _Unknown
            stored = self.variables[variable_name(value)]
            if isinstance(stored.value, tuple) and id(stored.value) in self.mutated_arrays:
                raise _Unknown
            left, end = self.make(stored.value, stored.transforms), index + 1
        elif token.kind == 'word' and _NUMBER.fullmatch(value):
            if len(value) > 10:
                raise _Unknown
            left, end = self.make(int(value, 16 if value.startswith('0x') else 10)), index + 1
        elif token.kind == 'word' and value == '-join':
            operand, end = self.expression(index + 1, 80, depth + 1)
            items = operand.value if isinstance(operand.value, tuple) else (operand.value,)
            self.scan_items(items)
            if not all(isinstance(item, str) for item in items):
                raise _Unknown
            left = self.make(''.join(items), operand.transforms | {'char-join'})
        elif token.kind == 'op' and value in {'(', '@'}:
            begin = index + 1
            force_array = value == '@'
            if force_array:
                if self.value(begin) != '(':
                    raise _Unknown
                begin += 1
            items, end = self.items(begin, ')', depth + 1, call_target=call_target)
            if len(items) == 1 and not force_array:
                left = items[0]
            else:
                left = self.make(tuple(item.value for item in items), set().union(*(item.transforms for item in items)))
        elif token.kind == 'op' and value == '[':
            left, end = self.typed(index, depth + 1)
        elif call_target and token.kind == 'word' and value in {'gcm', 'get-command', 'gal', 'get-alias'}:
            position = index + 1 + int(self.value(index + 1) == '-name')
            target = self.tokens[position] if position < len(self.tokens) else None
            if target and target.kind == 'op' and target.value == '(':
                resolved, after = self.expression(position, depth=depth + 1)
                target_value = resolved.value
            else:
                target_value, after = target.value if target and target.kind in {'word', 'string'} else None, position + 1
            if not isinstance(target_value, str) or not re.fullmatch(r'[a-z][\w-]*', target_value.casefold(), re.ASCII):
                raise _Unknown
            left, end = self.make(target_value.casefold(), {'command-lookup'}), after
        else:
            raise _Unknown
        if call_target and token.kind == 'op' and value == '(':
            return left, end
        while end < len(self.tokens):
            operator = self.tokens[end]
            rank = {'+': 40, '-f': 70, '-join': 30}.get(operator.value, -1)
            if rank < precedence or operator.kind not in {'word', 'op'}:
                break
            right, after = self.expression(end + 1, rank + 1, depth + 1)
            transforms = left.transforms | right.transforms
            if operator.value == '+':
                if isinstance(left.value, str) and isinstance(right.value, (str, int)):
                    right_text = str(right.value)
                    if len(left.value) + len(right_text) > min(MAX_VALUE_CHARS, self.work):
                        self.limit('MAX_VALUE_CHARS=65536' if len(left.value) + len(right_text) > MAX_VALUE_CHARS
                                   else 'MAX_CONSTANT_WORK=2097152')
                    left = self.make(left.value + right_text, transforms | {'concatenation'})
                elif isinstance(left.value, int) and isinstance(right.value, int):
                    left = self.make(left.value + right.value, transforms)
                else:
                    raise _Unknown
            elif operator.value == '-join':
                values = left.value if isinstance(left.value, tuple) else (left.value,)
                self.scan_items(values)
                if not isinstance(right.value, str) or not all(isinstance(item, str) for item in values):
                    raise _Unknown
                size = sum(map(len, values)) + max(0, len(values) - 1) * len(right.value)
                if size > min(MAX_VALUE_CHARS, self.work):
                    self.limit('MAX_VALUE_CHARS=65536' if size > MAX_VALUE_CHARS else 'MAX_CONSTANT_WORK=2097152')
                left = self.make(right.value.join(values), transforms | {'char-join'})
            else:
                arguments = list(right.value) if isinstance(right.value, tuple) else [right.value]
                while self.value(after) == ',':
                    item, after = self.expression(after + 1, rank + 1, depth + 1)
                    arguments.append(item.value)
                    transforms |= item.transforms
                    if len(arguments) > MAX_ITEMS:
                        self.limit('MAX_ITEMS=4096')
                left = self.make(self.format(left.value, arguments), transforms | {'format-string'})
            end = after
        return left, end

    def items(self, begin, closing, depth, *, call_target=False):
        items, end = [], begin
        if self.value(end) == closing:
            return items, end + 1
        while True:
            item, end = self.expression(end, depth=depth, call_target=call_target)
            items.append(item)
            if len(items) > MAX_ITEMS:
                self.limit('MAX_ITEMS=4096')
            if self.value(end) == closing:
                return items, end + 1
            if self.value(end) != ',':
                raise _Unknown
            end += 1

    def typed(self, index, depth):
        end = index + 1
        # Only the small known type spelling is read, never a scan to a distant bracket.
        while end < min(index + 8, len(self.tokens)) and self.value(end) != ']':
            end += 1
        if self.value(end) != ']':
            raise _Unknown
        typename = ''.join(token.value for token in self.tokens[index + 1:end])
        if typename.endswith('[') and self.value(end + 1) == ']':
            typename, end = typename + ']', end + 1
        if typename in {'string', 'system.string'} and self.value(end + 1) == '::' and self.value(end + 2) == 'join' and self.value(end + 3) == '(':
            arguments, end = self.items(end + 4, ')', depth + 1)
            if len(arguments) < 2 or not isinstance(arguments[0].value, str):
                raise _Unknown
            values = arguments[1].value if len(arguments) == 2 and isinstance(arguments[1].value, tuple) else tuple(item.value for item in arguments[1:])
            self.scan_items(values)
            if not all(isinstance(item, str) for item in values):
                raise _Unknown
            separator = arguments[0].value
            size = sum(map(len, values)) + len(separator) * max(0, len(values) - 1)
            if size > min(MAX_VALUE_CHARS, self.work):
                self.limit('MAX_VALUE_CHARS=65536' if size > MAX_VALUE_CHARS else 'MAX_CONSTANT_WORK=2097152')
            return self.make(separator.join(values), set().union(*(item.transforms for item in arguments)) | {'string-join'}), end
        if typename not in {'char', 'system.char', 'char[]', 'system.char[]', 'string', 'system.string'}:
            raise _Unknown
        operand, end = self.expression(end + 1, 80, depth + 1)
        if typename in {'string', 'system.string'}:
            if not isinstance(operand.value, (str, int)):
                raise _Unknown
            return self.make(str(operand.value), operand.transforms), end
        values = operand.value if isinstance(operand.value, tuple) else tuple(operand.value) if isinstance(operand.value, str) and typename.endswith('[]') else (operand.value,)
        self.scan_items(values)
        chars = []
        for value in values:
            if isinstance(value, int) and 0 <= value <= 0xffff:
                chars.append(chr(value))
            elif isinstance(value, str) and len(value) == 1:
                chars.append(value)
            else:
                raise _Unknown
        if not typename.endswith('[]') and len(chars) != 1:
            raise _Unknown
        return self.make(tuple(chars) if typename.endswith('[]') else chars[0], operand.transforms | {'character-cast'}), end

    def format(self, template, arguments):
        if not isinstance(template, str):
            raise _Unknown
        parts, index, size = [], 0, 0
        while index < len(template):
            # Charge scans even when a malformed placeholder later makes this fold fail.
            if self.work <= 0:
                self.limit('MAX_CONSTANT_WORK=2097152')
            self.work -= 1
            if template.startswith('{{', index) or template.startswith('}}', index):
                piece, index = template[index], index + 2
            elif template[index] == '{':
                match = re.match(r'\{([0-9]{1,4})\}', template[index:index + 8])
                if not match or int(match[1]) >= len(arguments):
                    raise _Unknown
                argument = arguments[int(match[1])]
                if not isinstance(argument, (str, int)):
                    raise _Unknown
                piece, index = str(argument), index + len(match[0])
            elif template[index] == '}':
                raise _Unknown
            else:
                piece, index = template[index], index + 1
            size += len(piece)
            if size > min(MAX_VALUE_CHARS, self.work):
                self.limit('MAX_VALUE_CHARS=65536' if size > MAX_VALUE_CHARS else 'MAX_CONSTANT_WORK=2097152')
            parts.append(piece)
        return ''.join(parts)


def fold_constants(tokens, budget=None, limits=None):
    """Return folded tokens, original token/value/transformation evidence and an honest work-limit flag."""
    reader, out, evidence, index = _Reader(tokens, budget, limits), [], [], 0
    call_in_statement, argument_mode, failed_until, limited_until = False, False, -1, -1
    pending_call_prior = None
    bracket_stack, bracket_ends = [], {}
    for position, item in enumerate(tokens):
        if item.kind == 'op' and item.value == '[':
            bracket_stack.append(position)
        elif item.kind == 'op' and item.value == ']' and bracket_stack:
            bracket_ends[bracket_stack.pop()] = position

    def writes_variable(position):
        following = position + 1
        while following < len(tokens) and tokens[following].kind == 'op' and tokens[following].value == '[':
            if following not in bracket_ends:
                return True
            following = bracket_ends[following] + 1
        operator = reader.value(following)
        return (operator in {'=', '++', '--', '+=', '-=', '*=', '/=', '%='} or operator in {'+', '-'}
                and reader.value(following + 1) in {'=', operator})

    def note_evidence(begin, end, value):
        if len(evidence) < MAX_FOLD_EVIDENCE:
            evidence.append((tuple((item.kind, item.value) for item in tokens[begin:end]),
                             str(value.value), tuple(sorted(value.transforms))))
        else:
            reader.limits.add('MAX_FOLD_EVIDENCE=256')

    def skip_limited_statement(begin):
        end = begin
        while end < len(tokens) and not (tokens[end].kind == 'op' and tokens[end].value in {';', '\n'}):
            item = tokens[end]
            if item.kind == 'variable' and writes_variable(end):
                stored = reader.variables.pop(variable_name(item.value), None)
                if stored and isinstance(stored.value, tuple) and reader.value(end + 1) == '[':
                    # Retain the value object so a later allocation cannot reuse its identity.
                    reader.mutated_arrays[id(stored.value)] = stored.value
            if item.kind == 'word' and item.value.rsplit('\\', 1)[-1] in _VARIABLE_MUTATORS:
                reader.invalidate_mutator(end + 1)
            end += 1
        return end

    while index < len(tokens):
        token = tokens[index]
        previous = tokens[index - 1].value if index else ''
        if token.kind == 'op' and token.value in {';', '\n'}:
            if call_in_statement:
                reader.variables.clear()
            call_in_statement = False
            argument_mode = False
            pending_call_prior = None
        if token.kind == 'op' and token.value in {'&', '.'}:
            pending_call_prior = call_in_statement
        if (token.kind == 'op' and (token.value == '&' or token.value == '.' and
                                  (not index or previous in {';', '\n', '{', '=', '('}))
                or token.kind == 'word' and (not index or previous in {';', '\n', '{', '=', '('})
                and not token.value.startswith('-') and not _NUMBER.fullmatch(token.value)
                and token.value.rsplit('\\', 1)[-1] not in _VARIABLE_MUTATORS
                or token.kind in {'word', 'string'} and previous in {'.', '::'}
                and index + 1 < len(tokens) and tokens[index + 1].value == '('):
            # Unknown commands may change session variables after their arguments are evaluated.
            call_in_statement = True
            argument_mode = True
        if (token.kind in {'word', 'string'} and token.value.casefold().rsplit('\\', 1)[-1] in _VARIABLE_MUTATORS
                and (token.kind == 'word' and (not index or previous in {';', '\n', '{', '=', '(', '|'})
                     or previous == '&' and (index < 2 or not tokens[index-2].value.endswith('>'))
                     or previous == '.' and (index == 1 or tokens[index-2].value in {
                         ';', '\n', '{', '=', '(', '|'}))):
            reader.invalidate_mutator(index + 1)
            if previous in {'&', '.'} and pending_call_prior is not None:
                call_in_statement, pending_call_prior = pending_call_prior, None
        if token.kind == 'op' and token.value in {'{', '}'}:
            # No control-flow or function execution is assumed across a scriptblock boundary.
            reader.variables.clear()
        if token.kind == 'op' and token.value in {'=', '+=', '-=', '*=', '/=', '%='}:
            # Only exact scalar assignments below are understood. Indexed/property writes,
            # compound writes and aliases may mutate any shared array/object constant.
            reader.variables.clear()
        if (token.kind in {'word', 'op'} and token.value in {'++', '--'}
                or token.kind == 'op' and token.value in {'+', '-'} and index + 1 < len(tokens)
                and tokens[index + 1].kind == 'op' and tokens[index + 1].value == token.value):
            reader.variables.clear()
        if token.kind == 'variable' and index + 1 < len(tokens) and tokens[index + 1].value == '=':
            name = variable_name(token.value)
            out.extend(tokens[index:index + 2])
            try:
                if index < limited_until:
                    raise _Unknown
                value, end = reader.expression(index + 2)
                typed_scalar = (index >= 3 and [item.value for item in tokens[index-3:index]] in
                                (['[', 'string', ']'], ['[', 'system.string', ']'])
                                and (index == 3 or tokens[index-4].value in {';', '\n', '{'}))
                scalar_target = not index or previous in {';', '\n', '{'} or typed_scalar
                if scalar_target and _VARIABLE.fullmatch(name) and (end == len(tokens) or tokens[end].value in {';', '\n', '}'}):
                    reader.variables[name] = value
                    if not isinstance(value.value, tuple):
                        out.append(replace(tokens[index + 2], kind='string' if isinstance(value.value, str) else 'word',
                                           value=str(value.value), transforms=value.transforms))
                        note_evidence(index + 2, end, value)
                        index = end
                        continue
                else:
                    reader.variables.clear()
            except _Limited:
                limited_until = skip_limited_statement(index)
                out.extend(tokens[index + 2:limited_until])
                index = max(index + 2, limited_until)
                continue
            except _Unknown:
                reader.variables.pop(name, None)
            index += 2
            continue
        if (token.kind == 'variable' and index + 2 < len(tokens)
                and tokens[index + 1].value in {'+', '-', '++', '--'} and tokens[index + 2].value in {'=', '+', '-'}):
            reader.variables.pop(variable_name(token.value), None)
        if (token.kind == 'op' and token.value == '(' and index >= 2
                and tokens[index - 1].kind in {'word', 'string'} and tokens[index - 2].value in {'.', '::'}):
            # Keep call parentheses: constant arguments are data, not a replacement for the call itself.
            out.append(token)
            index += 1
            continue
        try:
            if index < limited_until or index < failed_until:
                raise _Unknown
            target = index > 0 and tokens[index - 1].kind == 'op' and tokens[index - 1].value in {'&', '.'}
            reader.furthest = index
            value, end = reader.expression(index, 100 if argument_mode and token.value not in {'(', '[', '-join'} else 0,
                                           call_target=target)
            if target and isinstance(value.value, str) and value.value.casefold().rsplit('\\', 1)[-1] in _VARIABLE_MUTATORS:
                reader.invalidate_mutator(end)
                if pending_call_prior is not None:
                    call_in_statement, pending_call_prior = pending_call_prior, None
            if isinstance(value.value, tuple):
                raise _Unknown
            kind = 'string' if isinstance(value.value, str) else 'word'
            folded = replace(token, kind=kind, value=str(value.value), transforms=value.transforms)
            out.append(folded)
            if end > index + 1 or token.kind == 'variable':
                note_evidence(index, end, value)
            index = end
        except _Unknown:
            failed_until = max(failed_until, reader.furthest)
            out.append(token)
            index += 1
        except _Limited:
            limited_until = skip_limited_statement(index)
            end = max(index + 1, limited_until)
            out.extend(tokens[index:end])
            index = end
    return out, evidence, reader.partial
