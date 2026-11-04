"""Sourced process-argument request shapes beyond the dedicated proxy families."""
from __future__ import annotations

import json
import ntpath
from urllib.parse import urlsplit

from romulus.detect.windows_cmdline import is_remote_path, is_user_writable, split_argv
from romulus.detect.windows_common import Hit, WindowsProcessRule, clip, image_name, parsed_field
from romulus.detect.windows_lolbin_data import ARGV_SHAPES, switch_operand


def _extension(value):
    try:
        path = urlsplit(value).path if '://' in value else value
    except ValueError:
        return ''
    return ntpath.splitext(path.casefold())[1]


def _valid_operand(value):
    if '://' not in value:
        return True
    try:
        parsed = urlsplit(value)
        return bool(parsed.scheme and parsed.netloc) or parsed.scheme.casefold() == 'file'
    except ValueError:
        return False


def _windows_destination(value):
    text = ntpath.normpath(value.replace('/', '\\')).casefold()
    parts = [part for part in text.split('\\') if part]
    if parts and parts[0] in {'%windir%', '%systemroot%'}:
        return True
    return len(parts) >= 2 and len(parts[0]) == 2 and parts[0][1] == ':' and parts[1] == 'windows'


class LolbinArgvExecution(WindowsProcessRule):
    id = 'win.lolbin_argv_shape'
    title = 'A Windows utility received a sourced proxy-execution or transfer request'
    reads_command_line = True
    assures_negative = False
    positive_only_reason = 'These argument shapes show requests; their absence does not establish that proxy execution did not occur.'
    attack = ('T1220', 'T1202', 'T1105', 'T1053.005', 'T1218.003', 'T1548.002')
    benign = ('Approved administration, software delivery and transformation tools use these same features.',)
    next_checks = ('Inspect the named target and independently verify the resulting activity.',)

    def judge(self, event):
        name = image_name(event.get('process.executable_key'))[0]
        row = ARGV_SHAPES.get(name)
        if row is None:
            return []
        argv = split_argv(str(event.get('process.command_line') or ''))
        if len(argv) < 2 or any(token.casefold() in {'/?', '-?', '/help', '--help'} for token in argv[1:]):
            return []
        grammar, attack, source = row
        payload = None
        if grammar == 'format_stylesheet':
            payload = next((value for value in switch_operand(argv, ('format',), separators=(':',))
                            if is_remote_path(value) or _extension(value) in {'.xsl', '.xslt'}), None)
        elif grammar == 'xml_transform':
            values, skip = [], False
            for token in argv[1:]:
                if skip:
                    skip = False
                    continue
                if token.casefold() in {'-o', '/o'}:
                    skip = True
                    continue
                if token.startswith(('-', '/')) and not is_remote_path(token):
                    continue
                if len(values) < 2:
                    values.append(token)
            if len(values) == 2:
                payload = values[1]
        elif grammar == 'application':
            payload = next(switch_operand(argv, ('a',), separators=()), None)
        elif grammar == 'script_file':
            payload = next(switch_operand(argv, ('s',), separators=(':',)), None)
        elif grammar == 'root_target':
            payload = next((token[len('/root,'):] for token in argv[1:]
                            if token.casefold().startswith('/root,') and len(token) > len('/root,')), None)
        elif grammar == 'exec_target':
            payload = next(switch_operand(argv, ('exec',), separators=('=',)), None)
        elif grammar == 'lockscreen_url':
            payload = next((value for value in switch_operand(argv, ('lockscreenurl',), separators=(':',))
                            if is_remote_path(value)), None)
        elif grammar == 'writable_task_xml':
            if any(token.casefold() == '/create' for token in argv[1:]):
                payload = next((value for value in switch_operand(argv, ('xml',), separators=())
                                if is_user_writable(value)), None)
        elif grammar == 'writable_profile':
            if any(token.casefold() in {'/au', '/s', '-au', '-s'} for token in argv[1:]):
                payload = next((token for token in argv[1:] if _extension(token) in {'.inf', '.ini'}
                                and is_user_writable(token)), None)
        elif grammar == 'windows_extract':
            package = next((token for token in argv[1:] if _extension(token) in {'.msu', '.cab'}), None)
            if package:
                payload = next((value for value in switch_operand(argv, ('extract',), separators=(':',))
                                if _windows_destination(value)), None)
        if payload is None or not _valid_operand(payload):
            return []
        text = f"{name} received a {grammar.replace('_', ' ')} request naming '{clip(payload)}'"
        return [Hit('lolbin_argument_request', text, 'lead', 'medium', (attack,),
                    [parsed_field(event, clip(' '.join(argv[1:])))],
                    content=json.dumps([name, grammar, argv[1:]], ensure_ascii=True),
                    notes=(f'Behavior source: {source}',
                           'Arguments show a request, not proof of execution, transfer, elevation or a completed change.'))]


RULES = (LolbinArgvExecution,)
