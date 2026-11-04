"""Curated native argument grammars and their primary behavioral sources."""

from romulus.detect.windows_cmdline import is_remote_path

ARGV_SHAPES = {
    'wmic.exe': ('format_stylesheet', 'T1220', 'https://lolbas-project.github.io/lolbas/Binaries/Wmic/'),
    'msxsl.exe': ('xml_transform', 'T1220', 'https://lolbas-project.github.io/lolbas/OtherMSBinaries/Msxsl/'),
    'pcalua.exe': ('application', 'T1202', 'https://lolbas-project.github.io/lolbas/Binaries/Pcalua/'),
    'ftp.exe': ('script_file', 'T1202', 'https://lolbas-project.github.io/lolbas/Binaries/Ftp/'),
    'explorer.exe': ('root_target', 'T1202', 'https://lolbas-project.github.io/lolbas/Binaries/Explorer/'),
    'vshadow.exe': ('exec_target', 'T1202', 'https://lolbas-project.github.io/lolbas/OtherMSBinaries/Vshadow/'),
    'desktopimgdownldr.exe': ('lockscreen_url', 'T1105', 'https://lolbas-project.github.io/lolbas/Binaries/Desktopimgdownldr/'),
    'schtasks.exe': ('writable_task_xml', 'T1053.005', 'https://learn.microsoft.com/windows-server/administration/windows-commands/schtasks-create'),
    'cmstp.exe': ('writable_profile', 'T1218.003', 'https://lolbas-project.github.io/lolbas/Binaries/Cmstp/'),
    'wusa.exe': ('windows_extract', 'T1548.002', 'https://learn.microsoft.com/troubleshoot/windows-client/installing-updates-features-roles/command-line-switches-deploy-update-packages'),
}

# These are observed attempted option spellings, not documented accepted switches.
# https://www.unicode.org/reports/tr44/#General_Category_Values
DASH_LIKE = frozenset({'-', '‐', '‑', '‒', '–', '—', '―', '−', '﹘', '﹣', '－'})


def switch_operand(argv, names, *, separators=(':', '='), short_attached=False):
    """Yield values bound to exact native switch names in one linear argv pass."""
    for index, token in enumerate(argv[1:], start=1):
        if not token.startswith(('/', '-')):
            continue
        body = token[1:]
        lowered = body.casefold()
        for name in names:
            if lowered == name:
                if index + 1 < len(argv):
                    value = argv[index + 1]
                    if value and (not value.startswith(('/', '-')) or is_remote_path(value)):
                        yield value
            elif any(lowered.startswith(name + separator) for separator in separators):
                value = body[len(name) + 1:]
                if value:
                    yield value
            elif short_attached and len(name) == 1 and lowered.startswith(name) and len(body) > 1:
                value = body[1:]
                # Attached one-letter switches are accepted only when the operand
                # itself looks like an explicit path/URL, not another long flag.
                if (any(character in value for character in ('\\', ':', '/'))
                        or value.casefold().endswith(('.msi', '.msp'))):
                    yield value

