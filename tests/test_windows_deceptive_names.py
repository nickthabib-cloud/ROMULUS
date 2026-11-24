"""win.deceptive_file_name: bidirectional overrides, document-then-executable extensions and user-path screen
savers, read from typed process images, script-host operands and created files."""
import pytest

from romulus.detect.registry import ALL_PLAYBOOKS
from romulus.detect.windows_deceptive_names import DeceptiveFileName, displayed, double_extension, escaped
from tests.test_windows_process_w4 import native
from tests.windows_process_support import run

RLO = "\u202e"
DOWNLOADS = "C:\\Users\\alice\\Downloads\\"
SECURITY = ("Security", "Microsoft-Windows-Security-Auditing")


def proc(image, n=1, *, command="", code=1, host="host.example.test"):
    data = {"Image": image, "CommandLine": command or f'"{image}"', "ParentImage": r"C:\Windows\explorer.exe",
            "ProcessId": "4100"}
    if code == 4688:
        data = {"NewProcessName": image, "CommandLine": command, "NewProcessId": "0x1004"}
        return native(data, n, code=4688, host=host, offset=n, channel=SECURITY[0], provider=SECURITY[1])[0]
    return native(data, n, code=1, host=host, offset=n)[0]


def created(path, n=1, *, writer=r"C:\Program Files\Mozilla Firefox\firefox.exe", host="host.example.test"):
    return native({"Image": writer, "ProcessId": "900", "TargetFilename": path}, n, code=11, host=host, offset=n)[0]


def judge(event):
    rule = DeceptiveFileName()
    try:
        return rule.judge(event)
    finally:
        rule.release_state()


def test_the_rule_is_registered_with_its_event_classes():
    assert DeceptiveFileName in ALL_PLAYBOOKS
    assert {code for _channel, _provider, code in DeceptiveFileName.windows_event_classes} == {1, 4688, 11}
    assert set(DeceptiveFileName.card) >= {"behavior", "telemetry", "fidelity", "benign_and_cost", "query_cost",
                                           "next_pivot", "adds", "research_basis", "retrieval", "lanes"}


@pytest.mark.parametrize("code", [1, 4688])
def test_a_process_image_with_a_right_to_left_override_is_high(code):
    [hit] = judge(proc(DOWNLOADS + f"invoice{RLO}fdp.exe", code=code, command="x"))
    assert (hit.lane, hit.severity) == ("high", "high") and hit.attack == ("T1036.002", "T1204.002")
    assert "RIGHT-TO-LEFT OVERRIDE" in hit.text and "[U+202E]" in hit.text and RLO not in hit.text
    assert "reads on screen roughly as 'invoiceexe.pdf'" in hit.text
    assert any(p.field.startswith("process.executable") for p in hit.predicate)


def test_a_created_file_with_an_override_is_high_and_not_said_to_have_run():
    [hit] = judge(created(DOWNLOADS + f"photo{RLO}gpj.scr"))
    assert hit.lane == "high" and hit.attack == ("T1036.002",)
    assert "whether the file was opened or run is not shown" in hit.text


@pytest.mark.parametrize("name", ["report.pdf.exe", "Scan_0042.JPG.scr", "invoice.docx.com", "song.mp3.pif",
                                  "statement.pdf          .exe"])
def test_an_executed_double_extension_is_high(name):
    [hit] = judge(proc(DOWNLOADS + name))
    assert hit.lane == "high" and "T1036.007" in hit.attack and "the process was created" in hit.text
    assert ("padding" in hit.text) == ("   " in name)


@pytest.mark.parametrize("host", ["wscript.exe", "cscript.exe", "mshta.exe"])
def test_a_script_host_running_a_double_extension_script_is_high(host):
    script = DOWNLOADS + "Order_Details.pdf.js" if host != "mshta.exe" else DOWNLOADS + "notice.txt.hta"
    [hit] = judge(proc("C:\\Windows\\System32\\" + host, command=f'{host} //B //Nologo "{script}"'))
    assert hit.lane == "high" and f"script run by {host}" in hit.text


def test_a_created_double_extension_file_is_a_lead_that_folds_per_directory():
    events = [created(DOWNLOADS + f"invoice{i}.pdf.exe", i + 1) for i in range(30)]
    rule = DeceptiveFileName()
    try:
        [match] = run(rule, [[event] for event in events])
    finally:
        rule.release_state()
    assert match.proposed_lane == "lead" and "30 Windows event record(s)" in match.claim
    assert len(match.events) <= 16


def test_a_screen_saver_from_a_user_path_is_a_lead_and_one_in_system32_is_not():
    [hit] = judge(proc(r"C:\Users\alice\AppData\Local\Temp\update.scr"))
    assert hit.lane == "lead" and "screen saver" in hit.text
    assert judge(proc(r"C:\Windows\System32\Bubbles.scr")) == []


@pytest.mark.parametrize("event", [
    lambda: proc(r"C:\Program Files\Python312\python-3.12.1-amd64.exe"),        # versions are not decoys
    lambda: proc(DOWNLOADS + "setup.x64.exe"),
    lambda: proc(DOWNLOADS + "jquery.min.js.exe"),
    lambda: proc(r"C:\Windows\System32\notepad.exe", command=r"notepad.exe C:\docs\report.pdf.exe.txt"),
    lambda: proc(r"C:\Windows\System32\cmd.exe", command=r'cmd /c echo invoice.pdf.exe'),  # a name in text
    lambda: proc(r"C:\Windows\System32\findstr.exe", command=r'findstr /s ".pdf.exe" C:\logs\*'),  # a search
    lambda: created(r"C:\Users\alice\AppData\Roaming\Microsoft\Windows\Recent\report.pdf.lnk",
                    writer=r"C:\Windows\explorer.exe"),                        # Explorer's own Recent shortcut
    lambda: created(r"C:\Users\alice\AppData\Roaming\Microsoft\Office\Recent\budget.xlsx.LNK",
                    writer=r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"),
    lambda: created(DOWNLOADS + "archive.tar.gz"),
    lambda: created(DOWNLOADS + "report.pdf"),
    lambda: created(DOWNLOADS + ".pdf.exe"),                                   # no visible stem to deceive with
    lambda: created(DOWNLOADS + "partial.pdf.crdownload"),
    lambda: proc(r"C:\Windows\System32\wscript.exe", command=r"wscript.exe C:\scripts\logon.vbs"),
])
def test_hard_benign_lookalikes_are_not_reported(event):
    assert judge(event()) == []


def test_a_script_host_without_a_recorded_command_line_is_noted_not_judged():
    rule = DeceptiveFileName()
    try:
        event = proc(r"C:\Windows\System32\wscript.exe", code=4688, command="")
        assert rule.judge(event) == []
        assert any("without a recorded command line" in note for note in rule.coverage_notes())
    finally:
        rule.release_state()


def test_records_without_a_path_or_of_other_classes_are_not_matched():
    assert judge(created("")) == []
    other = native({"Image": DOWNLOADS + "report.pdf.exe", "TargetObject": "HKLM\\x"}, 1, code=13)[0]
    assert judge(other) == []


def test_helpers():
    assert double_extension("a.pdf.exe") == ("pdf", "exe", False)
    assert double_extension("a.pdf.txt") is None and double_extension("a.exe") is None
    assert escaped(f"a{RLO}b") == "a[U+202E]b" and displayed(f"x{RLO}fdp.exe") == "xexe.pdf"
    assert displayed(f"x{RLO}cod\u202c.exe") == "xdoc.exe"


def test_a_fleets_ordinary_processes_and_downloads_give_nothing_but_the_disguised_one():
    images = [r"C:\Program Files\Google\Chrome\Application\chrome.exe", r"C:\Windows\System32\svchost.exe",
              r"C:\Users\bob\AppData\Local\Programs\Microsoft VS Code\Code.exe", r"C:\Windows\System32\cmd.exe"]
    files = ["report-2024.pdf", "photo.final.jpg", "setup.x64.exe", "data.tar.gz", "notes.txt.bak"]
    events = []
    for n in range(4_000):
        events.append(proc(images[n % len(images)], n + 1, host=f"ws{n % 50:03d}.example.test"))
        events.append(created(DOWNLOADS + files[n % len(files)], n + 1, host=f"ws{n % 50:03d}.example.test"))
    events.append(proc(DOWNLOADS + "Payroll.xlsx.exe", 9_999, host="ws007.example.test"))
    rule = DeceptiveFileName()
    try:
        out = run(rule, [events[i:i + 500] for i in range(0, len(events), 500)])
    finally:
        rule.release_state()
    assert [(m.proposed_lane, "Payroll.xlsx.exe" in m.claim) for m in out] == [("high", True)]


def test_real_sweep_publishes_the_executed_override_at_high(tmp_path, monkeypatch):
    from tests.test_windows_process_w4 import sweep_run
    batch = [native({"Image": DOWNLOADS + f"cv{RLO}cod.scr", "CommandLine": "x",
                     "ParentImage": r"C:\Windows\explorer.exe", "ProcessId": "4100"}, 1, offset=1)]
    found, _rule = sweep_run(tmp_path, monkeypatch, DeceptiveFileName(), [batch])
    [saved] = found
    assert saved["lane"] == "high" and "[U+202E]" in saved["claim"] and RLO not in saved["claim"]


RLE, LRE, PDF, FSI, PDI = "\u202b", "\u202a", "\u202c", "\u2068", "\u2069"


def test_direction_controls_without_an_override_in_an_executable_name_are_leads_folded_per_directory():
    folder = "C:\\Users\\amir\\Documents\\" + RLE + "\u062a\u0642\u0627\u0631\u064a\u0631" + PDF + "\\"
    events = [created(folder + name, n + 1) for n, name in enumerate(["notes.txt", "budget.xlsx", "photo.jpg"])]
    rule = DeceptiveFileName()
    try:
        out = run(rule, [[event] for event in events])
    finally:
        rule.release_state()
    assert len(out) == 1 and out[0].proposed_lane == "lead" and "3 Windows event record(s)" in out[0].claim
    assert [h.lane for h in judge(created(DOWNLOADS + FSI + "\u0645\u0644\u0641" + PDI + ".docx"))] == ["lead"]
    assert [h.lane for h in judge(created(DOWNLOADS + LRE + "report.pdf"))] == ["lead"]
    assert [h.lane for h in judge(created(DOWNLOADS + "report" + RLO + "fdp.txt"))] == ["lead"]


@pytest.mark.parametrize("name", ["invoice.pdf\u2003.exe", "invoice.pdf\u200b.exe", "invoice.pdf\u3000\u3000\u3000.exe",
                                  "invoice.pdf\ufeff.exe"])
def test_unicode_space_and_zero_width_padding_before_the_real_extension_is_read(name):
    [hit] = judge(proc(DOWNLOADS + name))
    assert hit.lane == "high" and "padding" in hit.text
