"""The attack-path picture for the executive report: a bounded layout of the manifest's incidents and a PNG of it.

The layout takes the strongest incidents first (an urgent step, then high, then lead; multi-step incidents before
single findings) and draws at most `MAX_INCIDENTS` rows of at most `MAX_STEPS` steps each. Everything it does not
draw is counted, so the report can say how much is not drawn and where it is listed; nothing is dropped from the
report, only from the picture.

The picture carries no telemetry: only step numbers (each finding's row in the report's finding index), incident
row labels, times and fixed legend words, in a built-in pixel font. Every name and claim stays in real document text
beside it. A link is drawn solid only when it was observed; any other strength (inferred, agent, unknown) is drawn
dashed and tagged `H`, a hypothesis. Pure standard library and deterministic: the same manifest gives the same bytes.
"""
from __future__ import annotations

import itertools
import struct
import zlib

from romulus.report.ooxml import HYPOTHESIS_COLOR, LANE_COLORS

MAX_INCIDENTS = 8
MAX_STEPS = 6          # steps drawn per incident row; a longer incident shows its first five and a "+N" box
LANE_RANK = {"urgent": 0, "high": 1, "lead": 2}

# canvas geometry (pixels); the picture is placed 6.5 inches wide
WIDTH = 1600
LEGEND_H = 150
ROW_H = 180
LABEL_W = 150
RIGHT = 30
BOX_W, BOX_H = 176, 84


def _rgb(hex_color: str) -> bytes:
    return bytes.fromhex(hex_color)


WHITE, INK, GREY, LIGHT = _rgb("FFFFFF"), _rgb("1F2937"), _rgb("9CA3AF"), _rgb("E5E7EB")
OBSERVED = _rgb("111827")
HYPOTHESIS = _rgb(HYPOTHESIS_COLOR)
OTHER_LANE = "6B7280"

# 5x7 glyphs, one string of five bits per row, for the fixed vocabulary the picture uses
_FONT_ROWS = {
    "A": "01110 10001 10001 11111 10001 10001 10001", "B": "11110 10001 10001 11110 10001 10001 11110",
    "C": "01110 10001 10000 10000 10000 10001 01110", "D": "11110 10001 10001 10001 10001 10001 11110",
    "E": "11111 10000 10000 11110 10000 10000 11111", "F": "11111 10000 10000 11110 10000 10000 10000",
    "G": "01110 10001 10000 10111 10001 10001 01111", "H": "10001 10001 10001 11111 10001 10001 10001",
    "I": "01110 00100 00100 00100 00100 00100 01110", "J": "00111 00010 00010 00010 00010 10010 01100",
    "K": "10001 10010 10100 11000 10100 10010 10001", "L": "10000 10000 10000 10000 10000 10000 11111",
    "M": "10001 11011 10101 10101 10001 10001 10001", "N": "10001 10001 11001 10101 10011 10001 10001",
    "O": "01110 10001 10001 10001 10001 10001 01110", "P": "11110 10001 10001 11110 10000 10000 10000",
    "Q": "01110 10001 10001 10001 10101 10010 01101", "R": "11110 10001 10001 11110 10100 10010 10001",
    "S": "01111 10000 10000 01110 00001 00001 11110", "T": "11111 00100 00100 00100 00100 00100 00100",
    "U": "10001 10001 10001 10001 10001 10001 01110", "V": "10001 10001 10001 10001 10001 01010 00100",
    "W": "10001 10001 10001 10101 10101 10101 01010", "X": "10001 10001 01010 00100 01010 10001 10001",
    "Y": "10001 10001 10001 01010 00100 00100 00100", "Z": "11111 00001 00010 00100 01000 10000 11111",
    "0": "01110 10001 10011 10101 11001 10001 01110", "1": "00100 01100 00100 00100 00100 00100 01110",
    "2": "01110 10001 00001 00010 00100 01000 11111", "3": "11111 00010 00100 00010 00001 10001 01110",
    "4": "00010 00110 01010 10010 11111 00010 00010", "5": "11111 10000 11110 00001 00001 10001 01110",
    "6": "00110 01000 10000 11110 10001 10001 01110", "7": "11111 00001 00010 00100 01000 01000 01000",
    "8": "01110 10001 10001 01110 10001 10001 01110", "9": "01110 10001 10001 01111 00001 00010 01100",
    " ": "00000 00000 00000 00000 00000 00000 00000", "+": "00000 00100 00100 11111 00100 00100 00000",
    "-": "00000 00000 00000 11111 00000 00000 00000", ":": "00000 01100 01100 00000 01100 01100 00000",
    "(": "00010 00100 01000 01000 01000 00100 00010", ")": "01000 00100 00010 00010 00010 00100 01000",
    ",": "00000 00000 00000 00000 01100 00100 01000", ".": "00000 00000 00000 00000 00000 01100 01100",
    "/": "00000 00001 00010 00100 01000 10000 00000", "=": "00000 00000 11111 00000 11111 00000 00000",
    "?": "01110 10001 00001 00010 00100 00000 00100", "#": "01010 01010 11111 01010 11111 01010 01010",
    ">": "01000 00100 00010 00001 00010 00100 01000",
}
FONT = {char: [[bit == "1" for bit in row] for row in rows.split()] for char, rows in _FONT_ROWS.items()}


def _lane_of(finding: dict | None) -> str:
    return (finding or {}).get("lane") or "unknown"


def _incident_order(incident: dict, by_id: dict[str, dict]) -> tuple:
    members = incident.get("finding_ids") or []
    best = min((LANE_RANK.get(_lane_of(by_id.get(item)), 9) for item in members), default=9)
    first = by_id.get((incident.get("timeline") or members or [""])[0]) or {}
    return (best, len(members) < 2, -len(members), first.get("observed_at") is None, first.get("observed_at") or "",
            incident.get("id") or "")


def edge_style(edge: dict) -> str:
    """`observed` only for a link stored as observed; every other strength is a hypothesis."""
    return "observed" if edge.get("style") == "observed" else "hypothesis"


def layout(manifest: dict, numbers: dict[str, int]) -> dict:
    """What the picture draws and what it leaves out. `numbers` maps a finding id to its row in the report's
    finding index (the label its box carries)."""
    graph = manifest.get("incident_graph") or {}
    by_id = {finding["id"]: finding for finding in manifest.get("findings") or []}
    incidents = sorted(graph.get("incidents") or [], key=lambda item: _incident_order(item, by_id))
    rows, drawn = [], {}
    for index, incident in enumerate(incidents[:MAX_INCIDENTS], 1):
        steps = list(incident.get("timeline") or incident.get("finding_ids") or [])
        shown = steps if len(steps) <= MAX_STEPS else steps[:MAX_STEPS - 1]
        row = {"label": f"I{index}", "incident": incident, "steps": shown, "total_steps": len(steps),
               "more": len(steps) - len(shown)}
        rows.append(row)
        for column, item in enumerate(shown):
            drawn[item] = (len(rows) - 1, column)
    # every stored edge is counted; two edges between the same pair in the same style are drawn as one arrow
    edges, seen = [], set()
    totals = {"observed": 0, "hypothesis": 0}
    shown = {"observed": 0, "hypothesis": 0}
    for edge in graph.get("edges") or []:
        style = edge_style(edge)
        totals[style] += 1
        if edge.get("from") not in drawn or edge.get("to") not in drawn or edge.get("from") == edge.get("to"):
            continue
        shown[style] += 1
        key = (edge["from"], edge["to"], style)
        if key not in seen:
            seen.add(key)
            edges.append({"from": edge["from"], "to": edge["to"], "style": style,
                          "link_type": edge.get("link_type") or ""})
    in_incidents = sum(len(incident.get("finding_ids") or []) for incident in incidents)
    return {
        "rows": rows, "edges": edges, "drawn": drawn, "numbers": numbers, "by_id": by_id,
        "counts": {
            "incidents": len(incidents), "incidents_drawn": len(rows),
            "findings": in_incidents, "findings_drawn": len(drawn),
            "observed_links": totals["observed"], "observed_drawn": shown["observed"],
            "hypothesis_links": totals["hypothesis"], "hypothesis_drawn": shown["hypothesis"],
        },
    }


def everything_drawn(counts: dict) -> bool:
    return (counts["incidents_drawn"] == counts["incidents"] and counts["findings_drawn"] == counts["findings"]
            and counts["observed_drawn"] == counts["observed_links"]
            and counts["hypothesis_drawn"] == counts["hypothesis_links"])


class Canvas:
    """An RGB pixel canvas with the few primitives the picture needs."""

    def __init__(self, width: int, height: int):
        self.width, self.height = width, height
        self.pixels = bytearray(WHITE * (width * height))

    def rect(self, x0: int, y0: int, x1: int, y1: int, color: bytes) -> None:
        x0, x1 = max(0, min(x0, x1)), min(self.width, max(x0, x1))
        y0, y1 = max(0, min(y0, y1)), min(self.height, max(y0, y1))
        if x0 >= x1:
            return
        span = color * (x1 - x0)
        for y in range(y0, y1):
            start = (y * self.width + x0) * 3
            self.pixels[start:start + len(span)] = span

    def frame(self, x0: int, y0: int, x1: int, y1: int, color: bytes, thickness: int = 2) -> None:
        self.rect(x0, y0, x1, y0 + thickness, color)
        self.rect(x0, y1 - thickness, x1, y1, color)
        self.rect(x0, y0, x0 + thickness, y1, color)
        self.rect(x1 - thickness, y0, x1, y1, color)

    def polyline(self, points: list[tuple[float, float]], color: bytes, thickness: int = 3,
                 dash: tuple[int, int] | None = None) -> None:
        """Stamp a square brush along the points; with `dash` (on, off) only the on stretches are drawn."""
        travelled = 0.0
        half = thickness // 2
        for (ax, ay), (bx, by) in itertools.pairwise(points):
            length = max(abs(bx - ax), abs(by - ay))
            steps = max(1, int(length))
            for step in range(steps + 1):
                t = step / steps
                distance = travelled + t * ((bx - ax) ** 2 + (by - ay) ** 2) ** 0.5
                if dash and distance % (dash[0] + dash[1]) >= dash[0]:
                    continue
                x, y = round(ax + (bx - ax) * t), round(ay + (by - ay) * t)
                self.rect(x - half, y - half, x - half + thickness, y - half + thickness, color)
            travelled += ((bx - ax) ** 2 + (by - ay) ** 2) ** 0.5

    def arrowhead(self, tip: tuple[float, float], before: tuple[float, float], color: bytes, size: int = 14) -> None:
        dx, dy = tip[0] - before[0], tip[1] - before[1]
        norm = (dx * dx + dy * dy) ** 0.5 or 1.0
        ux, uy = dx / norm, dy / norm
        base = (tip[0] - ux * size, tip[1] - uy * size)
        left = (base[0] - uy * size / 2, base[1] + ux * size / 2)
        right = (base[0] + uy * size / 2, base[1] - ux * size / 2)
        corners = (tip, left, right)
        xs, ys = [p[0] for p in corners], [p[1] for p in corners]

        def side(p, a, b):
            return (p[0] - b[0]) * (a[1] - b[1]) - (a[0] - b[0]) * (p[1] - b[1])

        for y in range(int(min(ys)), int(max(ys)) + 1):
            for x in range(int(min(xs)), int(max(xs)) + 1):
                p = (x + 0.5, y + 0.5)
                d1, d2, d3 = side(p, tip, left), side(p, left, right), side(p, right, tip)
                negative, positive = d1 < 0 or d2 < 0 or d3 < 0, d1 > 0 or d2 > 0 or d3 > 0
                if not (negative and positive):
                    self.rect(x, y, x + 1, y + 1, color)

    def text(self, x: int, y: int, value: str, color: bytes, scale: int = 3) -> int:
        """Draw text in the pixel font from (x, y), top left; returns the width drawn."""
        cursor = x
        for char in value.upper():
            glyph = FONT.get(char) or FONT["?"]
            for row_index, row in enumerate(glyph):
                for column, on in enumerate(row):
                    if on:
                        px, py = cursor + column * scale, y + row_index * scale
                        self.rect(px, py, px + scale, py + scale, color)
            cursor += 6 * scale
        return cursor - x

    def png(self) -> bytes:
        def chunk(kind: bytes, data: bytes) -> bytes:
            return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

        stride = self.width * 3
        raw = b"".join(b"\x00" + bytes(self.pixels[row * stride:(row + 1) * stride]) for row in range(self.height))
        header = struct.pack(">IIBBBBB", self.width, self.height, 8, 2, 0, 0, 0)
        return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(raw, 9))
                + chunk(b"IEND", b""))


def text_width(value: str, scale: int) -> int:
    return len(value) * 6 * scale - scale


def _time_label(observed_at, multi_day: bool) -> str:
    if not observed_at:
        return "NO TIME"
    value = str(observed_at).replace("T", " ")
    return value[5:16] if multi_day else value[11:16]


def _box(row: int, column: int) -> tuple[int, int, int, int]:
    slot = (WIDTH - LABEL_W - RIGHT) // MAX_STEPS
    x0 = LABEL_W + column * slot + (slot - BOX_W) // 2
    y0 = LEGEND_H + row * ROW_H + (ROW_H - BOX_H) // 2
    return x0, y0, x0 + BOX_W, y0 + BOX_H


def _legend(canvas: Canvas) -> None:
    x, y = 20, 18
    for name, color in (("URGENT", LANE_COLORS["urgent"]), ("HIGH", LANE_COLORS["high"]),
                        ("LEAD", LANE_COLORS["lead"]), ("OTHER", OTHER_LANE)):
        canvas.rect(x, y, x + 34, y + 26, _rgb(color))
        x += 46 + canvas.text(x + 46, y + 2, name, INK) + 40
    canvas.text(x + 20, y + 2, "F# = FINDING INDEX ROW", INK)
    y = 76
    x = 20
    canvas.polyline([(x, y + 12), (x + 70, y + 12)], OBSERVED, 4)
    canvas.arrowhead((x + 80, y + 12), (x + 60, y + 12), OBSERVED)
    x += 100 + canvas.text(x + 100, y + 2, "OBSERVED LINK", INK) + 50
    canvas.polyline([(x, y + 12), (x + 120, y + 12)], HYPOTHESIS, 4, dash=(14, 10))
    canvas.arrowhead((x + 130, y + 12), (x + 110, y + 12), HYPOTHESIS)
    _tag(canvas, x + 62, y + 12)
    x += 150 + canvas.text(x + 150, y + 2, "HYPOTHESIS (INFERRED, NOT PROVEN)", HYPOTHESIS) + 50
    canvas.polyline([(x, y + 12), (x + 60, y + 12)], GREY, 2)
    canvas.text(x + 80, y + 2, "TIME ORDER", INK)
    canvas.rect(0, LEGEND_H - 8, WIDTH, LEGEND_H - 6, LIGHT)


def _tag(canvas: Canvas, cx: float, cy: float) -> None:
    """The `H` marker every hypothesis link carries."""
    x0, y0 = int(cx) - 13, int(cy) - 14
    canvas.rect(x0, y0, x0 + 26, y0 + 28, WHITE)
    canvas.frame(x0, y0, x0 + 26, y0 + 28, HYPOTHESIS, 2)
    canvas.text(x0 + 6, y0 + 7, "H", HYPOTHESIS, 2)


def _curve(start, end, lift: float, steps: int = 24) -> list[tuple[float, float]]:
    # a positive lift bends the curve below both ends, a negative one above them
    control = ((start[0] + end[0]) / 2, max(start[1], end[1]) + lift if lift > 0 else
               min(start[1], end[1]) + lift)
    out = []
    for index in range(steps + 1):
        t = index / steps
        out.append(((1 - t) ** 2 * start[0] + 2 * (1 - t) * t * control[0] + t * t * end[0],
                    (1 - t) ** 2 * start[1] + 2 * (1 - t) * t * control[1] + t * t * end[1]))
    return out


def render_png(plan: dict) -> bytes:
    rows = plan["rows"]
    canvas = Canvas(WIDTH, LEGEND_H + max(1, len(rows)) * ROW_H + 10)
    _legend(canvas)
    by_id, numbers, drawn = plan["by_id"], plan["numbers"], plan["drawn"]
    times = [str(by_id.get(item, {}).get("observed_at") or "")[:10] for item in drawn]
    multi_day = len({value for value in times if value}) > 1
    for index, row in enumerate(rows):
        top = LEGEND_H + index * ROW_H
        if index:
            canvas.rect(LABEL_W - 20, top, WIDTH - RIGHT, top + 2, LIGHT)
        canvas.text(24, top + (ROW_H - 28) // 2, row["label"], INK, 4)
        # time order: a thin grey connector between consecutive steps
        boxes = [_box(index, column) for column in range(len(row["steps"]) + (1 if row["more"] else 0))]
        for left, right in itertools.pairwise(boxes):
            middle = (left[1] + left[3]) // 2
            canvas.polyline([(left[2] + 4, middle), (right[0] - 6, middle)], GREY, 2)
            canvas.arrowhead((right[0] - 2, middle), (right[0] - 12, middle), GREY, 10)
    # links under the boxes: observed arcs above a row, hypothesis arcs below it
    crossing: dict[tuple[int, int], int] = {}
    tags = []
    for edge in plan["edges"]:
        (row_a, col_a), (row_b, col_b) = drawn[edge["from"]], drawn[edge["to"]]
        a, b = _box(row_a, col_a), _box(row_b, col_b)
        observed = edge["style"] == "observed"
        color = OBSERVED if observed else HYPOTHESIS
        dash = None if observed else (14, 10)
        if row_a == row_b:
            if observed:
                start, end = ((a[0] + a[2]) / 2, a[1] - 2), ((b[0] + b[2]) / 2 + 10, b[1] - 4)
                points = _curve(start, end, -70)
            else:
                start, end = ((a[0] + a[2]) / 2, a[3] + 2), ((b[0] + b[2]) / 2 - 10, b[3] + 4)
                points = _curve(start, end, 70)
        else:
            # links between rows that share columns are spread sideways, so overlapping dashes never read as solid
            lane = crossing.get((col_a, col_b), 0)
            crossing[(col_a, col_b)] = lane + 1
            shift = (0 if observed else 24) + 18 * (lane % 4) * (1 if lane % 8 < 4 else -1)
            down = row_b > row_a
            start = ((a[0] + a[2]) / 2 + shift, a[3] + 2 if down else a[1] - 2)
            end = ((b[0] + b[2]) / 2 + shift, b[1] - 4 if down else b[3] + 4)
            points = [start, end]
        canvas.polyline(points, color, 3, dash)
        canvas.arrowhead(points[-1], points[-2] if len(points) > 1 else points[0], color)
        if not observed:
            middle = points[len(points) // 2] if len(points) > 2 else (
                (points[0][0] + points[-1][0]) / 2, (points[0][1] + points[-1][1]) / 2)
            tags.append(middle)
    for index, row in enumerate(rows):
        for column, item in enumerate(row["steps"]):
            x0, y0, x1, y1 = _box(index, column)
            finding = by_id.get(item)
            fill = _rgb(LANE_COLORS.get(_lane_of(finding), OTHER_LANE) if _lane_of(finding) in LANE_RANK
                        else OTHER_LANE)
            canvas.rect(x0, y0, x1, y1, fill)
            canvas.frame(x0, y0, x1, y1, INK, 2)
            label = f"F{numbers[item]}" if item in numbers else "F?"
            scale = 4 if text_width(label, 4) <= BOX_W - 16 else 3 if text_width(label, 3) <= BOX_W - 16 else 2
            canvas.text(x0 + (BOX_W - text_width(label, scale)) // 2, y0 + 12, label, WHITE, scale)
            when = _time_label((finding or {}).get("observed_at"), multi_day)
            canvas.text(x0 + (BOX_W - text_width(when, 2)) // 2, y1 - 26, when, WHITE, 2)
        if row["more"]:
            x0, y0, x1, y1 = _box(index, len(row["steps"]))
            canvas.frame(x0, y0, x1, y1, GREY, 2)
            label = f"+{row['more']} MORE"
            scale = 3 if text_width(label, 3) <= BOX_W - 12 else 2
            canvas.text(x0 + (BOX_W - text_width(label, scale)) // 2, y0 + (BOX_H - 7 * scale) // 2, label, GREY,
                        scale)
    # hypothesis tags last, so no box ever hides one
    for middle in tags:
        _tag(canvas, *middle)
    return canvas.png()
