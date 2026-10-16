"""Assemble demo/demo.html from its parts.

demo/demo.html is a generated, self-contained file: one double-click, no server, no network. That
is deliberate -- the manuscript's "Code availability" link should lead somewhere a reviewer can
actually run -- but a single 1,500-line file is where a second implementation quietly drifts from
the first. So the parts are kept separate and testable, and the built page sits beside them:

    demo/dashboard.template.html   markup and design tokens
    demo/engine.js                 the port of src/casebound (no DOM)
    demo/harness.js                the port of demo/kyc (no DOM)
    demo/ui.js                     rendering only
    demo/kyc/dataset.json          the generated population and policy corpus
    demo/demo.html                 <- the build output; never edit it directly

`tests/test_dashboard_build.py` rebuilds in memory and fails if the output is stale;
`tests/test_engine_parity.py` runs engine.js and harness.js in Node against the Python core.

    python -m demo.build_dashboard          # rewrite demo/demo.html
    python -m demo.build_dashboard --check  # exit 1 if it is out of date
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PARTS = {
    "@@DATASET@@": ROOT / "demo" / "kyc" / "dataset.json",
    "@@ENGINE@@": ROOT / "demo" / "engine.js",
    "@@HARNESS@@": ROOT / "demo" / "harness.js",
    "@@UI@@": ROOT / "demo" / "ui.js",
}
TEMPLATE = ROOT / "demo" / "dashboard.template.html"
OUTPUT = ROOT / "demo" / "demo.html"


def render() -> str:
    html = TEMPLATE.read_text(encoding="utf-8")
    for token, path in PARTS.items():
        body = path.read_text(encoding="utf-8").strip()
        if token != "@@DATASET@@":
            # A literal </script> inside a script body would close the tag early.
            body = body.replace("</script>", "<\\/script>")
        html = html.replace(token, body)
    missing = [t for t in PARTS if t in html]
    if missing:
        raise SystemExit(f"template still contains unreplaced tokens: {missing}")
    return html


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="casebound-build-dashboard")
    ap.add_argument("--check", action="store_true", help="verify demo/demo.html is up to date; do not write")
    a = ap.parse_args(argv)
    html = render()
    if a.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if current != html:
            print("demo/demo.html is out of date; run `python -m demo.build_dashboard`", file=sys.stderr)
            raise SystemExit(1)
        print("demo/demo.html is up to date")
        return
    OUTPUT.write_text(html, encoding="utf-8")
    print(f"wrote {OUTPUT} · {len(html):,} bytes")


if __name__ == "__main__":
    main()
