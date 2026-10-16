"""demo/demo.html is generated; this fails if it was edited by hand or left stale."""
from pathlib import Path

from demo.build_dashboard import OUTPUT, render


def test_demo_html_lives_beside_its_parts():
    """The build output sits in demo/ with the sources it is assembled from, so there is exactly
    one demo page in the tree and no copy at the repository root to drift."""
    assert OUTPUT.parent.name == "demo"
    assert not (OUTPUT.parent.parent / "demo.html").exists(), \
        "a stale copy of the dashboard is sitting at packages/casebound/demo.html; delete it"


def test_demo_html_is_up_to_date():
    assert OUTPUT.exists(), "demo/demo.html missing; run `python -m demo.build_dashboard`"
    assert OUTPUT.read_text(encoding="utf-8") == render(), \
        "demo/demo.html is stale; run `python -m demo.build_dashboard` and commit the result"


def test_dashboard_is_self_contained():
    """No network dependency except the webfont stylesheet, and no fetch(): the file has to work
    from a file:// URL on a reviewer's laptop with no server and no connection."""
    html = OUTPUT.read_text(encoding="utf-8")
    assert "fetch(" not in html and "XMLHttpRequest" not in html
    assert html.count("<script src=") == 0
    assert html.count("<link rel=\"stylesheet\"") == 1        # fonts only; degrades to system fonts


def test_embedded_dataset_is_the_generated_one():
    import json
    html = OUTPUT.read_text(encoding="utf-8")
    start = html.index('<script type="application/json" id="dataset">') + len('<script type="application/json" id="dataset">')
    embedded = json.loads(html[start:html.index("</script>", start)])
    on_disk = json.loads((Path(__file__).resolve().parent.parent / "demo" / "kyc" / "dataset.json").read_text(encoding="utf-8"))
    assert embedded == on_disk
    assert embedded["meta"]["synthetic"] is True
