"""Check repository-local Markdown links without contacting external sites."""
from pathlib import Path
import re
import urllib.parse

ROOT = Path(__file__).resolve().parents[2]


def broken_links(root):
    failures = []
    documents = sorted(root.glob("*.md")) + sorted((root / "docs").glob("*.md"))
    for document in documents:
        in_code = False
        for number, line in enumerate(document.read_text(encoding="utf-8-sig").splitlines(), 1):
            if line.lstrip().startswith("```"):
                in_code = not in_code
            if in_code:
                continue
            for match in re.finditer(r"!?\[[^\]]*\]\(([^)\n]+)\)", line):
                target = match.group(1).strip().split(' "', 1)[0].strip("<>")
                parsed = urllib.parse.urlsplit(target)
                if parsed.scheme or parsed.netloc or not parsed.path or parsed.path.startswith("/"):
                    continue
                path = document.parent / urllib.parse.unquote(parsed.path)
                if not path.exists():
                    failures.append("{}:{}: {}".format(document.relative_to(root), number, target))
    return documents, failures


if __name__ == "__main__":
    documents, failures = broken_links(ROOT)
    if failures:
        raise SystemExit("Missing local documentation links:\n" + "\n".join(failures))
    print("Documentation links passed: {} documents".format(len(documents)))
