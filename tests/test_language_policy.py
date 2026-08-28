from pathlib import Path
from html.parser import HTMLParser
import re
import unittest


PERSIAN_OR_ARABIC = re.compile(r"[\u0600-\u06ff]")
PROJECT_ROOT = Path(__file__).resolve().parents[1]


class DirectionAuditParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.stack: list[tuple[str, dict[str, str | None]]] = []
        self.errors: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        attributes = dict(attrs)
        self.stack.append((tag, attributes))
        if tag == "pre" and (
            attributes.get("dir") != "ltr" or attributes.get("align") != "left"
        ):
            self.errors.append("Every command block must be explicitly LTR and left-aligned")

    def handle_endtag(self, tag: str) -> None:
        if self.stack and self.stack[-1][0] == tag:
            self.stack.pop()

    def handle_data(self, data: str) -> None:
        if not data.strip() or not PERSIAN_OR_ARABIC.search(data):
            return
        if re.search(r"[A-Za-z]", data):
            self.errors.append(f"Mixed Persian and English text: {data.strip()!r}")
        if not self.stack:
            self.errors.append(f"Unwrapped Persian text: {data.strip()!r}")
            return
        tag, attributes = self.stack[-1]
        if tag not in {"h1", "h2", "p"}:
            self.errors.append(f"Persian text is inside an unsupported tag: {tag}")
        if attributes.get("dir") != "rtl" or attributes.get("align") != "right":
            self.errors.append(f"Persian text is not explicitly RTL: {data.strip()!r}")


class LanguagePolicyTests(unittest.TestCase):
    def test_source_code_contains_no_persian_or_arabic_text(self) -> None:
        source_files = (PROJECT_ROOT / "src").rglob("*.py")
        offending = [
            str(path.relative_to(PROJECT_ROOT))
            for path in source_files
            if PERSIAN_OR_ARABIC.search(path.read_text(encoding="utf-8"))
        ]
        self.assertEqual(offending, [])

    def test_readme_contains_no_persian_or_arabic_text(self) -> None:
        readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIsNone(PERSIAN_OR_ARABIC.search(readme))

    def test_learning_documents_have_isolated_text_directions(self) -> None:
        errors = []
        for lesson_path in (PROJECT_ROOT / "docs" / "learning").glob("*.md"):
            parser = DirectionAuditParser()
            parser.feed(lesson_path.read_text(encoding="utf-8"))
            errors.extend(
                f"{lesson_path.name}: {error}" for error in parser.errors
            )
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
