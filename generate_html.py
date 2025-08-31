import csv
from datetime import datetime
from pathlib import Path
import html

HTML_FILE = "index.html"
FILTERED_FILE = "filtered_articles.csv"

def generate_html():
    rows = []
    path = Path(FILTERED_FILE)
    if not path.exists():
        print("フィルタ済み記事がありません")
        return
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    # sort by Date descending
    def parse_date(s):
        for fmt in ("%Y/%m/%d", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                continue
        return datetime.min
    rows.sort(key=lambda r: parse_date(r.get("Date", "")), reverse=True)

    lines = [
        "<!DOCTYPE html>",
        '<html lang="ja">',
        "<head>",
        '    <meta charset="UTF-8">',
        "    <title>脆弱性情報一覧</title>",
        "    <style>",
        "        body { font-family: sans-serif; }",
        "        table { border-collapse: collapse; width: 100%; }",
        "        th, td { border: 1px solid #ccc; padding: 8px; }",
        "        th { background: #f2f2f2; }",
        "    </style>",
        "</head>",
        "<body>",
        "<h1>脆弱性情報一覧</h1>",
        "<table>",
        "  <thead><tr><th>Date</th><th>Site</th><th>Title</th><th>CVE</th><th>CVSS</th></tr></thead>",
        "  <tbody>",
    ]
    for row in rows:
        title = html.escape(row.get("Title", ""))
        link = html.escape(row.get("link", ""))
        site = html.escape(row.get("SiteName", ""))
        cve = html.escape(row.get("CVE", ""))
        cvss = html.escape(row.get("CVSS", ""))
        date = html.escape(row.get("Date", ""))
        lines.append(
            f"    <tr><td>{date}</td><td>{site}</td><td><a href='{link}'>{title}</a></td><td>{cve}</td><td>{cvss}</td></tr>"
        )
    lines.extend([
        "  </tbody>",
        "</table>",
        "</body>",
        "</html>",
    ])
    Path(HTML_FILE).write_text("\n".join(lines), encoding="utf-8")

if __name__ == "__main__":
    generate_html()
