from feedgen.feed import FeedGenerator
import datetime
import csv
import pytz  # タイムゾーンを設定するために追加

RSS_FILE = "rss.xml"
FILTERED_FILE = "filtered_articles.csv"

def parse_date(date_str):
    """異なるフォーマットの日付を変換する"""
    formats = ["%Y-%m-%d %H:%M:%S", "%Y/%m/%d", "%Y-%m-%d"]  # 追加したフォーマット
    for fmt in formats:
        try:
            date_obj = datetime.datetime.strptime(date_str, fmt)
            return date_obj.replace(tzinfo=pytz.utc)  # UTC タイムゾーンを追加
        except ValueError:
            continue
    print(f"日付の変換エラー: {date_str} - 形式が不明")
    return None  # 変換できない場合は None を返す

def generate_rss():
    fg = FeedGenerator()
    fg.id("https://AgetakoSec.github.io/vulnerability-update-rss/rss.xml")
    fg.title("脆弱性情報の更新確認RSS")
    fg.link(
        href="https://AgetakoSec.github.io/vulnerability-update-rss/rss.xml", rel="self"
    )
    fg.description("特定の脆弱性情報の更新情報")

    try:
        with open(FILTERED_FILE, mode="r", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            for row in reader:
                fe = fg.add_entry()
                fe.title(row["Title"])
                fe.link(href=row["link"])

                # CVE と CVSS を取得し、description に追加
                cve = row.get("CVE", "N/A")  # CVE が無い場合は "N/A"
                cvss = row.get("CVSS", "N/A")  # CVSS が無い場合は "N/A"

                description_text = (
                    f"{row['Description']}\n\n"
                    f"**CVE:** {cve}\n"
                    f"**CVSS Score:** {cvss}"
                )

                fe.description(description_text)

                # 日付を変換（フォーマットを自動判定）
                date_obj = parse_date(row["Date"])
                if date_obj:
                    fe.pubDate(date_obj)
                else:
                    print(f"スキップ: {row['Date']}（無効な日付）")

    except FileNotFoundError:
        print("フィルタ済み記事がありません")

    fg.rss_file(RSS_FILE)

if __name__ == "__main__":
    generate_rss()
