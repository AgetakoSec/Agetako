from feedgen.feed import FeedGenerator
import datetime
import csv

RSS_FILE = "rss.xml"
FILTERED_FILE = "filtered_articles.csv"

def generate_rss():
    fg = FeedGenerator()
    fg.id("https://AgetakoSec.github.io/vulnerability-update-rss/rss.xml")
    fg.title("サイト更新情報")
    fg.link(href="https://yourusername.github.io/vulnerability-update-rss/rss.xml", rel="self")
    fg.description("特定の脆弱性情報の更新情報")

    try:
        with open(FILTERED_FILE, mode="r", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            for row in reader:
                fe = fg.add_entry()
                fe.title(row["Title"])
                fe.link(href=row["link"])
                fe.description(row["Description"])
                fe.pubDate(row["Date"])
    except FileNotFoundError:
        print("フィルタ済み記事がありません")

    fg.rss_file(RSS_FILE)

if __name__ == "__main__":
    generate_rss()
