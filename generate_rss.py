from feedgen.feed import FeedGenerator
import datetime
import csv
import pytz  # タイムゾーンを設定するために追加

RSS_FILE = "rss.xml"
FILTERED_FILE = "filtered_articles.csv"

def generate_rss():
    fg = FeedGenerator()
    fg.id("https://AgetakoSec.github.io/vulnerability-update-rss/rss.xml")
    fg.title("脆弱性情報の更新確認RSS")
    fg.link(href="https://AgetakoSec.github.io/vulnerability-update-rss/rss.xml", rel="self")
    fg.description("特定の脆弱性情報の更新情報")

    try:
        with open(FILTERED_FILE, mode="r", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            for row in reader:
                fe = fg.add_entry()
                fe.title(row["Title"])
                fe.link(href=row["link"])
                fe.description(row["Description"])

                # 日付の変換（タイムゾーン付きのdatetimeオブジェクトに変換）
                try:
                    # CSVの日付フォーマットを確認して適切に修正
                    date_obj = datetime.datetime.strptime(row["Date"], "%Y-%m-%d %H:%M:%S")  
                    date_obj = date_obj.replace(tzinfo=pytz.utc)  # UTCタイムゾーンを付与
                    fe.pubDate(date_obj)
                except ValueError as e:
                    print(f"日付の変換エラー: {row['Date']} - {e}")

    except FileNotFoundError:
        print("フィルタ済み記事がありません")

    fg.rss_file(RSS_FILE)

# if __name__ == "__main__":
#     generate_rss()
