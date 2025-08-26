from html import unescape

import cloudscraper
import feedparser
import requests
from bs4 import BeautifulSoup

from config.site_config import HEADERS
from utils.date_utils import normalize_date


def fetch_data_with_rss(config):
    try:
        # まずは requests を利用して RSS フィードを取得する。
        # 取得に失敗した場合は cloudscraper を利用する。
        try:
            response = requests.get(config["url"], headers=HEADERS, timeout=30)
            response.raise_for_status()
        except requests.exceptions.RequestException:
            print("Debug: requests failed. Trying cloudscraper...")
            scraper = cloudscraper.create_scraper()
            response = scraper.get(config["url"], headers=HEADERS, timeout=30)
            response.raise_for_status()

        # feedparser で RSS を解析
        feed = feedparser.parse(response.content)
        data = []
        if feed.entries:
            for entry in feed.entries:
                date = entry.get("published", entry.get("pubDate", "Unknown"))
                normalized_date = normalize_date(date, config.get("date_formats"))

                cve = ""
                cvss = ""

                raw_description = entry.get("summary", "Unknown")
                if raw_description != "Unknown":
                    decoded_description = unescape(raw_description)
                    soup = BeautifulSoup(decoded_description, "html.parser")
                    clean_description = soup.get_text(separator=" ").strip()
                    description = " ".join(clean_description.split())
                else:
                    description = ""

                data.append(
                    {
                        "title": entry.get("title", "Unknown"),
                        "link": entry.get("link", "Unknown"),
                        "date": normalized_date,
                        "description": f'"{description}"',
                        "cve": cve,
                        "cvss": cvss,
                    }
                )
            return data

        # feedparser でデータが取得できない場合は BeautifulSoup で解析
        soup = BeautifulSoup(response.content, "xml")  # XMLとしてパース
        items = soup.find_all("item")
        for item in items:
            title = item.find("title").text if item.find("title") else "Unknown"
            link = item.find("link").text if item.find("link") else "Unknown"
            pub_date = item.find("pubDate").text if item.find("pubDate") else "Unknown"
            normalized_date = normalize_date(pub_date, config.get("date_formats"))

            # 説明文を整形
            raw_description = item.find("description")
            if raw_description:
                decoded_description = unescape(raw_description.text)
                soup = BeautifulSoup(decoded_description, "html.parser")
                clean_description = soup.get_text(separator=" ").strip()
                description = " ".join(clean_description.split())
            else:
                description = "Unknown"

            cve = ""
            cvss = ""

            data.append(
                {
                    "title": title,
                    "link": link,
                    "date": normalized_date,
                    "description": f'"{description}"',
                    "cve": cve,
                    "cvss": cvss,
                }
            )
        return data

    except requests.exceptions.RequestException as e:
        print(f"Error fetching RSS feed: {e}")
        return []
