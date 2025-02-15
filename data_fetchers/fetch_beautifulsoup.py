import re
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from utils.date_utils import normalize_date


def fetch_data_with_beautifulsoup(config):
    try:
        response = requests.get(config["url"])
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        # GNU C Library (glibc) の個別処理
        if config["url"] == "https://sourceware.org/glibc/":
            data = []

            # リリース情報の <p> タグを取得
            release_entries = soup.select("div#centercontent p")

            for entry in release_entries:
                text = entry.text.strip()

                # 日付を取得（YYYY-MM-DD 形式）
                match = re.search(r"(\d{4}-\d{2}-\d{2})", text)
                date_text = match.group(1) if match else "Unknown"
                normalized_date = normalize_date(date_text, config.get("date_formats"))

                # タイトル取得
                title_element = entry.find("a")
                title_text = title_element.text.strip() if title_element else "Unknown"

                # リンク取得
                link = (
                    urljoin(config["url"], title_element["href"])
                    if title_element
                    else "Unknown"
                )

                data.append(
                    {
                        "date": normalized_date,
                        "title": title_text,
                        "link": link,
                        "cve": "",
                        "cvss": "",
                    }
                )

            print(f"[DEBUG] Collected {len(data)} entries for GNU C Library (glibc).")
            return data

        # SAP の個別処理
        if (
            config["url"]
            == "https://support.sap.com/en/my-support/knowledge-base/security-notes-news.html"
        ):
            data = []

            # 年度を取得
            panel_title = soup.find("h4", class_="panel-title")
            year = None
            if panel_title and "Dates for" in panel_title.text:
                year_text = panel_title.text.strip()
                year = year_text.split("Dates for")[-1].strip()
                # print(f"Detected year: {year}")

            # 日付とリンクを取得
            rows = soup.select(config["selectors"]["rows"])
            # print(f"Found {len(rows)} rows")

            for row in rows:
                # タイトルとリンクを取得
                title = row.get("title", "").strip()  # `title` 属性から取得
                link = urljoin(
                    config["url"], row.get("href", "").strip()
                )  # `href` 属性から取得

                if not title or not link:
                    print(f"Missing title or link in row: {row}")
                    continue

                # 日付を取得し年度と結合
                date_text = row.text.strip()
                if date_text:
                    normalized_date = normalize_date(
                        f"{year} {date_text}", config.get("date_formats")
                    )
                else:
                    normalized_date = "Unknown"

                data.append(
                    {
                        "title": title,
                        "link": link,
                        "date": normalized_date,
                        "cve": "",
                        "cvss": "",
                    }
                )
            print(f"Collected {len(data)} entries for SAP")
            return data

        # Microsoft Edge Security Updates の個別処理
        if (
            config["url"]
            == "https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security"
        ):
            data = []

            # 日付セクションのタイトルを取得
            date_elements = soup.select("h2[id]")[:10]
            if not date_elements:
                print(
                    "[DEBUG] No date sections found. Check if the 'date' selector is correct."
                )
                return []

            for i, date_element in enumerate(date_elements):
                # 日付を正規化
                date_text = date_element.text.strip()
                normalized_date = normalize_date(date_text, config.get("date_formats"))

                # 次のセクションまでを記事内容として扱う
                current_element = date_element
                description = ""
                link = "https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security#" + date_text.lower().replace(
                    " ", "-"
                ).replace(
                    ",", ""
                )
                cve_list = []

                # 次の要素を順に解析
                while current_element:
                    current_element = current_element.find_next_sibling()
                    if not current_element or current_element.name == "h2":
                        break  # 次のセクションに到達したら終了

                    # 説明文を取得
                    if current_element.name == "p" and not description:
                        description = current_element.text.strip()

                    # CVE情報を取得
                    if current_element.name == "ul":
                        cve_links = current_element.select("li a[href]")
                        cve_list = [cve.text.strip() for cve in cve_links]

                    # リンクを取得
                    if current_element.name == "a" and not link:
                        link = urljoin(
                            config["url"], current_element.get("href", "").strip()
                        )

                # データを格納
                data.append(
                    {
                        "title": config["title"],
                        "link": link if link else "Unknown",
                        "date": normalized_date,
                        "description": description,
                        "cve": ", ".join(cve_list) if cve_list else "",
                    }
                )

            print(
                f"[DEBUG] Collected {len(data)} entries for Microsoft Edge Security Updates."
            )
            return data

        # NGINX の個別処理
        if config["url"] == "https://nginx.org/news.html":
            data = []
            rows = soup.select(config["selectors"]["rows"])[
                : config.get("max_entries", 10)
            ]

            for row in rows:
                # 日付取得
                date_element = row.select_one(config["selectors"]["date"])
                date_text = date_element.text.strip() if date_element else ""
                normalized_date = normalize_date(date_text, config.get("date_formats"))

                # タイトル取得
                title_element = row.select_one(config["selectors"]["title"])
                title_text = title_element.text.strip() if title_element else ""

                # リンク取得
                link_element = row.select_one(config["selectors"]["link"])
                link = (
                    urljoin(config["url"], link_element["href"].strip())
                    if link_element
                    else "Unknown"
                )

                # 説明文取得
                description_element = row.select_one(config["selectors"]["description"])
                description = (
                    " ".join(description_element.text.split())
                    if description_element
                    else ""
                )

                # データ構造に格納
                data.append(
                    {
                        "date": normalized_date,
                        "title": title_text,
                        "link": link,
                        "description": description,
                        "cve": "",
                        "cvss": "",
                    }
                )

            print(f"[DEBUG] Collected {len(data)} entries for NGINX News.")
            return data

        # SKYSEA Client View の個別処理
        if config["url"] == "https://www.skygroup.jp/security-info/":
            data = []
            rows = soup.select(config["selectors"]["rows"])[
                : config.get("max_entries", 20)
            ]
            for row in rows:
                link = row.get("href", "").strip()
                if not link:
                    print(f"Warning: Missing link in row: {row}")
                    continue
                link = urljoin(config["url"], link)

                date_element = row.select_one(config["selectors"]["date"])
                title_element = row.select_one(config["selectors"]["title"])

                if not date_element or not title_element:
                    print(f"Warning: Missing required fields in row: {row}")
                    continue

                date_text = date_element.text.strip()
                title_text = title_element.text.strip()
                normalized_date = normalize_date(date_text, config.get("date_formats"))

                data.append(
                    {
                        "date": normalized_date,
                        "title": title_text,
                        "link": link,
                        "cve": "",
                        "cvss": "",
                    }
                )
            return data

        # Apache Tomcat * の個別処理
        if "https://tomcat.apache.org/security-" in config["url"]:
            data = []

            # <h3> タグを取得（セキュリティ修正バージョン）
            h3_elements = soup.select("h3[id]")

            for h3 in h3_elements:
                # 日付取得
                date_element = h3.find("span", class_="pull-right")
                date_text = date_element.text.strip() if date_element else "Unknown"
                normalized_date = normalize_date(date_text, config.get("date_formats"))

                # タイトル取得
                title_text = h3.text.strip().replace(date_text, "").strip()

                # リンク生成（idを利用）
                link = f"{config['url']}#{h3['id']}"

                # CVE情報取得
                next_div = h3.find_next_sibling("div")
                cve_list = []
                if next_div:
                    cve_links = next_div.select("a[href*='cve.mitre.org']")
                    cve_list = [cve.text.strip() for cve in cve_links]

                data.append(
                    {
                        "date": normalized_date,
                        "title": title_text,
                        "link": link,
                        "cve": ", ".join(cve_list) if cve_list else "",
                        "cvss": "",
                    }
                )

            print(f"[DEBUG] Collected {len(data)} entries for Apache Tomcat 11.")
            return data

        # Mozilla Security Advisories の個別処理
        if config["url"] == "https://www.mozilla.org/en-US/security/advisories/":
            data = []

            # 日付を取得する <h2> タグを選択
            date_elements = soup.select("h2")

            for date_element in date_elements:
                date_text = date_element.text.strip()
                normalized_date = normalize_date(date_text, config.get("date_formats"))

                # 同じ日付内の <li> 要素を取得
                next_ul = date_element.find_next_sibling("ul")
                if next_ul:  # None でない場合のみ処理
                    list_items = next_ul.find_all("li", class_="level-item")

                    for item in list_items:
                        link_element = item.find("a", href=True)
                        if link_element:
                            link = urljoin(config["url"], link_element["href"])
                            title = link_element.text.strip()

                            # セキュリティレベルを取得
                            severity_element = link_element.find("span", class_="level")
                            severity = (
                                severity_element.text.strip()
                                if severity_element
                                else ""
                            )

                            data.append(
                                {
                                    "date": normalized_date,
                                    "title": title,
                                    "link": link,
                                    "severity": severity,
                                    "cve": "",
                                    "cvss": "",
                                }
                            )

            print(
                f"[DEBUG] Collected {len(data)} entries for Mozilla Security Advisories."
            )
            return data

        # 一般的なBeautifulSoup処理
        rows = soup.select(config["selectors"]["rows"])
        data = []
        for row in rows:
            entry = {}
            for field, selector in config["selectors"].items():
                if field == "rows":
                    continue
                element = row.select_one(selector)
                if field == "link" and element:
                    entry[field] = urljoin(
                        config["url"], element.get("href", "").strip()
                    )
                elif field == "date" and element:
                    entry[field] = normalize_date(
                        element.text.strip(), config.get("date_formats")
                    )
                elif element:
                    entry[field] = element.text.strip()
                else:
                    entry[field] = ""

            if entry.get("title") and entry.get("link"):
                data.append(entry)
        # print(data)
        return data
    except requests.RequestException as e:
        print(f"Error fetching site with BeautifulSoup: {e}")
        return []
