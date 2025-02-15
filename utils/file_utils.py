import csv
import os
from datetime import datetime, timedelta

import pandas as pd

from config.site_config import BASE_PATH, LATEST_ENTRIES_FILE, LATEST_FILE


def save_to_csv(site_name, data):
    if not data:
        print(
            f"No new data to save for site '{site_name}'. Existing data will be kept."
        )
        return

    grouped_data = {}
    now = datetime.now()
    cutoff_date = now - timedelta(days=30)

    for entry in data:
        date = entry.get("date", "Unknown")
        if "Unknown" in date:
            continue
        try:
            date_obj = datetime.strptime(date, "%Y/%m/%d")
            if date_obj < cutoff_date:
                continue
            month_folder = os.path.join(BASE_PATH, date_obj.strftime("%Y/%m"))
        except ValueError:
            continue
        if month_folder not in grouped_data:
            grouped_data[month_folder] = []
        grouped_data[month_folder].append(entry)

    for month_folder, entries in grouped_data.items():
        os.makedirs(month_folder, exist_ok=True)
        file_path = os.path.join(month_folder, f"{site_name}.csv")

        # 既存データを読み込む
        existing_data = []
        if os.path.exists(file_path):
            with open(file_path, mode="r", newline="", encoding="utf-8") as file:
                reader = csv.DictReader(file)
                existing_data = [row for row in reader]

        # 新しいデータを追加し、重複を除去
        all_entries = existing_data + entries
        all_entries = {entry["link"]: entry for entry in all_entries}.values()

        # ソートして保存
        sorted_entries = sorted(
            all_entries,
            key=lambda x: datetime.strptime(x["date"], "%Y/%m/%d"),
            reverse=True,
        )

        # 必須フィールドをすべて指定
        fieldnames = ["date", "title", "link", "description", "cve", "cvss"]

        with open(file_path, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
            writer.writeheader()
            for entry in sorted_entries:
                # 改行を削除して1行にまとめる
                title = (
                    entry.get("title", "")
                    .replace("\n", " ")
                    .replace("\r", " ")
                    .replace("  ", "")
                    .strip()
                )
                description = (
                    entry.get("description", "")
                    .replace("\n", " ")
                    .replace("\r", " ")
                    .replace("  ", "")
                    .strip()
                )
                cve = (
                    entry.get("cve", "")
                    .replace("\n", " ")
                    .replace("\r", " ")
                    .replace("  ", "")
                    .strip()
                )
                cvss = (
                    entry.get("cvss", "")
                    .replace("\n", " ")
                    .replace("\r", " ")
                    .replace("  ", "")
                    .strip()
                )

                row = {
                    "date": entry.get("date", ""),
                    "title": f'"{title}"',
                    "link": entry.get("link", "").strip(),
                    "description": f'"{description}"',
                    "cve": f'"{cve}"',
                    "cvss": f'"{cvss}"',
                }
                writer.writerow(row)

        print(f"Updated: {file_path} with {len(sorted_entries)} entries.")


def save_to_latest_csv(data):
    """
    収集したデータを最新の脆弱性情報として1つのCSVにまとめる。
    """
    latest_file = LATEST_FILE
    now = datetime.now()
    cutoff_date = now - timedelta(days=14)

    # データを収集してDataFrameに変換
    all_entries = []
    for site_name, entries in data.items():
        if not entries:
            print(f"No data found for site: {site_name}")
            continue
        for entry in entries:
            date = entry.get("date", "Unknown")
            if "Unknown" not in date:
                try:
                    entry_date = datetime.strptime(date, "%Y/%m/%d")
                    if entry_date >= cutoff_date:
                        title = (
                            entry.get("title", "")
                            .replace("\n", " ")
                            .replace("\r", " ")
                            .replace("  ", "")
                            .strip()
                        )
                        description = (
                            entry.get("description", "")
                            .replace("\n", " ")
                            .replace("\r", " ")
                            .replace("  ", "")
                            .strip()
                        )
                        cve = (
                            entry.get("cve", "")
                            .replace("\n", " ")
                            .replace("\r", " ")
                            .replace("  ", "")
                            .strip()
                        )
                        cvss = (
                            entry.get("cvss", "")
                            .replace("\n", " ")
                            .replace("\r", " ")
                            .replace("  ", "")
                            .strip()
                        )

                        all_entries.append(
                            {
                                "Date": date,
                                "SiteName": site_name,
                                "Title": f'"{title}"',
                                "link": entry.get("link", "").strip(),
                                "Description": f'"{description}"',
                                "CVE": f'"{cve}"',
                                "CVSS": f'"{cvss}"',
                            }
                        )
                except ValueError:
                    continue

    # DataFrame作成
    if not all_entries:
        print("No entries to save. Skipping CSV update.")
        return

    df = pd.DataFrame(all_entries)

    # 必須列のチェック
    required_columns = [
        "Date",
        "SiteName",
        "Title",
        "link",
        "Description",
        "CVE",
        "CVSS",
    ]
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        print(f"Error: Missing required columns: {missing_columns}")
        return

    # 重複削除とソート
    df.drop_duplicates(subset=["Date", "link"], inplace=True)
    df.sort_values(by="Date", ascending=False, inplace=True)

    # CSVに保存
    df.to_csv(latest_file, index=False, encoding="utf-8", quoting=csv.QUOTE_ALL)
    print(f"Updated {latest_file} with {len(df)} entries (within 14 days).")


def save_latest_site_entries(data):
    """
    各サイトごとの最新記事情報をCSVに保存する。
    CSVフォーマット: SiteName, date, title, link
    """
    latest_entries = []

    for site_name, entries in data.items():
        if not entries:
            print(f"No data found for site: {site_name}")
            continue

        # 最新記事を取得 (日付が新しいもの)
        try:
            latest_entry = max(
                entries,
                key=lambda x: datetime.strptime(
                    x.get("date", "1900/01/01"), "%Y/%m/%d"
                ),
            )
        except ValueError:
            print(f"Skipping site {site_name} due to invalid date format.")
            continue

        latest_entries.append(
            {
                "SiteName": site_name,
                "date": latest_entry.get("date", ""),
                "title": latest_entry.get("title", "").replace("\n", " ").strip(),
                "link": latest_entry.get("link", "").strip(),
            }
        )

    # DataFrame 作成
    if not latest_entries:
        print("No latest entries found. Skipping CSV update.")
        return

    df = pd.DataFrame(latest_entries)

    # CSV に保存
    latest_site_file = LATEST_ENTRIES_FILE
    df.to_csv(latest_site_file, index=False, encoding="utf-8", quoting=csv.QUOTE_ALL)
    print(f"Saved latest site entries to {latest_site_file}.")
