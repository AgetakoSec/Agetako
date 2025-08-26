import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from config.site_config import (
    BASE_PATH,
    FILTERED_FILE,
    LATEST_FILE,
    LOG_FILE,
    SITE_CONFIG,
)
from data_fetchers.fetch_beautifulsoup import fetch_data_with_beautifulsoup
from data_fetchers.fetch_rss import fetch_data_with_rss
from data_fetchers.fetch_selenium import fetch_data_with_selenium
from processors.data_processor import filter_articles
from processors.xlsx_exporter import save_filtered_articles_to_xlsx
from utils.file_utils import save_latest_site_entries, save_to_csv, save_to_latest_csv
from utils.logger import setup_logger
from generate_rss import generate_rss

logger = setup_logger(LOG_FILE)


def initialize_files():
    """初回実行時に必要なファイルとフォルダを作成"""
    os.makedirs(BASE_PATH, exist_ok=True)

    if not os.path.exists(LATEST_FILE):
        with open(LATEST_FILE, "w", encoding="utf-8") as file:
            file.write("Date,SiteName,Title,link,Description,CVE,CVSS\n")
        logger.info(f"Created empty file: {LATEST_FILE}")

    if not os.path.exists(FILTERED_FILE):
        with open(FILTERED_FILE, "w", encoding="utf-8") as file:
            file.write("Date,SiteName,Title,link,Description,CVE,CVSS\n")
        logger.info(f"Created empty file: {FILTERED_FILE}")


def fetch_site_data(site_name, config):
    try:
        if config["method"] == "rss":
            return fetch_data_with_rss(config)
        elif config["method"] == "beautifulsoup":
            return fetch_data_with_beautifulsoup(config)
        elif config["method"] == "selenium":
            return fetch_data_with_selenium(config)
        else:
            logger.error(f"Unknown method for site {site_name}")
            return []
    except Exception as e:
        logger.exception(f"Error fetching data for {site_name}: {e}")
        return []


def main():
    logger.info("Starting data collection process...")

    initialize_files()

    all_data = {}

    with ThreadPoolExecutor() as executor:
        future_to_site = {}
        for site_name, config in SITE_CONFIG.items():
            print(f"----------------------------------")
            logger.info(f"Processing site: {site_name}")
            print(f"----------------------------------")
            future_to_site[executor.submit(fetch_site_data, site_name, config)] = site_name

        for future in as_completed(future_to_site):
            site_name = future_to_site[future]
            site_data = future.result()
            if site_data:
                local_time = datetime.now().astimezone().strftime(
                    "%Y-%m-%d %H:%M:%S %Z"
                )
                logger.info(
                    f"{site_name}: Retrieved {len(site_data)} articles. Last update: {local_time}"
                )
                for entry in site_data:
                    title = (
                        entry.get("title", "")
                        .replace("\n", " ")
                        .replace("\r", " ")
                        .strip()
                    )
                    link = entry.get("link", "").strip()
                    logger.info(f" - {title} ({link})")
                save_to_csv(site_name, site_data)
            else:
                logger.info(f"{site_name}: No new articles found.")
            all_data[site_name] = site_data

    logger.info("Saving all collected data to the latest CSV...")
    print(f"----------------------------------")
    # サイトの取得状況の確認
    save_latest_site_entries(all_data)

    save_to_latest_csv(all_data)

    logger.info("Filtering articles...")
    filter_articles()

    try:
        with open(FILTERED_FILE, mode="r", encoding="utf-8") as file:
            import csv

            reader = csv.DictReader(file)
            filtered_articles = list(reader)

        if filtered_articles:
            logger.info("Saving filtered articles to Excel...")
            print(f"----------------------------------")
            save_filtered_articles_to_xlsx(filtered_articles)
            generate_rss()
        else:
            logger.info("No filtered articles found for saving to Excel.")
    except FileNotFoundError:
        logger.error(f"Filtered file not found: {FILTERED_FILE}")

    logger.info("Data collection process completed.")


if __name__ == "__main__":
    main()
