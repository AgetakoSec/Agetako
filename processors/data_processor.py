import csv
import os
import re
from datetime import datetime
import requests
from bs4 import BeautifulSoup
from cvss import CVSS3  # CVSS v3 のスコア計算

import pandas as pd

from config.site_config import FILTERED_FILE, LATEST_FILE, SITE_CONFIG


def extract_cve(text):
    """CVE情報を抽出する"""
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    return ", ".join(set(cve_pattern.findall(text)))


def extract_cvss(text):
    """CVSSスコアを抽出する"""
    cvss_pattern = re.compile(r"CVSS[:\s]?([0-9]\.[0-9])", re.IGNORECASE)
    return ", ".join(set(match.strip() for match in cvss_pattern.findall(text)))


def fetch_cvss_from_nvd(cve):
    """NVDのCVEページからCVSSスコアを取得"""
    if not cve or cve == '""':
        return ""

    url = f"https://nvd.nist.gov/vuln/detail/{cve}"
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Failed to fetch NVD data for {cve}: {e}")
        return ""

    soup = BeautifulSoup(response.text, "html.parser")

    # CVSS v3のスコアを取得
    cvss_element = soup.find("span", {"data-testid": "vuln-cvssv3-base-score"})
    if cvss_element:
        return cvss_element.text.strip()

    return ""


def fetch_cve_cvss_from_link(link):
    """link先からCVE, CVSS情報を取得し、CVSSスコアを計算する"""
    if not link:
        return "", "", ""

    try:
        # Webページの内容を取得
        response = requests.get(link, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Failed to fetch {link}: {e}")
        return "", "", ""

    # BeautifulSoupでHTML解析
    soup = BeautifulSoup(response.text, "html.parser")
    page_text = soup.get_text()

    # CVEを抽出
    cve = extract_cve(page_text)

    # CVSS ベクトルを抽出 (例: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    cvss_vector_pattern = re.compile(r"CVSS:\d+\.\d+/[A-Za-z:/]+")
    cvss_vector_match = cvss_vector_pattern.search(page_text)

    cvss_vector = cvss_vector_match.group(0) if cvss_vector_match else ""
    cvss_score = ""

    # CVSS スコアを計算
    if cvss_vector:
        try:
            cvss_score = str(CVSS3(cvss_vector).scores()[0])  # CVSSスコアを取得
        except Exception as e:
            print(f"Failed to calculate CVSS score from vector {cvss_vector}: {e}")

    # CVEがあり、CVSSスコアが取得できなかった場合、NVDを参照
    # if cve and cvss_score in ('', '""'):
    #     cvss_score = fetch_cvss_from_nvd(cve)

    return cve, cvss_vector, cvss_score


def filter_articles():
    """
    最新の脆弱性ファイルから記事をフィルタリングし、指定されたキーワードに一致する記事のみを抽出する。
    タイトルとDescriptionの両方を対象にフィルタを適用する。
    """
    filtered_data = []
    if not os.path.exists(LATEST_FILE):
        print(f"Latest vulnerability file not found: {LATEST_FILE}")
        return

    with open(LATEST_FILE, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            site_name = row.get("SiteName")
            title = row.get("Title", "")
            description = row.get("Description", "")
            link = row.get("link", "")
            cve = row.get("CVE", "").strip()
            cvss = row.get("CVSS", "").strip()

            if site_name and site_name in SITE_CONFIG:
                title_keywords = SITE_CONFIG[site_name].get("filter_title_keywords", [])
                description_keywords = SITE_CONFIG[site_name].get(
                    "filter_description_keywords", []
                )
                remove_words = SITE_CONFIG[site_name].get("remove_words", [])

                # 除外キーワードがタイトルまたは説明に含まれている場合はスキップ
                if any(word.lower() in title.lower() for word in remove_words) or any(
                    word.lower() in description.lower() for word in remove_words
                ):
                    continue

                if (
                    not title_keywords
                    or any(
                        keyword.lower() in title.lower() for keyword in title_keywords
                    )
                ) and (
                    not description_keywords
                    or any(
                        keyword.lower() in description.lower()
                        for keyword in description_keywords
                    )
                ):
                    # CVE, CVSSが '""'（空の文字列）なら更新
                    if cve in ('', '""'):
                        cve = extract_cve(title + " " + description)
                    if cvss in ('', '""'):
                        cvss = extract_cvss(title + " " + description)

                    # それでもCVE, CVSSが '""' ならリンク先から取得
                    # if cve in ('', '""') or cvss in ('', '""'):
                    #     fetched_cve, fetched_cvss_vector, fetched_cvss = fetch_cve_cvss_from_link(link)
                    #     cve = cve if cve not in ('', '""') else fetched_cve
                    #     cvss = cvss if cvss not in ('', '""') else fetched_cvss

                    row["CVE"] = cve
                    row["CVSS"] = cvss

                    # **ここで1回だけ追加**
                    filtered_data.append(row)

    with open(FILTERED_FILE, mode="w", newline="", encoding="utf-8") as file:
        # 必須列に "Description", "CVE", "CVSS" を追加
        fieldnames = ["Date", "SiteName", "Title", "link", "Description", "CVE", "CVSS"]
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for row in filtered_data:
            # データ内の不要なキーを除去
            filtered_row = {key: row.get(key, "Unknown") for key in fieldnames}
            writer.writerow(filtered_row)

    print(
        f"Filtered articles saved to {FILTERED_FILE} with {len(filtered_data)} entries."
    )
