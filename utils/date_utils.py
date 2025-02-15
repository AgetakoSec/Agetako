import re
from datetime import datetime

from dateutil.parser import parse

from config.site_config import TZINFOS


def normalize_date(date_str, site_formats=None):
    """
    日付文字列を標準フォーマット 'YYYY/MM/DD' に変換する。
    :param date_str: 日付文字列
    :param site_formats: サイト固有の日付フォーマット（リスト）
    :return: 標準フォーマットの日付文字列 または "Invalid Date"
    """
    # 前処理：序数表記を削除 (e.g., 4th -> 4)
    date_str = re.sub(r"(\d+)(st|nd|rd|th)", r"\1", date_str, flags=re.IGNORECASE)

    # 前処理：特定の固定フレーズを削除
    date_str = date_str.replace("Last updated", "").strip()
    date_str = date_str.replace("Security Bulletin - ", "").strip()

    # サイト固有のフォーマットが指定されている場合、優先的に処理
    if site_formats:
        for fmt in site_formats:
            try:
                return datetime.strptime(date_str, fmt).strftime("%Y/%m/%d")
            except ValueError:
                continue

    # dateutil を使用したパース処理
    try:
        return parse(date_str, tzinfos=TZINFOS).strftime("%Y/%m/%d")
    except Exception:
        pass

    # 再度 dateutil を使用するが、tzinfos を除外
    try:
        return parse(date_str).strftime("%Y/%m/%d")
    except Exception:
        return "Invalid Date"
