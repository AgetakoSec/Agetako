import platform

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from webdriver_manager.chrome import ChromeDriverManager

from utils.date_utils import normalize_date


def setup_webdriver():
    """
    Selenium WebDriverをセットアップする。
    :return: WebDriverインスタンス
    """
    service = Service(ChromeDriverManager().install())
    # Windows: creation_flags を設定
    if platform.system() == "Windows":
        service.creation_flags = 0x08000000  # headless

    options = Options()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--log-level=3")

    return webdriver.Chrome(service=service, options=options)


def fetch_data_with_selenium(config):
    driver = setup_webdriver()
    try:
        driver.get(config["url"])
        WebDriverWait(driver, 20).until(
            EC.presence_of_all_elements_located((By.XPATH, config["Xpath"]["article"]))
        )
        articles = driver.find_elements(By.XPATH, config["Xpath"]["article"])
        data = []
        for article in articles:
            try:
                # タイトル
                title_element = article.find_element(By.XPATH, config["Xpath"]["title"])
                title = title_element.text.strip()

                # リンク
                link_element = article.find_element(By.XPATH, config["Xpath"]["link"])
                link = link_element.get_attribute("href").strip()

                # 日付
                date = ""
                if "date" in config["Xpath"] and config["Xpath"]["date"]:
                    date_element = article.find_element(
                        By.XPATH, config["Xpath"]["date"]
                    )
                    date = normalize_date(
                        date_element.text.strip(), config.get("date_formats", [])
                    )

                # CVE
                cve = ""
                if "cve" in config["Xpath"] and config["Xpath"]["cve"]:
                    cve_element = article.find_element(By.XPATH, config["Xpath"]["cve"])
                    cve = cve_element.text.strip()

                # CVSS
                cvss = ""
                if "cvss" in config["Xpath"] and config["Xpath"]["cvss"]:
                    cvss_element = article.find_element(
                        By.XPATH, config["Xpath"]["cvss"]
                    )
                    cvss = cvss_element.text.strip()

                # データ追加
                data.append(
                    {
                        "title": title,
                        "link": link,
                        "date": date,
                        "cve": cve,
                        "cvss": cvss,
                    }
                )
            except Exception as e:
                print(f"Error processing article: {e}")
        return data
    finally:
        driver.quit()
