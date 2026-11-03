"""Экспертная система анализа результатов сканирования безопасности."""
import argparse
import ast
import datetime
import random
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
import requests
from bs4 import BeautifulSoup
from tabulate import tabulate

try:
    from googlesearch import search as google_search
except ImportError:
    google_search = None


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
NMAP_XML = DATA_DIR / "nmap_output.xml"
NIKTO_JSON = DATA_DIR / "nikto_output.json"
MASSCAN_JSON = DATA_DIR / "masscan_output.json"


@dataclass
class ScanConfig:
    target: str
    rate: int = 20


# ---------- запуск сканеров ----------

def _require_tool(name: str) -> None:
    if shutil.which(name) is None:
        raise RuntimeError(f"Утилита '{name}' не найдена в PATH")


def run_scan(cfg: ScanConfig) -> None:
    """Запускает nmap, nikto и masscan. Без shell=True — нет injection."""
    _require_tool("nmap")
    _require_tool("nikto")
    _require_tool("masscan")

    DATA_DIR.mkdir(exist_ok=True)

    subprocess.run(
        ["nmap", "-T4", "-A", cfg.target, "-oX", str(NMAP_XML)],
        check=True,
    )
    subprocess.run(
        ["nikto", "-h", cfg.target, "-Format", "json", "-o", str(NIKTO_JSON)],
        check=True,
    )
    subprocess.run(
        ["masscan", cfg.target, "-p80,443,8000-8100,0-200",
         f"--rate={cfg.rate}", "-oJ", str(MASSCAN_JSON)],
        check=True,
    )


# ---------- конвертация ----------

def json_to_csv(json_path: Path) -> Path:
    csv_path = json_path.with_suffix(".csv")
    pd.read_json(json_path).to_csv(csv_path, index=False)
    return csv_path


def convert_all() -> dict:
    result = {
        "nikto": json_to_csv(NIKTO_JSON),
        "masscan": json_to_csv(MASSCAN_JSON),
    }
    nmap_csv = DATA_DIR / "nmap_output.csv"
    subprocess.run(
        [sys.executable, str(BASE_DIR / "xml2csv.py"),
         "-f", str(NMAP_XML), "-csv", str(nmap_csv)],
        check=True,
    )
    result["nmap"] = nmap_csv
    return result


# ---------- обработка masscan ----------

def parse_masscan(masscan_df: pd.DataFrame) -> pd.DataFrame:
    """Извлекает port/ttl из поля 'ports' и конвертирует timestamp."""
    def _first_port(cell):
        try:
            ports = ast.literal_eval(str(cell))
            return ports[0] if ports else {}
        except (ValueError, SyntaxError):
            return {}

    parsed = masscan_df["ports"].map(_first_port)
    masscan_df = masscan_df.copy()
    masscan_df["port"] = parsed.map(lambda d: d.get("port"))
    masscan_df["ttl"] = parsed.map(lambda d: d.get("ttl"))
    masscan_df["timestamp"] = masscan_df["timestamp"].map(
        lambda ts: time.mktime(
            datetime.datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").timetuple()
        )
        if isinstance(ts, str) else ts
    )
    return masscan_df


# ---------- обработка nikto ----------

def parse_nikto(nikto_df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for cell in nikto_df["vulnerabilities"]:
        try:
            vulns = ast.literal_eval(str(cell))
        except (ValueError, SyntaxError):
            continue
        if isinstance(vulns, dict):
            rows.append({
                "id": vulns.get("id"),
                "references": vulns.get("references"),
                "msg": vulns.get("msg"),
            })
    return pd.DataFrame(rows)


# ---------- основная логика ----------

def build_report(nmap_csv: Path, masscan_csv: Path, nikto_csv: Path) -> None:
    data_nmap = pd.read_csv(nmap_csv)
    data_masscan = parse_masscan(pd.read_csv(masscan_csv))
    data_nikto = pd.read_csv(nikto_csv)

    combined = pd.concat([data_nmap, data_masscan], ignore_index=True)
    print(tabulate(combined, headers="keys", tablefmt="psql"))

    ports_view = combined[["port", "timestamp", "ttl"]].dropna()
    print(tabulate(ports_view.sort_values("timestamp", ascending=False),
                   headers="keys", tablefmt="psql"))

    nikto_view = parse_nikto(data_nikto)
    print(tabulate(nikto_view, headers="keys", tablefmt="psql"))


def ask_int(prompt: str, validator=None) -> int:
    while True:
        raw = input(prompt).strip()
        if not raw.isdigit():
            print("Ожидается целое число.")
            continue
        value = int(raw)
        if validator and not validator(value):
            print("Недопустимое значение, попробуйте снова.")
            continue
        return value


def web_search_vulns(port: int, limit: int) -> None:
    if google_search is None:
        print("Модуль googlesearch не установлен — пропускаем поиск.")
        return
    try:
        urls = list(google_search(f"Port Vulners {port}", num_results=limit))
    except Exception as exc:
        print(f"Поиск не удался: {exc}")
        return
    if not urls:
        print("Ничего не найдено.")
        return
    url = random.choice(urls)
    print(f"Открываем: {url}")
    response = requests.get(url, timeout=10)
    soup = BeautifulSoup(response.text, "html.parser")
    for div in soup.find_all("div"):
        for p in div.find_all("p"):
            print(p.get_text())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", help="IP-адрес для сканирования")
    parser.add_argument("--skip-scan", action="store_true",
                        help="Не запускать сканеры (использовать готовые файлы)")
    args = parser.parse_args()

    target = args.target or input("Введите IP-адрес для сканирования: ").strip()
    if not target and not args.skip_scan:
        print("Пустой адрес.", file=sys.stderr)
        return 1

    if not args.skip_scan:
        run_scan(ScanConfig(target=target))

    files = convert_all()
    build_report(files["nmap"], files["masscan"], files["nikto"])

    limit = ask_int("Сколько результатов поиска выполнить: ",
                    validator=lambda x: x > 0)
    port = ask_int("Порт для поиска уязвимостей: ")
    web_search_vulns(port, limit)
    return 0


if __name__ == "__main__":
    sys.exit(main())
