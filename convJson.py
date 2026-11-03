"""Конвертация JSON-выходов nikto/masscan в CSV."""
import argparse
import sys
from pathlib import Path

import pandas as pd


def json_to_csv(json_path: Path, csv_path: Path) -> None:
    """Читает JSON и сохраняет его в CSV без индекса."""
    df = pd.read_json(json_path)
    df.to_csv(csv_path, index=False)
    print(f"Данные конвертированы и сохранены в {csv_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-i", "--input", required=True, help="Входной JSON-файл")
    parser.add_argument("-o", "--output", help="Выходной CSV (по умолчанию — с тем же именем)")
    args = parser.parse_args()

    json_path = Path(args.input)
    if not json_path.is_file():
        print(f"Ошибка: файл {json_path} не найден", file=sys.stderr)
        return 1

    csv_path = Path(args.output) if args.output else json_path.with_suffix(".csv")
    json_to_csv(json_path, csv_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
