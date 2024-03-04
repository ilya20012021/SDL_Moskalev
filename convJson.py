import pandas as pd

json_data = pd.read_json('nikto_output.json')
json_data1 = pd.read_json('masscan_output.json')

csv_file = 'nikto_output.csv'
csv_file1 = 'masscan_output.csv'
json_data.to_csv(csv_file, index=False)
json_data1.to_csv(csv_file1, index=False)

print(f'Данные конвертированы и сохранены в {csv_file}')