import subprocess
import pandas as pd
import numpy as np
from tabulate import tabulate
from numpy import poly1d
from bs4 import BeautifulSoup
import requests
import random
import os
import time
import datetime
import json
import ast
from googlesearch import search

# Запрос ввода IP-адреса
ip = input("Введите IP-адрес для сканирования: ")
try:
    # Nmap сканирование и сохранение в XML
    nmap_cmd = f'nmap -T4 -A {ip} -oX nmap_output.xml'
    subprocess.run(nmap_cmd, shell=True)

    # Nikto сканирование и сохранение в JSON
    nikto_cmd = f'nikto -h {ip} -Format json -o nikto_output.json'
    subprocess.run(nikto_cmd, shell=True)

    # Masscan сканирование и сохранение в JSON
    masscan_cmd = f'masscan {ip} -p80,443,8000-8100 -oJ masscan_output.json'
    subprocess.run(masscan_cmd, shell=True)


    def convert_json_to_csv(json_file_path):
        command = f'python convJson.py -i {"/media/sf_Kali-linux/LastSborka/nikto_output.json"}'  # Предполагая, что convert_json_to_csv.py - это скрипт конвертации
        subprocess.run(command, shell=True)


    def convert_json_to_csv(json_file_path):
        command = f'python convJson.py -i {"/media/sf_Kali-linux/LastSborka/masscan_output.json"}'  # Предполагая, что convert_json_to_csv.py - это скрипт конвертации
        subprocess.run(command, shell=True)


    # Конвертация .json файлов в .csv
    convert_json_to_csv("/media/sf_Kali-linux/LastSborka/nikto_output.json")

    convert_json_to_csv("/media/sf_Kali-linux/LastSborka/masscan_output.json")

    # Конвертация .xml файлов в .csv
    xml2csv = f"python3 xml2csv.py -f nmap_output.xml -csv nmap_output.csv"
    subprocess.run(xml2csv, shell=True)

    # Загрузка данных из csv-файла
    # data9 = pd.read_json('/media/sf_Kali-linux/LastSborka/masscan_output.json')
    data = pd.read_csv('/media/sf_Kali-linux/LastSborka/nmap_output.csv')
    data1 = pd.read_csv('/media/sf_Kali-linux/LastSborka/masscan_output.csv')
    data6 = pd.read_csv('/media/sf_Kali-linux/LastSborka/nikto_output.csv')

    # timestamp
    d1 = []
    for timestamp in data1['timestamp']:
        a2 = time.mktime(datetime.datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S').timetuple())
        d1.append(a2)
    data1['timestamp'] = d1

    # dict
    h1 = []
    h2 = []
    h3 = []
    h4 = []
    h5 = []
    sunofdog1 = data1["ports"]
    t = sunofdog1.to_dict()
    for i in range(len(t)):
        b = t[i].split()
        data_str = "".join(b)
        result = ast.literal_eval(data_str)
        r1 = result[0].get('port')
        r2 = result[0].get('proto')
        r3 = result[0].get('status')
        r4 = result[0].get('reason')
        r5 = result[0].get('ttl')
        h1.append(r1)
        h2.append(r2)
        h3.append(r3)
        h4.append(r4)
        h5.append(r5)
    data1['port'] = h1
    data1['ttl'] = h5

    data3 = pd.concat([data, data1], ignore_index=True)
    data4 = data3[['port', 'timestamp', 'ttl']]
    data5 = data4.dropna()
    print(tabulate(data3, headers="keys", tablefmt="psql"))
    s = list(data5["timestamp"])
    s1 = list(data5["port"])
    s2 = list(data5["ttl"])

    s1[len(s1) - 1] = s1[len(s1) - 1] - s[0]
    s2[len(s2) - 1] = s2[len(s2) - 1] - s[1]
    p1 = np.poly1d(s1)
    p2 = np.poly1d(s2)
    roots1 = list(p1.r)
    roots2 = list(p2.r)

    d = []

    for i in roots2:
        roots1.append(i)

    a = roots1
    b = []
    for i in range(len(a)):
        t = abs(abs(a[i].real))
        b.append(t)
    c = [int(i) for i in b]

    u = 1
    for i in c:
        u *= i

    for i in range(len(s1)):
        y = abs(s1[i] * u + s2[i])
        d.append(y)

    data5.drop('timestamp', axis=1, inplace=True)
    data5.insert(2, 'timestamp', d)
    print(tabulate(data5, headers="keys", tablefmt="psql"))

    o = []
    o1 = []
    o2 = []
    sunofdog2 = data6["vulnerabilities"]
    t2 = sunofdog2.to_dict()
    for i in range(len(t2)):
        b = t2[i].split()
        data_str = "".join(b)
        result = ast.literal_eval(data_str)
        r1 = result.get('id')
        r2 = result.get('references')
        r3 = result.get('msg')
        o.append(r1)
        o1.append(r2)
        o2.append(r3)
    data5["id"] = o
    data5["references"] = o1
    data5["msg"] = o2

    res = list(data3["OS"])
    ind = res[:len(data5["port"])]
    data5["OS"] = ind

    res1 = list(data3["NSE Script ID"])
    ind1 = res1[:len(data5["port"])]
    data5["NSE Script(s)"] = ind1

    res2 = list(data3["Proto"])
    ind2 = res2[:len(data5["port"])]
    data5["Proto"] = ind2

    res3 = list(data3["IP"])
    ind3 = res3[:len(data5["port"])]
    data5["IP"] = ind3

    data7 = data5.sort_values("timestamp", ascending=False)
    print(tabulate(data7, headers="keys", tablefmt="psql"))

    total_searches = str(input("How many searches you would like to do: "))
    while not total_searches.isdigit():
        print("wrong number")
        total_searches1 = str(input("How many searches you would like to do: "))
        total_searches = total_searches1
    zz = int(total_searches)

    prt = list(data7["port"])
    prt1 = [int(i) for i in prt]
    searchTerm = str(input("Please enter your search term(Open Port:""port""Vulnerabilities):"))
    while not searchTerm.isdigit():
        ss1 = str(input())
        searchTerm = ss1
    searchTerm = int(searchTerm)
    while searchTerm not in prt1:
        print("this port is not include, change him")
        searchTerm1 = int(input("Please enter your search term(Open Port:""port""Vulnerabilities):"))
        searchTerm = searchTerm1

    cc = searchTerm
    cc = str(cc)
    cc1 = list(search(f"Port Vulners {cc}", stop=zz))
    cc2 = []
    for i in cc1:
        cc2.append(i)
    cc3 = random.randint(0, len(cc2) - 1)
    response = cc2[cc3]
    response1 = requests.get(response)
    soup = BeautifulSoup(response1.text, "html.parser")
    soup1 = soup.find_all("div")
    for soup2 in soup1:
        soup3 = soup2.find_all("p")
        for tag in soup3:
            print(tag.get_text())
except Exception as e:
    print(e)