import os
import argparse
import subprocess
import logging
import xml.etree.ElementTree as ET
import requests
import concurrent.futures
import re
import tempfile
from loguru import logger

logger_file = logging.getLogger(__name__)

# функция для сканирования поддоменов домена с помощью subfinder и assetfinder
def scanSubDomain(domain_dir, domain):
    subfinder_result_file = os.path.join(domain_dir, "subfinder.txt") 
    assetfinder_result_file = os.path.join(domain_dir, "assetfinder.txt")
    waybackurls_result_file = os.path.join(domain_dir, "waybackurls.txt")
    targets_list_file = os.path.join(domain_dir, "targets_list.txt") 

    # проверяем, существует ли файл с результатами subfinder, если нет, то запускаем subfinder
    if not os.path.exists(subfinder_result_file): 
        logger.info("Starting subfinder")
        subprocess.run(["subfinder", "-d", domain, "-silent", "-o", subfinder_result_file]) 

    # проверяем, существует ли файл с результатами assetfinder, если нет, то запускаем
    if not os.path.exists(assetfinder_result_file):
        with open(assetfinder_result_file, "w") as outfile:

            # запускаем assetfinder с нужными параметрами и перенаправляем вывод в файл
            logger.info("Starting assetfinder")
            subprocess.run(["assetfinder", "--subs-only", domain], stdout=outfile)
    if not os.path.exists(waybackurls_result_file): 
        with open(waybackurls_result_file, "w") as outfile: 
            logger.info("Starting waybackurls")
            subprocess.run(["waybackurls", domain], stdout=outfile) 

            # открываем файл targets_list.txt для записи и записываем содержимое из subfinder.txt и amass.txt
    with open(targets_list_file, "w") as targets_file:  
        # проверяем, существует ли файл с результатами subfinder, если да, то открываем его и записываем содержимое в targets_list.txt
        if os.path.exists(subfinder_result_file): 
            with open(subfinder_result_file, "r") as subfinder_file: 
                targets_file.write(subfinder_file.read()) 

        # Проверяем, существует ли файл с результатами assetfinder, если да, то открываем его и записываем содержимое в targets_list.txt
        if os.path.exists(assetfinder_result_file):
            with open(assetfinder_result_file, "r") as assetfinder_file:
                targets_file.write(assetfinder_file.read())
        # Проверяем, существует ли файл с результатами waybackurls
        if os.path.exists(waybackurls_result_file): 
            with open(waybackurls_result_file, "r") as waybackurls_file: 
            
                targets_file.write(waybackurls_file.read()) 

                # Очистка файла targets_list.txt от лишних символов
    cleaned_lines = set() # создаем множество для хранения очищенных строк
    with open(targets_list_file, "r") as targets_file: # открываем файл targets_list.txt для чтения
        for line in targets_file: # цикл по каждой строке в файле
            domain_names = re.findall(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", line) # ищем все доменные имена в строке с помощью регулярного выражения
            if domain_names: # если нашли хотя бы одно доменное имя
                for domain_name in domain_names: # цикл по каждому найденному доменному имени
                    cleaned_domain_name = domain_name.replace("www.", "") # удаляем префикс www. из доменного имени
                    cleaned_lines.add(cleaned_domain_name) # добавляем очищенное доменное имя в множество   

    # открываем файл targets_list.txt и записываем множество очищенных строк в файл, разделяя их переносом строки
    with open(targets_list_file, "w") as targets_file:
        targets_file.write("\n".join(cleaned_lines)) 

        # Проверка файла targets_list.txt на наличие доменного имени пользователя в каждой строке
    user_domain = domain.replace("www.", "") # удаляем префикс www. из доменного имени пользователя
    filtered_lines = set() # создаем множество для хранения отфильтрованных строк
    with open(targets_list_file, "r") as targets_file: 
        for line in targets_file: # цикл по каждой строке в файле
            if user_domain in line: # если доменное имя пользователя есть в строке
                filtered_lines.add(line.strip()) # добавляем строку в множество, удаляя пробелы по краям  

    # открываем файл targets_list.txt и записываем множество отфильтрованных строк в файл, разделяя их переносом строки
    with open(targets_list_file, "w") as targets_file:
        targets_file.write("\n".join(filtered_lines))                

        # Запуск утилиты dnsx для проверки поддоменов и запись результата в новый файл live_sub_list.txt
    live_sub_list_file = os.path.join(domain_dir, "live_sub_list.txt") # создаем путь к новому файлу
    # проверяем, существует ли файл с результатами dnsx
    if not os.path.exists(live_sub_list_file): 
        # если нет, то запускаем утилиту dnsx
        logger.info("Starting dnsx")
        subprocess.run(["dnsx", "-l", targets_list_file, "-silent","-o", live_sub_list_file]) # запускаем утилиту dnsx с входным файлом targets_list_file и выходным файлом live_sub_list_file
    # возвращаем имя нового файла с общим списком поддоменов
    return live_sub_list_file


# функция для сканирования портов и сервисов с помощью nmap
def scan_nmap(domain, directory, cookie):
    logger_file.info(f"scan_nmap({domain}, {directory}, {cookie})")

    nmap_xml_result_file = os.path.join(directory, "nmap.xml") 
    nmap_plain_result_file = os.path.join(directory, "nmap.txt") 
    temp_xml_file = os.path.join(directory, "temp_stage1.xml") # временный файл для хранения результатов первого этапа

    # проверяем, существует ли файл nmap.xml в заданной директории
    if os.path.exists(nmap_xml_result_file):
        logger_file.info(f"{nmap_xml_result_file} file exists, return None")
        # если да, то возвращаем None и выходим из функции
        return None


    # добавляем проверку значения переменной domain
    if domain.count(".") == 3 and all(part.isdigit() for part in domain.split(".")): # если domain состоит из трех точек и все части являются цифрами
        ip_addr = domain # то это ip адрес и мы присваиваем его переменной ip_addr
        nslookup_output = "" # и пропускаем запуск утилиты nslookup
    else: # иначе
        # запуск утилиты nslookup на целевой доменный адрес
        nslookup_output = subprocess.check_output(["nslookup", domain]) # получаем вывод утилиты в виде байтов
        nslookup_output = nslookup_output.decode("utf-8") # декодируем байты в строку
        ip_addr = "" # переменная для хранения ip адреса
        for line in nslookup_output.split("\n"): # разбиваем строку по переносам строки
            if line.startswith("Address:"): # если строка начинается с Address:
                ip_addr = line.split()[1] # берем второй элемент строки после разделения по пробелам
                if not line.endswith("#53"): # если строка не заканчивается на #53
                    break # прерываем цикл

    # первый этап сканирования
    if not os.path.exists(os.path.join(directory, temp_xml_file)): # если файл не существует
        logger.info("Starting nmap fast scan")
        subprocess.run(["sudo", "nmap", ip_addr, "-sS", "-Pn", "-p-", "-v", "-T4", "--min-parallelism", "10", "--max-retries", "2", "-oX", temp_xml_file]) 

        # парсинг xml-файла 
    open_ports = [] # переменная для хранения списка открытых портов
    tree = ET.parse(temp_xml_file)
    root = tree.getroot() 
    for port_tag in root.iter('port'): 
        if 'portid' in port_tag.attrib: 
            open_ports.append(port_tag.get('portid')) 

    os.remove(temp_xml_file)

    if not os.path.exists(os.path.join(directory, "nmap.xml")): 
        # второй этап сканирования
        port_range = re.sub("[^0-9,]", "", ",".join(open_ports))
        logger.info("Starting nmap full scan")
        subprocess.run(["sudo", "nmap", ip_addr, "-sS", "-Pn", "-O", "--osscan-limit", "-v", "-sC", "-sV", "-T4", "--min-parallelism", "10", "-p" + port_range, "--max-retries", "2", "-oX", nmap_xml_result_file, "-oN", nmap_plain_result_file]) 

        # проверяем, существует ли файл с xml-результатами nmap, если нет, то выбрасываем исключение     
    if not os.path.exists(nmap_xml_result_file): 
        raise FileNotFoundError 
    try:
        ports = get_open_ports(directory, nmap_xml_result_file, domain) # пытаемся получить список открытых портов из xml-файла
    # если возникла ошибка при парсинге xml-файла
    except ValueError as e: 
        print(str(e)) # выводим сообщение об ошибке
        return # выходим из функции 

    #функция для получения и сохранения веб-сервисов
    get_and_save_web_services(ports, directory, cookie)


# функция поиска открытых портов

def get_open_ports(directory, nmap_xml_result_file, domain):

    open_ports = [] # создаем список для хранения открытых портов
    tree = ET.parse(nmap_xml_result_file) # парсим xml-файл как дерево элементов
    root = tree.getroot() # получаем корневой элемент дерева
    host_tag = root.find('host') # ищем элемент <host> в корне
    if host_tag is None: # если не нашли такой элемент
        raise ValueError(f'Could not find tag <host> on file {nmap_xml_result_file}') # выбрасываем исключение
    hostname = None # создаем переменную для хранения имени хоста
    hostnames_tag = host_tag.find('hostnames') # ищем элемент <hostnames> в <host>
    if hostnames_tag is not None: # если нашли такой элемент
        hostname_tag = hostnames_tag.find('hostname') # ищем элемент <hostname> в <hostnames>
        if hostname_tag is not None: # если нашли такой элемент
            if 'name' in hostname_tag.attrib: # если у элемента есть атрибут name
                hostname = hostname_tag.get('name') # получаем значение атрибута name как имя хоста
    print(hostname) # выводим имя хоста
    address_tag = host_tag.find('address') # ищем элемент <address> в <host>
    if address_tag is None: # если не нашли такой элемент
        raise ValueError(f'Could not find tag <address> in <host> on file {nmap_xml_result_file}') # выбрасываем исключение
    if 'addr' not in address_tag.attrib: # если у элемента нет атрибута addr
        raise ValueError(f'Could not find attribute addr in tag <address> on file {nmap_xml_result_file}') # выбрасываем исключение
    if hostname is None: # если имя хоста не определено
        hostname = address_tag.get('addr') # используем значение атрибута addr как имя хоста
    ports_tag = host_tag.find('ports') # ищем элемент <ports> в <host>
    if ports_tag is None: # если не нашли такой элемент
        return # выходим из функции
    for port_tag in ports_tag.findall('port'): # цикл по каждому элементу <port> в <ports>
        if 'portid' not in port_tag.attrib: # если у элемента нет атрибута portid
            continue # переходим к следующему элементу
        state_tag = port_tag.find('state') # ищем элемент <state> в <port>
        if state_tag is None: # если не нашли такой элемент
            continue # переходим к следующему элементу
        if 'state' not in state_tag.attrib: # если у элемента нет атрибута state
            continue # переходим к следующему элементу
        if state_tag.get('state') == 'open': # если значение атрибута state равно open
            open_ports.append(f"{domain}:{port_tag.get('portid')}") # добавляем строку с доменным именем и номером порта в список открытых портов
    if len(open_ports) > 0: # если список открытых портов не пустой
        with open(os.path.join(directory, 'open_ports.txt'), 'w') as fp: # открываем файл open_ports.txt для записи
            fp.write("\n".join(open_ports)) # записываем список открытых портов в файл, разделяя их переносом строки
    return open_ports # возвращаем список открытых портов



# функция проверки открытых портов на наличие http сервисов
def check_if_http(session, url):
    try:
        _ = session.get(f"http://{url}") # пытаемся отправить http-запрос по заданному url с помощью сессии requests
    except requests.exceptions.ConnectionError: # если возникла ошибка подключения
        return False # возвращаем False, т.е. url не является http-сервисом
    return True # возвращаем True, т.е. url является http-сервисом

# функция создания файла со списком http портов
def get_and_save_web_services(ports, directory, cookie):
    if not ports: # если список портов пустой
        return # выходим из функции

    # создаем словарь с заголовками http-запросов
    headers = { 
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36", 
        "Cookie": cookie 
    }
    # создаем сессию requests и обновляем заголовки сессии
    session = requests.Session() 
    session.headers.update(headers) 

    # создаем список для хранения http-портов
    http_ports = [] 
    with concurrent.futures.ThreadPoolExecutor() as executor: # создаем пул потоков для параллельной обработки
        futures = {executor.submit(check_if_http, session, url): url for url in ports} # запускаем функцию check_if_http для каждого url в списке портов и сохраняем результаты в словаре futures
        for future in concurrent.futures.as_completed(futures): # цикл по каждому завершенному результату в futures
            url = futures[future] # получаем url, соответствующий результату
            try:
                is_http = future.result() # пытаемся получить значение результата (True или False)
            except Exception as exc: # если возникла ошибка
                print('%r generated an exception: %s' % (url, exc)) 
            else: # если ошибки не было
                if is_http: # если результат равен True, т.е. url является http-сервисом
                    http_ports.append(url) # добавляем url в список http-портов 
    print(http_ports) # выводим список http-портов
    if len(http_ports) > 0: # если список не пустой
        with open(os.path.join(directory, 'http_ports.txt'), 'w') as fp: 
            fp.write("\n".join(http_ports)) # записываем список http-портов в файл, разделяя их переносом строки
    session.close() 


# запуск утилиты httpx    

def run_httpx(directory, cookie):
    logger_file.debug(f"run_httpx({directory}, {cookie})")

    open_ports_file = os.path.join(directory, 'open_ports.txt')
    #http_ports_file = os.path.join(directory, 'http_ports.txt')
    httpx_output_file = os.path.join(directory, 'httpx_res.txt')
    httpx_silent_output_file = os.path.join(directory, 'httpx_silent_res.txt')

    if not os.path.exists(httpx_output_file):
        logger.info("Starting httpx full")
        subprocess.run(["httpx", "-l", open_ports_file, "-silent","-H", f"Cookie: {cookie}", "-status-code", "-follow-redirects", "-tech-detect", "-fc", "500,501,502,503,504,505,403,401,404,405,400", "-server", "-websocket", "-ip", "-cname", "-asn", "-cdn", "-location", "-x", "ALL", "-tls-probe", "-o", httpx_output_file])
        
        logger.info("Starting httpx silent")
        subprocess.run(["httpx", "-l", open_ports_file, "-silent", "-o", httpx_silent_output_file])

    return

# запуск утилиты katana    
def run_katana(directory, cookie):
    logger_file.debug(f"run_katana({directory}, {cookie})")

    http_ports_file = os.path.join(directory, 'http_ports.txt')
    katana_output_file = os.path.join(directory, 'katana_res.txt')
    httpx_silent_output_file = os.path.join(directory, 'httpx_silent_res.txt') 
    fff_output_file = os.path.join(directory, 'fff_res.txt')
    
    # добавляем проверку на пустой файл
    if os.path.getsize(httpx_silent_output_file) == 0:
        logger_file.info(f"{httpx_silent_output_file} is empty, skip process")
        return # выходим из функции
    
    if not os.path.exists(katana_output_file):
        logger.info("Starting katana")
        #subprocess.run(["katana", "-u", httpx_silent_output_file, "-d", "10", "-jc", "-f", "url", "-ef", "css,png,jpg,gif,mp3,mp4,bmp,ico,svg", "-p", "1", "-c", "5", "-rl", "50", "-kf", "all", "-H", f"Cookie: {cookie}", "-o", katana_output_file])
        subprocess.run(["katana", "-u", httpx_silent_output_file, "-d", "10", "-jc", "-f", "url", "-silent", "-ef", "css,png,jpg,gif,mp3,mp4,bmp,ico,svg", "-p", "1", "-ct", "500", "-c", "5", "-rl", "50", "-kf", "all", "-H", f"Cookie: {cookie}", "-o", katana_output_file])

    # запуск утилиты fff
    if not os.path.exists(fff_output_file):
        logger_file.info(f"{fff_output_file} does not exist, run process")
        f = open(katana_output_file, "r")
        outfile = open(fff_output_file, "w")

        logger.info("Starting fff")
        subprocess.run(["fff", "-d", "1000", "-x", "http://127.0.0.1:8080", "-H", f"Cookie: {cookie}"], stdin=f, stdout=outfile) 

        f.close()
        outfile.close()

    return

# запуск утилиты nuclei
def run_nuclei(directory, cookie):
    logger_file.debug(f"run_nuclei({directory}, {cookie})")

    open_ports_file = os.path.join(directory, 'open_ports.txt')
    nuclei_output_file_js = os.path.join(directory, 'nuclei.json')
    nuclei_output_file_txt = os.path.join(directory, 'nuclei.txt')
    nuclei_templates_path = os.path.expanduser('/nuclei-templates/')
    #nuclei_templates_path = os.path.expanduser('~/cent-nuclei-templates/')

    if not os.path.exists(nuclei_templates_path):
        logger.error("nuclei-templates folder not found")
        logger.warning("You have to download nuclei-templates!")
        raise FileNotFoundError(f"nuclei-templates folder not found. Your folder {nuclei_templates_path}")

    if not os.path.exists(nuclei_output_file_txt) or not os.path.exists(nuclei_output_file_js):
        logger.info("Starting nuclei")
        subprocess.run(["nuclei", "-l", open_ports_file, "-t", nuclei_templates_path, "-H", f"Cookie: {cookie}", "-stats", "-s", "low,medium,high,critical", "-retries", "1", "-rl", "150", "-jle", nuclei_output_file_js, "-o", nuclei_output_file_txt, "-silent"])
        
    elif os.path.exists(nuclei_output_file_txt) and os.path.exists(nuclei_output_file_js):
        logger.debug("Skipping nuclei")
    else:
        logger.error("ERROR!")
    return

# функция для преобразования xml-файлов с результатами nmap в таблицу
# принимает на вход директорию с xml-файлами
# возвращает имя файла с таблицей в формате txt
def xml_to_table(domain_dir, domain):
    # создаем список для хранения строк таблицы
    table = []
    # создаем заголовочную строку с названиями столбцов
    header = ["HOST", "IP", "PORT / PROTOCOL", "STATE", "SERVICE", "VERSION"]
    # добавляем заголовочную строку в таблицу
    table.append(header)
    # цикл по всем файлам и поддиректориям в заданной директории
    for root_dir, dirs, files in os.walk(domain_dir):
        # цикл по всем файлам
        for file in files:
            # проверяем, имеет ли файл расширение .xml
            if file.endswith(".xml"):
                # парсим xml-файл как дерево элементов
                tree = ET.parse(os.path.join(root_dir, file))
                # получаем корневой элемент дерева
                root = tree.getroot()
                # цикл по всем элементам <host> в корне
                for host_elem in root.findall("host"):
                    # получаем значение ip из элемента <address>
                    ip = host_elem.find("address").get("addr")
                    # получаем значение host из элемента <hostname>, или используем ip, если не найдено
                    host = os.path.basename(root_dir)
                    # создаем новую строку с значениями host и ip
                    row = [host, ip, "", "", "", ""]
                    # добавляем строку в таблицу
                    table.append(row)
                    # цикл по всем элементам <port> в элементе <ports>
                    for port_elem in host_elem.find("ports").findall("port"):
                        # получаем значения port, state и service из атрибутов и подэлементов
                        port = port_elem.get("portid") + "/" + port_elem.get("protocol")
                        state = port_elem.find("state").get("state")
                        # проверяем, есть ли подэлемент <service>
                        if port_elem.find("service") is not None:
                            # получаем значение service из атрибута name
                            service = port_elem.find("service").get("name")
                            # проверяем, есть ли значение version
                            if port_elem.find("service").get("product"):
                                # получаем значение version из атрибута product, и добавляем другие атрибуты, если есть
                                version = port_elem.find("service").get("product")
                                for attr in ["version", "extrainfo", "ostype"]:
                                    if port_elem.find("service").get(attr):
                                        version += " " + port_elem.find("service").get(attr)
                            else:
                                # устанавливаем значение version как пустое
                                version = ""
                        else:
                            # устанавливаем значения service и version как пустые
                            service = ""
                            version = ""
                        # обновляем последнюю строку с значениями port, state, service и version
                        table[-1][2] = port
                        table[-1][3] = state
                        table[-1][4] = service
                        table[-1][5] = version.strip()
                        # создаем новую строку с пустыми значениями для host и ip
                        row = ["", "", "", "", "", ""]
                        # добавляем строку в таблицу
                        table.append(row)
    # удаляем последнюю пустую строку из таблицы
    table.pop()
    # создаем строку для хранения вывода
    output = ""
    # создаем список для хранения ширины столбцов
    widths = []
    # цикл по каждому столбцу в заголовочной строке
    for i in range(len(header)):
        # получаем максимальную длину любого значения в этом столбце, или используем 10 как минимальную ширину
        width = max(len(row[i]) for row in table) + 2 
        width = max(width, 10)
        # добавляем ширину в список
        widths.append(width)
    # цикл по каждой строке в таблице
    for row in table:
        # соединяем значения строки с символом | и добавляем пробелы для выравнивания, обрезая их, если они слишком длинные
        output += "|{:<{w[0]}.{w[0]}}|{:<{w[1]}.{w[1]}}|{:<{w[2]}.{w[2]}}|{:<{w[3]}.{w[3]}}|{:<{w[4]}.{w[4]}}|{:<{w[5]}.{w[5]}}|\n".format(*row, w=widths)
        # добавляем горизонтальную линию после каждой строки, используя символ | для соединения линий
        output += "|{:-<{w[0]}}|{:-<{w[1]}}|{:-<{w[2]}}|{:-<{w[3]}}|{:-<{w[4]}}|{:-<{w[5]}}|\n".format("", "", "", "", "", "", w=widths)
    # записываем вывод в файл с именем infra.txt
    output_file = os.path.join(domain_dir, "infra.txt")

    with open(output_file, "w") as f:
        f.write(output)

    # возвращаем вывод как сообщение
    return output_file


def run_process(domain: str,
                domain_dir: str,
                subdomains: list,
                cookie: str):
    logger_file.warning("--- STARTUP PARAMS ---")
    logger_file.info(domain)
    logger_file.info(domain_dir)
    logger_file.info(subdomains)
    logger_file.info(cookie)

    for subdomain in sorted(subdomains): # цикл по каждому поддомену в отсортированном списке
        logger_file.info(f"for loop subdomain: {subdomain}")

        # проверяем, является ли поддомен ip адресом
        if re.match(r"\d+\.\d+\.\d+\.\d+", subdomain): # если да, то используем его как domain_alias
            logger_file.info(f"subdomain {subdomain} is IP")
            domain_alias = subdomain
        elif subdomain == domain: # если поддомен совпадает с доменом, то используем "main" как domain_alias
            logger_file.info(f"subdomain is equal of domain. {subdomain} == {domain}")
            domain_alias = domain + "_main_name"
            # subdomain_dir = os.path.join(domain_dir, domain_alias) # создаем путь к папке поддомена
            # os.makedirs(subdomain_dir)
        else: # если нет, то используем первую часть поддомена как domain_alias
            splitted_subdomain = subdomain.split(".")
            logger_file.info(f"{splitted_subdomain}")
            #domain_alias = ".".join(splitted_subdomain[:-2])
            domain_alias = subdomain

        subdomain_dir = os.path.join(domain_dir, domain_alias) 
        logger_file.info(f"creating subdomain {subdomain_dir} folder")
        os.makedirs(subdomain_dir, exist_ok=True) 

        logger_file.info(f"current subdomain_dir: {subdomain_dir}")

        scan_nmap(subdomain, subdomain_dir, cookie) 

        # проверяем, существуют ли файлы с открытыми портами и с веб сервисами
        open_ports_file = os.path.join(subdomain_dir, "open_ports.txt") 
        http_ports_file = os.path.join(subdomain_dir, "http_ports.txt")

        if not (os.path.exists(open_ports_file) or os.path.exists(http_ports_file)):
            # если нет, то пропускаем дальнейшее сканирование этого хоста
            continue

        run_httpx(subdomain_dir, cookie) 
        run_katana(subdomain_dir, cookie) 
        run_nuclei(subdomain_dir, cookie) 

        output_file = xml_to_table(domain_dir, domain) 

        logger.info(f"File infra.txt Created at the path: {output_file}") 


def main(domain, domains, mode, cookie):
    # mode = int(input("Select mode: 1 - scan the entire domain completely, 2 - only a specific scope "))
    # domain = input("Enter the domain address. For example: example.com: ")
    # cookie = input("Enter authentication cookie or token: ")

    if int(mode) != 1 and int(mode) != 2:
        logger.error('Invalid mode. Please choose 1 or 2.')
        return

    result_dir = "results" 
    os.makedirs(result_dir, exist_ok=True) 
    # получаем имя домена из адреса
    domain_name = domain.split(".")[0] 
    # создаем путь к директории для хранения результатов по домену
    domain_dir = os.path.join(result_dir, domain_name) 
    # создаем директорию, если она не существует
    if not os.path.exists(domain_dir):
        logger_file.info(f"{domain_dir} does not exist, creating")
        os.makedirs(domain_dir, exist_ok=True) 

    if mode == 1: # 1 - сканировать весь домен целиком
        # logger_file.info(f"choose mode 1")

        subdomain_list = scanSubDomain(domain_dir, domain) # вызываем функцию scanSubDomain для поиска поддоменов и получаем имя файла со списком поддоменов
        # открываем файл со списком поддоменов для чтения
        with open(subdomain_list, "r") as file: 
            subdomains = list(set([subdomain.strip() for subdomain in file.readlines()])) # читаем все строки из файла

        if len(subdomains) == 0:
            logger.error(f"subdomains list is empty")
            return

        run_process(domain, domain_dir, subdomains, cookie)
    elif mode == 2: # 2 - сканировать определенный скоуп
        # logger.info(f"choose mode 2")

        subdomain_list = os.path.join(domain_dir, "subdomain_list.txt") # задаем имя файла со списком поддоменов
        # user_input = input("Enter subdomains, separating them with spaces: ") # запрашиваем у пользователя поддомены, разделенные пробелами
        subdomains = [subdomain.strip() for subdomain in domains.split()] 

        if len(subdomains) == 0:
            logger.error(f"subdomains list is empty")
            return

        with open(subdomain_list, "w") as file: # открываем файл со списком поддоменов для записи
            file.write("\n".join(subdomains)) # записываем список поддоменов в файл, разделяя их переносом строки

        run_process(domain, domain_dir, subdomains, cookie)
    else:
        logger.error(f"mode {mode} does not support")
        raise ValueError(f"mode {mode} does not support")


if __name__ == "__main__":
    LOG_FORMAT = ('[%(asctime)s] %(levelname)s %(name)s %(filename)s:%(lineno)d  %(funcName)s %(message)s')

    os.makedirs("logs", exist_ok=True) 
    logging.basicConfig(format=LOG_FORMAT, level=logging.INFO, filename="logs/scan.log")

    parser = argparse.ArgumentParser()
    parser.add_argument("-d",
                        "--domain",
                        type=str,
                        help="Domain for scanning",
                        required=True)
    parser.add_argument("-l",
                        "--domains",
                        type=str,
                        default=None,
                        help="Domain list for scanning(ONLY if use mode 2)",
                        required=False)
    parser.add_argument("-m",
                        "--mode",
                        type=int,
                        help="Select mode: 1 - scan the entire domain completely, 2 - only a specific scope ",
                        required=True)
    parser.add_argument("-c",
                        "--cookie",
                        type=str,
                        default=None,
                        help="Authentication cookie or token",
                        required=False)

    args = parser.parse_args()

    main(args.domain, args.domains, int(args.mode), args.cookie)

