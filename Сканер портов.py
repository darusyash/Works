from threading import Thread # Потоки, оптимизация
import PySimpleGUI as sg # Графика
import socket # Сканирование данных
import ipaddress # Работа с IP-адресами
import sys #Системаная библиотека
import netifaces # Сетевая библиотека

#Процедура создание подключения к адресу
def getServiceName(port, proto): 
    try: 
        name = socket.getservbyport(int(port), proto) 
    except: 
        return None 
    return name 

# Процедура сканирования UDF
def scan_portUDF(ip,results,RPORT,inx): 
    UDP_IP = ip
    MESSAGE = "ping" 
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) 
    if client == -1: 
        # Вывод ошибки при создании связи с UPD
        results[inx] = 'Данный порт '+ ip + str(RPORT) + ' имеет ошибку при создании сокета UDP '
    sock1 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) 
    if sock1 == -1: 
        # Вывод ошибки при создании связи с ICMP
        results[inx] ='Данный порт '+ ip + str(RPORT) + ' имеет ошибку при создании сокета ICMP ' 
    try: 
        client.sendto(MESSAGE.encode('utf_8'), (UDP_IP, RPORT)) 
        sock1.settimeout(1) 
        data, addr = sock1.recvfrom(1024) 
    except socket.timeout: 
        serv = getServiceName(RPORT, 'UDP') 
        if not serv: 
            pass 
        else: 
            # Вывод результата сканирования UDF
            results[inx] = 'Данный порт '+ ip + str(RPORT) + ' открыт для доступа ' 
    except socket.error as sock_err: 
            if (sock_err.errno == socket.errno.ECONNREFUSED): 
                # Вывод при отказе в соединение 
                results[inx] ='С данным портом '+ ip + str(RPORT) + ' невозможно создать соединение '
            client.close() 
            sock1.close() 

# Процедура сканирования TCP
def scan_portTCP(ip,results,port,inx): 
  soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   
  soc.settimeout(0.5) 
  try: 
     connect = soc.connect((ip,port))
     # Вывод результата сканирования TPC
     results[inx] ='Данный порт '+ ip + str(port) + ' открыт для доступа '  
     connect.close() 
  except: 
     pass 

# Процедура, возращающая массив IP-адресов из указанного диапазона
def RIP(ip1,ip2): 
    sp = [] 
    start_ip = ipaddress.IPv4Address(ip1) 
    end_ip = ipaddress.IPv4Address(ip2) 
    for ip_int in range(int(start_ip), int(end_ip)+1): 
       #print(ipaddress.IPv4Address(ip_int)) 
       sp.append(str(ipaddress.IPv4Address(ip_int))) 
    return sp 

# Получение данных об хосте
hostname = socket.gethostname()
IP = socket.gethostbyname(hostname)
interfaces = netifaces.interfaces()
spippc=[] 

# Интерфейс программы
for i in interfaces: 
    if i == 'lo': 
        continue 
    iface = netifaces.ifaddresses(i).get(netifaces.AF_INET) 
    if iface != None: 
        for j in iface: 
            spippc.append(j['addr'])
sg.theme("DarkTeal12")
layout = [ 
    [sg.Text('IP'), sg.InputText(IP), 
     ], 
     [sg.Radio('TCP', "RADIO1", default=True), sg.Radio('UDP', "RADIO1")], 
    [sg.Text('Port'), sg.InputText('1-1000'), 
     ], 
    [sg.Output(size=(88, 20))], 
    [sg.Submit(), sg.Cancel()], 
    [sg.InputCombo((spippc), size=(20, 1))] 
] 

# Создание окна приложения  
window = sg.Window('Сканер портов', layout=layout) 

# Цикл, запращивающий информацию о событиях в объекте приложения
while True: 
     
    event, values = window.read() 
    # print(values) 
     
    if event in (None, 'Exit', 'Cancel'): 
        break 
  
    # Массив, содержащий диапозон IP-адресов
    spip = values[0].split('-') 
    if  len(spip) == 0 or len(spip) > 2: 
        continue 
    if  len(spip) == 1: 
        ip1 = spip[0] 
        ip2 = spip[0] 
    if len(spip) == 2: 
        ip1 = spip[0] 
        ip2 = spip[1]         
    sp = RIP(ip1,ip2) 
  
    # Массив, содержащий диапозонон портов
    sport = values[3].split('-') 
    if  len(sport) == 0 or len(sport) > 2: 
        continue 
    if  len(sport) == 1: 
        port1 = sport[0] 
        port2 = sport[0] 
    if len(sport) == 2: 
        port1 = sport[0] 
        port2 = sport[1]  
  
    # Работа с диапозоном
    for ip in sp: 
        Nsport = int(port2) - int(port1) + 1  
        threads = [None] * Nsport 
        results = [''] * Nsport 
        # Вывод об начале сканирования
        print('Идёт сканирование ',ip, '\nОжидайте результатов') 
        inx = 0 
        # Перебор портов
        for i in range(len(threads)): 
            inx+=1
            #TCP
            if values[1]: 
                threads[i] = Thread(target=scan_portTCP, args=(ip, results, i,inx)) 
                threads[i].start() 
            #UDP
            if values[2]: 
                threads[i] = Thread(target=scan_portUDF, args=(ip, results, i,inx)) 
                threads[i].start() 

        # Завершение работы с потоком и получение даанных
        for i in range(len(threads)): 
            threads[i].join() 
  
        # Вывод оконачательного результата сканирования
        for y in results: 
            if y != '': 
                print (y)
        print(ip,' просканирован')
