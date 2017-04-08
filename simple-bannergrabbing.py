import socket
import sys
#socket IPV4 protocolo TCP
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#podemos recorrerlos hasta 254
for host in range(10, 80):
	ports = open('ports.txt', 'r')#abrimos los puertos que queremos escanear
	vulnbanners = open('vulnbanners.txt', 'r')#servicios vulnerables
	for port in ports:#recorremos los puertos
		try:
			socket.connect(( str(sys.argv[1]+'.'+str(host)), int(port) ))#nos conectamos a cada host con el puerto
			print 'Connecting to '+str(sys.argv[1]+'.'+str(host))+' in the port: '+str(port)
			socket.settimeout(1)#esperamos un segundo
			banner = socket.recv(1024)#recuperamos el banner
			for vulnbanner in vulnbanners:
				if banner.strip() in vulnbanner.strip():#si el baner es igual al vulnbanners hay una vulnerabilidad
					print 'We have a winner! '+banner
					print 'Host: '+str(sys.argv[1]+'.'+str(host))
					print 'Port: '+str(port)
		except :# no se esta utilizando el puerto se aumenta en mas 1 sys.argv[1]+
			print 'Error connecting to: '+str(sys.argv[1]+'.'+str(host)) +':'+ str(port)
			pass
