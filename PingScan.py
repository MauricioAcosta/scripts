#!/usr/bin/env python
from subprocess import Popen, PIPE
#maquinas activas en un segmento de red "se puede hasta 254"
for ip in range(1,40):#conformacion de direccion IP
	ipAddress = '192.168.0.'+str(ip)
	print "Scanning %s " %(ipAddress)
	subprocess = Popen(['/bin/ping', '-c 1 ', ipAddress], stdin=PIPE, stdout=PIPE, stderr=PIPE)#INSTANCIA DEL COMANDO PING CON LOS ARGUMENTOS stdin=PIPE, stdout=PIPE, stderr=PIPE
	stdout, stderr= subprocess.communicate(input=None)
	if "bytes from " in stdout:#SI CONTIENE LA CADENA ES PORQUE LA MAQUINA NOS A CONTESTADO
		print "The Ip Address %s has responded with a ECHO_REPLY!" %(stdout.split()[1])
		with open("ips.txt", "a") as myfile:#creacion de un archivo ips para guardar las ips que respondieron
			myfile.write(stdout.split()[1]+'\n')
