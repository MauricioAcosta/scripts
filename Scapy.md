#Tutorial básico de Scapy-Python.

https://en.wikipedia.org/wiki/Scapy

```bash
sudo apt install python-scapy
```
## Funciones Scapy
Protocolos soportados
```bash
ls()
```
Funciones disponibles
```bash
lsc()
```
Declaración de un paquete ICMP()
--hay que declarar la composición completa del paquete
```bash
packet = Ether()/IP(dst="google.com")/ICMP()/"ABCD"
```
Estructura de un paquete determinado
--información completa de cada paquete
```bash
ls(packet)
```
Con la función sendp() enviamos el paquete a su correspondiente destino.
```bash
sendp(packet)
```
Con las funciones loop e inter podemos enviar el paquede cada N segundos.
```bash
sendp(packet, loop=1, inter=1)
```
#con Wireshark podemos ver el trafico del paquete

Para enviar y recibir paquetes con un formato amigable y simplificado.
```bash
srp1(packet)
_.show()
_.summary()
```
con la funcion sniff() podemos capturar paquetes al igual que Wireshark, en este caso se capturaran 3 paquetes.
```bash
paquetes = sniff(iface="wlan0", count=3)
--Podemos observar cada paquete de la siguiente forma:
paquetes[0]
paquetes[1]
paquetes[2]
len(paquetes)
```
Si queremos almacenar un conjunto de paquetes en un fichero pk podemos utilizar la siguiente funcion.
```bash
wrpcap("demo.pcap",paquetes)
--con la funcion rdpcap podmos leer el fichero pcap y obtener el listado de paquetes que podemos utilizar en python.
readed = rdpcap("demo.pcap")
readed[0]
readed[1]
readed[2]
```
Filtro de paquetes icmp
```bash
icmpPkts = sniff(iface="wlan0", filter="icmp", count=3)
```
inyectar y manipular paquetes de datos
```bash
sniff(iface="wlan0", filter="icmp", count=3, prn=lambda_x:_x.summary()) # el _ remplazar por un espacio
```
ver y editar la configuración con la que trabaja scapy
```bash
conf
conf.route
--agregamos una nueva configuración
conf.route.add[net="192.168.2.0/24", gw="192.168.2.1"]
conf.route
--reiniciar el bloque de route de scapy
conf.route.resync()
conf.route
```
-http://www.secdev.org/projects/scapy/
