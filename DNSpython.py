#!/usr/bin/env python
import dns
import dns.resolver
#Registros para servidores de correo
ansMX = dns.resolver.query('google.com', 'A')
ansMX = dns.resolver.query('google.com', 'MK')
#Registros para servidores de nombres
ansNS = dns.resolver.query('google.com', 'NS')
#Registros para direcciones IPV4
ansA = dns.resolver.query('google.com', 'A')
#Registros para direciones IPV6
ansAAAA = dns.resolver.query('google.com', 'AAAA')
#registros del tipo SDA
ansSDA = dns.resolver.query('google.com', 'SDA')
#registros textuales
ansTXT = dns.resolver.query('google.com', 'TXT')

for ans in ansMX:
    print ans
for ans in ansNS:
    print ans
for ans in ansA:
    print ans
for ans in ansAAAA:
    print ans
for ans in ansSDA:
    print ans
for ans in ansTXT:
    print ans
