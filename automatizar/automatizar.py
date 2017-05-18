#!/usr/bin/env python
# Autor: MauricioAcosta

from selenium import webdriver
from selenium.webdriver.common.keys import Keys
import time

#Ruta de nuestro navegador Probado con Chrome() con Firefox() no me funciona T_T
browser = webdriver.Chrome()
browser.get("https://facebook.com")
time.sleep(2)
#inspeccionamos la pagina de facebook y obtenemos el nombre de los campos
username = browser.find_element_by_id("email")
password = browser.find_element_by_id("pass")

#Cambiamos los datos que seran ingreados a los campos email y pass
username.send_keys("<tu_email>")
password.send_keys("<tu_password>")

#Emula el hacer click en "Iniciar Sesion"
login_attempt = browser.find_element_by_xpath("//*[@type='submit']")
login_attempt.submit()
time.sleep(5)#espera 5 segundos antes de colocar los datos
browser.close()
