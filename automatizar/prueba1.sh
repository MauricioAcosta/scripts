#!/bin/bash
echo "¿Cuantas veces desea ejecutar el Remoto? "
read num
for i in `seq $num`
do
  python github_python.py &
done
exit 1
