#!/bin/bash
for i in `seq 1`
do
  python github_python.py &
done
exit 1
