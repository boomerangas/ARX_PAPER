#!/bin/bash

for a in {1..7}
do
	for b in {1..7}
	do
		./eval.elf $a $b
	done
done
