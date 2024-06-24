all: exp eval ABDTi ABCT ABCT-old

exp: toy-exp.cpp
	g++ toy-exp.cpp -o exp.elf

eval: toy-eval.cpp
	g++ toy-eval.cpp -o eval.elf

ABDTi: arx-bdti.cpp
	g++ arx-bdti.cpp -o ABDTi.elf

ABCT: arx-bct-2.cpp 
	g++ arx-bct-2.cpp -o ABCT.elf

ABCT-old: arx-bct.cpp 
	g++ arx-bct.cpp -o ABCT-ori.elf

clean:
	rm *.elf

