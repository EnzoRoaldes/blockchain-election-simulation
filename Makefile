all : main test simulation block_main

main : prime.o crypto.o vote.o syst_central.o utilities.o main.o
	gcc prime.o crypto.o vote.o syst_central.o utilities.o main.o -lm -g -o main

test : prime.o crypto.o vote.o syst_central.o utilities.o test.o
	gcc prime.o crypto.o vote.o syst_central.o utilities.o test.o -lm -g -o test

simulation : prime.o crypto.o vote.o syst_central.o utilities.o simulation.o
	gcc prime.o crypto.o vote.o syst_central.o utilities.o simulation.o -lm -g -o simulation

block_main : prime.o crypto.o vote.o syst_central.o block.o utilities.o block_main.o
	gcc prime.o crypto.o vote.o syst_central.o block.o utilities.o block_main.o -lm -g -o block_main -lssl -lcrypto

main.o : main.c 
	gcc -g -c main.c

test.o : test.c
	gcc -g -c test.c

simulation.o : simulation.c
	gcc -g -c simulation.c

block_main.o : block_main.c
	gcc -g -c block_main.c

vote.o : vote.h vote.c
	gcc -g -c vote.c

crypto.o : crypto.h crypto.c
	gcc -g -c crypto.c

prime.o : prime.h prime.c
	gcc -g -c prime.c

syst_central.o : syst_central.h syst_central.c
	gcc -g -c syst_central.c

block.o : block.h block.c
	gcc -g -c block.c

utilities.o : utilities.c utilities.h
	gcc -g -c utilities.c

clean : 
	rm -f *.o
	rm -f *.txt 
	rm -f *.ps
	rm -f ./Blockchain/*.txt
	rm -f main
	rm -f test
	rm -f simulation
	rm -f block_main