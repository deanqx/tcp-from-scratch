run: build
	sudo ./a.out

build:
	gcc -std=c89 -pedantic-errors main.c
