

PKGS=check
CFLAGS=-Wall -Wextra -O3 --std=c2x -g3  `pkg-config --cflags ${PKGS}`
LDFLAGS=`pkg-config --libs ${PKGS}`

main: main.o patricia/patricia.o patricia/patricia_check.o
	${CC} -o $@ $^ ${LDFLAGS}

patricia.o: patricia/patricia.h patricia/patricia_internal.h

patricia_check.o: patricia/patricia_check.c patricia/patricia_internal.h patricia/patricia.h

clean:
	rm -f *.o */*.o main 
