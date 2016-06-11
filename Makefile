CXX=gcc
PARAMSTD=-g
PARAMOBJ=-c


all: crypto.h crypto.c crypto.o main.c
	$(CXX) $(PARAMSTD) -o xxtea main.c crypto.o

crypto.o: crypto.c crypto.h
	$(CXX) $(PARAMSTD) $(PARAMOBJ) crypto.c

clean:
	rm -f *~ *.bak *.o
