CC=clang
CXX=clang++
CXXFLAGS=-Wall -Wextra -g3 -fsanitize=address

all: main tracer

main: main.c probes.o probes.h
	$(CC) $(CXXFLAGS) -lbcc -o $@ $< probes.o

tracer: tracer.cc
	$(CXX) $(CXXFLAGS) -lbcc -o $@ $<

probes.o: probes.d
	dtrace -s $< -o $@ -G

probes.h: probes.d
	dtrace -s $< -o $@ -h

clean:
	rm -rf probes.o probes.h *.o main tracer

.PHONEY: all clean
