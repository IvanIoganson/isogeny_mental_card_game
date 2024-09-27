Default: 
	gcc \
		-static -pedantic \
		-march=native \
		-Wall -Wextra \
		-O3 -funroll-loops \
		-lpthread \
		faster-csidh/rng.c \
		faster-csidh/u512.s faster-csidh/fp.s \
		faster-csidh/mont.c \
		faster-csidh/csidh.c \
		CSI-Fish/reduce.c \
		src/main.c src/protocols.c src/ZKP.c \
		faster-csidh/mcl.o -lmcl -L faster-csidh/mcl/lib -lstdc++ \
		-o main