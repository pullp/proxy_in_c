CC = gcc
GFLAGS = -g

catch: catch.c
	${CC} $^ -o $@ ${CFLAGS} -g

catch32: catch.c
	${CC} $^ -o $@ ${CFLAGS} -m32

clean:
	rm -f *.o *~ *.so *.bin test catch 2catch
