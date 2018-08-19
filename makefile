CC = gcc
GFLAGS = -g

2catch: 2catch.c
	${CC} $^ -o $@ ${CFLAGS} -g

test: test.c
	${CC} $^ -o $@ ${CFLAGS}

catch: catch.c
	${CC} $^ -o $@ ${CFLAGS}



clean:
	rm -f *.o *~ *.so *.bin test catch 2catch
