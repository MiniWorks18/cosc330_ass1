COMPILER = gcc
FLAGS = -g -Wall -pedantic

EXES: parallel_search_keyspace search_keyspace generate_ciphertext decrypt_ciphertext

all: ${EXES}

generate_ciphertext: generate_ciphertext.c
	${COMPILER} ${FLAGS} -lcrypto generate_ciphertext.c -o generate_ciphertext

decrypt_ciphertext: decrypt_ciphertext.c
	${COMPILER} ${FLAGS} -lcrypto decrypt_ciphertext.c -o decrypt_ciphertext

search_keyspace: search_keyspace.c
	${COMPILER} ${FLAGS} -lcrypto search_keyspace.c -o search_keyspace

parallel_search_keyspace: parallel_search_keyspace.c
	${COMPILER} ${FLAGS} -lcrypto parallel_search_keyspace.c -o parallel_search_keyspace

clean:
	rm -f *~ *.o ${EXES}
