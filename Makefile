appleuuid: sha1.c sha1.h appleuuid.c
	cc -o appleuuid sha1.c appleuuid.c

clean:
	rm -f appleuuid
