strongtcp: strongtcp.o
	$(CC) $(LDFLAGS) strongtcp.o -o strongtcp -lnfnetlink -lnetfilter_queue
strongtcp.o: strongtcp.c
	$(CC) $(CFLAGS) -c strongtcp.c
# remove object files and executable when user executes "make clean"
clean:
	rm *.o strongtcp