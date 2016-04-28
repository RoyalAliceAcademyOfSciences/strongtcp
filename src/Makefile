strongtcp: strongtcp.o pcap.o
	$(CC) $(LDFLAGS) strongtcp.o pcap.o -o strongtcp -lnfnetlink -lnetfilter_queue
strongtcp.o: strongtcp.c
	$(CC) $(CFLAGS) -c strongtcp.c
pcap.o:
	$(CC) $(CFLAGS) -c pcap.c pcap.h
# remove object files and executable when user executes "make clean"
clean:
	rm *.gch *.o strongtcp
