CFLAGS=-std=gnu99 -O2 -Wall -fPIC  # -DENABLE_TRACE
run: timemachine.so
	LD_PRELOAD=./$< ./Auswahlen
timemachine.so: timemachine.o
	$(CC) $(LDFLAGS) -fPIC -shared $(LDFLAGS) $^ -o $@ $(LDLIBS)
clean:
	rm -f *.o *.so
