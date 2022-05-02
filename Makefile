
CFLAGS  = -I. -Wall -DSAVE_HTTPS_DATA
LDFLAGS = -lssl -lcrypto
OBJS = main.o timer.o
CC = gcc

all: https

https: $(OBJS)
	@echo " [https] CC $@"
	@$(CC) -o $@ $^ $(LDFLAGS) 

clean:
	rm -f https *.o .*.depend

%.o: %.c .%.depend
	@echo " [https] CC $@"
	@$(CC) $(CFLAGS) -c $< 

.%.depend: %.c
	@$(CC) $(CFLAGS) -M $< > $@

-include $(OBJS:%.o=.%.depend)

