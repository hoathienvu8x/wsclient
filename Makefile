MODNAME = lib/libwwsocket.a
 
objects := $(addprefix objects/,$(patsubst %.c,%.o,$(wildcard *.c)))

MODOBJ = $(objects) 

MODCFLAGS = -Wall -Wextra -pedantic --std=gnu99

INCLUDE= -I. -I./include -lpthread

ifdef openssl
	INCLUDE += -lssl -lcrypto -DHAVE_OPENSSL
endif
 
CC = gcc
ifeq ($(build),release)
	CFLAGS = -fPIC -O3 $(MODCFLAGS) $(INCLUDE)
else
	CFLAGS = -fPIC -g -ggdb $(MODCFLAGS) $(INCLUDE)
endif

ifdef debug
	CFLAGS += -g -ggdb -DDEBUG 
endif

.PHONY: all Debug Release
all: $(MODNAME)

$(MODNAME): objects $(MODOBJ)
	@ar rcs $(MODNAME) $(MODOBJ)
	ranlib $@

objects:
	@mkdir -p objects

objects/%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

.PHONY: clean

clean: 
	rm -f $(MODNAME) $(MODOBJ)

dist: clean all
