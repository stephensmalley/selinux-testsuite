TARGETS=test_open test_lookup test_open_base test_validate
CFLAGS += -O2 -Werror -Wall
LDLIBS += -lselinux

all: $(TARGETS)

$(TARGETS): internal.o

clean:
	rm -f $(TARGETS) *.o
