CC:=aarch64-linux-gnu-gcc


# The target machines is Cavium ThunderX2 CN9975
# release: replace -O0 -ggdb3 -DDEBUG by  -02
CFLAGS+=\
-std=gnu11 \
-O0 -ggdb3 -DDEBUG \
-mcpu=vulcan -flto \
-Wall -Wextra -Wpedantic -Wformat=2 -Wswitch-default -Wswitch-enum -Wfloat-equal -Wsign-conversion \
-Werror=format-security \
-Werror=vla

CFLAGS += -D_GNU_SOURCE=1
CFLAGS += -Iinclude/

src/%.o: src/%.c
	$(CC) -c $(CFLAGS) -o $@ $^

libcall.so: src/libcall.o
	$(CC) -shared $(CFLAGS) -o $@ $^

.PHONY: clean
clean:
	rm src/libcall.o
	rm libcall.so
