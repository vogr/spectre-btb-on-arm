CC:=aarch64-linux-gnu-gcc

all: attacker

# The target machines is Cavium ThunderX2 CN9975
# release: replace -O0 -ggdb3 -DDEBUG by  -02
CFLAGS+=\
-no-pie \
-std=gnu11 \
-O0 -ggdb3 -DDEBUG \
-mcpu=vulcan -flto \
-Wall -Wextra -Wpedantic -Wformat=2 -Wswitch-default -Wswitch-enum -Wfloat-equal -Wsign-conversion \
-Werror=format-security \
-Werror=vla

CFLAGS += -D_GNU_SOURCE=1
CFLAGS += -I../kmod_uapi

src/%.o: src/%.c
	$(CC) -c $(CFLAGS) -o $@ $^

attacker: main.o timing.o flush_reload.o
	$(CC) $(CFLAGS) -o $@ $^ 



.PHONY: clean
clean:
	rm main.o timing.o flush_reload.o
	rm attacker
