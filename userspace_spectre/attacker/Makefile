CC:=aarch64-linux-gnu-gcc

all: attacker_ca attacker_sa

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
CFLAGS += -I../libcall/include


src/%.o: src/%.c
	$(CC) -c $(CFLAGS) -o $@ $^

attacker_ca: src/main_ca.o src/timing.o src/flush_reload.o src/utils.o
	$(CC) -L../libcall/ $(CFLAGS) -o $@ $^ -lcall

attacker_sa: src/main_sa.o src/timing.o src/flush_reload.o src/utils.o
	$(CC) $(CFLAGS) -o $@ $^


.PHONY: clean
clean:
	rm src/main_ca.o src/main_sa.o src/timing.o src/flush_reload.o src/utils.o
	rm attacker_ca attacker_ca
