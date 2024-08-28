CC:=aarch64-linux-gnu-gcc
FILES:=main.c


MAIN:=victim

all: $(MAIN)

MAIN_SRC:=src/main.c src/timing.c
MAIN_OBJ=$(MAIN_SRC:.c=.o)

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

$(MAIN): $(MAIN_OBJ)
	$(CC) -L "../libcall/" $(CFLAGS) -o $@ $^ -lcall

.PHONY: clean
clean:
	rm $(MAIN_OBJ)
	rm $(MAIN)
