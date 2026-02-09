CC      = clang
# CFLAGS  = -Wall -Wextra -pedantic -std=c11 -g -O0 -fsanitize=address \
#           -I/usr/local/include -Iinclude
CFLAGS  = -Wall -Wextra -pedantic -std=c11 -O2 \
          -I/usr/local/include -Iinclude
LDFLAGS = -L/usr/local/lib
LIBS    = -lsodium -ljansson -lcurl -lncurses

PREFIX  ?= /usr/local
BINDIR  = $(PREFIX)/bin

SRCDIR  = src
OBJDIR  = obj
INCDIR  = include

SRCS    = $(SRCDIR)/main.c \
          $(SRCDIR)/util.c \
          $(SRCDIR)/keys.c \
          $(SRCDIR)/crypto.c \
          $(SRCDIR)/sigchain.c \
          $(SRCDIR)/identity.c \
          $(SRCDIR)/discover.c \
          $(SRCDIR)/share.c \
          $(SRCDIR)/dht.c \
          $(SRCDIR)/tui.c

OBJS    = $(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
TARGET  = lockbox

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(INCDIR)/lockbox.h | $(OBJDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJDIR):
	mkdir -p $(OBJDIR)

clean:
	rm -rf $(OBJDIR) $(TARGET)

install: $(TARGET)
	install -d $(BINDIR)
	install -m 755 $(TARGET) $(BINDIR)/$(TARGET)

.PHONY: all clean install
