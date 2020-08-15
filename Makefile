TARGET=trace6
LIBRAWDIR=libraw/
LIBRAW=$(LIBRAWDIR)libraw.a
LDFLAGS=$(LIBRAW)
CFLAGS+=-Wall -Wextra -g -fdiagnostics-color=auto -I$(LIBRAWDIR)include -fno-strict-aliasing
BUILDDIR=build

OBJECTS=build/traceroute.o build/assignment3.o

.PHONY: all clean fresh

all: $(TARGET)

$(TARGET): $(OBJECTS) $(LIBRAW)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $(TARGET)

$(LIBRAW):
	$(MAKE) -C $(LIBRAWDIR)

$(BUILDDIR)/%.o: src/%.c $(BUILDDIR)/.empty
	$(CC) $(CFLAGS) $< -c -o $@

.PRECIOUS: $(BUILDDIR)/.empty

$(BUILDDIR)/.empty:
	@mkdir -p $(BUILDDIR)
	@touch $@

clean:
	-rm -rf $(OBJECTS)
	-rm -rf $(BUILDDIR)
	-rm -f $(TARGET)
	-$(MAKE) -C $(LIBRAWDIR) clean

fresh: clean
	$(MAKE) all
