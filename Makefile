# Entry point.  `make deps && make test` is the whole story; see README.md.
#   make vienna   no-security build (Homebrew/apt libcoap): coap_server, coap_client
#   make secure   Group OSCORE build against the patched libcoap fork: coap_server_sec, coap_client_sec
#   make deps     fetch the libcoap fork at the pinned revision (needed once, by `secure` and `test`)
#   make test     build and run the unit tests of the secure profile
.PHONY: all vienna secure deps test clean distclean

all: vienna secure

vienna:
	$(MAKE) -f Makefile.vienna

secure: deps
	$(MAKE) -f Makefile.secure all

deps:
	$(MAKE) -f Makefile.secure deps

test: deps
	$(MAKE) -f Makefile.secure test

clean:
	$(MAKE) -f Makefile.vienna clean
	$(MAKE) -f Makefile.secure clean

distclean: clean
	$(MAKE) -f Makefile.secure distclean
