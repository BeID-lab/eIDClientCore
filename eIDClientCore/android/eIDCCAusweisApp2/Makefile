all:
	sed -i.org '/^libeIDClientConnection_la_CPPFLAGS/{/-DSKIP_PEER_VERIFICATION -DSKIP_HOSTNAME_VERIFICATION/! s/$$/ -DSKIP_PEER_VERIFICATION -DSKIP_HOSTNAME_VERIFICATION/}' ../../lib/eIDClientConnection/Makefile.am
	make -C ../ ANDROID_NDK_ROOT=$(ANDROID_NDK_ROOT) ANDROID_SDK_ROOT=$(ANDROID_SDK_ROOT) ANDROID_API=$(ANDROID_API)
	$(ANDROID_SDK_ROOT)/tools/android update project --path . --target $(ANDROID_API)
	ant debug