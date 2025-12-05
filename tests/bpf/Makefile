TARGETS = bpf_test token_child_helper
BPF_TEST_SRCS = bpf_test.c bpf_common.c token_test.c token_test_common.c
TOKEN_CHILD_HELPER_SRCS = token_child_helper.c bpf_common.c token_test_common.c
LDLIBS += -lselinux -lbpf

# export so that BPF_ENABLED entries get built correctly on local build
export CFLAGS += -DHAVE_BPF

BPF_ENABLED = ../fdreceive ../binder

all: $(TARGETS)
	@set -e; for i in $(BPF_ENABLED); do $(MAKE) -C $$i all ; done

clean:
	rm -f $(TARGETS) test_sock flag *_flag
	@set -e; for i in $(BPF_ENABLED); do $(MAKE) -C $$i clean ; done

bpf_test: $(BPF_TEST_SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

token_child_helper: $(TOKEN_CHILD_HELPER_SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)
