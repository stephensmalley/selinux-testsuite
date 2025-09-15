#include "bpf_common.h"

#define write_verbose(verbose, fmt, ...) \
	do { \
		if (verbose) \
			printf(fmt "\n", ##__VA_ARGS__); \
	} while (0)

static void usage(char *progname)
{
	fprintf(stderr,
		"usage:  %s -m|-p|-c|-l [-v]\n"
		"Where:\n\t"
		"-m    Create BPF map fd\n\t"
		"-p    Create BPF prog fd\n\t"
		"-c    Test BPF token map create\n\t"
		"-l    Test BPF token program load\n\t"
		"-v Print information.\n", progname);
	exit(-1);
}

int main(int argc, char *argv[])
{
	int opt, result, ret;
	bool verbose = false, is_fd = true;
	char *context;

	enum {
		MAP_FD = 1,
		PROG_FD,
		MAP_CREATE,
		PROG_LOAD,
	} bpf_fd_type;

	while ((opt = getopt(argc, argv, "mpclv")) != -1) {
		switch (opt) {
		case 'm':
			bpf_fd_type = MAP_FD;
			break;
		case 'p':
			bpf_fd_type = PROG_FD;
			break;
		case 'c':
			bpf_fd_type = MAP_CREATE;
			break;
		case 'l':
			bpf_fd_type = PROG_LOAD;
			break;
		case 'v':
			verbose = true;
			break;
		default:
			usage(argv[0]);
		}
	}

	result = getcon(&context);
	if (result < 0) {
		fprintf(stderr, "Failed to obtain SELinux context\n");
		exit(-1);
	}

	write_verbose(verbose, "Process context:\n\n%s", context);

	free(context);

	/* If BPF enabled, then need to set limits */
	bpf_setrlimit();

	switch (bpf_fd_type) {
	case MAP_FD:
		write_verbose(verbose, "Creating BPF map");

		ret = create_bpf_map();
		break;
	case PROG_FD:
		write_verbose(verbose, "Creating BPF prog");

		ret = create_bpf_prog();
		break;
	case MAP_CREATE:
		is_fd = false;
		write_verbose(verbose, "Testing BPF map create");

		ret = test_bpf_map_create();
		break;
	case PROG_LOAD:
		is_fd = false;
		write_verbose(verbose, "Testing BPF prog load");

		ret = test_bpf_prog_load();
		break;
	default:
		usage(argv[0]);
	}

	if (ret < 0)
		return ret;

	if (is_fd)
		close(ret);

	return 0;
}
