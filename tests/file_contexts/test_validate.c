#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <selinux/label.h>
#include <selinux/selinux.h>

#include "internal.h"

int main(int argc, char **argv)
{
	char *path;
	struct selabel_handle *hnd;

	if (argc != 2) {
		fprintf(stderr, "basedir not provided\n");
		exit(1);
	}

	asprintf(&path, "%s/f1.fc", argv[1]);
	struct selinux_opt f1_opts[] = {
		{ .type = SELABEL_OPT_PATH, .value = path },
		{ .type = SELABEL_OPT_VALIDATE, .value = "1" }
	};

	/* f1 types are not defined in the test policy. */
	hnd = selabel_open(SELABEL_CTX_FILE, f1_opts, ARRAY_SIZE(f1_opts));
	free(path);

	if (hnd) {
		fprintf(stderr, "The validation of f1 should have failed.\n");
		exit(2);
	}

	asprintf(&path, "%s/f2.fc", argv[1]);
	struct selinux_opt f2_opts[] = {
		{ .type = SELABEL_OPT_PATH, .value = path },
		{ .type = SELABEL_OPT_VALIDATE, .value = "1" }
	};

	/* f2 types are defined in the test policy. */
	hnd = selabel_open(SELABEL_CTX_FILE, f2_opts, ARRAY_SIZE(f2_opts));
	free(path);

	if (!hnd) {
		perror("Unable to read valid file_contexts");
		exit(2);
	}

	selabel_close(hnd);

	return 0;
}
