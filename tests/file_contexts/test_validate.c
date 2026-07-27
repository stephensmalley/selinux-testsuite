#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <selinux/label.h>
#include <selinux/selinux.h>

#include "internal.h"

void test_validate_unknown_fails(const char *basedir)
{
	char *path;
	asprintf(&path, "%s/f1.fc", basedir);
	struct selinux_opt f1_opts[] = {
		{ .type = SELABEL_OPT_PATH, .value = path },
		{ .type = SELABEL_OPT_VALIDATE, .value = "1" }
	};

	/* f1 types are not defined in the test policy. */
	struct selabel_handle *hnd =
		selabel_open(SELABEL_CTX_FILE, f1_opts, ARRAY_SIZE(f1_opts));
	free(path);

	if (hnd) {
		log_err("The validation of f1 should have failed");
		selabel_close(hnd);
		exit(2);
	}
}

void test_validate_known_succeeds(const char *basedir)
{
	char *path;
	asprintf(&path, "%s/f2.fc", basedir);
	struct selinux_opt f2_opts[] = {
		{ .type = SELABEL_OPT_PATH, .value = path },
		{ .type = SELABEL_OPT_VALIDATE, .value = "1" }
	};

	/* f2 types are defined in the test policy. */
	struct selabel_handle *hnd =
		selabel_open(SELABEL_CTX_FILE, f2_opts, ARRAY_SIZE(f2_opts));
	free(path);

	if (!hnd) {
		log_errno("Unable to read valid file_contexts");
		exit(2);
	}

	selabel_close(hnd);
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		log_err("basedir not provided");
		exit(1);
	}

	test_validate_unknown_fails(argv[1]);
	test_validate_known_succeeds(argv[1]);

	return 0;
}
