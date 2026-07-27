#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <selinux/label.h>
#include <selinux/selinux.h>

#include "internal.h"

void test_no_options(void)
{
	struct stat default_stat;
	if (stat(selinux_file_context_path(), &default_stat))
		return;

	/* Empty options */
	struct selabel_handle *hnd = selabel_open(
					     SELABEL_CTX_FILE, /* options= */ NULL, /* nopt= */ 0);

	if (!hnd) {
		log_errno("Unable to open default content file");
		exit(2);
	}
	selabel_close(hnd);
}

void test_null_path(void)
{
	struct stat default_stat;
	if (stat(selinux_file_context_path(), &default_stat))
		return;

	/* Default options */
	struct selinux_opt null_opts[] = { {
			.type = SELABEL_OPT_PATH,
			.value = NULL
		}
	};

	struct selabel_handle *hnd = selabel_open(SELABEL_CTX_FILE, null_opts,
						  ARRAY_SIZE(null_opts));

	if (!hnd) {
		log_errno("Unable to open default content file");
		exit(2);
	}
	selabel_close(hnd);
}

void test_valid_path(const char *basedir)
{
	/* f1.fc file */
	char *path;
	asprintf(&path, "%s/f1.fc", basedir);
	struct selinux_opt f1_opts[] = { {
			.type = SELABEL_OPT_PATH,
			.value = path
		}
	};

	struct selabel_handle *hnd =
		selabel_open(SELABEL_CTX_FILE, f1_opts, ARRAY_SIZE(f1_opts));
	free(path);

	if (!hnd) {
		log_errno("Unable to open file backend");
		exit(2);
	}

	char *context = NULL;
	if (selabel_lookup(hnd, &context, "/", S_IFREG)) {
		log_errno("Unable to lookup \"/\"");
		exit(2);
	}

	const char *expected = "system_u:object_r:rootfs:s0";
	if (strcmp(context, expected)) {
		log_err("Incorrect context returned, expected %s got %s",
			expected, context);
		exit(2);
	}

	free(context);

	selabel_close(hnd);
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		log_err("basedir not provided");
		exit(1);
	}

	test_no_options();
	test_null_path();
	test_valid_path(argv[1]);

	return 0;
}
