#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <selinux/label.h>
#include <selinux/selinux.h>

#include "internal.h"

/*
 * Validate the behaviour of the SELABEL_OPT_BASEONLY option. That is, if set,
 * the .local and .homedirs part of the policy should not be loaded.
 *
 * Also validates the path substitutions (.subs and .subs_dist).
 */

void test_default_options(const char *basedir)
{
	struct selabel_handle *hnd;

	char *path;
	asprintf(&path, "%s/f3.fc", basedir);
	struct selinux_opt f3_opts[] = { {
			.type = SELABEL_OPT_PATH,
			.value = path
		}
	};

	hnd = selabel_open(SELABEL_CTX_FILE, f3_opts, ARRAY_SIZE(f3_opts));
	free(path);

	if (!hnd) {
		log_errno("Unable to open file backend");
		exit(2);
	}

	struct test_t tests[] = {
		{ .path = "/", .context = "system_u:object_r:rootfs:s0" },
		{
			.path = "/local",
			.context = "system_u:object_r:test_local:s0"
		},
		{
			.path = "/homedirs",
			.context = "system_u:object_r:test_homedirs:s0"
		},
		{
			.path = "/sub",
			.context = "system_u:object_r:test_subbed:s0"
		},
		{
			.path = "/sub_dist",
			.context = "system_u:object_r:test_subbed:s0"
		},
	};
	assertContextsMatch(hnd, __func__, tests, ARRAY_SIZE(tests));

	selabel_close(hnd);
}

void test_base_only_option(const char *basedir)
{
	struct selabel_handle *hnd;

	char *path;
	asprintf(&path, "%s/f3.fc", basedir);
	struct selinux_opt f3_with_base_only_opts[] = {
		{ .type = SELABEL_OPT_PATH, .value = path },
		{ .type = SELABEL_OPT_BASEONLY, .value = "1" }
	};

	hnd = selabel_open(SELABEL_CTX_FILE, f3_with_base_only_opts,
			   ARRAY_SIZE(f3_with_base_only_opts));
	free(path);

	if (!hnd) {
		log_errno("Unable to open file backend");
		exit(2);
	}

	struct test_t tests[] = {
		{ .path = "/", .context = "system_u:object_r:rootfs:s0" },
		{ .path = "/local", .context = NULL },
		{ .path = "/homedirs", .context = NULL },
		{
			.path = "/sub",
			.context = "system_u:object_r:test_subbed:s0"
		},
		{
			.path = "/sub_dist",
			.context = "system_u:object_r:test_subbed:s0"
		},
	};
	assertContextsMatch(hnd, __func__, tests, ARRAY_SIZE(tests));

	selabel_close(hnd);
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		log_err("basedir not provided");
		exit(1);
	}

	test_default_options(argv[1]);
	test_base_only_option(argv[1]);

	return 0;
}
