#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <selinux/label.h>
#include <selinux/selinux.h>

#include "internal.h"

void test_multiple_no_validation(const char *basedir)
{
	struct selabel_handle *hnd;

	/* f1.fc and f2.fc file */
	char *f1_path, *f2_path;
	asprintf(&f1_path, "%s/f1.fc", basedir);
	asprintf(&f2_path, "%s/f2.fc", basedir);
	struct selinux_opt opts[] = {
		{ .type = SELABEL_OPT_PATH, .value = f1_path },
		{ .type = SELABEL_OPT_PATH, .value = f2_path }
	};

	hnd = selabel_open(SELABEL_CTX_FILE, opts, ARRAY_SIZE(opts));
	free(f1_path);
	free(f2_path);

	if (!hnd) {
		log_errno("Unable to open file backend");
		exit(2);
	}

	struct test_t tests[] = {
		{ .path = "/", .context = "system_u:object_r:rootfs:s0" },
		{
			.path = "/base",
			.context = "system_u:object_r:test_base_t:s0"
		},
	};
	assertContextsMatch(hnd, __func__, tests, ARRAY_SIZE(tests));

	selabel_close(hnd);
}

void test_multiple_with_validation(const char *basedir)
{
	struct selabel_handle *hnd;

	/* f1.fc and f2.fc file - f1 has undefined type rootfs in test policy */
	char *f1_path, *f2_path;
	asprintf(&f1_path, "%s/f1.fc", basedir);
	asprintf(&f2_path, "%s/f2.fc", basedir);
	struct selinux_opt opts[] = {
		{ .type = SELABEL_OPT_PATH, .value = f1_path },
		{ .type = SELABEL_OPT_PATH, .value = f2_path },
		{ .type = SELABEL_OPT_VALIDATE, .value = "1" }
	};

	hnd = selabel_open(SELABEL_CTX_FILE, opts, ARRAY_SIZE(opts));
	free(f1_path);
	free(f2_path);

	if (hnd) {
		log_err("Validation of f1 and f2 should have failed");
		selabel_close(hnd);
		exit(2);
	}
}

void test_multiple_with_extras(const char *basedir)
{
	struct selabel_handle *hnd;
	char *f2_path, *f3_path;
	asprintf(&f2_path, "%s/f2.fc", basedir);
	asprintf(&f3_path, "%s/f3.fc", basedir);

	/* 1. f3.fc is the first path: extras (.subs, .local, .homedirs) of f3 ARE processed */
	struct selinux_opt opts_f3_first[] = {
		{ .type = SELABEL_OPT_PATH, .value = f3_path },
		{ .type = SELABEL_OPT_PATH, .value = f2_path }
	};
	hnd = selabel_open(SELABEL_CTX_FILE, opts_f3_first,
			   ARRAY_SIZE(opts_f3_first));
	if (!hnd) {
		log_errno("Unable to open file backend");
		exit(2);
	}

	struct test_t tests_f3_first[] = {
		{ .path = "/", .context = "system_u:object_r:rootfs:s0" },
		{
			.path = "/sub",
			.context = "system_u:object_r:test_subbed:s0"
		},
		{
			.path = "/local",
			.context = "system_u:object_r:test_local:s0"
		},
		{
			.path = "/homedirs",
			.context = "system_u:object_r:test_homedirs:s0"
		},
		{
			.path = "/base",
			.context = "system_u:object_r:test_base_t:s0"
		},
	};
	assertContextsMatch(hnd, __func__, tests_f3_first,
			    ARRAY_SIZE(tests_f3_first));
	selabel_close(hnd);

	/* 2. f2.fc is the first path, f3.fc is second: extras from f3 are NOT processed */
	struct selinux_opt opts_f2_first[] = {
		{ .type = SELABEL_OPT_PATH, .value = f2_path },
		{ .type = SELABEL_OPT_PATH, .value = f3_path }
	};
	hnd = selabel_open(SELABEL_CTX_FILE, opts_f2_first,
			   ARRAY_SIZE(opts_f2_first));
	if (!hnd) {
		log_errno("Unable to open file backend");
		exit(2);
	}

	struct test_t tests_f2_first[] = {
		{
			.path = "/base",
			.context = "system_u:object_r:test_base_t:s0"
		},
		{ .path = "/", .context = "system_u:object_r:rootfs:s0" },
		{
			.path = "/subbed",
			.context = "system_u:object_r:test_subbed:s0"
		},
		/* /sub, /local, /homedirs should NOT match the f3 extra contexts */
		{ .path = "/sub", .context = NULL },
		{ .path = "/local", .context = NULL },
		{ .path = "/homedirs", .context = NULL },
	};
	assertContextsMatch(hnd, __func__, tests_f2_first,
			    ARRAY_SIZE(tests_f2_first));
	selabel_close(hnd);

	free(f2_path);
	free(f3_path);
}

void test_multiple_three_paths(const char *basedir)
{
	struct selabel_handle *hnd;
	char *f1_path, *f2_path, *f3_path;
	asprintf(&f1_path, "%s/f1.fc", basedir);
	asprintf(&f2_path, "%s/f2.fc", basedir);
	asprintf(&f3_path, "%s/f3.fc", basedir);

	struct selinux_opt opts[] = {
		{ .type = SELABEL_OPT_PATH, .value = f1_path },
		{ .type = SELABEL_OPT_PATH, .value = f2_path },
		{ .type = SELABEL_OPT_PATH, .value = f3_path }
	};

	hnd = selabel_open(SELABEL_CTX_FILE, opts, ARRAY_SIZE(opts));
	free(f1_path);
	free(f2_path);
	free(f3_path);

	if (!hnd) {
		log_errno("Unable to open file backend");
		exit(2);
	}

	struct test_t tests[] = {
		{ .path = "/", .context = "system_u:object_r:rootfs:s0" },
		{
			.path = "/base",
			.context = "system_u:object_r:test_base_t:s0"
		},
		{
			.path = "/subbed",
			.context = "system_u:object_r:test_subbed:s0"
		},
	};
	assertContextsMatch(hnd, __func__, tests, ARRAY_SIZE(tests));
	selabel_close(hnd);
}

void test_multiple_duplicate_validation(const char *basedir)
{
	struct selabel_handle *hnd;

	/* Two copies of f2.fc to provide duplicate specifications */
	char *f2_path;
	asprintf(&f2_path, "%s/f2.fc", basedir);
	struct selinux_opt opts[] = {
		{ .type = SELABEL_OPT_PATH, .value = f2_path },
		{ .type = SELABEL_OPT_PATH, .value = f2_path },
		{ .type = SELABEL_OPT_VALIDATE, .value = "1" }
	};

	hnd = selabel_open(SELABEL_CTX_FILE, opts, ARRAY_SIZE(opts));
	free(f2_path);

	if (!hnd) {
		log_errno("Unable to open file backend");
		exit(2);
	}

	struct test_t tests[] = {
		{
			.path = "/base",
			.context = "system_u:object_r:test_base_t:s0"
		},
	};
	assertContextsMatch(hnd, __func__, tests, ARRAY_SIZE(tests));

	selabel_close(hnd);
}

/* Check if multiple paths are supported. Returns 0 if they are; 1 otherwise */
static int check_multiple_path_support(const char *basedir)
{
	struct selabel_handle *hnd;
	char *f1_path, *f2_path;
	char *context1 = NULL, *context2 = NULL;
	bool supported = false;

	asprintf(&f1_path, "%s/f1.fc", basedir);
	asprintf(&f2_path, "%s/f2.fc", basedir);

	struct selinux_opt opts[] = {
		{ .type = SELABEL_OPT_PATH, .value = f1_path },
		{ .type = SELABEL_OPT_PATH, .value = f2_path }
	};

	hnd = selabel_open(SELABEL_CTX_FILE, opts, ARRAY_SIZE(opts));
	free(f1_path);
	free(f2_path);

	if (!hnd) {
		/* On older libselinux releases, the second file_context would
		 * be ignored but selabel_open should not fail. */
		log_err("Unable to open file backend");
		exit(2);
	}

	if (selabel_lookup(hnd, &context1, "/", S_IFREG) == 0 &&
	    selabel_lookup(hnd, &context2, "/base", S_IFREG) == 0) {
		supported = true;
	}

	free(context1);
	free(context2);
	selabel_close(hnd);
	return supported ? 0 : 1;
}

int main(int argc, char **argv)
{
	if (argc < 2 || argc > 3) {
		log_err("usage: %s <basedir> [check]", argv[0]);
		exit(1);
	}

	if (argc == 3 && strcmp(argv[2], "check") == 0) {
		return check_multiple_path_support(argv[1]);
	}

	test_multiple_no_validation(argv[1]);
	test_multiple_with_validation(argv[1]);
	test_multiple_duplicate_validation(argv[1]);
	test_multiple_with_extras(argv[1]);
	test_multiple_three_paths(argv[1]);

	return 0;
}
