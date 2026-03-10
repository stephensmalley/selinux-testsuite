#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <selinux/label.h>
#include <selinux/selinux.h>

#include "internal.h"

int main(int argc, char **argv)
{
	struct selabel_handle *hnd;

	if (argc != 2) {
		fprintf(stderr, "basedir not provided\n");
		exit(1);
	}

	char *path;
	asprintf(&path, "%s/f2.fc", argv[1]);
	struct selinux_opt f2_opts[] = {
		{ .type = SELABEL_OPT_PATH, .value = path }
	};

	hnd = selabel_open(SELABEL_CTX_FILE, f2_opts, ARRAY_SIZE(f2_opts));

	free(path);

	if (!hnd) {
		perror("file_context:f2_options");
		exit(2);
	}

	struct test_t tests[] = {
		{ .path = "/base", .context = "system_u:object_r:test_base_t:s0" },
		{ .path = "/base/unkown", .context = "system_u:object_r:test_base_wildcard_t:s0" },
		{ .path = "/base/sub", .context = "system_u:object_r:test_base_sub_t:s0" },
		{ .path = "/base/file.list", .context = "system_u:object_r:test_file_list_t:s0" },
		{ .path = "/base/file_list", .context = "system_u:object_r:test_base_wildcard_t:s0" },
	};
	assertContextsMatch(hnd, tests, ARRAY_SIZE(tests));

	return 0;
}
