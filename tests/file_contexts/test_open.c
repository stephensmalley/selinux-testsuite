#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <selinux/label.h>
#include <selinux/selinux.h>

int main(int argc, char **argv)
{
	bool has_default_path = false;
	struct selabel_handle *hnd;
	struct stat default_stat;

	if (argc != 2) {
		fprintf(stderr, "basedir not provided\n");
		exit(1);
	}

	const char *default_path = selinux_file_context_path();
	if (!stat(default_path, &default_stat)) {
		has_default_path = true;
	}

	if (has_default_path) {
		/* Empty options */
		hnd = selabel_open(SELABEL_CTX_FILE, /* options= */ NULL, /* nopt= */ 0);

		if (!hnd) {
			perror("file_context:no_options");
			exit(2);
		}
		selabel_close(hnd);

		/* Default options */
		struct selinux_opt null_opts[] = {
			{ .type = SELABEL_OPT_PATH, .value = NULL }
		};

		hnd = selabel_open(SELABEL_CTX_FILE, /* options= */ null_opts, /* nopt= */ 1);

		if (!hnd) {
			perror("file_context:default_options");
			exit(2);
		}
		selabel_close(hnd);
	}

	/* f1.fc file */
	char *path;
	asprintf(&path, "%s/f1.fc", argv[1]);
	struct selinux_opt f1_opts[] = {
		{ .type = SELABEL_OPT_PATH, .value = path }
	};

	hnd = selabel_open(SELABEL_CTX_FILE, /* options= */ f1_opts, /* nopt= */ 1);
	free(path);

	if (!hnd) {
		perror("file_context:f1_options");
		exit(2);
	}

	char *context = NULL;
	if (selabel_lookup(hnd, &context, "/", S_IFREG)) {
		perror("file_contexts:f1_lookup");
		exit(2);
	}

	if (strcmp(context, "system_u:object_r:rootfs:s0")) {
		perror("file_contexts:f1_strcmp");
		exit(2);
	}

	free(context);

	selabel_close(hnd);

	return 0;
}
