#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <selinux/label.h>
#include <selinux/selinux.h>

#include "internal.h"

void assertContextsMatch(struct selabel_handle *hnd, struct test_t *tests,
			 size_t n)
{
	for (int i = 0; i < n; i++) {
		char *context = NULL;
		struct test_t test = tests[i];

		if (selabel_lookup(hnd, &context, test.path, S_IFREG)) {
			if (test.context) {
				perror("file_contexts:selabel_lookup");
				fprintf(stderr, "Lookup for %s failed\n", test.path);
				exit(2);
			}
			// Expected failure. Continue to the next test.
			continue;
		} else if (!test.context) {
			fprintf(stderr, "Lookup for %s was supposed to failed\n", test.path);
			exit(2);
		}

		if (strcmp(context, tests[i].context)) {
			fprintf(stderr, "Lookup for %s returned %s, expected %s\n",
				tests[i].path, context, tests[i].context);
			exit(2);
		}

		free(context);
	}
}
