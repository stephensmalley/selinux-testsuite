#include <selinux/label.h>
#include <selinux/selinux.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* Structure to capture a test. The |path| will be resolved and expected to
 * match the |context|. If |context| is NULL, the lookup is expected to fail. */
struct test_t {
	const char *path;
	const char *context;
};

/* Assert that all paths described in |tests| resolve appropriately. |hnd| must
 * be opened. |n| is the number of tests in |tests|. */
void assertContextsMatch(struct selabel_handle *hnd, struct test_t *tests,
			 size_t n);
