#include <errno.h>
#include <string.h>

#include <selinux/label.h>
#include <selinux/selinux.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* Log an error message with the file name, function name and line */
#define log_err(fmt, ...)                                                    \
	fprintf(stderr, "%s:%s:%d: " fmt "\n", __FILE__, __func__, __LINE__, \
		##__VA_ARGS__)

/* Log an error message as well as errno */
#define log_errno(fmt, ...)                                            \
	fprintf(stderr, "%s:%s:%d " fmt " (%s)\n", __FILE__, __func__, \
		__LINE__, ##__VA_ARGS__, strerror(errno))

/* Structure to capture a test. The |path| will be resolved and expected to
 * match the |context|. If |context| is NULL, the lookup is expected to fail. */
struct test_t {
	const char *path;
	const char *context;
};

/* Assert that all paths described in |tests| resolve appropriately. |hnd| must
 * be opened. |n| is the number of tests in |tests|. |log_prefix| is added to
 * any log message */
void assertContextsMatch(struct selabel_handle *hnd, const char *log_prefix,
			 struct test_t *tests, size_t n);
