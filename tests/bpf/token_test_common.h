#ifndef TOKEN_TEST_COMMON_H
#define TOKEN_TEST_COMMON_H

#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <bpf/libbpf.h>

#ifdef DEBUG
#define _CHECK(condition, format...) ({    \
	int __ret = !!(condition); \
	int __save_errno = errno;   \
	if (__ret) {    \
		fprintf(stderr, ##format);   \
	}   \
	errno = __save_errno;   \
	__ret;  \
})
#else
#define _CHECK(condition, format...) ({    \
	int __ret = !!(condition); \
	__ret;  \
})
#endif

#define ASSERT_OK(res, name) ({     \
	long long ___res = (res);       \
	bool ___ok = ___res == 0;       \
	_CHECK(!___ok, \
			"%s failed. unexpected error: %lld (errno %d)\n",  \
			 name, ___res, errno);  \
	___ok;                          \
})

#define ASSERT_GT(actual, expected, name) ({    \
	typeof(actual) ___act = (actual);   \
	typeof(expected) ___exp = (expected);   \
	bool ___ok = ___act > ___exp;       \
	_CHECK(!___ok,  \
			"unexpected %s: actual %lld <= expected %lld (errno %d)\n",   \
			(name), (long long)(___act), (long long)(___exp), errno);  \
	___ok;  \
})


#define ASSERT_GE(actual, expected, name) ({    \
	typeof(actual) ___act = (actual);       \
	typeof(expected) ___exp = (expected);   \
	bool ___ok = ___act >= ___exp;          \
	_CHECK(!___ok,  \
			"unexpected %s: actual %lld < expected %lld (errno %d)\n",   \
			(name), (long long)(___act), (long long)(___exp), errno);          \
	___ok;  \
})


#define ASSERT_EQ(actual, expected, name) ({    \
	typeof(actual) ___act = (actual);           \
	typeof(expected) ___exp = (expected);       \
	bool ___ok = ___act == ___exp;              \
	_CHECK(!___ok,   \
			"unexpected %s: actual %lld != expected %lld (errno %d)\n",   \
			(name), (long long)(___act), (long long)(___exp), errno);          \
	___ok;  \
})


#define ASSERT_OK_PTR(ptr, name) ({     \
	const void *___res = (ptr);         \
	int ___err = libbpf_get_error(___res);  \
	bool ___ok = ___err == 0;           \
	_CHECK(!___ok,  \
			"%s unexpected error: %d\n", name, ___err);  \
	___ok;      \
})


#define zclose(fd) do { if (fd >= 0) close(fd); fd = -1; } while (0)

int sys_fsopen(const char *fsname, unsigned int flags);
int sys_mount(const char *dev_name, const char *dir_name,
	      const char *type, unsigned long flags,
	      const void *data);
int sys_fsconfig(int fs_fd, unsigned int cmd, const char *key,
		 const void *val, int aux);
int sys_fsmount(int fs_fd, unsigned int flags,
		unsigned int ms_flags);
int write_file(const char *path, const void *buf, size_t count);
int create_bpffs_fd(void);
int create_and_enter_userns(void);
int sendfd(int sockfd, int fd);
int recvfd(int sockfd, int *fd);

#endif /* TOKEN_TEST_COMMON_H */

