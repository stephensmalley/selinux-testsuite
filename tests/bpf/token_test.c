// SPDX-License-Identifier: GPL-2.0
/* Code derived from: linux/source/tools/testing/selftests/bpf/prog_tests/token.c
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpf_common.h"
#include "signal.h"
#include "linux/mount.h"
#include <linux/unistd.h>
#include "sys/wait.h"
#include "sys/socket.h"
#include "fcntl.h"
#include "sched.h"
#include <bpf/btf.h>

#define bit(n) (1ULL << (n))

#define zclose(fd) do { if (fd >= 0) close(fd); fd = -1; } while (0)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

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

struct bpffs_opts {
	__u64 cmds;
	__u64 maps;
	__u64 progs;
	__u64 attachs;
	const char *cmds_str;
	const char *maps_str;
	const char *progs_str;
	const char *attachs_str;
};

typedef int (*child_callback_fn)(int bpffs_fd);

static inline int sys_mount(const char *dev_name, const char *dir_name,
			    const char *type, unsigned long flags,
			    const void *data)
{
	return syscall(__NR_mount, dev_name, dir_name, type, flags, data);
}

static inline int sys_fsopen(const char *fsname, unsigned int flags)
{
	return syscall(__NR_fsopen, fsname, flags);
}

static inline int sys_fsconfig(int fs_fd, unsigned int cmd, const char *key,
			       const void *val, int aux)
{
	return syscall(__NR_fsconfig, fs_fd, cmd, key, val, aux);
}

static inline int sys_fsmount(int fs_fd, unsigned int flags,
			      unsigned int ms_flags)
{
	return syscall(__NR_fsmount, fs_fd, flags, ms_flags);
}

static int set_delegate_mask(int fs_fd, const char *key, __u64 mask,
			     const char *mask_str)
{
	char buf[32];
	int err;

	if (!mask_str) {
		if (mask == ~0ULL) {
			mask_str = "any";
		} else {
			snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)mask);
			mask_str = buf;
		}
	}

	err = sys_fsconfig(fs_fd, FSCONFIG_SET_STRING, key,
			   mask_str, 0);
	if (err < 0)
		err = -errno;
	return err;
}

static int create_bpffs_fd(void)
{
	int fs_fd;

	/* create VFS context */
	fs_fd = sys_fsopen("bpf", 0);
	ASSERT_GE(fs_fd, 0, "fs_fd");

	return fs_fd;
}

static int materialize_bpffs_fd(int fs_fd, struct bpffs_opts *opts)
{
	int mnt_fd, err;

	/* set up token delegation mount options */
	err = set_delegate_mask(fs_fd, "delegate_cmds", opts->cmds, opts->cmds_str);
	if (!ASSERT_OK(err, "fs_cfg_cmd"))
		return err;
	err = set_delegate_mask(fs_fd, "delegate_maps", opts->maps, opts->maps_str);
	if (!ASSERT_OK(err, "fs_cfg_maps"))
		return err;
	err = set_delegate_mask(fs_fd, "delegate_progs", opts->progs, opts->progs_str);
	if (!ASSERT_OK(err, "fs_cfg_progs"))
		return err;
	err = set_delegate_mask(fs_fd, "delegate_attachs", opts->attachs,
				opts->attachs_str);
	if (!ASSERT_OK(err, "fs_cfg_attachs"))
		return err;

	/* instantiate FS object */
	err = sys_fsconfig(fs_fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
	if (err < 0)
		return -errno;

	/* create O_PATH fd for detached mount */
	mnt_fd = sys_fsmount(fs_fd, 0, 0);
	if (err < 0)
		return -errno;

	return mnt_fd;
}

static ssize_t write_nointr(int fd, const void *buf, size_t count)
{
	ssize_t ret;

	do {
		ret = write(fd, buf, count);
	} while (ret < 0 && errno == EINTR);

	return ret;
}

static int write_file(const char *path, const void *buf, size_t count)
{
	int fd;
	ssize_t ret;

	fd = open(path, O_WRONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0)
		return -1;

	ret = write_nointr(fd, buf, count);
	close(fd);
	if (ret < 0 || (size_t)ret != count)
		return -1;

	return 0;
}

static int create_and_enter_userns(void)
{
	uid_t uid;
	gid_t gid;
	char map[100];

	uid = getuid();
	gid = getgid();

	if (unshare(CLONE_NEWUSER))
		return -1;

	if (write_file("/proc/self/setgroups", "deny", sizeof("deny") - 1) &&
	    errno != ENOENT)
		return -1;

	snprintf(map, sizeof(map), "0 %d 1", uid);
	if (write_file("/proc/self/uid_map", map, strlen(map)))
		return -1;


	snprintf(map, sizeof(map), "0 %d 1", gid);
	if (write_file("/proc/self/gid_map", map, strlen(map)))
		return -1;

	if (setgid(0))
		return -1;

	if (setuid(0))
		return -1;

	return 0;
}

static int sendfd(int sockfd, int fd)
{
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	int fds[1] = { fd }, err;
	char iobuf[1];
	struct iovec io = {
		.iov_base = iobuf,
		.iov_len = sizeof(iobuf),
	};
	union {
		char buf[CMSG_SPACE(sizeof(fds))];
		struct cmsghdr align;
	} u;

	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = u.buf;
	msg.msg_controllen = sizeof(u.buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fds));
	memcpy(CMSG_DATA(cmsg), fds, sizeof(fds));

	err = sendmsg(sockfd, &msg, 0);
	if (err < 0)
		err = -errno;
	if (!ASSERT_EQ(err, 1, "sendmsg"))
		return -EINVAL;

	return 0;
}

static int recvfd(int sockfd, int *fd)
{
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	int fds[1], err;
	char iobuf[1];
	struct iovec io = {
		.iov_base = iobuf,
		.iov_len = sizeof(iobuf),
	};
	union {
		char buf[CMSG_SPACE(sizeof(fds))];
		struct cmsghdr align;
	} u;

	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = u.buf;
	msg.msg_controllen = sizeof(u.buf);

	err = recvmsg(sockfd, &msg, 0);
	if (err < 0)
		err = -errno;
	if (!ASSERT_EQ(err, 1, "recvmsg"))
		return -EINVAL;

	cmsg = CMSG_FIRSTHDR(&msg);
	if (!ASSERT_OK_PTR(cmsg, "cmsg_null") ||
	    !ASSERT_EQ(cmsg->cmsg_len, CMSG_LEN(sizeof(fds)), "cmsg_len") ||
	    !ASSERT_EQ(cmsg->cmsg_level, SOL_SOCKET, "cmsg_level") ||
	    !ASSERT_EQ(cmsg->cmsg_type, SCM_RIGHTS, "cmsg_type"))
		return -EINVAL;

	memcpy(fds, CMSG_DATA(cmsg), sizeof(fds));
	*fd = fds[0];

	return 0;
}

static int wait_for_pid(pid_t pid)
{
	int status, ret;

again:
	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		if (errno == EINTR)
			goto again;

		return -1;
	}

	if (!WIFEXITED(status))
		return -1;

	return WEXITSTATUS(status);
}

static int child(int sock_fd, struct bpffs_opts *bpffs_opts,
		 child_callback_fn callback)
{
	int mnt_fd = -1, fs_fd = -1, err = 0, bpffs_fd = -1, token_fd = -1;

	err = create_and_enter_userns();
	if (!ASSERT_OK(err, "create_and_enter_userns"))
		goto cleanup;

	err = unshare(CLONE_NEWNS);
	if (!ASSERT_OK(err, "create_mountns"))
		goto cleanup;

	err = sys_mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, 0);
	if (!ASSERT_OK(err, "remount_root"))
		goto cleanup;

	fs_fd = create_bpffs_fd();
	if (!ASSERT_GE(fs_fd, 0, "create_bpffs_fd")) {
		err = -EINVAL;
		goto cleanup;
	}

	err = sendfd(sock_fd, fs_fd);
	if (!ASSERT_OK(err, "send_fs_fd"))
		goto cleanup;
	zclose(fs_fd);

	err = recvfd(sock_fd, &mnt_fd);
	if (!ASSERT_OK(err, "recv_mnt_fd"))
		goto cleanup;

	bpffs_fd = openat(mnt_fd, ".", 0, O_RDWR);
	if (!ASSERT_GE(bpffs_fd, 0, "bpffs_open")) {
		err = -EINVAL;
		goto cleanup;
	}

	err = callback(bpffs_fd);
	if (!ASSERT_OK(err, "test_callback"))
		goto cleanup;

	err = 0;

cleanup:
	zclose(sock_fd);
	zclose(mnt_fd);
	zclose(fs_fd);
	zclose(bpffs_fd);
	zclose(token_fd);

	exit(-err);
}

static int parent(int child_pid, struct bpffs_opts *bpffs_opts, int sock_fd)
{
	int fs_fd = -1, mnt_fd = -1, token_fd = -1, err;

	err = recvfd(sock_fd, &fs_fd);
	if (!ASSERT_OK(err, "recv_bpffs_fd"))
		goto cleanup;

	mnt_fd = materialize_bpffs_fd(fs_fd, bpffs_opts);
	if (!ASSERT_GE(mnt_fd, 0, "materialize_bpffs_fd")) {
		err = -EINVAL;
		goto cleanup;
	}
	zclose(fs_fd);

	err = sendfd(sock_fd, mnt_fd);
	if (!ASSERT_OK(err, "send_mnt_fd"))
		goto cleanup;
	zclose(mnt_fd);

	err = wait_for_pid(child_pid);
	if (!ASSERT_OK(err, "waitpid_child")) {
		err = -EINVAL;
		goto cleanup;
	}

cleanup:
	zclose(sock_fd);
	zclose(fs_fd);
	zclose(mnt_fd);
	zclose(token_fd);

	if (child_pid > 0)
		(void)kill(child_pid, SIGKILL);

	return err;
}

static int subtest(struct bpffs_opts *bpffs_opts, child_callback_fn child_cb)
{
	int sock_fds[2] = { -1, -1 };
	int child_pid = 0, err;

	err = socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fds);
	if (!ASSERT_OK(err, "socketpair"))
		goto cleanup;

	child_pid = fork();
	if (!ASSERT_GE(child_pid, 0, "fork"))
		goto cleanup;

	if (child_pid == 0) {
		zclose(sock_fds[0]);
		return child(sock_fds[1], bpffs_opts, child_cb);
	} else {
		zclose(sock_fds[1]);
		return parent(child_pid, bpffs_opts, sock_fds[0]);
	}

cleanup:
	zclose(sock_fds[0]);
	zclose(sock_fds[1]);
	if (child_pid > 0)
		(void)kill(child_pid, SIGKILL);

	return -err;
}

static int userns_map_create(int mnt_fd)
{
	LIBBPF_OPTS(bpf_map_create_opts, map_opts);
	int err = 0, token_fd = -1, map_fd = -1;

	/* create BPF token from BPF FS mount */
	token_fd = bpf_token_create(mnt_fd, NULL);
	if (!ASSERT_GT(token_fd, 0, "userns_map_create/token_create")) {
		err = -EINVAL;
		goto cleanup;
	}

	map_opts.map_flags = BPF_F_TOKEN_FD;
	map_opts.token_fd = token_fd;
	map_fd = bpf_map_create(BPF_MAP_TYPE_STACK, "userns_map_create", 0, 8, 1,
				&map_opts);
	if (!ASSERT_GT(map_fd, 0, "userns_map_create/bpf_map_create")) {
		err = -EINVAL;
		goto cleanup;
	}

cleanup:
	zclose(token_fd);
	zclose(map_fd);

	if (err)
		fprintf(stderr, "Failed to create BPF map with BPF token enabled: %s\n",
			strerror(errno));

	return err;
}

static int userns_prog_load(int mnt_fd)
{
	LIBBPF_OPTS(bpf_prog_load_opts, prog_opts);
	int err, token_fd = -1, prog_fd = -1;
	struct bpf_insn insns[] = {
		/* bpf_jiffies64() requires CAP_BPF */
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_jiffies64),
		/* bpf_get_current_task() requires CAP_PERFMON */
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_current_task),
		/* r0 = 0; exit; */
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	size_t insn_cnt = ARRAY_SIZE(insns);

	token_fd = bpf_token_create(mnt_fd, NULL);
	if (!ASSERT_GT(token_fd, 0, "userns_prog_load/token_create")) {
		err = -EINVAL;
		goto cleanup;
	}

	prog_opts.prog_flags = BPF_F_TOKEN_FD;
	prog_opts.token_fd = token_fd;
	prog_opts.expected_attach_type = BPF_XDP;
	prog_fd = bpf_prog_load(BPF_PROG_TYPE_XDP, "token_prog", "GPL",
				insns, insn_cnt, &prog_opts);
	if (!ASSERT_GT(prog_fd, 0, "userns_prog_load/bpf_prog_load")) {
		err = -EPERM;
		goto cleanup;
	}

	err = 0;

cleanup:
	zclose(prog_fd);
	zclose(token_fd);

	if (err)
		fprintf(stderr, "Failed to load BPF prog with token enabled: %s\n",
			strerror(errno));

	return err;
}

int test_bpf_map_create(void)
{
	struct bpffs_opts opts = {
		.cmds_str = "map_create",
		.maps_str = "stack"
	};

	return subtest(&opts, userns_map_create);
}

int test_bpf_prog_load(void)
{
	struct bpffs_opts opts = {
		.cmds_str = "prog_load",
		.progs_str = "XDP",
		.attachs_str = "xdp",
	};

	return subtest(&opts, userns_prog_load);
}
