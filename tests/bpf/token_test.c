// SPDX-License-Identifier: GPL-2.0
/* Code derived from: linux/source/tools/testing/selftests/bpf/prog_tests/token.c
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpf_common.h"
#include <signal.h>
#include <linux/mount.h>
#include <linux/unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sched.h>
#include <bpf/btf.h>
#include <selinux/selinux.h>
#include "token_test_common.h"

#define bit(n) (1ULL << (n))

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

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

static int set_delegate_mask(int fs_fd, const char *key, __u64 mask,
			     const char *mask_str)
{
	char buf[32];
	int err;

	if (!mask_str) {
		if (mask == ~0ULL)
			mask_str = "any";
		else {
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
	if (mnt_fd < 0)
		return -errno;

	return mnt_fd;
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

/* Child helper that execs token_child_helper
 * SELinux domain transition is automatic, controlled by file label:
 *   - test_file_t: no transition, stays in test_bpf_t
 *   - test_bpf_deny_helper_exec_t: auto-transitions to test_bpf_deny_token_cap_t
 */
static int child_exec_helper(int sock_fd, const char *helper_path)
{
	char sock_fd_str[32];

	/* Pass socket FD as argument */
	snprintf(sock_fd_str, sizeof(sock_fd_str), "%d", sock_fd);

	/* Exec the helper program - transition determined by file label */
	execl(helper_path, helper_path, sock_fd_str, NULL);

	/* If we get here, exec failed */
	fprintf(stderr, "exec failed: %s\n", strerror(errno));
	_exit(1);
}

/* Cross-domain test with automatic SELinux transition based on file label */
int test_bpf_token_cap_cross_domain_exec(void)
{
	struct bpffs_opts opts = {
		.cmds_str = "map_create",
		.maps_str = "stack"
	};
	int sock_fds[2] = {-1, -1};
	int child_pid = 0, err;
	char helper_path[256];
	char *basedir;

	/* Find the helper program */
	basedir = getenv("TEST_BASEDIR");
	if (!basedir)
		basedir = ".";
	snprintf(helper_path, sizeof(helper_path), "%s/token_child_helper", basedir);

	/* Parent stays in init_user_ns to call materialize_bpffs_fd()
	 * Child will create its own user namespace after exec
	 */

	err = socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fds);
	if (!ASSERT_OK(err, "socketpair"))
		goto cleanup;

	child_pid = fork();
	if (!ASSERT_GE(child_pid, 0, "fork"))
		goto cleanup;

	if (child_pid == 0) {
		zclose(sock_fds[0]);
		/* Child process - exec helper, transition based on file label */
		child_exec_helper(sock_fds[1], helper_path);
	}

	/* Parent process - materializes bpffs and sends mnt_fd to child */
	zclose(sock_fds[1]);
	return parent(child_pid, &opts, sock_fds[0]);

cleanup:
	zclose(sock_fds[0]);
	zclose(sock_fds[1]);
	if (child_pid > 0)
		(void)kill(child_pid, SIGKILL);

	return -err;
}

/* Wrapper for cross-domain success test
 * Test expects token_child_helper to be labeled test_file_t (no transition)
 */
int test_bpf_token_cap_cross_success(void)
{
	return test_bpf_token_cap_cross_domain_exec();
}

/* Wrapper for cross-domain failure test
 * Test expects token_child_helper to be labeled test_bpf_deny_helper_exec_t (auto-transition)
 */
int test_bpf_token_cap_cross_failure(void)
{
	return test_bpf_token_cap_cross_domain_exec();
}
