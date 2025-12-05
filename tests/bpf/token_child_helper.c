#include "bpf_common.h"
#include <sys/socket.h>
#include <linux/unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <linux/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "token_test_common.h"

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_map_create_opts, map_opts);
	int sock_fd, token_fd = -1, map_fd = -1, fs_fd = -1, mnt_fd = -1, bpffs_fd = -1;
	int err;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <socket_fd>\n", argv[0]);
		return 1;
	}

	sock_fd = atoi(argv[1]);

	/* Create user namespace - required for bpf_token_create() */
	err = create_and_enter_userns();
	if (!ASSERT_OK(err, "token_child_helper/create_and_enter_userns"))
		goto cleanup;

	/* Create mount namespace for isolation */
	err = unshare(CLONE_NEWNS);
	if (!ASSERT_OK(err, "token_child_helper/create_mountns"))
		goto cleanup;

	err = sys_mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, 0);
	if (!ASSERT_OK(err, "token_child_helper/remount_root"))
		goto cleanup;

	/* Create bpffs fd and send to parent for configuration */
	fs_fd = create_bpffs_fd();
	if (!ASSERT_GT(fs_fd, 0, "token_child_helper/create_bpffs_fd")) {
		err = -EINVAL;
		goto cleanup;
	}

	err = sendfd(sock_fd, fs_fd);
	if (!ASSERT_OK(err, "token_child_helper/send_fs_fd"))
		goto cleanup;
	zclose(fs_fd);

	err = recvfd(sock_fd, &mnt_fd);
	if (!ASSERT_OK(err, "token_child_helper/recv_mnt_fd"))
		goto cleanup;

	/* Open bpffs from mnt_fd */
	bpffs_fd = openat(mnt_fd, ".", 0, O_RDWR);
	if (!ASSERT_GT(bpffs_fd, 0, "token_child_helper/bpffs_open")) {
		err = -EINVAL;
		goto cleanup;
	}

	token_fd = bpf_token_create(bpffs_fd, NULL);
	if (!ASSERT_GT(token_fd, 0, "token_child_helper/bpf_token_create")) {
		err = -EINVAL;
		goto cleanup;
	}

	/* Try to use the token - this will trigger selinux_bpf_token_capable()
	 * Kernel will check: avc_has_perm(current_sid, grantor_sid, cap2_userns, bpf)
	 */
	map_opts.map_flags = BPF_F_TOKEN_FD;
	map_opts.token_fd = token_fd;
	map_fd = bpf_map_create(BPF_MAP_TYPE_STACK, "cross_domain_map", 0, 8, 1,
				&map_opts);
	if (!ASSERT_GT(map_fd, 0, "token_child_helper/bpf_map_create")) {
		err = -EINVAL;
		goto cleanup;
	}

	err = 0;

cleanup:
	zclose(fs_fd);
	zclose(mnt_fd);
	zclose(bpffs_fd);
	zclose(map_fd);
	zclose(token_fd);
	zclose(sock_fd);

	if (err)
		fprintf(stderr, "BPF token cross-domain capability check failed: %s\n",
			strerror(errno));

	return err;
}

