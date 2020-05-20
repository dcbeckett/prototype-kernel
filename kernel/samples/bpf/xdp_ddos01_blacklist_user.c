/* Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc.
 *  Copyright(c) 2017 Andy Gospodarek, Broadcom Limited, Inc.
 */
static const char *__doc__=
 " XDP: DDoS protection via IPv4 blacklist\n"
 "\n"
 "This program loads the XDP eBPF program into the kernel.\n"
 "Use the cmdline tool for add/removing source IPs to the blacklist\n"
 "and read statistics.\n"
 ;

#include <linux/bpf.h>

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>

#include <sys/resource.h>
#include <getopt.h>
#include <net/if.h>

#include <sys/statfs.h>
#include <libgen.h>  /* dirname */

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>

#define MAX_MAPS 32
const char *prefix = "/sys/fs/bpf/";
struct bpf_map_data {
	int fd;
	char *name;
	size_t elf_offset;
	struct bpf_map_def def;
};
extern struct bpf_map_data map_data[MAX_MAPS];
//#include "bpf_load.h"
#include "bpf_util.h"
#include "libbpf.h"

#include "xdp_ddos01_blacklist_common.h"

static char ifname_buf[IF_NAMESIZE];
static char *ifname = NULL;
static int ifindex = -1;

#define NR_MAPS 5
int maps_marked_for_export[MAX_MAPS] = { 0 };

static const char* map_idx_to_export_filename(int idx)
{
	const char *file = NULL;

	/* Mapping map_fd[idx] to export filenames */
	switch (idx) {
	case 0: /* map_fd[0]: blacklist */
		file =   file_blacklist;
		break;
	case 1: /* map_fd[1]: verdict_cnt */
		file =   file_verdict;
		break;
	case 2: /* map_fd[2]: port_blacklist */
		file =   file_port_blacklist;
		break;
	case 3: /* map_fd[3]: port_blacklist_drop_count_tcp */
		file =   file_port_blacklist_count[DDOS_FILTER_TCP];
		break;
	case 4: /* map_fd[4]: port_blacklist_drop_count_udp */
		file =   file_port_blacklist_count[DDOS_FILTER_UDP];
		break;
	default:
		break;
	}
	return file;
}

static void remove_xdp_program(int ifindex, const char *ifname, __u32 xdp_flags)
{
	int i;
	fprintf(stderr, "Removing XDP program on ifindex:%d device:%s\n",
		ifindex, ifname);
	if (ifindex > -1)
		bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);

	/* Remove all exported map file */
	for (i = 0; i < NR_MAPS; i++) {
		const char *file = map_idx_to_export_filename(i);

		if (unlink(file) < 0) {
			printf("WARN: cannot rm map(%s) file:%s err(%d):%s\n",
			       map_data[i].name, file, errno, strerror(errno));
		}
	}
}

static const struct option long_options[] = {
	{"help",	no_argument,		NULL, 'h' },
	{"remove",	no_argument,		NULL, 'r' },
	{"dev",		required_argument,	NULL, 'd' },
	{"quiet",	no_argument,		NULL, 'q' },
	{"owner",	required_argument,	NULL, 'o' },
	{"skb-mode",	no_argument,		NULL, 'S' },
	{"nic-offload",	no_argument,		NULL, 'n' },
	{0, 0, NULL,  0 }
};

static void usage(char *argv[])
{
	int i;
	printf("\nDOCUMENTATION:\n%s\n", __doc__);
	printf(" Usage: %s (options-see-below)\n",
	       argv[0]);
	printf(" Listing options:\n");
	for (i = 0; long_options[i].name != 0; i++) {
		printf(" --%-12s", long_options[i].name);
		if (long_options[i].flag != NULL)
			printf(" flag (internal value:%d)",
			       *long_options[i].flag);
		else
			printf(" short-option: -%c",
			       long_options[i].val);
		printf("\n");
	}
	printf("\n");
}

static void do_pinning(struct bpf_object *obj, char *filename, char *map_name)
{
	struct bpf_map *map;
	char path[256];
	int fixed_len;
	int map_fd;

	fixed_len = strlen(prefix) + 1;
	snprintf(path, sizeof(path) - fixed_len, "%s%s", prefix, filename);

	map = bpf_object__find_map_by_name(obj, map_name);
	if (!map) {
		printf("failed to find map %s\n", map_name);
		bpf_object__close(obj);
	}

	map_fd = bpf_map__fd(map);
	if (map_fd < 0) {
		printf("failed to find map fd for server mapping\n");
		bpf_object__close(obj);
	}

	if (bpf_obj_pin(map_fd, path)) {
		printf("failed to pin map: %s\n", strerror(errno));
		bpf_object__close(obj);
	}

	printf("Pinned map at %s\n", path);
}

void chown_maps(uid_t owner, gid_t group)
{
	const char *file;
	int i;

	for (i = 0; i < NR_MAPS; i++) {
		file = map_idx_to_export_filename(i);

		/* Change permissions and user for the map file, as this allow
		 * an unpriviliged user to operate the cmdline tool.
		 */
		if (chown(file, owner, group) < 0)
			fprintf(stderr,
				"WARN: Cannot chown file:%s err(%d):%s\n",
				file, errno, strerror(errno));
	}
}

int main(int argc, char **argv)
{
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type = BPF_PROG_TYPE_XDP,
		.file = "xdp_ddos01_blacklist_kern.o",
	};
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	bool rm_xdp_prog = false;
	struct passwd *pwd = NULL;
	struct bpf_object *obj;
	__u32 xdp_flags = 0;
	char filename[256];
	int longindex = 0;
	uid_t owner = -1; /* -1 result in no-change of owner */
	gid_t group = -1;
	int prog_fd;
	int opt;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	/* Parse commands line args */
	while ((opt = getopt_long(argc, argv, "hSrqd:",
				  long_options, &longindex)) != -1) {
		switch (opt) {
		case 'q':
			verbose = 0;
			break;
		case 'r':
			rm_xdp_prog = true;
			break;
		case 'o': /* extract owner and group from username */
			if (!(pwd = getpwnam(optarg))) {
				fprintf(stderr,
					"ERR: unknown owner:%s err(%d):%s\n",
					optarg, errno, strerror(errno));
				goto error;
			}
			owner = pwd->pw_uid;
			group = pwd->pw_gid;
			break;
		case 'd':
			if (strlen(optarg) >= IF_NAMESIZE) {
				fprintf(stderr, "ERR: --dev name too long\n");
				goto error;
			}
			ifname = (char *)&ifname_buf;
			strncpy(ifname, optarg, IF_NAMESIZE);
			ifindex = if_nametoindex(ifname);
			if (ifindex == 0) {
				fprintf(stderr,
					"ERR: --dev name unknown err(%d):%s\n",
					errno, strerror(errno));
				goto error;
			}
			break;
		case 'S':
			xdp_flags |= XDP_FLAGS_SKB_MODE;
			break;
		case 'n':
			xdp_flags |= XDP_FLAGS_HW_MODE;
			break;
		case 'h':
		error:
		default:
			usage(argv);
			return EXIT_FAIL_OPTION;
		}
	}
	/* Required options */
	if (ifindex == -1) {
		printf("ERR: required option --dev missing");
		usage(argv);
		return EXIT_FAIL_OPTION;
	}
	if (rm_xdp_prog) {
		remove_xdp_program(ifindex, ifname, xdp_flags);
		return EXIT_OK;
	}
	if (verbose) {
		printf("Documentation:\n%s\n", __doc__);
		printf(" - Attached to device:%s (ifindex:%d)\n",
		       ifname, ifindex);
	}

	/* Increase resource limits */
	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK, RLIM_INFINITY)");
		return 1;
	}

	if (xdp_flags & XDP_FLAGS_HW_MODE)
		prog_load_attr.ifindex = ifindex;

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd)) {
		printf("load_bpf_file: %s\n", strerror(errno));
		return -1;
	}

	if (prog_fd < 1) {
		printf("error creating prog_fd\n");
		bpf_object__close(obj);
		return -1;
	}

	do_pinning(obj, "ddos_blacklist", "blacklist");
	do_pinning(obj, "ddos_blacklist_stat_verdict", "verdict_cnt");
	do_pinning(obj, "ddos_port_blacklist", "port_blacklist");
	do_pinning(obj, "ddos_port_blacklist_count_tcp", "port_blacklist_drop_count_tcp");
	do_pinning(obj, "ddos_port_blacklist_count_udp", "port_blacklist_drop_count_udp");
	if (owner >= 0)
		chown_maps(owner, group);

	if (bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags) < 0) {
		printf("error setting fd onto xdp\n");
		bpf_object__close(obj);
		return(-1);
	}

	return EXIT_OK;
}
