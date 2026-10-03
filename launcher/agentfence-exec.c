/* agentfence-exec: apply an agentfence `profile.rules` with Landlock, then exec.
 *
 * This is the trusted last step before the agent starts, so it is deliberately
 * small: raw Landlock syscalls, no libraries beyond libc. The policy it builds
 * must equal what `agentfence run` (src/run.rs) builds from the same profile:
 *
 *   handled fs rights: all of ABI 9 except ioctl_dev
 *   handled net rights: TCP connect+bind, iff `option net_enforce`
 *   scopes: signal / abstract unix socket, per `option scope_*`
 *
 * Exit status: 2 usage or rules-file error, 1 Landlock error, 127 exec failure. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/landlock.h>
#include <linux/prctl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "rules.h"

#ifndef LANDLOCK_ACCESS_FS_RESOLVE_UNIX
#define LANDLOCK_ACCESS_FS_RESOLVE_UNIX (1ULL << 16)
#endif

/* rules.h bit n == kernel bit n, so rights need no translation. */
_Static_assert(RIGHT_EXECUTE == LANDLOCK_ACCESS_FS_EXECUTE, "bit layout");
_Static_assert(RIGHT_WRITE_FILE == LANDLOCK_ACCESS_FS_WRITE_FILE, "bit layout");
_Static_assert(RIGHT_READ_FILE == LANDLOCK_ACCESS_FS_READ_FILE, "bit layout");
_Static_assert(RIGHT_TRUNCATE == LANDLOCK_ACCESS_FS_TRUNCATE, "bit layout");
_Static_assert(RIGHT_IOCTL_DEV == LANDLOCK_ACCESS_FS_IOCTL_DEV, "bit layout");
_Static_assert(RIGHT_RESOLVE_UNIX == LANDLOCK_ACCESS_FS_RESOLVE_UNIX, "bit layout");

#define DEFAULT_RULES "./.agentfence/profile.rules"
#define ALL_FS_ABI9   ((1ULL << 17) - 1)
/* Same as run.rs handled_fs(): everything the ABI knows, minus device ioctl. */
#define HANDLED_FS    (ALL_FS_ABI9 & ~(uint64_t) LANDLOCK_ACCESS_FS_IOCTL_DEV)
#define NET_TCP       (LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP)
#define SCOPES(r)     (((r)->scope_signal ? LANDLOCK_SCOPE_SIGNAL : 0ULL) | \
                       ((r)->scope_abstract_unix ? LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET : 0ULL))

static bool verbose;

#define warn(...)  do { fputs("agentfence-exec: warning: ", stderr); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } while (0)
#define note(...)  do { if (verbose) { fputs("agentfence-exec: ", stderr); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } } while (0)

static int die(int code, const char *what, const char *detail)
{
        fprintf(stderr, "agentfence-exec: %s%s%s\n", what, detail ? ": " : "", detail ? detail : "");
        return code;
}

static int usage(FILE *out, int code)
{
        fputs("Usage: agentfence-exec [--rules FILE] [--best-effort|--strict] [--verbose] -- CMD [ARGS...]\n"
              "       agentfence-exec --check [--rules FILE]\n\n"
              "Apply a Landlock sandbox from an agentfence profile.rules, then exec CMD.\n"
              "  --rules FILE   default " DEFAULT_RULES "\n"
              "  --best-effort  (default) warn about rights the kernel cannot enforce\n"
              "  --strict       fail if any requested right cannot be enforced\n"
              "  --verbose      describe what is applied\n"
              "  --check        only parse the rules file (exit 0 if valid)\n", out);
        return code;
}

/* Which fs rights exist at a given Landlock ABI (kernel docs, compatibility table). */
static uint64_t abi_fs_mask(int abi)
{
        uint64_t m = (1ULL << 13) - 1;                 /* ABI 1: execute .. make_sym */

        if (abi >= 2) m |= LANDLOCK_ACCESS_FS_REFER;
        if (abi >= 3) m |= LANDLOCK_ACCESS_FS_TRUNCATE;
        if (abi >= 5) m |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
        if (abi >= 9) m |= LANDLOCK_ACCESS_FS_RESOLVE_UNIX;
        return m;
}

static long ll_create(const struct landlock_ruleset_attr *a, size_t size, __u32 flags)
{
        return syscall(SYS_landlock_create_ruleset, a, size, flags);
}

static long ll_add_rule(int fd, enum landlock_rule_type t, const void *attr)
{
        return syscall(SYS_landlock_add_rule, fd, t, attr, 0);
}

static void report_unsupported(uint64_t lost_fs, bool lost_net, bool lost_scope, bool *any)
{
        static const char *const names[] = { "execute", "write_file", "read_file", "read_dir",
                "remove_dir", "remove_file", "make_char", "make_dir", "make_reg", "make_sock",
                "make_fifo", "make_block", "make_sym", "refer", "truncate", "ioctl_dev", "resolve_unix" };

        for (unsigned i = 0; i < sizeof names / sizeof *names; i++)
                if (lost_fs >> i & 1) {
                        warn("not enforced on this kernel: filesystem right %s", names[i]);
                        *any = true;
                }
        if (lost_net) { warn("not enforced on this kernel: TCP connect/bind port rules (needs ABI 4)"); *any = true; }
        if (lost_scope) { warn("not enforced on this kernel: signal / abstract-unix-socket scoping (needs ABI 6)"); *any = true; }
}

/* Open path and add it to the ruleset. Returns 0, or -1 on a Landlock error. */
static int add_fs_rule(int ruleset, const struct fs_rule *r, uint64_t handled)
{
        struct landlock_path_beneath_attr pb = { 0 };
        struct stat st;
        int fd;

        /* A path with an embedded NUL can never be opened (Rust's PathFd::new fails the same way). */
        errno = ENOENT;
        fd = strlen(r->path) == r->path_len ? open(r->path, O_PATH | O_CLOEXEC) : -1;
        if (fd < 0) {
                warn("skipping rule: cannot open %s: %s", r->path, strerror(errno));
                return 0;
        }
        bool is_dir = fstat(fd, &st) < 0 || S_ISDIR(st.st_mode);   /* as run.rs: unknown means dir */
        uint64_t access = r->rights & handled;
        if (!is_dir)
                access &= RIGHTS_FILE_OK;
        if (access == 0) {
                close(fd);
                return 0;
        }
        pb.allowed_access = access;
        pb.parent_fd = fd;
        if (ll_add_rule(ruleset, LANDLOCK_RULE_PATH_BENEATH, &pb) < 0) {
                fprintf(stderr, "agentfence-exec: landlock_add_rule(%s): %s\n", r->path, strerror(errno));
                close(fd);
                return -1;
        }
        note("allow %s: 0x%llx%s", r->path, (unsigned long long) access, is_dir ? "" : " (file)");
        close(fd);
        return 0;
}

static int apply(const struct rules *rules, bool strict)
{
        struct landlock_ruleset_attr attr = { 0 };
        int abi = (int) ll_create(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);

        if (abi < 1)
                return die(1, "Landlock is unavailable (kernel without it, or not enabled in lsm=)", strerror(errno));

        uint64_t fs_mask = abi_fs_mask(abi);
        uint64_t fs_handled = HANDLED_FS & fs_mask;
        bool net = rules->net_enforce && abi >= 4;
        uint64_t scoped = abi >= 6 ? SCOPES(rules) : 0;
        bool any_lost = false;

        report_unsupported(HANDLED_FS & ~fs_mask, rules->net_enforce && abi < 4, SCOPES(rules) && abi < 6, &any_lost);
        if (any_lost && strict)
                return die(1, "--strict: refusing to run with a policy the kernel cannot fully enforce", NULL);
        note("Landlock ABI %d, %zu fs rules, %zu net rules", abi, rules->n_fs, rules->n_net);

        attr.handled_access_fs = fs_handled;
        if (net) attr.handled_access_net = NET_TCP;
        attr.scoped = scoped;
        /* Pass only the struct size this ABI knows; the kernel rejects non-zero unknown tails. */
        size_t size = abi >= 6 ? sizeof attr : abi >= 4 ? offsetof(struct landlock_ruleset_attr, scoped)
                                                         : offsetof(struct landlock_ruleset_attr, handled_access_net);
        int ruleset = (int) ll_create(&attr, size, 0);
        if (ruleset < 0)
                return die(1, "landlock_create_ruleset", strerror(errno));

        for (size_t i = 0; i < rules->n_fs; i++)
                if (add_fs_rule(ruleset, &rules->fs[i], fs_handled) < 0)
                        return 1;
        for (size_t i = 0; net && i < rules->n_net; i++) {
                struct landlock_net_port_attr np = {
                        .allowed_access = rules->net[i].bind ? LANDLOCK_ACCESS_NET_BIND_TCP : LANDLOCK_ACCESS_NET_CONNECT_TCP,
                        .port = rules->net[i].port,
                };
                if (ll_add_rule(ruleset, LANDLOCK_RULE_NET_PORT, &np) < 0)
                        return die(1, "landlock_add_rule(net)", strerror(errno));
        }
        if (!net && rules->n_net)
                note("ignoring %zu net rules (TCP rights not handled)", rules->n_net);

        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
                return die(1, "prctl(PR_SET_NO_NEW_PRIVS)", strerror(errno));
        if (syscall(SYS_landlock_restrict_self, ruleset, 0) < 0)
                return die(1, "landlock_restrict_self", strerror(errno));
        close(ruleset);
        return 0;
}

int main(int argc, char **argv)
{
        static const struct option opts[] = {
                { "rules", required_argument, NULL, 'r' }, { "best-effort", no_argument, NULL, 'b' },
                { "strict", no_argument, NULL, 's' },      { "verbose", no_argument, NULL, 'v' },
                { "check", no_argument, NULL, 'c' },       { "help", no_argument, NULL, 'h' },
                {},
        };
        const char *path = DEFAULT_RULES;
        bool strict = false, check = false;
        char err[256];
        struct rules rules;
        int c;

        while ((c = getopt_long(argc, argv, "+", opts, NULL)) >= 0)
                switch (c) {
                case 'r': path = optarg; break;
                case 'b': strict = false; break;
                case 's': strict = true; break;
                case 'v': verbose = true; break;
                case 'c': check = true; break;
                case 'h': return usage(stdout, 0);
                default:  return usage(stderr, 2);
                }
        if (!check && optind >= argc)
                return usage(stderr, 2);

        FILE *f = fopen(path, "re");
        if (!f)
                return die(2, path, strerror(errno));
        int rc = rules_parse(f, &rules, err, sizeof err);
        fclose(f);
        if (rc < 0) {
                fprintf(stderr, "agentfence-exec: %s: %s\n", path, err);
                rules_free(&rules);
                return 2;
        }
        if (check) {
                rules_free(&rules);
                return 0;
        }
        rc = apply(&rules, strict);
        rules_free(&rules);
        if (rc)
                return rc;

        execvp(argv[optind], argv + optind);
        return die(127, argv[optind], strerror(errno));
}
