/* Parser for agentfence `profile.rules` (see docs/PROFILE_FORMAT.md).
 *
 * Pure parsing: no syscalls except reading the stream, so the same code is
 * linked into agentfence-exec and into the libFuzzer target. It must accept
 * exactly what src/rules.rs `parse` accepts. */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Right bit n is the same bit as the kernel's LANDLOCK_ACCESS_FS_* (checked
 * with _Static_assert in agentfence-exec.c). */
enum {
        RIGHT_EXECUTE      = 1 << 0,
        RIGHT_WRITE_FILE   = 1 << 1,
        RIGHT_READ_FILE    = 1 << 2,
        RIGHT_TRUNCATE     = 1 << 14,
        RIGHT_IOCTL_DEV    = 1 << 15,
        RIGHT_RESOLVE_UNIX = 1 << 16,
        /* Rights a non-directory may carry (Landlock's ACCESS_FILE). */
        RIGHTS_FILE_OK = RIGHT_EXECUTE | RIGHT_WRITE_FILE | RIGHT_READ_FILE |
                         RIGHT_TRUNCATE | RIGHT_IOCTL_DEV | RIGHT_RESOLVE_UNIX,
};

struct fs_rule {
        char *path;          /* NUL terminated, but may contain NUL bytes: use path_len */
        size_t path_len;
        uint32_t rights;
};

struct net_rule {
        uint16_t port;
        bool bind;           /* false: connect */
};

struct rules {
        int version;         /* 1 or 2 */
        bool net_enforce, scope_signal, scope_abstract_unix;
        struct fs_rule *fs;
        size_t n_fs, cap_fs;
        struct net_rule *net;
        size_t n_net, cap_net;
};

/* Parse the whole stream. Returns 0, or -1 with a message (including the
 * line number) in err. On failure *r still must be released with rules_free(). */
int rules_parse(FILE *f, struct rules *r, char *err, size_t errlen);
void rules_free(struct rules *r);
