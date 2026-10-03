#include "rules.h"

#include <stdlib.h>
#include <string.h>

static const struct { const char *name; unsigned bit; } fs_names[] = {
        { "execute", 0 },    { "write_file", 1 }, { "read_file", 2 },  { "read_dir", 3 },
        { "remove_dir", 4 }, { "remove_file", 5 }, { "make_char", 6 }, { "make_dir", 7 },
        { "make_reg", 8 },   { "make_sock", 9 },  { "make_fifo", 10 }, { "make_block", 11 },
        { "make_sym", 12 },  { "refer", 13 },     { "truncate", 14 },  { "ioctl_dev", 15 },
        { "resolve_unix", 16 },
};

struct str { const char *p; size_t n; };

static bool is(struct str s, const char *lit)
{
        return s.n == strlen(lit) && memcmp(s.p, lit, s.n) == 0;
}

static bool utf8_valid(const unsigned char *s, size_t n)
{
        for (size_t i = 0; i < n;) {
                unsigned char c = s[i];
                size_t len;
                uint32_t cp, min;

                if (c < 0x80) { i++; continue; }
                else if ((c & 0xe0) == 0xc0) { len = 2; cp = c & 0x1f; min = 0x80; }
                else if ((c & 0xf0) == 0xe0) { len = 3; cp = c & 0x0f; min = 0x800; }
                else if ((c & 0xf8) == 0xf0) { len = 4; cp = c & 0x07; min = 0x10000; }
                else return false;
                if (n - i < len)
                        return false;
                for (size_t k = 1; k < len; k++) {
                        if ((s[i + k] & 0xc0) != 0x80)
                                return false;
                        cp = cp << 6 | (s[i + k] & 0x3f);
                }
                if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))
                        return false;
                i += len;
        }
        return true;
}

static int fail(char *err, size_t errlen, size_t lineno, const char *what, struct str arg)
{
        char shown[41];
        size_t n = arg.n < sizeof shown - 1 ? arg.n : sizeof shown - 1;

        for (size_t i = 0; i < n; i++)
                shown[i] = (arg.p[i] >= 0x20 && arg.p[i] < 0x7f) ? arg.p[i] : '?';
        shown[n] = 0;
        snprintf(err, errlen, "line %zu: %s%s%s%s", lineno, what, arg.p ? " `" : "", arg.p ? shown : "",
                 arg.p ? "`" : "");
        return -1;
}

static int parse_rights(struct str s, int version, uint32_t *out, struct str *bad)
{
        size_t i = 0;

        *out = 0;
        for (;;) {
                size_t j = i;
                bool known = false;

                while (j < s.n && s.p[j] != ',')
                        j++;
                struct str tok = { s.p + i, j - i };
                for (size_t k = 0; k < sizeof fs_names / sizeof *fs_names; k++)
                        if (is(tok, fs_names[k].name) && (version >= 2 || fs_names[k].bit != 16)) {
                                *out |= 1u << fs_names[k].bit;
                                known = true;
                        }
                if (!known) { *bad = tok; return -1; }
                if (j == s.n)
                        return 0;
                i = j + 1;          /* a trailing comma yields an empty token: rejected */
        }
}

static int parse_port(struct str s, uint16_t *out)
{
        unsigned v = 0;

        if (s.n == 0)
                return -1;
        for (size_t i = 0; i < s.n; i++) {
                if (s.p[i] < '0' || s.p[i] > '9')
                        return -1;
                v = v * 10 + (unsigned) (s.p[i] - '0');
                if (v > 65535)
                        return -1;
        }
        *out = (uint16_t) v;
        return 0;
}

static void *grow(void *p, size_t *cap, size_t n, size_t elem)
{
        if (n < *cap)
                return p;
        size_t ncap = *cap ? *cap * 2 : 16;
        void *q = reallocarray(p, ncap, elem);
        if (!q)
                return NULL;
        *cap = ncap;
        return q;
}

static int parse_line(struct rules *r, const char *line, size_t len, size_t no, char *err, size_t errlen)
{
        static const struct str none;
        const char *end = line + len, *t1, *t2 = NULL;

        if (len == 0 || line[0] == '#')
                return 0;
        t1 = memchr(line, '\t', len);
        if (t1)
                t2 = memchr(t1 + 1, '\t', end - (t1 + 1));
        struct str kind = { line, t1 ? (size_t) (t1 - line) : len };

        if (is(kind, "option") && t1 && !t2 && r->version >= 2) {
                struct str name = { t1 + 1, end - (t1 + 1) };
                if (is(name, "net_enforce")) r->net_enforce = true;
                else if (is(name, "scope_signal")) r->scope_signal = true;
                else if (is(name, "scope_abstract_unix")) r->scope_abstract_unix = true;
                else return fail(err, errlen, no, "malformed rule", none);
                return 0;
        }
        if (!t2 || memchr(t2 + 1, '\t', end - (t2 + 1)))
                return fail(err, errlen, no, "malformed rule", none);

        struct str f1 = { t1 + 1, t2 - (t1 + 1) }, f2 = { t2 + 1, end - (t2 + 1) };

        if (is(kind, "fs")) {
                uint32_t rights;
                struct str bad;

                if (f1.n == 0 || f1.p[0] != '/')
                        return fail(err, errlen, no, "path must be absolute", none);
                if (parse_rights(f2, r->version, &rights, &bad) < 0)
                        return fail(err, errlen, no, "unknown right", bad);
                struct fs_rule *n = grow(r->fs, &r->cap_fs, r->n_fs, sizeof *n);
                char *path = n ? malloc(f1.n + 1) : NULL;
                if (!path)
                        return fail(err, errlen, no, "out of memory", none);
                r->fs = n;
                memcpy(path, f1.p, f1.n);
                path[f1.n] = 0;
                r->fs[r->n_fs++] = (struct fs_rule) { path, f1.n, rights };
        } else if (is(kind, "net") && (is(f1, "connect") || is(f1, "bind"))) {
                uint16_t port;

                if (parse_port(f2, &port) < 0)
                        return fail(err, errlen, no, "bad port", f2);
                struct net_rule *n = grow(r->net, &r->cap_net, r->n_net, sizeof *n);
                if (!n)
                        return fail(err, errlen, no, "out of memory", none);
                r->net = n;
                r->net[r->n_net++] = (struct net_rule) { port, is(f1, "bind") };
        } else
                return fail(err, errlen, no, "malformed rule", none);
        return 0;
}

int rules_parse(FILE *f, struct rules *r, char *err, size_t errlen)
{
        static const struct str none;
        char *line = NULL;
        size_t cap = 0, no = 0;
        ssize_t n;
        int rc = 0;

        memset(r, 0, sizeof *r);
        while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
                size_t len = (size_t) n;

                no++;
                if (!utf8_valid((unsigned char *) line, len)) {
                        rc = fail(err, errlen, no, "invalid UTF-8", none);
                        break;
                }
                /* Same line splitting as Rust's str::lines(): strip LF, then one CR. */
                if (len && line[len - 1] == '\n') {
                        len--;
                        if (len && line[len - 1] == '\r')
                                len--;
                }
                if (no == 1) {
                        struct str h = { line, len };
                        if (is(h, "agentfence-rules 1")) r->version = 1;
                        else if (is(h, "agentfence-rules 2")) r->version = 2;
                        else rc = fail(err, errlen, 1,
                                       "missing or unsupported header (expected `agentfence-rules 1` or `2`)", none);
                } else
                        rc = parse_line(r, line, len, no, err, errlen);
        }
        if (rc == 0 && ferror(f))
                rc = fail(err, errlen, no, "read error", none);
        else if (rc == 0 && no == 0)
                rc = fail(err, errlen, 1, "missing or unsupported header (empty file)", none);
        free(line);
        if (rc == 0 && r->version == 1) {
                /* v1 carries no options: defaults mirror `agentfence run` on a default profile. */
                r->net_enforce = r->n_net > 0;
                r->scope_signal = r->scope_abstract_unix = true;
        }
        return rc;
}

void rules_free(struct rules *r)
{
        for (size_t i = 0; i < r->n_fs; i++)
                free(r->fs[i].path);
        free(r->fs);
        free(r->net);
        memset(r, 0, sizeof *r);
}
