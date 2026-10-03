/* libFuzzer target for the profile.rules parser.
 *   clang -g -O1 -D_GNU_SOURCE -fsanitize=fuzzer,address,undefined -I.. fuzz_rules.c ../rules.c -o fuzz_rules
 *   ./fuzz_rules -max_total_time=60 corpus/ */
#include <stdint.h>
#include <stdio.h>

#include "rules.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
        struct rules r;
        char err[256];
        FILE *f;

        if (size == 0)
                return 0;
        f = fmemopen((void *) data, size, "r");
        if (!f)
                return 0;
        (void) rules_parse(f, &r, err, sizeof err);
        rules_free(&r);
        fclose(f);
        return 0;
}
