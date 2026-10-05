project('agentfence-exec', 'c',
        version : '0.1.0',
        license : 'MIT',
        default_options : ['c_std=c11', 'warning_level=2', 'werror=true', 'buildtype=plain'])

add_project_arguments('-D_FORTIFY_SOURCE=2', '-O2', '-Wall', '-Wextra', '-Werror', language : 'c')

rules_lib = static_library('rules', 'rules.c', c_args : ['-D_GNU_SOURCE'])
exe = executable('agentfence-exec', 'agentfence-exec.c',
                 link_with : rules_lib, install : true)

# clang with libFuzzer: `meson compile fuzz_rules` builds it (not in `all`).
clang = find_program('clang', required : false)
if clang.found()
  run_target('fuzz_rules_build',
             command : [clang, '-g', '-O1', '-D_GNU_SOURCE', '-fsanitize=fuzzer,address,undefined',
                        '-fno-sanitize-recover=undefined', '-I', meson.current_source_dir(),
                        meson.current_source_dir() / 'fuzz/fuzz_rules.c',
                        meson.current_source_dir() / 'rules.c',
                        '-o', meson.current_build_dir() / 'fuzz_rules'])
endif

bash = find_program('bash')
test('differential', bash,
     args : [files('tests/differential.sh')],
     env : {'AGENTFENCE_EXEC': exe.full_path(), 'AGENTFENCE_BIN': get_option('agentfence_bin')},
     timeout : 300)
