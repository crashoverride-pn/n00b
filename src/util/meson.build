# Cross-cutting utilities used by the core.

subdir('simd')

n00b_util_src = (
    files(
        'assert.c',
        'base64.c',
        'der_encode.c',
        'dynamic_lib.c',
        'errno_str.c',
        'marshal.c',
        'parse_num.c',
        'path.c',
        'pkcs7.c',
        'queue.c',
        'worker_pool.c',
        'x509_walk.c',
    )
    + n00b_util_simd_src
)
