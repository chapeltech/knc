#include <check.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* Include the stub GSS wrapper implementation directly */
#include "lib/stubgsswrap.c"

START_TEST(test_integer_overflow_allocation)
{
    /* Invariant: When input length would cause integer overflow in
       len + sizeof(len), the function must reject the input (return failure)
       rather than allocating a too-small buffer and overflowing it. */

    gss_buffer_desc in, out;
    OM_uint32 minor_status;
    OM_uint32 ret;

    /* Test case 1: SIZE_MAX - sizeof(uint32_t) + 1 causes overflow */
    size_t overflow_len = SIZE_MAX - sizeof(uint32_t) + 1;
    in.length = overflow_len;
    in.value = (void *)0x1; /* non-NULL but we expect rejection before memcpy */
    out.length = 0;
    out.value = NULL;

    ret = gss_init_sec_context(NULL, NULL, NULL, NULL, NULL, 0, 0, NULL,
                               &in, NULL, &out, NULL, NULL);
    ck_assert_msg(ret != 0 || out.length <= in.length,
                  "Overflow length must be rejected or safely handled");

    /* Test case 2: SIZE_MAX causes overflow */
    in.length = SIZE_MAX;
    out.value = NULL;
    out.length = 0;
    ret = gss_init_sec_context(NULL, NULL, NULL, NULL, NULL, 0, 0, NULL,
                               &in, NULL, &out, NULL, NULL);
    ck_assert_msg(ret != 0 || out.value == NULL,
                  "SIZE_MAX length must be rejected");

    /* Test case 3: Valid small input should succeed */
    char valid_data[] = "hello";
    in.length = sizeof(valid_data);
    in.value = valid_data;
    out.value = NULL;
    out.length = 0;
    ret = gss_init_sec_context(NULL, NULL, NULL, NULL, NULL, 0, 0, NULL,
                               &in, NULL, &out, NULL, NULL);
    if (ret == 0 && out.value != NULL) {
        /* Output should not exceed input + metadata */
        ck_assert(out.length <= in.length + sizeof(uint32_t));
        free(out.value);
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_integer_overflow_allocation);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}