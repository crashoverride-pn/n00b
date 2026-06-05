/* WP-011 baseline-test fixture (copy of fixture_null.c). */
int
main(void)
{
    int *p = NULL;
    return p == NULL ? 0 : 1;
}
