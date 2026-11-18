/* External component source. Each bit denotes one independent named right. */
_Static_assert(sizeof(unsigned) == 4, "The enrolled ABI uses i32 parameters.");

unsigned ocs_grant(unsigned imported, unsigned offered) {
    return imported & offered;
}
