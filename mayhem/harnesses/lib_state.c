/*
 * Hamlib keeps a few values in file-scope and function-local statics that outlive a rig and change what a later
 * call does.  Every harness resets them at the start of each input, so the result of an input depends only on
 * that input.  build.sh makes the symbols linkable (objcopy --globalize-symbol on a copy of libhamlib.a; the
 * oracle build is untouched) and the asm labels below name them as they appear in the object files.
 */
extern int hl_minlen __asm__("read_string_generic.minlen");        /* src/iofunc.c: byte count of the next read */
extern int hl_set_freq_band __asm__("rig_set_freq.last_band");     /* src/rig.c: decides band_changing */
extern int hl_get_freq_band __asm__("rig_get_freq.last_band");     /* src/rig.c: same, in the get path */
/* rigs/kenwood/ts590.c: latches off the SF command.  An int in the source, but it only ever holds 0 or 1 and the
 * optimizer shrinks such a global to one byte, so it is written as a byte (the other bytes, if any, stay 0). */
extern unsigned char hl_ts590_sf_fails __asm__("sf_fails");
extern float hl_dummy_rfpower __asm__("dummy_get_level.rfpower");  /* rigs/dummy/dummy.c: RFPOWER_METER scaling */
extern int hl_dummy_dcd_twiddle __asm__("dummy_get_dcd.twiddle");  /* rigs/dummy/dummy.c: alternates get_dcd results */

void mayhem_reset_library_state(void);

void mayhem_reset_library_state(void)
{
    hl_minlen = 1;
    hl_set_freq_band = -1;
    hl_get_freq_band = -1;
    hl_ts590_sf_fails = 0;
    hl_dummy_rfpower = 0;
    hl_dummy_dcd_twiddle = 0;
}
