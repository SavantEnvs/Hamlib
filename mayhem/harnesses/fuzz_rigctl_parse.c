/*
 * Fuzz the rigctl / rigctld command interpreter (tests/rigctl_parse.c) against the dummy rig.
 *
 * The input is a list of newline-separated records.  Each record picks one command from the
 * allow-list below (byte 0), a form/prefix (byte 1) and carries the raw argument text (the rest),
 * so the fuzzer chooses the commands and their arguments but can never reach the commands that
 * terminate or stall the process (halt, pause) or touch GPIO / configuration (set_gpio, set_conf).
 * The first byte of the whole input selects the dummy rig flavour (VFO-aware or no-VFO).
 *
 * State kept across inputs, on purpose: rigctl_parse_init() runs once (it creates the process-wide
 * thread_data_key, which is only ever read back as NULL here), and the two function-local statics in
 * rigctl_parse() (last_was_ret, last_cmd) only decide whether a blank line is skipped or answered and are
 * rewritten by the first command of every input. Everything else is reset per input: the interpreter's own
 * variables (reset_interpreter_state), the library statics that change later calls (read length, last_band,
 * see lib_state.c), the dummy rig's clock (rig_set_clock after rig_open), the virtual clock, and the rig itself.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>

#include <hamlib/rig.h>

#include "fifo.h"

/* Compiled into this translation unit (instead of linking rigctl-rigctl_parse.o) so the interpreter's own
 * file-scope state (chk_vfo_executed, rigctld_secret) can be reset per input; see reset_interpreter_state(). */
#include "rigctl_parse.c"

struct cmd_name
{
    int cmd;           /* short command character, or 0 when the command only has a long name */
    const char *name;  /* long name, used as "\name" */
};

static const struct cmd_name allow[] =
{
    { 'F', "set_freq" }, { 'f', "get_freq" }, { 'M', "set_mode" }, { 'm', "get_mode" },
    { 'I', "set_split_freq" }, { 'i', "get_split_freq" }, { 'X', "set_split_mode" },
    { 'x', "get_split_mode" }, { 'K', "set_split_freq_mode" }, { 'k', "get_split_freq_mode" },
    { 'S', "set_split_vfo" }, { 's', "get_split_vfo" }, { 'N', "set_ts" }, { 'n', "get_ts" },
    { 'L', "set_level" }, { 'l', "get_level" }, { 'U', "set_func" }, { 'u', "get_func" },
    { 'P', "set_parm" }, { 'p', "get_parm" }, { 'G', "vfo_op" }, { 'g', "scan" },
    { 'A', "set_trn" }, { 'a', "get_trn" }, { 'R', "set_rptr_shift" }, { 'r', "get_rptr_shift" },
    { 'O', "set_rptr_offs" }, { 'o', "get_rptr_offs" }, { 'C', "set_ctcss_tone" },
    { 'c', "get_ctcss_tone" }, { 'D', "set_dcs_code" }, { 'd', "get_dcs_code" },
    { 0, "set_ctcss_sql" }, { 0, "get_ctcss_sql" }, { 0, "set_dcs_sql" }, { 0, "get_dcs_sql" },
    { 'V', "set_vfo" }, { 'v', "get_vfo" }, { 'T', "set_ptt" }, { 't', "get_ptt" },
    { 'E', "set_mem" }, { 'e', "get_mem" }, { 'H', "set_channel" }, { 'h', "get_channel" },
    { 'B', "set_bank" }, { '_', "get_info" }, { 'J', "set_rit" }, { 'j', "get_rit" },
    { 'Z', "set_xit" }, { 'z', "get_xit" }, { 'Y', "set_ant" }, { 'y', "get_ant" },
    { 0, "set_powerstat" }, { 0, "get_powerstat" }, { 0, "send_dtmf" }, { 0, "recv_dtmf" },
    { 'w', "send_cmd" }, { 'W', "send_cmd_rx" }, { '*', "reset" }, { 'b', "send_morse" },
    { 0, "stop_morse" }, { 0, "wait_morse" }, { 0, "send_voice_mem" }, { 0, "stop_voice_mem" },
    { 0, "get_dcd" }, { 0, "uplink" }, { 0, "set_twiddle" }, { 0, "get_twiddle" },
    { 0, "set_cache" }, { 0, "get_cache" }, { '2', "power2mW" }, { '4', "mW2power" },
    { '1', "dump_caps" }, { '3', "dump_conf" }, { 0, "dump_state" }, { 0, "chk_vfo" },
    { 0, "set_vfo_opt" }, { 0, "get_vfo_info" }, { 0, "get_rig_info" }, { 0, "get_vfo_list" },
    { 0, "get_modes" }, { 0, "get_clock" }, { 0, "set_clock" }, { 0, "password" },
    { 0, "set_separator" }, { 0, "get_separator" }, { 0, "set_lock_mode" },
    { 0, "get_lock_mode" }, { 0, "get_mode_bandwidths" }, { 0, "send_raw" },
    { 0, "client_version" }, { 0, "hamlib_version" }, { 0, "get_conf" },
};

#define NALLOW (sizeof(allow) / sizeof(allow[0]))
#define MAX_NAME_LEN 24 /* >= strlen of the longest name in allow[]; checked in LLVMFuzzerInitialize */

static const char *const prefixes[] = { "", "+", ";", "|", ",", "\\" };

extern int LLVMFuzzerInitialize(int *argc, char ***argv);
extern void mayhem_clock_reset(void);
extern void mayhem_reset_library_state(void);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc;
    (void) argv;

    for (size_t k = 0; k < NALLOW; k++)
    {
        if (strlen(allow[k].name) > MAX_NAME_LEN) { abort(); }
    }

    rig_set_debug(RIG_DEBUG_NONE);
    int devnull = open("/dev/null", O_WRONLY);

    if (devnull >= 0) { dup2(devnull, STDOUT_FILENO); close(devnull); } /* dump_conf and friends print to stdout */

    skip_init = 1; /* rigctl --skip-init: no poll / morse / async threads and no start-up sleeps */
    rigctl_parse_init();
    return 0;
}

/* The interpreter's process-wide variables that a command can write, back to what a fresh rigctl starts
 * with: \chk_vfo, \set_separator, \password / rigctld_password_configure, \set_powerstat. */
static void reset_interpreter_state(void)
{
    chk_vfo_executed = 0;
    rig_resp_sep = '\n';
    memset(rigctld_secret, 0, sizeof(rigctld_secret));
    rig_powerstat = RIG_POWER_ON; /* rigctl.c: "defaults to power on" */
}

/* Build the command text the interpreter will read from the fuzz input. */
static char *build_script(const uint8_t *data, size_t size, size_t *out_len)
{
    /* worst case is a record with no argument bytes (a bare newline, or a last record with no newline):
     * one input byte becomes prefix + backslash + name (at most MAX_NAME_LEN) + blank + newline */
    size_t cap = size * (MAX_NAME_LEN + 4) + 64;
    char *buf = malloc(cap);
    size_t n = 0;
    size_t i = 0;

    if (buf == NULL) { return NULL; }

    while (i < size)
    {
        size_t end = i;
        const struct cmd_name *e;
        unsigned flags;

        while (end < size && data[end] != '\n') { end++; }

        e = &allow[data[i] % NALLOW];
        flags = (i + 1 < end) ? data[i + 1] : 0;
        const char *pfx = prefixes[(flags >> 1) % (sizeof(prefixes) / sizeof(prefixes[0]))];
        int use_short = (flags & 1) && e->cmd != 0;

        n += (size_t) snprintf(buf + n, cap - n, "%s", pfx);

        if (use_short)
        {
            buf[n++] = (char) e->cmd;
        }
        else
        {
            n += (size_t) snprintf(buf + n, cap - n, "\\%s", e->name);
        }

        buf[n++] = ' ';

        /* Arguments stay printable ASCII (the protocol is text). */
        for (size_t k = i + 2; k < end; k++)
        {
            unsigned char c = data[k] & 0x7f;
            buf[n++] = (char)((c < 0x20 && c != '\t') ? ' ' : c);
        }

        buf[n++] = '\n';
        i = end + 1;
    }

    *out_len = n;
    return buf;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    size_t script_len = 0;

    mayhem_clock_reset();
    mayhem_reset_library_state();
    reset_interpreter_state();
    char *script;
    FILE *fout;
    RIG *rig;
    int vfo_opt = 0;
    int ext_resp = 0;
    char resp_sep = '\n';
    int ret;

    if (size < 2) { return -1; }

    script = build_script(data + 1, size - 1, &script_len);

    if (script == NULL) { return 0; }

    rig = rig_init((data[0] & 1) ? RIG_MODEL_DUMMY_NOVFO : RIG_MODEL_DUMMY);

    if (rig == NULL)
    {
        free(script);
        return 0;
    }

    fout = fopen("/dev/null", "w");

    if (fout != NULL && rig_open(rig) == RIG_OK)
    {
        char *line = script;
        char *script_end = script + script_len;

        /* rig_open() returns before starting the morse thread under skip_init, and that thread is what
         * allocates the FIFO that send_morse / stop_morse use. A real rigctl always has it, so give the rig
         * the same (empty) FIFO; nothing drains it, as nothing sends CW here. */
        STATE(rig)->fifo_morse = calloc(1, sizeof(FIFO_RIG));

        if (STATE(rig)->fifo_morse != NULL) { initFIFO(STATE(rig)->fifo_morse); }

        /* \get_clock reads back what \set_clock wrote, in statics of the dummy backend; zero them. hour >= 0
         * makes dummy_set_clock write every field. */
        rig_set_clock(rig, 0, 0, 0, 0, 0, 0, 0.0, 0);

        /* One stream per record, one rigctl_parse() call per record: the interpreter treats whatever is left
         * on a line after a command's arguments as the next command, so a record whose argument text reads
         * "\halt" would otherwise run a command the allow-list excludes. The unread rest of the line is
         * dropped with the stream. */
        while (line < script_end)
        {
            char *eol = memchr(line, '\n', (size_t)(script_end - line));
            size_t len = (eol != NULL ? (size_t)(eol - line) : (size_t)(script_end - line)) + 1;

            FILE *fin = fmemopen(line, len, "r");

            if (fin == NULL) { break; }

            ret = rigctl_parse(rig, fin, fout, NULL, 0, NULL, 1, 0, &vfo_opt, '\n',
                               &ext_resp, &resp_sep, 0);
            fclose(fin);
            line += len;

            if (ret != RIG_OK && !RIG_IS_SOFT_ERRCODE(ret) && ret != RIGCTL_PARSE_ERROR) { break; }
        }

        rig_close(rig);
        free(STATE(rig)->fifo_morse);
        STATE(rig)->fifo_morse = NULL;
    }

    if (fout != NULL) { fclose(fout); }

    rig_cleanup(rig);
    free(script);
    return 0;
}
