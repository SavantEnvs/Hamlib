/*
 * Fuzz a Hamlib backend's reply parsers: the bytes a radio (or rigctld) sends back.
 *
 * The backend runs unmodified over one end of a socketpair; the other end is pre-loaded with the fuzz
 * input and half-closed, as upstream's own tests do with testicomsock (tests/testg90swr.c).  The input
 * is: bytes 0-3 choose two rig API calls (call, argument), the rest is the reply stream those calls read.
 * One source, one binary per backend family: -DTARGET_ICOM, _KENWOOD, _NEWCAT or _NETRIGCTL.
 *
 * Each input starts from the same state: the library statics that change how a later call behaves (the read
 * length in read_string_generic(), last_band in rig_set_freq()/rig_get_freq(), the TS-590's sf_fails latch) are
 * reset by mayhem_reset_library_state() (lib_state.c), the virtual clock by mayhem_clock_reset(), and the rig,
 * its priv data, caps and socketpair are created per input.  Kept across inputs on purpose: nothing but
 * rig_set_debug() and skip_init, set once in LLVMFuzzerInitialize.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "hamlib/rig.h"
#include "hamlib/port.h"
#include "hamlib/rig_state.h"
#include "misc.h"

#if defined(TARGET_ICOM)
#include "icom.h"
#define MODEL RIG_MODEL_IC7300
#elif defined(TARGET_KENWOOD)
#define MODEL RIG_MODEL_TS590S
#elif defined(TARGET_NEWCAT)
#define MODEL RIG_MODEL_FT991
#elif defined(TARGET_NETRIGCTL)
#define MODEL RIG_MODEL_NETRIGCTL
#else
#error "define one of TARGET_ICOM, TARGET_KENWOOD, TARGET_NEWCAT, TARGET_NETRIGCTL"
#endif

#define MAX_REPLY 16384

int LLVMFuzzerInitialize(int *argc, char ***argv);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc;
    (void) argv;
    rig_set_debug(RIG_DEBUG_NONE);
    skip_init = 1;
    return 0;
}

static void run_op(RIG *rig, unsigned op, unsigned sel)
{
    freq_t freq = 0;
    rmode_t mode = 0;
    pbwidth_t width = 0;
    value_t val;
    ptt_t ptt = 0;
    split_t split = 0;
    vfo_t vfo = RIG_VFO_NONE;
    int i = 0;
    shortfreq_t sf = 0;
    setting_t bit = (setting_t) 1 << (sel % RIG_SETTING_MAX);

    memset(&val, 0, sizeof(val));

    switch (op % 20)
    {
    case 0: rig_get_freq(rig, RIG_VFO_CURR, &freq); break;

    case 1: rig_get_mode(rig, RIG_VFO_CURR, &mode, &width); break;

    case 2: rig_get_ptt(rig, RIG_VFO_CURR, &ptt); break;

    case 3: rig_get_split_vfo(rig, RIG_VFO_CURR, &split, &vfo); break;

    case 4: rig_get_vfo(rig, &vfo); break;

    case 5: rig_get_level(rig, RIG_VFO_CURR, bit, &val); break;

    case 6: rig_get_func(rig, RIG_VFO_CURR, bit, &i); break;

    case 7: rig_get_rit(rig, RIG_VFO_CURR, &sf); break;

    case 8: rig_get_xit(rig, RIG_VFO_CURR, &sf); break;

    case 9: rig_get_ts(rig, RIG_VFO_CURR, &sf); break;

    case 10: rig_set_freq(rig, RIG_VFO_CURR, 14250000.0 + sel); break;

    case 11: rig_set_mode(rig, RIG_VFO_CURR, (rmode_t) 1 << (sel % 30), 2400); break;

    case 12: rig_set_ptt(rig, RIG_VFO_CURR, (sel & 1) ? RIG_PTT_ON : RIG_PTT_OFF); break;

    case 13: val.f = 0.5f; rig_set_level(rig, RIG_VFO_CURR, bit, val); break;

    case 14: rig_set_split_vfo(rig, RIG_VFO_CURR, (sel & 1) ? RIG_SPLIT_ON : RIG_SPLIT_OFF,
                               RIG_VFO_B); break;

    case 15: rig_get_ant(rig, RIG_VFO_CURR, RIG_ANT_CURR, &val, &i, &val, &i); break;

    case 16: rig_get_powerstat(rig, (powerstat_t *) &i); break;

    case 17: rig_vfo_op(rig, RIG_VFO_CURR, (vfo_op_t) 1 << (sel % 24)); break;

    case 18: rig_get_split_freq(rig, RIG_VFO_CURR, &freq); break;

    case 19: rig_get_vfo_info(rig, RIG_VFO_CURR, &freq, &mode, &width, &split, &i); break;
    }
}

extern void mayhem_clock_reset(void);
extern void mayhem_reset_library_state(void);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int sockets[2];
    RIG *rig;

    /* 4 header bytes (two calls and their arguments) are part of this harness's input format */
    if (size < 5) { return -1; }

    mayhem_clock_reset();
    mayhem_reset_library_state();

    if (size > MAX_REPLY + 4) { size = MAX_REPLY + 4; }

    rig = rig_init(MODEL);

    if (rig == NULL) { return 0; }

    /* backends (netrigctl_open() in particular) write capabilities into rig->caps, which points at a static
     * table shared by every rig; give each input its own copy so no input sees another's changes */
    struct rig_caps caps = *rig->caps;
    rig->caps = &caps;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
    {
        rig_cleanup(rig);
        return 0;
    }

    /* the whole reply is queued before the backend runs, then the radio "hangs up" */
    if (write(sockets[1], data + 4, size - 4) < 0) { /* socket buffer is larger than MAX_REPLY */ }

    shutdown(sockets[1], SHUT_WR);

    RIGPORT(rig)->fd = sockets[0];
    RIGPORT(rig)->type.rig = RIG_PORT_NETWORK;
    RIGPORT(rig)->timeout = 50;
    RIGPORT(rig)->retry = 0;
#ifdef TARGET_ICOM
    ((struct icom_priv_data *) STATE(rig)->priv)->serial_USB_echo_off = 1;
#endif
    STATE(rig)->comm_state = 1;
    rig_set_cache_timeout_ms(rig, HAMLIB_CACHE_ALL, 0);

#ifdef TARGET_NETRIGCTL
    /* netrigctl_open() reads rigctld's dump_state and builds the rig's capabilities from it */
    if (rig->caps->rig_open != NULL) { rig->caps->rig_open(rig); }

#else
    rig_set_current_vfo_state(rig, RIG_VFO_A);
#endif

    run_op(rig, data[0], data[1]);
    run_op(rig, data[2], data[3]);

    STATE(rig)->comm_state = 0;
    RIGPORT(rig)->fd = -1;
    rig_cleanup(rig);
    close(sockets[0]);
    close(sockets[1]);
    return 0;
}
