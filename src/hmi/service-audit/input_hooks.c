/*
 * Version-guarded VM adapter for the original NBT HmiMain3D input path.
 * Included by the graphics bridge; enabled only by the verified controller
 * profile. Uses original event allocation and application queue routines.
 * No native code patches, device access, worker threads or generated keys.
 *
 * Integration contract:
 * 1. The runner must hash the exact ORIGINAL HmiMain3D that it launches and
 *    match NBT_INPUT_HMI_SHA256 outside the guest before enabling this API.
 *    Passing a literal digest alone is not image verification.
 * 2. Configure once while input is quiescent, using the observed tHMI_App TID
 *    from this launch. Do not assume a permanent TID of 9.
 * 3. Call nbt_input_after_swap only after the real swap returned EGL_TRUE.
 *    nbt_input_on_app_thread is the shared guarded implementation for a
 *    separately verified native app-thread hook armed after the first real
 *    frame. Pass NULL to probe without an event. Never use an RPC worker.
 * 4. Keep disabled until the native frame and shader work is verified.
 *
 * Exact ABI and disassembly evidence: native-input/input-abi-findings.json.
 * This supports only the non-PIE x86 firmware identified by the digest.
 */

#if !defined(__i386__)
#error "NBT input hook requires the original 32-bit x86 guest ABI"
#endif

typedef unsigned char nbt_u8;
typedef unsigned short nbt_u16;
typedef unsigned int nbt_u32;
typedef signed int nbt_i32;
typedef char nbt_pointer_must_be_32_bits[(sizeof(void *) == 4) ? 1 : -1];

extern nbt_u32 pthread_self(void);
extern void *pthread_getspecific(nbt_u32 key);
extern char *getenv(const char *name);

#define NBT_INPUT_HMI_SHA256 \
    "554b67d4d6317cfb1715d544874fae8ddd2c975be503c9e2514e2dc2f3a0d693"

enum nbt_input_status {
    NBT_INPUT_READY = 0,
    NBT_INPUT_SUBMITTED = 1,
    NBT_INPUT_DISABLED = -1,
    NBT_INPUT_WRONG_THREAD = -2,
    NBT_INPUT_IMAGE_MISMATCH = -3,
    NBT_INPUT_NOT_APP_PROC_UNIT = -4,
    NBT_INPUT_NOT_INITIALIZED = -5,
    NBT_INPUT_INVALID_EVENT = -6,
    NBT_INPUT_NATIVE_REJECTED = -7,
    NBT_INPUT_SWAP_NOT_SUCCESSFUL = -8,
    NBT_INPUT_NO_KEY_STATISTIC_CONTEXT = -9
};

enum nbt_input_key {
    NBT_KEY_MENU = 1,
    NBT_KEY_BACK = 2,
    NBT_KEY_OPTION = 3,
    NBT_KEY_PRESS = 8,
    NBT_KEY_NORTH = 9,
    NBT_KEY_SOUTH = 10,
    NBT_KEY_WEST = 11,
    NBT_KEY_EAST = 12,
    NBT_KEY_ROTATE_RIGHT = 13,
    NBT_KEY_ROTATE_LEFT = 14
};

struct nbt_input_event {
    nbt_u32 key;
    nbt_u32 pressed;
    nbt_i32 repeat;
    nbt_u32 long_press;
};

static nbt_u32 nbt_expected_tid;
static nbt_u32 nbt_input_enabled;

static nbt_u32 nbt_read_word(nbt_u32 address)
{
    return *(volatile const nbt_u32 *)address;
}

static int nbt_bytes_match(nbt_u32 address, const nbt_u8 *expected,
                           nbt_u32 count)
{
    volatile const nbt_u8 *actual = (volatile const nbt_u8 *)address;
    nbt_u32 i;
    for (i = 0; i < count; ++i)
        if (actual[i] != expected[i])
            return 0;
    return 1;
}

/* This is an acknowledgement of the runner's external verification. */
int nbt_input_configure_verified_image(const char *verified_sha256,
                                       nbt_u32 observed_hmi_app_tid)
{
    static const char expected[] = NBT_INPUT_HMI_SHA256;
    nbt_u32 i;
    nbt_input_enabled = 0;
    nbt_expected_tid = 0;
    if (!verified_sha256 || !observed_hmi_app_tid)
        return NBT_INPUT_DISABLED;
    for (i = 0; i < sizeof(expected); ++i)
        if (verified_sha256[i] != expected[i])
            return NBT_INPUT_IMAGE_MISMATCH;
    nbt_expected_tid = observed_hmi_app_tid;
    nbt_input_enabled = 1;
    return NBT_INPUT_READY;
}

void nbt_input_disable(void)
{
    /* Configure/disable only while calls are quiescent on the same thread. */
    nbt_input_enabled = 0;
    nbt_expected_tid = 0;
}

static int nbt_input_image_matches(void)
{
    static const nbt_u8 submit_prefix[] = {
        0x55,0x89,0xe5,0x57,0x56,0x53,0x83,0xec,0x28,0x8b,0x7d,0x08,
        0x8b,0x55,0x0c,0x8b,0x4d,0x10,0x8b,0x45,0x14,0x89,0x45,0xe0,
        0x88,0x55,0xe7,0x0f,0xb7,0x35,0x8c,0x6d
    };
    static const nbt_u8 proc_unit_prefix[] = {
        0x55,0x89,0xe5,0x56,0x53,0x83,0xec,0x0c,0x68,0x38,0x9d,0x87,
        0x09,0xe8,0xb1,0xb0,0xa8,0x00,0x83,0xc4,0x10,0x8b,0x00,0x85,
        0xc0,0x75,0x7b,0xe8,0x51,0x07,0xff,0xff
    };
    return nbt_bytes_match(0x089c329cU, submit_prefix, sizeof(submit_prefix))
        && nbt_bytes_match(0x089bb9fdU, proc_unit_prefix, sizeof(proc_unit_prefix))
        && nbt_read_word(0x0944a80cU) == 0x089bbce4U
        && nbt_read_word(0x0944a838U) == 0x080643daU
        && nbt_read_word(0x096217b0U) == 0x089c205eU;
}

/*
 * Inspect an ALREADY POPULATED native TLS cache without invoking the lazy
 * accessor or getHmiProcUnit, both of which can allocate/assert. Source:
 * 0x09446ac9..0x09446b05, followed by 0x089bba0f..0x089bba16.
 */
static int nbt_input_has_app_proc_unit(nbt_u32 *context, nbt_u32 *proc_out)
{
    nbt_u32 index = nbt_read_word(0x09879d40U);
    nbt_u32 *tls;
    nbt_u32 slot;
    nbt_u32 proc;
    if (!index || index > 65536U)
        return NBT_INPUT_NOT_INITIALIZED;
    tls = (nbt_u32 *)pthread_getspecific(nbt_read_word(0x099bc700U));
    if (!tls || index > tls[0])
        return NBT_INPUT_NOT_INITIALIZED;
    slot = tls[index];
    if (!slot || (slot & 3U))
        return NBT_INPUT_NOT_INITIALIZED;
    proc = nbt_read_word(slot);
    if (!proc || (proc & 3U))
        return NBT_INPUT_NOT_INITIALIZED;
    /* Primary CHmiAppProcUnit vtable, not another valid HMI proc-unit. */
    if (nbt_read_word(proc) != 0x0944a7f8U)
        return NBT_INPUT_NOT_APP_PROC_UNIT;
    /* Native event queue and app context must exist before submission. */
    if (!nbt_read_word(proc + 0x288U) || !nbt_read_word(proc + 0x28cU)
            || !*(volatile const nbt_u16 *)0x09906d8cU)
        return NBT_INPUT_NOT_INITIALIZED;
    *context = nbt_read_word(proc + 0x28cU);
    if (proc_out)
        *proc_out = proc;
    return NBT_INPUT_READY;
}

/*
 * A pressed event also calls IHmiContext::getAbkStatisticManager (service
 * 0x27), then CHmiAbkStatisticManager::countKeyInputCounter. Its missing-
 * service assertion is not a NULL guard. For the exact CHmiContext type,
 * slot+0x10 (0x089c205e) is a read-only direct array lookup. Do not call an
 * unknown virtual lookup, create the service, or skip its native side effect.
 */
static int nbt_input_has_key_statistic_context(nbt_u32 context)
{
    if (!context || (context & 3U)
            || nbt_read_word(context) != 0x096217a0U
            || !nbt_read_word(context + 0xa0U))
        return NBT_INPUT_NO_KEY_STATISTIC_CONTEXT;
    return NBT_INPUT_READY;
}

static int nbt_input_event_valid(const struct nbt_input_event *event)
{
    if (!((event->key >= 1U && event->key <= 3U)
            || (event->key >= 8U && event->key <= 14U)))
        return 0;
    if (event->pressed > 1U || event->long_press > 1U)
        return 0;
    if (event->key == NBT_KEY_ROTATE_RIGHT || event->key == NBT_KEY_ROTATE_LEFT)
        return event->pressed == 0U && event->long_press == 0U
            && event->repeat >= 1 && event->repeat <= 16;
    return event->repeat == 1;
}

int nbt_input_on_app_thread(const struct nbt_input_event *event)
{
    typedef nbt_u32 (__attribute__((cdecl)) *native_factory_fn)(void);
    typedef nbt_u8 (__attribute__((cdecl)) *native_enqueue_fn)(void *,void *);
    /* Keep this an absolute indirect call. Clang may otherwise fold a
     * constant function pointer to a PC-relative call in the relocatable DSO,
     * incorrectly adding the interposer's load address at runtime. */
    native_factory_fn volatile allocate = (native_factory_fn)0x080968a0U;
    native_enqueue_fn volatile enqueue = (native_enqueue_fn)0x089bbba0U;
    static const nbt_u8 factory_prefix[]={0x55,0x89,0xe5,0x56,0x53,0x0f,0xb7,0x1d,0x8c,0x6d,0x90,0x09};
    nbt_u32 context = 0,proc = 0,native_event;
    int guard;
    if (!nbt_input_enabled)
        return NBT_INPUT_DISABLED;
    if (pthread_self() != nbt_expected_tid)
        return NBT_INPUT_WRONG_THREAD;
    if (!nbt_input_image_matches())
        return NBT_INPUT_IMAGE_MISMATCH;
    guard = nbt_input_has_app_proc_unit(&context, &proc);
    if (guard != NBT_INPUT_READY)
        return guard;
    if (!event)
        return NBT_INPUT_READY;
    if (!nbt_input_event_valid(event))
        return NBT_INPUT_INVALID_EVENT;
    if (event->pressed) {
        guard = nbt_input_has_key_statistic_context(context);
        if (guard != NBT_INPUT_READY)
            return guard;
    }
    if(nbt_read_word(context+0x3cu)!=proc
            || nbt_read_word(0x0944a7f8u+0x1cu)!=0x089bbba0u
            || !nbt_bytes_match(0x080968a0u,factory_prefix,sizeof(factory_prefix)))
        return NBT_INPUT_IMAGE_MISMATCH;
    {
        char *direct_gui=getenv("NBT_VM_GUI_INPUT");
        if(direct_gui && direct_gui[0]=='1' && !direct_gui[1]
                && event->key>=1u && event->key<=3u) {
            typedef struct {nbt_u32 words[5];} state_snapshot;
            typedef state_snapshot (__attribute__((cdecl)) *state_fn)(void *);
            typedef nbt_u8 (__attribute__((cdecl)) *menu_fn)(void *,nbt_u32);
            typedef nbt_u8 (__attribute__((cdecl)) *back_fn)(void *);
            nbt_u32 manager=nbt_read_word(context+0x2cu);
            if(!manager || nbt_read_word(manager)!=0x09619228u
                    || !*(volatile const nbt_u8 *)(manager+0x2eu))return NBT_INPUT_NOT_INITIALIZED;
            if(event->key==3u) {
                typedef void *(__attribute__((cdecl)) *lookup_fn)(void *,nbt_u32);
                lookup_fn volatile lookup=(lookup_fn)0x08984244u;
                back_fn volatile options=(back_fn)0x081b2f9cu;
                static const nbt_u8 prefix[]={0x55,0x89,0xe5,0x57,0x56,0x53,0x83,0xec,0x48,0x8b,0x75,0x08};
                nbt_u32 main_menu,home,activity;
                if(!event->pressed)return NBT_INPUT_SUBMITTED;
                if(nbt_read_word(0x09619228u+0xe0u)!=0x08984244u
                        || !nbt_bytes_match(0x081b2f9cu,prefix,sizeof(prefix)))return NBT_INPUT_IMAGE_MISMATCH;
                main_menu=(nbt_u32)lookup((void *)manager,0x35au);
                if(!main_menu || nbt_read_word(main_menu)!=0x0946da80u)return NBT_INPUT_NOT_INITIALIZED;
                home=main_menu-0x6cu;activity=home+0x36cu;
                if(nbt_read_word(home)!=0x0946d2b0u || nbt_read_word(home+0x10u)!=context
                        || nbt_read_word(activity)!=0x0946e9a0u
                        || !nbt_read_word(activity+0x9cu))return NBT_INPUT_NOT_INITIALIZED;
                /* Exact original Home Option hard-key branch 081a4e8c. */
                return options((void *)activity)?NBT_INPUT_SUBMITTED:NBT_INPUT_NATIVE_REJECTED;
            } else if(event->key==1u) {
                menu_fn volatile menu=(menu_fn)0x08984888u;
                if(nbt_read_word(0x09619228u+0x34u)!=0x08984888u)return NBT_INPUT_IMAGE_MISMATCH;
                if(!event->pressed)return NBT_INPUT_SUBMITTED;
                return menu((void *)manager,0x35au)?NBT_INPUT_SUBMITTED:NBT_INPUT_NATIVE_REJECTED;
            } else {
                state_fn volatile current=(state_fn)0x08985332u;
                back_fn volatile back;
                state_snapshot state;
                if(event->pressed)return NBT_INPUT_SUBMITTED;
                if(nbt_read_word(0x09619228u+0x54u)!=0x08985332u
                        || nbt_read_word(0x09619228u+0xc0u)!=0x08984bc6u
                        || nbt_read_word(0x09619228u+0x7cu)!=0x089893e8u)return NBT_INPUT_IMAGE_MISMATCH;
                /* Original Home Back-release branch 081a5756..081a57a1. */
                state=current((void *)manager);
                back=(back_fn)(state.words[2]==2u?0x089893e8u:0x08984bc6u);
                return back((void *)manager)?NBT_INPUT_SUBMITTED:NBT_INPUT_NATIVE_REJECTED;
            }
        }
        if(direct_gui && direct_gui[0]=='1' && !direct_gui[1]
                && event->key>=8u && event->key<=14u) {
            typedef nbt_u8 (__attribute__((cdecl)) *gui_key_fn)
                (void *,nbt_u32,nbt_u32,nbt_u32,const void *);
            gui_key_fn volatile key;
            static const nbt_u8 table_prefix[]={0x55,0x89,0xe5,0x57,0x56,0x53,0x83,0xec,0x28,0x8b,0x5d,0x08};
            static const nbt_u8 container_prefix[]={0x55,0x89,0xe5,0x57,0x56,0x53,0x83,0xec,0x34,0x8b,0x5d,0x08};
            nbt_u32 manager=nbt_read_word(context+0x98u),handler,vt;
            struct {nbt_i32 repeat,tag;nbt_u32 x,y;nbt_i32 extra;nbt_u32 flags;} details=
                {event->repeat,-1,0,0,-1,0};
            if(!manager || nbt_read_word(manager)!=0x096abed8u)return NBT_INPUT_NOT_INITIALIZED;
            handler=nbt_read_word(manager+4u);
            if(!handler)return NBT_INPUT_NOT_INITIALIZED;
            vt=nbt_read_word(handler);
            if(vt==0x096ab8c8u) {
                key=(gui_key_fn)0x08d30726u;
                if(nbt_read_word(vt+0x0cu)!=0x08d30726u
                        || !nbt_bytes_match(0x08d30726u,table_prefix,sizeof(table_prefix)))
                    return NBT_INPUT_IMAGE_MISMATCH;
            } else if(vt==0x096ac390u) {
                /* CHmiDefaultContainerInputHandler, active in Settings.
                 * Same native IHmiInputHandler ABI, delegates to the
                 * container's focused original control. */
                key=(gui_key_fn)0x08d3396cu;
                if(nbt_read_word(vt+0x0cu)!=0x08d3396cu
                        || !nbt_bytes_match(0x08d3396cu,container_prefix,sizeof(container_prefix))
                        || !nbt_read_word(handler+0x14u))
                    return NBT_INPUT_IMAGE_MISMATCH;
            } else return NBT_INPUT_IMAGE_MISMATCH;
            /* Original Home callback 081a542d..081a5466 invokes this
             * current handler with repeat + 17 bytes of event details.
             * Zero padding completes its 24-byte aligned local copy. */
            return key((void *)handler,event->key,event->pressed,event->long_press,&details)
                ? NBT_INPUT_SUBMITTED:NBT_INPUT_NATIVE_REJECTED;
        }
    }
    /* Native CCS rotary path 0809d2d5..0809d2e6 uses context service 0xe
     * and virtual+1c, not the broadcast helper. Its native factory returns
     * a new event with reference count zero. Direct post takes the first
     * reference and the native app loop releases it after processing. */
    native_event=allocate();
    if(!native_event || nbt_read_word(native_event)!=0x096218e8u
            || nbt_read_word(native_event+0x0cu)!=0u)
        return NBT_INPUT_NATIVE_REJECTED;
    *(nbt_u32 *)(native_event+0x10u)=event->key;
    *(nbt_u8 *)(native_event+0x14u)=(nbt_u8)event->pressed;
    *(nbt_i32 *)(native_event+0x18u)=event->repeat;
    *(nbt_u8 *)(native_event+0x1cu)=(nbt_u8)event->long_press;
    return enqueue((void *)proc,(void *)native_event)
        ? NBT_INPUT_SUBMITTED : NBT_INPUT_NATIVE_REJECTED;
}

/* Read-only identity for a separately scoped app-thread wait hook. */
nbt_u32 nbt_input_verified_app_proc_unit(void)
{
    nbt_u32 context = 0;
    nbt_u32 proc = 0;
    if (!nbt_input_enabled || pthread_self() != nbt_expected_tid
            || !nbt_input_image_matches()
            || nbt_input_has_app_proc_unit(&context, &proc) != NBT_INPUT_READY)
        return 0;
    return proc;
}

int nbt_input_after_swap(nbt_u32 real_egl_swap_result,
                         const struct nbt_input_event *event)
{
    if (real_egl_swap_result != 1U)
        return NBT_INPUT_SWAP_NOT_SUCCESSFUL;
    return nbt_input_on_app_thread(event);
}
