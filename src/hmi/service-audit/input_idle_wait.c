/*
 * Opt-in controller-DSO idle-input experiment for the exact original NBT image.
 * Compile separately from input_hooks.c; do not include it in another .c.
 *
 * The parent bridge supplies void nbt_controller_poll_idle(void), using
 * nbt_input_on_app_thread for each event. It must be bounded, must not throw
 * or longjmp, and must not change this thread's cancellation state.
 *
 * First configure input_hooks with the runner-verified original image hash.
 * On the native tHMI_App thread, after an ACTUAL successful eglSwapBuffers,
 * call nbt_idle_arm_after_swap(real_result). This arms only that thread and
 * its verified CHmiAppProcUnit. Other wait/timer calls forward unchanged.
 * Do not call the arming function with a fabricated successful result.
 *
 * QNX libc evidence: native-input/libc-*.asm and idle-wrapper-abi.json.
 * CANCEL_DISABLE is 0x10 and ETIMEDOUT is 0x104 on this image.
 * These deliberately differ from values on other operating systems.
 * Native libc addresses derive from the eagerly relocated clock_gettime
 * function-address GOT entry. Never call dlsym in this wrapper: its loader
 * operations can consume a native TimerTimeout_r next-block deadline.
 * The app's timed queue arms a relative timeout separately. Its exact call
 * path is converted to an explicit absolute deadline before arming, and
 * short internal polling waits never extend or shorten that saved deadline.
 * No native instructions, vtables, TLS entries, or queue data are patched.
 */

#if !defined(__i386__)
#error "This scoped wait hook requires the verified 32-bit x86 QNX image"
#endif

typedef unsigned char idle_u8;
typedef unsigned int idle_u32;
typedef signed int idle_i32;
typedef unsigned long long idle_u64;
typedef char idle_pointer_is_32_bits[(sizeof(void *) == 4) ? 1 : -1];

/* Native libc reads seconds at +0 and nanoseconds at +4, both 32 bits. */
struct idle_timespec {
    idle_u32 seconds;
    idle_i32 nanoseconds;
};
typedef char idle_timespec_is_8_bytes[(sizeof(struct idle_timespec) == 8) ? 1 : -1];

extern int clock_gettime(int, struct idle_timespec *);
extern idle_u32 pthread_self(void);
extern idle_u32 nbt_input_verified_app_proc_unit(void);
extern void nbt_controller_poll_idle(void);
extern idle_u32 nbt_controller_input_generation(void);

typedef int (*idle_wait_fn)(void *, void *);
typedef int (*idle_timedwait_fn)(void *, void *, const struct idle_timespec *);
typedef int (*idle_mutex_fn)(void *);
typedef int (*idle_clock_fn)(int, struct idle_timespec *);
typedef int (*idle_cancel_state_fn)(int, int *);
typedef void (*idle_testcancel_fn)(void);
typedef int (*idle_timer_fn)(int, int, const void *, const idle_u64 *, idle_u64 *);

#define IDLE_QNX_EINVAL 22
#define IDLE_QNX_EINTR 4
#define IDLE_QNX_ETIMEDOUT 0x104
#define IDLE_QNX_CANCEL_DISABLE 0x10
#define IDLE_POLL_NANOSECONDS 100000000U
#define IDLE_NATIVE_WAIT_RETURN_PC 0x089ba9cfU
#define IDLE_NATIVE_TIMED_WAIT_RETURN_PC 0x089ba72eU
#define IDLE_NATIVE_TIMER_RETURN_PC 0x089ba806U
#define IDLE_NATIVE_APP_POP_RETURN_PC 0x0805f3afU
#define IDLE_QNX_CONDVAR 0x4000U
#define IDLE_QNX_ABSTIME 0x80000000U

/* The real-wait cache may be populated before arming by several threads. */
static idle_wait_fn idle_real_wait;
static idle_timedwait_fn idle_real_timedwait;
static idle_mutex_fn idle_real_lock;
static idle_mutex_fn idle_real_unlock;
static idle_clock_fn idle_real_clock;
static idle_cancel_state_fn idle_real_cancel_state;
static idle_testcancel_fn idle_real_testcancel;
static idle_timer_fn idle_real_timer;
static idle_u32 idle_armed;
static idle_u32 idle_app_tid;
static idle_u32 idle_app_proc;
static int idle_polling; /* Used only after exact app-thread identity check. */
static int idle_last_status;
static idle_u32 idle_recorded_return_pc;
static idle_u32 idle_recorded_condition;
static idle_u32 idle_recorded_mutex;
/* Only the armed app thread accesses this preserved native timer state. */
static idle_u64 idle_original_deadline;
static idle_u32 idle_original_timer_valid;
static int idle_original_clock;

static idle_u32 idle_word(idle_u32 address)
{
    return *(volatile const idle_u32 *)address;
}

static int idle_code_matches(idle_u32 address, const idle_u8 *bytes,
                              idle_u32 length)
{
    const volatile idle_u8 *actual = (const volatile idle_u8 *)address;
    idle_u32 i;
    for (i = 0; i < length; ++i)
        if (actual[i] != bytes[i])
            return 0;
    return 1;
}

/*
 * Only loads, integer arithmetic and code-byte comparisons occur here.
 * Taking an imported function ADDRESS uses R_386_GLOB_DAT, not a lazy PLT
 * call. Verify that relocation in the final DSO on every build. This first
 * forwarding path must preserve any native TimerTimeout_r pending deadline.
 */
static idle_wait_fn idle_resolve_wait(void)
{
    static const idle_u8 clock_prefix[] = {
        0x55,0x89,0xe5,0x83,0xec,0x18,0x89,0x5d,
        0xf8,0x8b,0x45,0x08,0xe8,0x38,0x7d,0xff
    };
    static const idle_u8 wait_prefix[] = {
        0x55,0xb8,0x01,0x00,0x00,0x00,0x89,0xe5,
        0x83,0xec,0x18,0x8b,0x4d,0x0c,0x89,0x5d
    };
    idle_wait_fn fn = __atomic_load_n(&idle_real_wait, __ATOMIC_ACQUIRE);
    if (!fn) {
        idle_u32 clock_address = (idle_u32)&clock_gettime;
        idle_u32 wait_address;
        if (clock_address < 0x1dfe0U
                || !idle_code_matches(clock_address, clock_prefix, sizeof(clock_prefix)))
            return 0;
        wait_address = clock_address - 0x1dfe0U + 0x20b90U;
        if (!idle_code_matches(wait_address, wait_prefix, sizeof(wait_prefix)))
            return 0;
        fn = (idle_wait_fn)wait_address;
        __atomic_store_n(&idle_real_wait, fn, __ATOMIC_RELEASE);
    }
    return fn;
}

/* Like wait resolution, this performs no loader, libc, or kernel calls. */
static idle_timer_fn idle_resolve_timer(void)
{
    static const idle_u8 timer_prefix[] = {
        0xb8,0x4b,0x00,0x00,0x00,0xe8,0x00,0x00,
        0x00,0x00,0x5a,0x89,0xd1,0x81,0xc1,0xc2
    };
    idle_timer_fn fn = __atomic_load_n(&idle_real_timer, __ATOMIC_ACQUIRE);
    if (!fn) {
        idle_wait_fn wait = idle_resolve_wait();
        idle_u32 address;
        if (!wait || (idle_u32)wait < 0x20b90U)
            return 0;
        address = (idle_u32)wait - 0x20b90U + 0x3f04cU;
        if (!idle_code_matches(address, timer_prefix, sizeof(timer_prefix)))
            return 0;
        fn = (idle_timer_fn)address;
        __atomic_store_n(&idle_real_timer, fn, __ATOMIC_RELEASE);
    }
    return fn;
}

static int idle_resolve_verified_libc(void)
{
    static const idle_u8 wait_prefix[] = {
        0x55,0xb8,0x01,0x00,0x00,0x00,0x89,0xe5,
        0x83,0xec,0x18,0x8b,0x4d,0x0c,0x89,0x5d
    };
    static const idle_u8 timedwait_prefix[] = {
        0x55,0xb8,0x01,0x00,0x00,0x00,0x89,0xe5,
        0x83,0xec,0x58,0x89,0x75,0xf8,0x8b,0x75
    };
    static const idle_u8 lock_prefix[] = {
        0x55,0x89,0xe5,0x56,0x53,0x83,0xec,0x10,
        0x8b,0x75,0x08,0x64,0xa1,0x00,0x00,0x00
    };
    static const idle_u8 unlock_prefix[] = {
        0x55,0x89,0xe5,0x83,0xec,0x28,0x89,0x75,
        0xf8,0x8b,0x75,0x08,0x89,0x5d,0xf4,0x89
    };
    static const idle_u8 cancel_state_prefix[] = {
        0x55,0x89,0xe5,0x83,0xec,0x28,0x8b,0x55,
        0x08,0x89,0x5d,0xf4,0x89,0x7d,0xfc,0xe8
    };
    static const idle_u8 testcancel_prefix[] = {
        0x55,0x89,0xe5,0x53,0x83,0xec,0x14,0x64,
        0xa1,0x00,0x00,0x00,0x00,0x8b,0x40,0x10
    };
    static const idle_u8 pthread_self_prefix[] = {
        0x55,0x89,0xe5,0x64,0xa1,0x00,0x00,0x00,
        0x00,0x5d,0x8b,0x40,0x18,0xc3
    };
    idle_wait_fn wait = idle_resolve_wait();
    idle_u32 libc_base;
    if (!wait || (idle_u32)wait < 0x20b90U || !idle_resolve_timer())
        return 0;
    libc_base = (idle_u32)wait - 0x20b90U;
    if (!idle_code_matches((idle_u32)wait, wait_prefix, sizeof(wait_prefix))
            || !idle_code_matches(libc_base + 0x20aa0U,
                                  timedwait_prefix, sizeof(timedwait_prefix))
            || !idle_code_matches(libc_base + 0x21500U,
                                  lock_prefix, sizeof(lock_prefix))
            || !idle_code_matches(libc_base + 0x21740U,
                                  unlock_prefix, sizeof(unlock_prefix))
            || !idle_code_matches(libc_base + 0x22270U,
                                  cancel_state_prefix, sizeof(cancel_state_prefix))
            || !idle_code_matches(libc_base + 0x22870U,
                                  testcancel_prefix, sizeof(testcancel_prefix))
            || !idle_code_matches(libc_base + 0x22260U,
                                  pthread_self_prefix, sizeof(pthread_self_prefix)))
        return 0;
    idle_real_timedwait = (idle_timedwait_fn)(libc_base + 0x20aa0U);
    idle_real_lock = (idle_mutex_fn)(libc_base + 0x21500U);
    idle_real_unlock = (idle_mutex_fn)(libc_base + 0x21740U);
    idle_real_clock = (idle_clock_fn)(libc_base + 0x1dfe0U);
    idle_real_cancel_state = (idle_cancel_state_fn)(libc_base + 0x22270U);
    idle_real_testcancel = (idle_testcancel_fn)(libc_base + 0x22870U);
    return 1;
}

int nbt_idle_arm_after_swap(idle_u32 real_egl_swap_result)
{
    static const idle_u8 native_wait_call[] = {0xe8,0xf5,0xf9,0x69,0xff};
    static const idle_u8 native_timed_wait_call[] = {0xe8,0x96,0xfc,0x69,0xff};
    static const idle_u8 native_timer_call[] = {0xe8,0x5e,0xea,0x69,0xff};
    static const idle_u8 native_app_pop_call[] = {0xe8,0xd1,0xb2,0x95,0x00};
    idle_u32 proc;
    if (real_egl_swap_result != 1U)
        return -8;
    proc = nbt_input_verified_app_proc_unit();
    if (!proc)
        return -5;
    if (__atomic_load_n(&idle_armed, __ATOMIC_ACQUIRE))
        return idle_app_tid == pthread_self() && idle_app_proc == proc ? 0 : -2;
    if (!idle_code_matches(0x089ba9caU, native_wait_call, sizeof(native_wait_call))
            || !idle_code_matches(0x089ba729U, native_timed_wait_call, sizeof(native_timed_wait_call))
            || !idle_code_matches(0x089ba801U, native_timer_call, sizeof(native_timer_call))
            || !idle_code_matches(0x0805f3aaU, native_app_pop_call, sizeof(native_app_pop_call))
            || !idle_resolve_verified_libc()) {
        idle_last_status = -10;
        return -10;
    }
    idle_app_tid = pthread_self();
    idle_app_proc = proc;
    idle_last_status = 0;
    __atomic_store_n(&idle_armed, 1U, __ATOMIC_RELEASE);
    return 0;
}

/* Call only on the armed app thread while no poll callback is in progress. */
void nbt_idle_disable(void)
{
    idle_original_timer_valid = 0U;
    __atomic_store_n(&idle_armed, 0U, __ATOMIC_RELEASE);
}

/* Diagnostic accessor: call on the app thread, not a concurrent worker. */
int nbt_idle_get_last_status(void)
{
    return idle_last_status;
}

/*
 * Deferred diagnostics only; call after a real swap on the app thread.
 * Capture uses the exact native pthread_self implementation's two TLS loads
 * directly, so neither a PLT lookup nor any kernel call can consume a pending
 * TimerTimeout_r deadline. The implementation bytes are verified on arming.
 */
static void idle_record_unscoped_wait(idle_u32 return_pc, void *condition,
                                       void *mutex)
{
    idle_u32 tls;
    if (!__atomic_load_n(&idle_armed, __ATOMIC_ACQUIRE))
        return;
    __asm__ __volatile__("movl %%fs:0, %0" : "=r"(tls));
    if (!tls || idle_word(tls + 0x18U) != idle_app_tid)
        return;
    if (return_pc == IDLE_NATIVE_WAIT_RETURN_PC
            && (idle_u32)condition == idle_app_proc + 0x14cU
            && (idle_u32)mutex == idle_app_proc + 0x144U)
        return;
    idle_recorded_return_pc = return_pc;
    idle_recorded_condition = (idle_u32)condition;
    idle_recorded_mutex = (idle_u32)mutex;
}

static int idle_is_app_thread(void)
{
    idle_u32 tls;
    if (!__atomic_load_n(&idle_armed, __ATOMIC_ACQUIRE))
        return 0;
    __asm__ __volatile__("movl %%fs:0, %0" : "=r"(tls));
    return tls && idle_word(tls + 0x18U) == idle_app_tid;
}

static int idle_now(int clock_id, idle_u64 *nanoseconds)
{
    struct idle_timespec now;
    if (idle_real_clock(clock_id, &now) != 0 || now.nanoseconds < 0
            || now.nanoseconds >= 1000000000)
        return 0;
    *nanoseconds = (idle_u64)now.seconds * 1000000000U
        + (idle_u32)now.nanoseconds;
    return 1;
}

/*
 * Preserve the exact app timed-pop deadline before any timeout is armed.
 * All other callers forward using loads/branches only. This conversion to
 * an equivalent absolute deadline makes the start time explicit; QNX's
 * otime argument cannot query a pending condition-variable deadline.
 *
 * The caller frame checks are reads, not changes: this firmware uses EBP
 * frames, its queue argument is caller[+8], relative ns is caller[-0x20],
 * and only the original CHmiAppProcUnit::run call site is accepted.
 */
__attribute__((noinline)) int TimerTimeout_r(int clock_id, int flags,
                                            const void *notify,
                                            const idle_u64 *ntime,
                                            idle_u64 *otime)
{
    idle_u32 return_pc = (idle_u32)__builtin_return_address(0);
    idle_u32 caller_frame = idle_word((idle_u32)__builtin_frame_address(0));
    idle_timer_fn real_timer = idle_resolve_timer();
    idle_u64 now;
    idle_u64 deadline;
    int result;
    if (!real_timer)
        return -IDLE_QNX_EINVAL;
    if (return_pc != IDLE_NATIVE_TIMER_RETURN_PC || !idle_is_app_thread()
            || idle_polling || clock_id != 2 || flags != (int)IDLE_QNX_CONDVAR
            || notify || otime || !ntime || !caller_frame
            || idle_word(caller_frame + 4U) != IDLE_NATIVE_APP_POP_RETURN_PC
            || idle_word(caller_frame + 8U) != idle_app_proc + 0x104U
            || (idle_u32)ntime != caller_frame - 0x20U)
        return real_timer(clock_id, flags, notify, ntime, otime);
    idle_original_timer_valid = 0U;
    if (!idle_now(clock_id, &now) || *ntime > ~((idle_u64)0) - now)
        return real_timer(clock_id, flags, notify, ntime, otime);
    deadline = now + *ntime;
    /* No call of any kind follows this kernel arm before returning. */
    result = real_timer(clock_id, (int)(IDLE_QNX_CONDVAR | IDLE_QNX_ABSTIME),
                        0, &deadline, 0);
    if (result >= 0) {
        idle_original_deadline = deadline;
        idle_original_clock = clock_id;
        idle_original_timer_valid = 1U;
    }
    return result;
}

int nbt_idle_last_wait(idle_u32 *return_pc, idle_u32 *condition, idle_u32 *mutex)
{
    if (!return_pc || !condition || !mutex || !idle_recorded_return_pc)
        return 0;
    *return_pc = idle_recorded_return_pc;
    *condition = idle_recorded_condition;
    *mutex = idle_recorded_mutex;
    return 1;
}

static int idle_scoped_call(void *condition, void *mutex, idle_u32 return_pc)
{
    if (!__atomic_load_n(&idle_armed, __ATOMIC_ACQUIRE)
            || return_pc != IDLE_NATIVE_WAIT_RETURN_PC
            || pthread_self() != idle_app_tid || idle_polling)
        return 0;
    return nbt_input_verified_app_proc_unit() == idle_app_proc
        && (idle_u32)condition == idle_app_proc + 0x14cU
        && (idle_u32)mutex == idle_app_proc + 0x144U;
}

static int idle_queue_has_event(void)
{
    /* Caller holds native queue mutex. Three priority deques, as native pop. */
    return idle_word(idle_app_proc + 0x118U)
        || idle_word(idle_app_proc + 0x12cU)
        || idle_word(idle_app_proc + 0x140U);
}

static int idle_deadline(void *condition, struct idle_timespec *out)
{
    int clock_id;
    idle_u32 nanoseconds;
    /* Reproduce libc pthread_cond_timedwait's exact sync_t clock selection. */
    clock_id = idle_word((idle_u32)condition + 4U) == 0xffffffffU
        ? 0 : (int)idle_word((idle_u32)condition);
    if (idle_real_clock(clock_id, out) != 0 || out->nanoseconds < 0
            || out->nanoseconds >= 1000000000)
        return 0;
    nanoseconds = (idle_u32)out->nanoseconds + IDLE_POLL_NANOSECONDS;
    if (nanoseconds >= 1000000000U) {
        if (out->seconds == 0xffffffffU)
            return 0;
        ++out->seconds;
        nanoseconds -= 1000000000U;
    }
    out->nanoseconds = (idle_i32)nanoseconds;
    return 1;
}

/* Never insert another libc/kernel call between the arm and real wait. */
static int idle_wait_until(idle_wait_fn real_wait, void *condition, void *mutex,
                            int clock_id, idle_u64 deadline)
{
    int result = idle_real_timer(clock_id,
                                (int)(IDLE_QNX_CONDVAR | IDLE_QNX_ABSTIME),
                                0, &deadline, 0);
    if (result < 0) {
        idle_last_status = -16;
        return -result;
    }
    return real_wait(condition, mutex);
}

static int idle_preserved_timed_wait(idle_wait_fn real_wait, void *condition,
                                     void *mutex)
{
    idle_u64 original_deadline = idle_original_deadline;
    int clock_id = idle_original_clock;
    idle_u64 now;
    idle_u64 slice_deadline;
    int old_cancel_state;
    int result;
    int restore_result;
    idle_u32 input_before;

    /*
     * Consume our known armed condition timeout explicitly before RPC or
     * any other kernel operation. The original absolute deadline is local.
     */
    result = idle_real_timer(clock_id, 0, 0, 0, 0);
    idle_original_timer_valid = 0U;
    /*
     * The documented success value is the previous timeout flags. Accept
     * the exact known ABS|CONDVAR mask too if this kernel includes the
     * request's high absolute-time option in that returned bitmask.
     */
    if (result < 0
            && (idle_u32)result != (IDLE_QNX_ABSTIME | IDLE_QNX_CONDVAR)) {
        idle_last_status = -15;
        return real_wait(condition, mutex);
    }
    for (;;) {
        if (!idle_now(clock_id, &now) || now >= original_deadline)
            return idle_wait_until(real_wait, condition, mutex,
                                    clock_id, original_deadline);

        result = idle_real_cancel_state(IDLE_QNX_CANCEL_DISABLE, &old_cancel_state);
        if (result) {
            idle_last_status = -11;
            return idle_wait_until(real_wait, condition, mutex,
                                    clock_id, original_deadline);
        }
        result = idle_real_unlock(mutex);
        if (result) {
            idle_real_cancel_state(old_cancel_state, 0);
            idle_last_status = -12;
            return result;
        }
        input_before=nbt_controller_input_generation();
        idle_polling = 1;
        nbt_controller_poll_idle();
        idle_polling = 0;
        result = idle_real_lock(mutex);
        restore_result = idle_real_cancel_state(old_cancel_state, 0);
        if (result || restore_result) {
            idle_last_status = -13;
            return result ? result : restore_result;
        }
        idle_real_testcancel();
        /* The GUI input callback has run on this very application thread.
         * Return an ordinary successful condition wake with the mutex held.
         * Native timed-pop handles an empty wake by cancelling its old wait,
         * doing a zero-time pop and recomputing its render deadline. Never
         * invent ETIMEDOUT or shorten an unrelated native timer here. */
        if(nbt_controller_input_generation()!=input_before)return 0;
        if (!idle_now(clock_id, &now) || now >= original_deadline)
            return idle_wait_until(real_wait, condition, mutex,
                                    clock_id, original_deadline);
        if (idle_queue_has_event())
            return 0;
        if (!idle_is_app_thread())
            return idle_wait_until(real_wait, condition, mutex,
                                    clock_id, original_deadline);

        slice_deadline = now + IDLE_POLL_NANOSECONDS;
        if (slice_deadline < now || slice_deadline > original_deadline)
            slice_deadline = original_deadline;
        result = idle_wait_until(real_wait, condition, mutex,
                                clock_id, slice_deadline);
        if (result == IDLE_QNX_ETIMEDOUT && slice_deadline < original_deadline)
            continue; /* The original application's deadline has not expired. */
        return result; /* Native wait maps EINTR to zero itself. */
    }
}

/*
 * Export only when explicitly linked as an interposer. The wrapper itself
 * always obtains the real implementation at runtime; no absolute-address
 * function call can be folded into an incorrect PC-relative relocation.
 */
__attribute__((noinline)) int pthread_cond_wait(void *condition, void *mutex)
{
    idle_u32 return_pc = (idle_u32)__builtin_return_address(0);
    idle_wait_fn real_wait = idle_resolve_wait();
    struct idle_timespec deadline;
    int old_cancel_state;
    int result;
    int restore_result;
    if (!real_wait)
        return IDLE_QNX_EINVAL;
    idle_record_unscoped_wait(return_pc, condition, mutex);
    if (return_pc == IDLE_NATIVE_TIMED_WAIT_RETURN_PC
            && idle_is_app_thread() && !idle_polling
            && idle_original_timer_valid
            && (idle_u32)condition == idle_app_proc + 0x14cU
            && (idle_u32)mutex == idle_app_proc + 0x144U)
        return idle_preserved_timed_wait(real_wait, condition, mutex);
    if (!idle_scoped_call(condition, mutex, return_pc))
        return real_wait(condition, mutex);

    for (;;) {
        /*
         * Native pop calls us with its queue mutex held. Cancellation must
         * not interrupt the interval while this wrapper unlocks that mutex.
         */
        result = idle_real_cancel_state(IDLE_QNX_CANCEL_DISABLE, &old_cancel_state);
        if (result) {
            idle_last_status = -11;
            return real_wait(condition, mutex);
        }
        result = idle_real_unlock(mutex);
        if (result) {
            idle_real_cancel_state(old_cancel_state, 0);
            idle_last_status = -12;
            return result;
        }
        idle_polling = 1;
        nbt_controller_poll_idle();
        idle_polling = 0;
        result = idle_real_lock(mutex);
        restore_result = idle_real_cancel_state(old_cancel_state, 0);
        if (result || restore_result) {
            idle_last_status = -13;
            return result ? result : restore_result;
        }
        /* Keep the cancellation-point behavior when an event avoids a wait. */
        idle_real_testcancel();
        if (idle_queue_has_event())
            return 0;
        if (!idle_scoped_call(condition, mutex, return_pc)
                || !idle_deadline(condition, &deadline)) {
            idle_last_status = -14;
            return real_wait(condition, mutex);
        }
        result = idle_real_timedwait(condition, mutex, &deadline);
        if (result == IDLE_QNX_ETIMEDOUT)
            continue; /* Never expose our polling timeout to native pop. */
        if (result == IDLE_QNX_EINTR)
            return 0; /* Real QNX pthread_cond_wait also maps EINTR to zero. */
        if (!result)
            return 0;
        /* Preserve ordinary wait semantics if timed polling cannot proceed. */
        idle_last_status = result;
        return real_wait(condition, mutex);
    }
}
