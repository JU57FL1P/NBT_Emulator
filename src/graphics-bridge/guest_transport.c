#include "guest_transport.h"

/* QNX6.5 i386 libc scalar ABI. No termios/pthread struct is reproduced. */
extern int open(const char *path, int flags, ...);
extern int read(int descriptor, void *buffer, unsigned int count);
extern int write(int descriptor, const void *buffer, unsigned int count);
extern int close(int descriptor);
extern void *malloc(unsigned int bytes);
extern void free(void *pointer);
extern void *memcpy(void *destination, const void *source, unsigned int length);
extern int usleep(unsigned int microseconds);
extern int gettid(void);
extern char *getenv(const char *);
extern void *mmap_device_memory(void *, nbt_u32, int, int, unsigned long long);
extern void perror(const char *);

/* Verified against the matching original ELF32 i386 libz.so.2 exports and
 * disassembly: zlib uLong/uLongf and all scalar size arguments are 32 bits.
 * Runtime uses the original library, not the build's link-only ELF copy. */
_Static_assert(sizeof(unsigned long) == 4, "QNX i386 zlib length ABI");
extern unsigned long compressBound(unsigned long source_length);
extern int compress2(nbt_u8 *destination, unsigned long *destination_length,
                     const nbt_u8 *source, unsigned long source_length,
                     int level);
extern int uncompress(nbt_u8 *destination, unsigned long *destination_length,
                      const nbt_u8 *source, unsigned long source_length);

/* O_RDWR is 2 in the owned QNX ABI; no O_CREAT/O_TRUNC or other flags used. */
#define NBT_QNX_O_RDWR 2

static volatile unsigned int exchange_lock;
static int serial_descriptor = -1;
static int initialized;
static int closed;
static nbt_u32 next_request_id = 1;
static int batch_configured, batch_enabled;
static nbt_u8 *batch_data;
static nbt_u32 batch_length = 4u, batch_count;
static nbt_u8 *ram;
static volatile nbt_u32 *ram_control;
static nbt_u32 ram_tx, ram_rx;
static int ram_posted;
static nbt_u32 ram_spin_mask=65535u;
#define RAM_BASE 0x70000000ULL
#define RAM_SPAN 0x08001000u
#define RAM_RESPONSE 0x04000100u
#define RAM_LIMIT (NBT_RPC_MAX_PAYLOAD + 16u)

static void copy_bytes(void *dst, const void *src, nbt_u32 length) {
    if (length) (void)memcpy(dst, src, length);
}

/* Only commands with no caller-visible output may be deferred. Queries,
 * glFinish, every EGL/WAL call and controller poll remain ordering barriers.
 * Payloads are copied now, preserving transient native client pointers. */
static int batchable(nbt_u32 opcode) {
    return opcode == 40u || (opcode >= 200u && opcode <= 210u)
        || (opcode >= 212u && opcode <= 218u)
        || (opcode >= 221u && opcode <= 235u)
        || (opcode >= 237u && opcode <= 239u)
        || (opcode >= 256u && opcode <= 259u)
        || (opcode >= 261u && opcode <= 286u);
}

static void lock_channel(void) {
    while (__sync_lock_test_and_set(&exchange_lock, 1u)) {
        /* Yield CPU even across unequal QNX priorities; no guessed mutex ABI. */
        (void)usleep(1000u);
    }
}

static void unlock_channel(void) {
    __sync_lock_release(&exchange_lock);
}

static void fail_channel(void) {
    if (serial_descriptor >= 0) (void)close(serial_descriptor);
    serial_descriptor = -1;
    closed = 1;
    if (ram_control) { __sync_synchronize(); ram_control[1] = ~0u; }
}

static int exact_write(const void *buffer, nbt_u32 length) {
    const nbt_u8 *bytes = (const nbt_u8 *)buffer;
    if (ram) {
        if (ram_tx > RAM_LIMIT || length > RAM_LIMIT - ram_tx) return -1;
        copy_bytes(ram + 64u + ram_tx, buffer, length); ram_tx += length;
        return 0;
    }
    while (length) {
        int written = write(serial_descriptor, bytes, length);
        if (written <= 0 || (nbt_u32)written > length) return -1;
        bytes += written;
        length -= (nbt_u32)written;
    }
    return 0;
}

static int exact_read(void *buffer, nbt_u32 length) {
    nbt_u8 *bytes = (nbt_u8 *)buffer;
    if (ram) {
        nbt_u32 size, spins=0;
        if (!ram_posted) {
            ram_control[2] = ram_tx;
            __sync_synchronize(); ram_control[1] = 1u; ram_posted = 1;
        }
        while (ram_control[1] != 2u) {
            if (ram_control[1] == ~0u) return -1;
            /* PAUSE exits QEMU TCG's execution loop, so avoid it here.
             * Poll briefly for replies, then still yield periodically so
             * lower-priority native service threads can run. */
            __asm__ volatile("" ::: "memory");
            if ((++spins & ram_spin_mask) == 0u) (void)usleep(100u);
        }
        __sync_synchronize(); size = ram_control[3];
        if (size > RAM_LIMIT || ram_rx > size || length > size - ram_rx) return -1;
        copy_bytes(buffer, ram + RAM_RESPONSE + ram_rx, length); ram_rx += length;
        if (ram_rx == size) { __sync_synchronize(); ram_control[1] = 0u; }
        return 0;
    }
    while (length) {
        int received = read(serial_descriptor, bytes, length);
        if (received <= 0 || (nbt_u32)received > length) return -1;
        bytes += received;
        length -= (nbt_u32)received;
    }
    return 0;
}

static int exchange_locked(nbt_u32 opcode, const void *payload, nbt_u32 length,
                 struct nbt_rpc_reply *reply) {
    nbt_u32 request[4], response[4];
    nbt_u32 wire_length = length;
    const void *wire_payload = payload;
    nbt_u8 *compressed_request = (nbt_u8 *)0;
    int result = NBT_RPC_OK;
    void *response_payload = (void *)0;
    void *decoded_payload = (void *)0;
    if (!reply) return NBT_RPC_INVALID;
    reply->status = 0;
    reply->length = 0;
    reply->payload = (void *)0;
    if (length > NBT_RPC_MAX_PAYLOAD || (length && !payload))
        return NBT_RPC_INVALID;
    if (closed) {
        result = NBT_RPC_CLOSED;
        goto done;
    }
    if (!initialized) {
        const char *flag = getenv("NBT_VM_RPC_RAM");
        initialized = 1;
        if (flag && flag[0] == '1' && !flag[1]) {
            const char *long_poll=getenv("NBT_VM_RAM_LONG_POLL");
            if(long_poll && long_poll[0]=='1' && !long_poll[1])ram_spin_mask=1048575u;
            /* Matching original libc wrapper verified: physical offset is
             * uint64, flags are transformed to shared physical mapping.
             * This range is inside the VM's existing reserved 1-2 GiB RAM. */
            void *mapped = mmap_device_memory((void *)0, RAM_SPAN, 0x300, 0, RAM_BASE);
            if (mapped == (void *)~0u || !mapped) { perror("NBT_VM_RAM_MAP");closed=1;result=NBT_RPC_OPEN_FAILED;goto done; }
            ram = mapped; ram_control = (volatile nbt_u32 *)ram;
            ram_control[1]=0; ram_control[2]=ram_control[3]=0;
            __sync_synchronize(); ram_control[0]=0x4e425452u;
        } else {
        serial_descriptor = open("/dev/ser2", NBT_QNX_O_RDWR);
        if (serial_descriptor < 0) {
            closed = 1;
            result = NBT_RPC_OPEN_FAILED;
            goto done;
        }
        }
    }
    ram_tx = ram_rx = 0; ram_posted = 0;
    request[0] = NBT_RPC_REQUEST_MAGIC;
    if (!ram && length >= NBT_RPC_COMPRESSION_THRESHOLD) {
        unsigned long compressed_length = compressBound(length);
        /* Optional optimization: allocation/compression failure keeps the
         * original request intact and uses the existing raw framing. */
        if (compressed_length <= ~0u - 4u) {
            compressed_request = (nbt_u8 *)malloc((nbt_u32)compressed_length + 4u);
            if (compressed_request &&
                compress2(compressed_request + 4u, &compressed_length,
                          (const nbt_u8 *)payload, length, 1) == 0 &&
                compressed_length + 4u < length) {
                compressed_request[0] = (nbt_u8)length;
                compressed_request[1] = (nbt_u8)(length >> 8);
                compressed_request[2] = (nbt_u8)(length >> 16);
                compressed_request[3] = (nbt_u8)(length >> 24);
                wire_payload = compressed_request;
                wire_length = (nbt_u32)compressed_length + 4u;
                request[0] = NBT_RPC_COMPRESSED_REQUEST_MAGIC;
            }
        }
    }
    request[1] = opcode;
    request[2] = wire_length;
    request[3] = (((nbt_u32)gettid() & 0xffffu) << 16) | next_request_id++;
    if (next_request_id > 0xffffu) next_request_id = 1;
    /* Both VM and wire are little-endian. Four uint32 values, no padding. */
    if (exact_write(request, sizeof(request)) || exact_write(wire_payload, wire_length)) {
        result = NBT_RPC_IO_FAILED;
        goto fail;
    }
    free(compressed_request);
    compressed_request = (nbt_u8 *)0;
    if (exact_read(response, sizeof(response))) {
        result = NBT_RPC_IO_FAILED;
        goto fail;
    }
    if ((response[0] != NBT_RPC_RESPONSE_MAGIC &&
         response[0] != NBT_RPC_COMPRESSED_RESPONSE_MAGIC) || response[3] != request[3]
        || response[2] > NBT_RPC_MAX_PAYLOAD) {
        result = NBT_RPC_BAD_RESPONSE;
        goto fail;
    }
    if (response[2]) {
        response_payload = malloc(response[2]);
        if (!response_payload) {
            result = NBT_RPC_NO_MEMORY;
            goto fail;
        }
        if (exact_read(response_payload, response[2])) {
            result = NBT_RPC_IO_FAILED;
            goto fail;
        }
    }
    if (response[0] == NBT_RPC_COMPRESSED_RESPONSE_MAGIC) {
        const nbt_u8 *wire = (const nbt_u8 *)response_payload;
        nbt_u32 original_length;
        unsigned long decoded_length;
        if (response[2] <= 4u) {
            result = NBT_RPC_BAD_RESPONSE;
            goto fail;
        }
        original_length = (nbt_u32)wire[0] | ((nbt_u32)wire[1] << 8) |
                          ((nbt_u32)wire[2] << 16) | ((nbt_u32)wire[3] << 24);
        if (original_length > NBT_RPC_MAX_PAYLOAD) {
            result = NBT_RPC_BAD_RESPONSE;
            goto fail;
        }
        /* A one-byte buffer also permits a valid empty zlib stream; the
         * exact expanded-length comparison still requires zero output. */
        decoded_length = original_length ? original_length : 1u;
        decoded_payload = malloc((nbt_u32)decoded_length);
        if (!decoded_payload) {
            result = NBT_RPC_NO_MEMORY;
            goto fail;
        }
        if (uncompress((nbt_u8 *)decoded_payload, &decoded_length,
                       wire + 4u, response[2] - 4u) != 0 ||
            decoded_length != original_length) {
            result = NBT_RPC_BAD_RESPONSE;
            goto fail;
        }
        free(response_payload);
        response_payload = decoded_payload;
        decoded_payload = (void *)0;
        response[2] = original_length;
    }
    reply->status = response[1];
    reply->length = response[2];
    reply->payload = response_payload;
    goto done;
fail:
    free(decoded_payload);
    free(response_payload);
    fail_channel();
done:
    free(compressed_request);
    return result;
}

static int flush_batch(void) {
    struct nbt_rpc_reply reply;
    int result;
    if (!batch_count) return NBT_RPC_OK;
    copy_bytes(batch_data, &batch_count, 4u);
    result = exchange_locked(NBT_RPC_BATCH, batch_data, batch_length, &reply);
    batch_count = 0; batch_length = 4u;
    if (!result && (reply.status || reply.length)) result = NBT_RPC_BAD_RESPONSE;
    nbt_rpc_reply_free(&reply);
    /* An unknown/failed remote side effect cannot be replayed safely. */
    if (result) fail_channel();
    return result;
}

/* Execute the queued void commands followed by this real synchronous query
 * in ONE exchange. The reply is the final call's unmodified actual result. */
static int batch_call(nbt_u32 opcode, const void *payload, nbt_u32 length,
                       struct nbt_rpc_reply *reply) {
    nbt_u32 header[3] = {opcode, (nbt_u32)gettid(), length};
    int result;
    copy_bytes(batch_data + batch_length, header, sizeof(header));
    copy_bytes(batch_data + batch_length + sizeof(header), payload, length);
    batch_length += sizeof(header) + length; ++batch_count;
    copy_bytes(batch_data, &batch_count, 4u);
    result = exchange_locked(NBT_RPC_BATCH_CALL, batch_data, batch_length, reply);
    batch_count = 0; batch_length = 4u;
    if (result || reply->status) fail_channel();
    return result;
}

int nbt_rpc_call(nbt_u32 opcode, const void *payload, nbt_u32 length,
                 struct nbt_rpc_reply *reply) {
    int result;
    if (!reply) return NBT_RPC_INVALID;
    reply->status = 0; reply->length = 0; reply->payload = (void *)0;
    if (length > NBT_RPC_MAX_PAYLOAD || (length && !payload)) return NBT_RPC_INVALID;
    lock_channel();
    if (!batch_configured) {
        const char *flag = getenv("NBT_VM_RPC_BATCH");
        batch_configured = 1;
        batch_enabled = flag && flag[0] == '1' && !flag[1];
    }
    if (closed) { result = NBT_RPC_CLOSED; goto done; }
    if (batch_enabled && batchable(opcode) && length <= NBT_RPC_BATCH_BYTES - 16u) {
        nbt_u32 header[3] = {opcode, (nbt_u32)gettid(), length};
        nbt_u32 *queued;
        if (batch_count == NBT_RPC_BATCH_COMMANDS
                || batch_length > NBT_RPC_BATCH_BYTES - 12u - length) {
            result = flush_batch(); if (result) goto done;
        }
        if (!batch_data) batch_data = malloc(NBT_RPC_BATCH_BYTES);
        if (!batch_data) goto synchronous;
        queued = malloc(8u);
        if (!queued) { result = NBT_RPC_NO_MEMORY; goto done; }
        queued[0] = queued[1] = 0;
        copy_bytes(batch_data + batch_length, header, sizeof(header));
        copy_bytes(batch_data + batch_length + sizeof(header), payload, length);
        batch_length += sizeof(header) + length; ++batch_count;
        /* This acknowledges copying a void command into the queue. Actual
         * GL execution/errors are observed at the next synchronous barrier. */
        reply->length = 8u; reply->payload = queued;
        result = NBT_RPC_OK; goto done;
    }
synchronous:
    if (batch_count && opcode >= 100u && opcode <= 286u
            && length <= NBT_RPC_BATCH_BYTES - 12u
            && batch_length <= NBT_RPC_BATCH_BYTES - 12u - length) {
        result = batch_call(opcode, payload, length, reply);
        goto done;
    }
    result = flush_batch();
    if (!result) result = exchange_locked(opcode, payload, length, reply);
done:
    unlock_channel();
    return result;
}

void nbt_rpc_reply_free(struct nbt_rpc_reply *reply) {
    if (!reply) return;
    free(reply->payload);
    reply->payload = (void *)0;
    reply->length = 0;
    reply->status = 0;
}

void nbt_rpc_close(void) {
    lock_channel();
    if (!closed) (void)flush_batch();
    fail_channel();
    free(batch_data); batch_data = (void *)0;
    unlock_channel();
}
