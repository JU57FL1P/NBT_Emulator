/* VM-only byte transport. No QNX SDK header or guessed kernel structure. */
#ifndef NBT_GUEST_TRANSPORT_H
#define NBT_GUEST_TRANSPORT_H

typedef unsigned int nbt_u32;
typedef unsigned char nbt_u8;
_Static_assert(sizeof(void *) == 4 && sizeof(nbt_u32) == 4,
               "This ABI is for the owned i386 QNX6.5 image only");

#define NBT_RPC_REQUEST_MAGIC 0x4e425447u
#define NBT_RPC_RESPONSE_MAGIC 0x4e425452u
#define NBT_RPC_COMPRESSED_REQUEST_MAGIC 0x4e42545au
#define NBT_RPC_COMPRESSED_RESPONSE_MAGIC 0x4e425443u
#define NBT_RPC_MAX_PAYLOAD (64u * 1024u * 1024u)
#define NBT_RPC_COMPRESSION_THRESHOLD 4096u
#define NBT_RPC_PING 0u
#define NBT_RPC_BATCH 56u
#define NBT_RPC_BATCH_CALL 57u
#define NBT_RPC_BATCH_BYTES (256u * 1024u)
#define NBT_RPC_BATCH_COMMANDS 512u

/* Compressed frames retain opcode/status and request ID. Header length is
 * wire length; payload is uint32 little-endian original length + zlib stream.
 * Both wire and expanded payloads are bounded by NBT_RPC_MAX_PAYLOAD. */

enum nbt_rpc_result {
    NBT_RPC_OK = 0,
    NBT_RPC_INVALID = -1,
    NBT_RPC_OPEN_FAILED = -2,
    NBT_RPC_IO_FAILED = -3,
    NBT_RPC_BAD_RESPONSE = -4,
    NBT_RPC_NO_MEMORY = -5,
    NBT_RPC_CLOSED = -6
};

struct nbt_rpc_reply {
    nbt_u32 status;
    nbt_u32 length;
    void *payload;
};

/* Lazy opens /dev/ser2 once. Driver must already be raw, no flow control.
 * Serializes an entire request/response and allocates reply payload with libc.
 * A transport error closes and latches the channel failed; no automatic retry
 * can safely replay a request whose remote side effects are unknown.
 * Remote status is kept separate from the return value (transport success).
 * Caller initializes reply by this call and must eventually release it.
 * Blocking I/O: the external VM runner must bound tests and kill a hung guest.
 */
int nbt_rpc_call(nbt_u32 opcode, const void *payload, nbt_u32 length,
                 struct nbt_rpc_reply *reply);
void nbt_rpc_reply_free(struct nbt_rpc_reply *reply);
/* Terminal close; no implicit reconnect or request replay. */
void nbt_rpc_close(void);

#endif
