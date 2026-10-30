/* Real WAL RPC hooks for the VM-only adapter. This is transport/marshalling,
 * not a renderer. Every operation requires an acknowledged host operation. */
#include "wal_adapter.h"
#include "guest_transport.h"

typedef struct {
    nbt_u32 tag,bits,length;
    const void *input;
    void *output;
} argument;
#define SCALAR(v) ((argument){0,(v),0,0,0})
#define OUTPUT(p,n) ((argument){3,0,(n),0,(p)})
#define INPUT(p,n) ((argument){2,0,(n),(p),0})
#define REQUEST_CAPACITY 1200u

static void copy_bytes(void *destination,const void *source,nbt_u32 length) {
    nbt_u8 *d=destination;const nbt_u8 *s=source;
    while(length--)*d++=*s++;
}
static void put32(nbt_u8 *p,nbt_u32 value) {
    p[0]=(nbt_u8)value;p[1]=(nbt_u8)(value>>8);
    p[2]=(nbt_u8)(value>>16);p[3]=(nbt_u8)(value>>24);
}
static nbt_u32 get32(const nbt_u8 *p) {
    return (nbt_u32)p[0]|((nbt_u32)p[1]<<8)|((nbt_u32)p[2]<<16)|((nbt_u32)p[3]<<24);
}
static int invoke(nbt_u32 opcode,argument *args,nbt_u32 count) {
    nbt_u8 payload[REQUEST_CAPACITY];nbt_u32 used=4,i,pos,outcount,result;
    nbt_u32 observed=0;struct nbt_rpc_reply reply;const nbt_u8 *bytes;int rc;
    if(count>8)return -1;
    put32(payload,count);
    for(i=0;i<count;i++) {
        nbt_u32 body=(args[i].tag==2 || args[i].tag==4)?args[i].length:0;
        if(body>REQUEST_CAPACITY || used>REQUEST_CAPACITY-12 || body>REQUEST_CAPACITY-used-12)return -1;
        put32(payload+used,args[i].tag);put32(payload+used+4,args[i].bits);put32(payload+used+8,args[i].length);
        used+=12;if(body){if(!args[i].input)return -1;copy_bytes(payload+used,args[i].input,body);used+=body;}
    }
    rc=nbt_rpc_call(opcode,payload,used,&reply);
    if(rc)return rc;
    if(reply.status || reply.length<8){nbt_rpc_reply_free(&reply);return -1;}
    bytes=reply.payload;result=get32(bytes);outcount=get32(bytes+4);pos=8;
    /* First validate the entire reply. Do not partially update caller data
     * from malformed/truncated or duplicated output records. */
    if(outcount>count)goto bad;
    for(i=0;i<outcount;i++) {
        nbt_u32 index,length;
        if(pos>reply.length-8)goto bad;
        index=get32(bytes+pos);length=get32(bytes+pos+4);pos+=8;
        if(index>=count || (observed&(1u<<index)) || !args[index].output || length!=args[index].length || length>reply.length-pos)goto bad;
        observed|=1u<<index;pos+=length;
    }
    if(pos!=reply.length)goto bad;
    if(result==0)for(i=0;i<count;i++)if(args[i].output && !(observed&(1u<<i)))goto bad;
    if(result!=0){nbt_rpc_reply_free(&reply);return -1;}
    pos=8;
    for(i=0;i<outcount;i++) {
        nbt_u32 index=get32(bytes+pos),length=get32(bytes+pos+4);pos+=8;
        copy_bytes(args[index].output,bytes+pos,length);pos+=length;
    }
    nbt_rpc_reply_free(&reply);return 0;
bad:
    nbt_rpc_reply_free(&reply);return -1;
}

int nbt_bridge_ready(void) {
    /* Host contract: listener starts only after genuine EGL initialization. */
    static const nbt_u8 challenge[]={0x4e,0x42,0x54,0x5f,0x57,0x41,0x4c,0x5f,0x52,0x45,0x41,0x44,0x59};
    struct nbt_rpc_reply reply;nbt_u32 i;int ok;
    int rc=nbt_rpc_call(NBT_RPC_PING,challenge,sizeof(challenge),&reply);
    if(rc)return rc;
    ok=!reply.status && reply.length==sizeof(challenge);
    if(ok)for(i=0;i<sizeof(challenge);i++)if(((nbt_u8 *)reply.payload)[i]!=challenge[i]){ok=0;break;}
    nbt_rpc_reply_free(&reply);return ok?0:-1;
}
int nbt_bridge_select_zone(nbt_u32 zone) {
    argument args[]={SCALAR(zone)};return invoke(26,args,1);
}
int nbt_bridge_window_create(nbt_u32 id,nbt_u32 display,nbt_u32 config,nbt_u32 width,nbt_u32 height,nbt_u32 *native,nbt_u32 *surface) {
    argument args[]={SCALAR(id),SCALAR(display),SCALAR(config),SCALAR(width),SCALAR(height),OUTPUT(native,4),OUTPUT(surface,4)};
    if(!native || !surface)return -1;
    *native=0;*surface=0;return invoke(20,args,7);
}
int nbt_bridge_window_destroy(nbt_u32 id) {
    argument args[]={SCALAR(id)};return invoke(21,args,1);
}
int nbt_bridge_window_geometry(nbt_u32 id,nbt_u32 x,nbt_u32 y,nbt_u32 width,nbt_u32 height) {
    argument args[]={SCALAR(id),SCALAR(x),SCALAR(y),SCALAR(width),SCALAR(height)};return invoke(22,args,5);
}
int nbt_bridge_window_alpha(nbt_u32 id,nbt_u8 alpha) {
    argument args[]={SCALAR(id),SCALAR(alpha)};return invoke(23,args,2);
}
int nbt_bridge_window_visible(nbt_u32 id,nbt_u8 visible) {
    argument args[]={SCALAR(id),SCALAR(!!visible)};return invoke(24,args,2);
}
int nbt_bridge_window_zorder(const nbt_wal_order *orders,nbt_u32 count) {
    argument args[]={SCALAR(count),INPUT(orders,count*8)};
    if(count>128 || (count && !orders))return -1;
    return invoke(25,args,2);
}
