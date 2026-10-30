/* VM-only GLES marshaling implementation. Included by generated guest_gl.c.
 * Every rendering operation executes on the real host GLES implementation.
 * Client-side state below preserves native pointer semantics across RPC. */
#include "guest_transport.h"
extern void *malloc(unsigned int);
extern void free(void *);
extern void *memcpy(void *,const void *,unsigned int);
extern void *memset(void *,int,unsigned int);
extern int write(int,const void *,unsigned int);
extern int gettid(void);
extern int usleep(unsigned int);
extern void nbt_controller_after_swap(unsigned int);

#define MAX_BLOB (NBT_RPC_MAX_PAYLOAD-4096u)
#define GL_BAD_ENUM 0x0500u
#define GL_BAD_VALUE 0x0501u
#define GL_BAD_OPERATION 0x0502u
#define GL_OUT_OF_MEMORY 0x0505u
typedef struct { unsigned tag,bits,len; const void *in; void *out; } Arg;
typedef struct Buffer { unsigned id,share,len; unsigned char *data,*valid; struct Buffer *next; } Buffer;
typedef struct { unsigned size,type,normalized,stride,buffer,enabled; const void *pointer; } Attrib;
typedef struct Context { unsigned id,share,ab,eb,pack,unpack; Attrib attrs[16]; struct Context *next; } Context;
typedef struct Thread { unsigned id,context,glerror,eglerror; struct Thread *next; } Thread;
typedef struct String { unsigned context,name; char *text; struct String *next; } String;
static volatile int bridge_lock;
static Context *contexts;
static Buffer *buffers;
static Thread *threads;
static String *strings;
static Thread *thread;
static unsigned diagnostic_count;
static void copy(void *dst,const void *src,unsigned n) { if(n) (void)memcpy(dst,src,n); }
static void zero(void *dst,unsigned n) { if(n) (void)memset(dst,0,n); }
static unsigned length(const char *s) { unsigned n=0; if(s) while(s[n]&&n<MAX_BLOB) ++n; return n; }
static void diagnostic(const char *name) {
  if(diagnostic_count++<24) { static const char a[]="NBT_GL_BRIDGE_ERROR: ",b[]="\n"; write(2,a,sizeof(a)-1); write(2,name,length(name)); write(2,b,1); }
}
static void enter(void) {
  unsigned id=(unsigned)gettid();
  while(__sync_lock_test_and_set(&bridge_lock,1)) usleep(1000);
  for(thread=threads;thread && thread->id!=id;thread=thread->next) {}
  if(!thread) { thread=malloc(sizeof(*thread)); if(thread) { zero(thread,sizeof(*thread)); thread->id=id; thread->next=threads; threads=thread; } }
}
static void leave(void) { __sync_lock_release(&bridge_lock); }
static void error(unsigned e,int egl,const char *name) {
  if(thread) { unsigned *p=egl?&thread->eglerror:&thread->glerror; if(!*p) *p=egl?0x3002u:e; }
  diagnostic(name);
}
static Context *context_id(unsigned id,int create) {
  Context *c; unsigned i;
  if(!id) return 0;
  for(c=contexts;c && c->id!=id;c=c->next) {}
  if(!c && create) { c=malloc(sizeof(*c)); if(c) { zero(c,sizeof(*c)); c->id=c->share=id; c->pack=c->unpack=4; for(i=0;i<16;i++){c->attrs[i].size=4;c->attrs[i].type=0x1406;} c->next=contexts;contexts=c; } }
  return c;
}
static Context *context(int create) {return thread?context_id(thread->context,create):0;}
static Arg scalar(unsigned n) { Arg a={0,n,0,0,0}; return a; }
static Arg floating(float n) { union {float f;unsigned u;} x; x.f=n;return scalar(x.u); }
static Arg input(const void *p,unsigned n) { Arg a={p?2u:1u,0,p?n:0,p,0};return a; }
static Arg output(void *p,unsigned n) { Arg a={p?3u:1u,0,p?n:0,0,p};return a; }
static Arg offset(const void *p) { Arg a={5,(unsigned)p,0,0,0};return a; }
static unsigned amount(int count,unsigned stride) { if(count<0 || (unsigned)count>MAX_BLOB/stride) return ~0u; return (unsigned)count*stride; }
static unsigned attrs_size(const int *p) { unsigned n; if(!p)return 0; for(n=0;n<256;n+=2)if(p[n]==0x3038)return (n+1)*4;return ~0u; }
static unsigned text_size(const char *s) { unsigned n=length(s);return n==MAX_BLOB?~0u:n+1; }
static int issue(unsigned opcode,Arg *args,unsigned argc,unsigned *result,char **string_output) {
  unsigned total=4,i,pos,nout,ret; unsigned char *data,*p; struct nbt_rpc_reply reply; int rc;
  for(i=0;i<argc;i++){ if(args[i].len>MAX_BLOB || total>MAX_BLOB-12) return 0; total+=12;
    if(args[i].tag==2 || args[i].tag==4){if(args[i].len>MAX_BLOB-total)return 0;total+=args[i].len;} }
  data=malloc(total);if(!data)return 0;copy(data,&argc,4);pos=4;
  for(i=0;i<argc;i++){copy(data+pos,&args[i].tag,4);copy(data+pos+4,&args[i].bits,4);copy(data+pos+8,&args[i].len,4);pos+=12;
    if(args[i].tag==2 || args[i].tag==4){copy(data+pos,args[i].in,args[i].len);pos+=args[i].len;} }
  rc=nbt_rpc_call(opcode,data,total,&reply);free(data);
  if(rc || reply.status || reply.length<8){nbt_rpc_reply_free(&reply);return 0;}
  p=reply.payload;copy(&ret,p,4);copy(&nout,p+4,4);pos=8;
  if(nout>argc+1){nbt_rpc_reply_free(&reply);return 0;}
  /* Validate every output before writing any caller-owned buffer. */
  for(i=0;i<nout;i++){unsigned index,n;if(pos>reply.length-8){nbt_rpc_reply_free(&reply);return 0;}copy(&index,p+pos,4);copy(&n,p+pos+4,4);pos+=8;
    if(n>reply.length-pos || (index==~0u ? (!string_output || !n || p[pos+n-1]) : (index>=argc || args[index].tag!=3 || n>args[index].len))){nbt_rpc_reply_free(&reply);return 0;}pos+=n;}
  if(pos!=reply.length){nbt_rpc_reply_free(&reply);return 0;}pos=8;
  for(i=0;i<nout;i++){unsigned index,n;copy(&index,p+pos,4);copy(&n,p+pos+4,4);pos+=8;
    if(index==~0u){char *s=malloc(n);if(!s){nbt_rpc_reply_free(&reply);return 0;}copy(s,p+pos,n);*string_output=s;}else copy(args[index].out,p+pos,n);pos+=n;}
  *result=ret;nbt_rpc_reply_free(&reply);return 1;
}
static unsigned query_count(unsigned pname) {
  switch(pname){
  case 0x0b70:case 0x0d3a:case 0x846d:case 0x846e:return 2;
  case 0x0ba2:case 0x0c10:case 0x0c22:case 0x0c23:case 0x8005:return 4;
  case 0x86a3:case 0x8df8:{unsigned value=0,ret=0;Arg a[2];a[0]=scalar(pname==0x86a3?0x86a2:0x8df9);a[1]=output(&value,4);if(!issue(NBT_OP_glGetIntegerv,a,2,&ret,0)||value>4096)return ~0u;return value;}
  default:return 1;
  }
}
static unsigned pixel_bytes(int width,int height,unsigned format,unsigned type,unsigned alignment) {
  unsigned components,unit,row,stride;
  if(width<0||height<0)return ~0u;if(!width||!height)return 0;
  switch(format){case 0x1906:case 0x1909:case 0x1902:components=1;break;case 0x190a:components=2;break;case 0x1907:components=3;break;case 0x1908:case 0x80e1:components=4;break;default:return ~0u;}
  switch(type){case 0x1401:unit=1;break;case 0x1403:case 0x140b:case 0x8d61:unit=2;break;case 0x1405:case 0x1406:unit=4;break;case 0x8363:case 0x8033:case 0x8034:unit=2;components=1;break;default:return ~0u;}
  row=amount(width,components*unit);if(row==~0u||row>MAX_BLOB-8)return ~0u;stride=(row+alignment-1)&~(alignment-1);
  if((unsigned)(height-1)>MAX_BLOB/stride)return ~0u;return (unsigned)(height-1)*stride+row;
}
static unsigned component_bytes(unsigned type) {switch(type){case 0x1400:case 0x1401:return 1;case 0x1402:case 0x1403:return 2;case 0x1404:case 0x1405:case 0x1406:case 0x140c:return 4;default:return 0;}}
static Buffer *buffer(Context *c,unsigned id,int create){Buffer *b;for(b=buffers;b&&(b->id!=id||b->share!=c->share);b=b->next){}if(!b&&create&&id){b=malloc(sizeof(*b));if(b){zero(b,sizeof(*b));b->id=id;b->share=c->share;b->next=buffers;buffers=b;}}return b;}
static unsigned binding(Context*c,unsigned target){return target==0x8892?c->ab:target==0x8893?c->eb:0;}
static int shadow_data(Context*c,unsigned target,int size,const void*data){Buffer*b;unsigned char*p,*v;if(size<0||(unsigned)size>MAX_BLOB)return 0;b=buffer(c,binding(c,target),1);if(!b)return 0;p=size?malloc((unsigned)size):0;v=size?malloc((unsigned)size):0;if(size&&(!p||!v)){free(p);free(v);return 0;}if(data){copy(p,data,(unsigned)size);for(int i=0;i<size;i++)v[i]=1;}else zero(v,(unsigned)size);free(b->data);free(b->valid);b->data=p;b->valid=v;b->len=(unsigned)size;return 1;}
static int shadow_sub(Context*c,unsigned target,int at,int size,const void*data){Buffer*b=buffer(c,binding(c,target),0);if(!b||at<0||size<0||(unsigned)at>b->len||(unsigned)size>b->len-(unsigned)at||(!data&&size))return 0;copy(b->data+at,data,(unsigned)size);for(int i=0;i<size;i++)b->valid[at+i]=1;return 1;}
static void shadow_delete(Context*c,unsigned id){Buffer**p=&buffers;while(*p){Buffer*b=*p;if(b->id==id&&b->share==c->share){*p=b->next;free(b->data);free(b->valid);free(b);break;}p=&b->next;}if(c->ab==id)c->ab=0;if(c->eb==id)c->eb=0;for(unsigned i=0;i<16;i++)if(c->attrs[i].buffer==id)c->attrs[i].buffer=0;}
static int client_arrays(Context*c){for(unsigned i=0;i<16;i++)if(c->attrs[i].enabled&&!c->attrs[i].buffer)return 1;return 0;}
static int upload_arrays(Context*c,unsigned maxindex){
  for(unsigned i=0;i<16;i++){Attrib*a=&c->attrs[i];if(a->enabled&&!a->buffer){unsigned elem=a->size*component_bytes(a->type),step=a->stride?a->stride:elem,bytes;unsigned char *p;struct nbt_rpc_reply r;int rc;
    if(!elem||!step||!a->pointer||maxindex>(MAX_BLOB-elem)/step)return 0;bytes=maxindex*step+elem;if(bytes>MAX_BLOB-24)return 0;p=malloc(bytes+24);if(!p)return 0;
    copy(p,&i,4);copy(p+4,&a->size,4);copy(p+8,&a->type,4);copy(p+12,&a->normalized,4);copy(p+16,&a->stride,4);copy(p+20,&bytes,4);copy(p+24,a->pointer,bytes);
    rc=nbt_rpc_call(40,p,bytes+24,&r);free(p);if(rc||r.status){nbt_rpc_reply_free(&r);return 0;}nbt_rpc_reply_free(&r);
  }}return 1;
}
static int element_max(Context*c,int count,unsigned type,const void*indices,unsigned *maxindex){
  unsigned unit=component_bytes(type),bytes,pos=0,max=0;const unsigned char *p=indices;
  if(count<0||(type!=0x1401&&type!=0x1403&&type!=0x1405)||!unit)return 0;bytes=amount(count,unit);if(bytes==~0u)return 0;
  if(c->eb){Buffer*b=buffer(c,c->eb,0);pos=(unsigned)indices;if(!b||pos>b->len||bytes>b->len-pos)return 0;for(unsigned i=0;i<bytes;i++)if(!b->valid[pos+i])return 0;p=b->data+pos;}
  if(!p&&bytes)return 0;for(unsigned i=0;i<(unsigned)count;i++){unsigned v=0;copy(&v,p+i*unit,unit);if(v>max)max=v;}*maxindex=max;return 1;
}
