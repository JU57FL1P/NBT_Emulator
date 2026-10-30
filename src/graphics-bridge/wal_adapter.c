/* VM-only, stateful Wal ABI adapter. Requires a real rendering bridge core.
 * No original firmware is patched. No EGL/GL success is fabricated here.
 * Native Wal processEvent already returns zero without work; our host hooks
 * are synchronous and notifications occur only after a successful operation.
 */
#include "wal_adapter.h"
extern void *malloc(unsigned int size);
extern void free(void *pointer);
extern int write(int fd, const void *buffer, unsigned int length);
extern int usleep(unsigned int microseconds);

#define EXPORT __attribute__((visibility("default")))
#define WAL_MAX_WINDOWS 128
#define WAL_MAX_LISTENERS 16

EXPORT void nbt_wal_app_construct(nbt_wal_public *) __asm__("_ZN3wal23WalApplicationInterfaceC1Ev");
EXPORT void nbt_wal_app_destruct(nbt_wal_public *) __asm__("_ZN3wal23WalApplicationInterfaceD1Ev");
EXPORT nbt_u8 nbt_wal_select_zone(nbt_wal_public *,nbt_u32) __asm__("_ZN3wal23WalApplicationInterface10selectZoneEm");
EXPORT void nbt_wal_create_window(nbt_wal_public *,nbt_u32,void *,void *,void **,void **,void *) __asm__("_ZN3wal23WalApplicationInterface12createWindowEmPvS1_PP8KDWindowPS1_PNS_11WalListenerE");
EXPORT void nbt_wal_hmi_construct(nbt_wal_public *,void *) __asm__("_ZN3wal15WalHmiInterfaceC1ERNS_11WalListenerE");
EXPORT void nbt_wal_hmi_destruct(nbt_wal_public *) __asm__("_ZN3wal15WalHmiInterfaceD1Ev");
EXPORT int nbt_wal_process_event(nbt_wal_public *) __asm__("_ZN3wal15WalHmiInterface12processEventEv");
EXPORT void nbt_wal_set_geometry(nbt_wal_public *,nbt_u32,nbt_u32,nbt_u32,nbt_u32,nbt_u32) __asm__("_ZN3wal15WalHmiInterface24setWindowPositionAndSizeEmmmmm");
EXPORT void nbt_wal_set_alpha(nbt_wal_public *,nbt_u32,nbt_u8) __asm__("_ZN3wal15WalHmiInterface8setAlphaEmh");
EXPORT void nbt_wal_set_visible(nbt_wal_public *,nbt_u32,nbt_u8) __asm__("_ZN3wal15WalHmiInterface10setVisibleEmb");
EXPORT void nbt_wal_set_zorder(nbt_wal_public *,const nbt_wal_order *,nbt_u32) __asm__("_ZN3wal15WalHmiInterface9setZOrderEPKNS0_12OrderTypeDefEm");

typedef struct context {
    nbt_u32 kind,zone;
    void *listener;
    struct context *next;
} context;
typedef struct {
    nbt_u32 used,id,x,y,width,height,native,surface,display,config;
    unsigned short order;
    nbt_u8 alpha,visible,has_geometry;
    context *owner;
    void *listener;
} window_state;
static context *hmi_contexts;
static window_state windows[WAL_MAX_WINDOWS];
static volatile unsigned int operation_lock;

static void lock(void) {
    /* The VM has one CPU. A higher-priority HMI thread must not busy-spin
     * forever while a lower-priority owner is waiting for the renderer. */
    while (__sync_lock_test_and_set(&operation_lock,1)) (void)usleep(1000u);
}
static void unlock(void) { __sync_lock_release(&operation_lock); }
static void failed(void) {
    static const char msg[]="NBT_VM_WAL: operation failed; no success notification\n";
    (void)write(2,msg,sizeof(msg)-1);
}
static window_state *find_window(nbt_u32 id,int create) {
    window_state *empty=0;unsigned int i;
    for(i=0;i<WAL_MAX_WINDOWS;i++) {
        if(windows[i].used && windows[i].id==id)return &windows[i];
        if(!windows[i].used && !empty)empty=&windows[i];
    }
    if(!create || !empty)return 0;
    *empty=(window_state){0};empty->used=1;empty->id=id;
    empty->width=1280;empty->height=480;empty->alpha=255;
    return empty;
}
static unsigned int listeners(void **out,void *extra) {
    unsigned int n=0,i;context *c;
    for(c=hmi_contexts;c && n<WAL_MAX_LISTENERS;c=c->next)
        if(c->listener)out[n++]=c->listener;
    if(extra && n<WAL_MAX_LISTENERS) {
        for(i=0;i<n;i++)if(out[i]==extra)return n;
        out[n++]=extra;
    }
    return n;
}
static void notify_id(void **targets,unsigned int count,unsigned int slot,nbt_u32 id) {
    unsigned int i;
    for(i=0;i<count;i++) {
        void **vtable=*(void ***)targets[i];
        if(vtable && vtable[slot])((void (*)(void *,nbt_u32))vtable[slot])(targets[i],id);
    }
}
static context *new_context(nbt_u32 kind,void *listener) {
    context *c=(context *)malloc(sizeof(*c));
    if(c){c->kind=kind;c->zone=0;c->listener=listener;c->next=0;}
    return c;
}

void nbt_wal_app_construct(nbt_wal_public *object) {
    if(!object)return;
    object->state=new_context(1,0);if(!object->state)failed();
}
void nbt_wal_app_destruct(nbt_wal_public *object) {
    context *c;unsigned int i;
    if(!object || !(c=(context *)object->state))return;
    for(i=0;i<WAL_MAX_WINDOWS;i++) {
        void *targets[WAL_MAX_LISTENERS];unsigned int n=0;nbt_u32 id=0;
        lock();
        if(windows[i].used && windows[i].owner==c) {
            id=windows[i].id;
            if(nbt_bridge_window_destroy(id)==0) {
                n=listeners(targets,windows[i].listener);windows[i]=(window_state){0};
            } else {
                /* Keep the live host-resource record, but never retain the
                 * context/listener that is about to be destroyed. */
                windows[i].owner=0;windows[i].listener=0;failed();
            }
        }
        unlock();if(n)notify_id(targets,n,2,id);
    }
    object->state=0;free(c);
}
nbt_u8 nbt_wal_select_zone(nbt_wal_public *object,nbt_u32 zone) {
    context *c;int result;
    if(!object || !(c=(context *)object->state))return 0;
    lock();result=nbt_bridge_select_zone(zone);if(result==0)c->zone=zone;unlock();
    if(result)failed();return result==0;
}
void nbt_wal_hmi_construct(nbt_wal_public *object,void *listener) {
    context *c;int ready;unsigned int count=0;context *it;
    if(!object)return;
    object->state=0;c=new_context(2,listener);if(!c){failed();return;}
    lock();for(it=hmi_contexts;it;it=it->next)count++;
    if(count>=WAL_MAX_LISTENERS){unlock();free(c);failed();return;}
    c->next=hmi_contexts;hmi_contexts=c;object->state=c;
    ready=nbt_bridge_ready();unlock();
    if(ready==0 && listener) {
        void **vtable=*(void ***)listener;
        if(vtable && vtable[0])((void (*)(void *))vtable[0])(listener);
    } else if(ready)failed();
}
void nbt_wal_hmi_destruct(nbt_wal_public *object) {
    context *c,**p;if(!object || !(c=(context *)object->state))return;
    lock();p=&hmi_contexts;while(*p && *p!=c)p=&(*p)->next;
    if(*p)*p=c->next;object->state=0;unlock();free(c);
}
int nbt_wal_process_event(nbt_wal_public *object) { (void)object;return 0; }

void nbt_wal_create_window(nbt_wal_public *object,nbt_u32 id,void *display,
    void *config,void **native,void **surface,void *listener) {
    context *c;window_state *w;nbt_u32 nt=0,st=0;int rc=-1;
    void *targets[WAL_MAX_LISTENERS];unsigned int n=0;
    if(native)*native=0;if(surface)*surface=0;
    if(!native || !surface || !object || !(c=(context *)object->state) || id==0xffffffffU){failed();return;}
    lock();w=find_window(id,1);
    if(w && !w->native) {
        rc=nbt_bridge_window_create(id,(nbt_u32)display,(nbt_u32)config,w->width,w->height,&nt,&st);
        if(rc==0 && nt && st) {
            w->native=nt;w->surface=st;w->display=(nbt_u32)display;w->config=(nbt_u32)config;
            w->owner=c;w->listener=listener;*native=(void *)nt;*surface=(void *)st;
            n=listeners(targets,listener);
        } else rc=-1;
    }
    unlock();if(rc)failed();else notify_id(targets,n,1,id);
}
void nbt_wal_set_geometry(nbt_wal_public *object,nbt_u32 id,nbt_u32 x,nbt_u32 y,nbt_u32 width,nbt_u32 height) {
    window_state *w;int rc=-1;if(!object || !object->state){failed();return;}
    lock();w=find_window(id,1);
    if(w){rc=nbt_bridge_window_geometry(id,x,y,width,height);if(!rc){w->x=x;w->y=y;w->width=width;w->height=height;w->has_geometry=1;}}
    unlock();if(rc)failed();
}
void nbt_wal_set_alpha(nbt_wal_public *object,nbt_u32 id,nbt_u8 alpha) {
    window_state *w;int rc=-1;if(!object || !object->state){failed();return;}
    lock();w=find_window(id,1);if(w){rc=nbt_bridge_window_alpha(id,alpha);if(!rc)w->alpha=alpha;}
    unlock();if(rc)failed();
}
void nbt_wal_set_visible(nbt_wal_public *object,nbt_u32 id,nbt_u8 visible) {
    window_state *w;int rc=-1;void *targets[WAL_MAX_LISTENERS];unsigned int n=0,i;
    if(!object || !object->state){failed();return;}visible=!!visible;
    lock();w=find_window(id,1);
    if(w){rc=nbt_bridge_window_visible(id,visible);if(!rc){w->visible=visible;n=listeners(targets,w->listener);}}
    unlock();if(rc){failed();return;}
    for(i=0;i<n;i++) {
        void **vt=*(void ***)targets[i];if(!vt)continue;
        /* Synchronous host completion maps to realized. HMI's slot5 can
         * itself forward into slot6, so emitting both duplicates completion. */
        if(vt[6])((void (*)(void *,nbt_u32,nbt_u8))vt[6])(targets[i],id,visible);
    }
}
void nbt_wal_set_zorder(nbt_wal_public *object,const nbt_wal_order *orders,nbt_u32 count) {
    nbt_u32 i;int rc=-1;
    if(!object || !object->state || (!orders && count) || count>WAL_MAX_WINDOWS){failed();return;}
    lock();
    for(i=0;i<count;i++)if(!find_window(orders[i].id,1))break;
    if(i==count){rc=nbt_bridge_window_zorder(orders,count);if(!rc)for(i=0;i<count;i++)find_window(orders[i].id,0)->order=orders[i].order;}
    unlock();if(rc)failed();
}
