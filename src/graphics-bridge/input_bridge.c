/* Guarded native controller delivery on the original HMI application thread. */
#include "guest_transport.h"
#include "../hmi/service-audit/input_hooks.c"
extern char *getenv(const char *);
extern int gettid(void);

static const char *verified_image;
static int configured;
static int last_status=-1000;
static int language_checked;
static nbt_u32 observed_manager;
static nbt_u32 text_observations;
static int language_refresh_pending;
static int controller_polling;
static nbt_u32 last_wait_pc;
static nbt_u32 wait_reports;
static volatile nbt_u32 input_generation;
nbt_u32 nbt_controller_input_generation(void) { return input_generation; }

__attribute__((weak,noinline))
int nbt_idle_last_wait(nbt_u32 *pc,nbt_u32 *condition,nbt_u32 *mutex) {
    (void)pc;(void)condition;(void)mutex;return 0;
}

static void describe_last_wait(void) {
    nbt_u32 body[4]={(nbt_u32)gettid(),0,0,0};
    struct nbt_rpc_reply reply;
    if(nbt_idle_last_wait(body+1,body+2,body+3) && body[1]!=last_wait_pc && wait_reports<8u) {
        last_wait_pc=body[1];++wait_reports;
        if(nbt_rpc_call(49,body,sizeof(body),&reply)==0)nbt_rpc_reply_free(&reply);
    }
}

static void refresh_language_presentation(void) {
    typedef struct {nbt_u32 words[5];} state_snapshot;
    typedef state_snapshot (__attribute__((cdecl)) *get_state_fn)(void *);
    typedef nbt_u8 (__attribute__((cdecl)) *refresh_state_fn)(void *,nbt_u32);
    typedef void *(__attribute__((cdecl)) *lookup_state_fn)(void *,nbt_u32);
    nbt_u32 context=0,manager,state=0,body[5];
    nbt_u8 result;
    state_snapshot snapshot;
    struct nbt_rpc_reply reply;
    if(!language_refresh_pending || nbt_input_has_app_proc_unit(&context,0)!=NBT_INPUT_READY)return;
    if(!context || nbt_read_word(context)!=0x096217a0u)return;
    manager=nbt_read_word(context+0x2cu);
    if(!manager || nbt_read_word(manager)!=0x09619228u
            || nbt_read_word(0x09619228u+0x54u)!=0x08985332u
            || nbt_read_word(0x09619228u+0x60u)!=0x0898982eu
            || !*(volatile const nbt_u8 *)(manager+0x2eu))return;
    {
        get_state_fn volatile get_state=(get_state_fn)0x08985332u;
        refresh_state_fn volatile refresh=(refresh_state_fn)0x0898982eu;
        snapshot=get_state((void *)manager);
        state=snapshot.words[0];
        language_refresh_pending=0;
        /* Same snapshot-and-state-refresh sequence as the factory manual
         * language handler, including GCC's 20-byte hidden-sret ABI. */
        result=refresh((void *)manager,state);
    }
    body[0]=(nbt_u32)gettid();body[1]=manager;body[2]=state;body[3]=1;body[4]=result;
    if(nbt_rpc_call(48,body,sizeof(body),&reply)==0)nbt_rpc_reply_free(&reply);
    if(nbt_read_word(0x09619228u+0xe0u)==0x08984244u) {
        lookup_state_fn volatile lookup=(lookup_state_fn)0x08984244u;
        nbt_u32 handler=(nbt_u32)lookup((void *)manager,state),vtable=0,typeinfo=0;
        nbt_u32 state_body[6]={(nbt_u32)gettid(),manager,state,handler,0,0};
        if(handler && !(handler&3u)) {
            vtable=nbt_read_word(handler);
            if(vtable>=0x09400000u && vtable<0x09800000u)typeinfo=nbt_read_word(vtable-4u);
        }
        state_body[4]=vtable;state_body[5]=typeinfo;
        if(nbt_rpc_call(50,state_body,sizeof(state_body),&reply)==0)nbt_rpc_reply_free(&reply);
        if(vtable==0x0946da80u) {
            char *rebuild_requested=getenv("NBT_VM_REFRESH_MENU");
            nbt_u32 list=nbt_read_word(handler+0xa0u),model=0;
            if(list && nbt_read_word(list)==0x0964a864u)
                model=nbt_read_word(list+0x2cu); /* Native getter 08a525e4. */
            if(rebuild_requested && rebuild_requested[0]=='1' && !rebuild_requested[1]
                    && model && nbt_read_word(model)==0x0964354cu) {
                static const nbt_u8 prefix[]={0x55,0x89,0xe5,0x57,0x56,0x53,0x81,0xec,0xcc,0,0,0};
                if(nbt_bytes_match(0x081acadeu,prefix,sizeof(prefix))) {
                    typedef void (__attribute__((cdecl)) *rebuild_fn)(void *);
                    rebuild_fn volatile rebuild=(rebuild_fn)0x081acadeu;
                    nbt_u32 rebuilt[5]={handler,list,model,nbt_read_word(model+0x4cu),0};
                    /* Original factory list rebuild, also called by native
                     * item-registration and menu update paths. App thread
                     * only; no replacement text or model-field writes. */
                    rebuild((void *)handler);
                    rebuilt[4]=nbt_read_word(model+0x4cu);
                    if(nbt_rpc_call(53,rebuilt,sizeof(rebuilt),&reply)==0)nbt_rpc_reply_free(&reply);
                }
            }
            {
                char *activate_requested=getenv("NBT_VM_ACTIVATE_MENU");
                static const nbt_u8 activate_prefix[]={0x55,0x89,0xe5,0x53,0x83,0xec,0x1c,0x8b,0x5d,0x08};
                if(activate_requested && activate_requested[0]=='1' && !activate_requested[1]
                        && state==0x35au && nbt_read_word(0x09619228u+0x34u)==0x08984888u
                        && nbt_bytes_match(0x08984888u,activate_prefix,sizeof(activate_prefix))
                        && !*(volatile const nbt_u8 *)(manager+0x2cu)
                        && !*(volatile const nbt_u8 *)(manager+0x2du)) {
                    typedef nbt_u8 (__attribute__((cdecl)) *activate_fn)(void *,nbt_u32);
                    activate_fn volatile activate=(activate_fn)0x08984888u;
                    nbt_u32 activated[4]={(nbt_u32)gettid(),manager,state,0};
                    /* Same native root-activation wrapper used by the
                     * factory Menu hard-key branch (081a4e7d..081a52e7). */
                    activated[3]=activate((void *)manager,state);
                    if(nbt_rpc_call(54,activated,sizeof(activated),&reply)==0)nbt_rpc_reply_free(&reply);
                }
            }
            {
                char *home_input_requested=getenv("NBT_VM_HOME_INPUT");
                nbt_u32 home=handler-0x6cu;
                static const nbt_u8 listen_prefix[]={0x55,0x89,0xe5,0x57,0x56,0x53,0x83,0xec,0x1c,
                    0x8b,0x5d,0x08,0x8a,0x55,0x0c,0x38,0x93,0x58,0x05,0,0};
                if(home_input_requested && home_input_requested[0]=='1' && !home_input_requested[1]
                        && nbt_read_word(home)==0x0946d2b0u
                        && nbt_read_word(home+0x10u)==context
                        && *(volatile const nbt_u8 *)(home+0x558u)<=1u
                        && nbt_bytes_match(0x081a44deu,listen_prefix,sizeof(listen_prefix))) {
                    typedef void (__attribute__((cdecl)) *listen_fn)(void *,nbt_u32);
                    listen_fn volatile listen=(listen_fn)0x081a44deu;
                    nbt_u32 listened[4]={(nbt_u32)gettid(),home,
                        *(volatile const nbt_u8 *)(home+0x558u),0};
                    /* Home embeds this exact main-menu activity at +6c
                     * (081a45db). Original routine registers its original
                     * controllerEvent callback, then sets its own flag. */
                    listen((void *)home,1u);
                    listened[3]=*(volatile const nbt_u8 *)(home+0x558u);
                    if(nbt_rpc_call(55,listened,sizeof(listened),&reply)==0)nbt_rpc_reply_free(&reply);
                }
            }
            /* Original CHmiActivityMainMenu init 081ac296 stores the
             * root view at +9c and list widget at +a0. Snapshot only;
             * do not invoke unverified widget/model virtual methods. */
            nbt_u32 words[28],index;
            words[0]=handler;
            for(index=0;index<21u;++index)
                words[index+1u]=nbt_read_word(handler+0x8cu+index*4u);
            for(index=0;index<2u;++index) {
                nbt_u32 widget=nbt_read_word(handler+0x9cu+index*4u),vt=0;
                if(widget && !(widget&3u))vt=nbt_read_word(widget);
                words[22u+index*3u]=widget;
                words[23u+index*3u]=vt;
                words[24u+index*3u]=(vt>=0x09400000u && vt<0x09800000u)
                    ? nbt_read_word(vt-4u):0;
            }
            if(nbt_rpc_call(52,words,sizeof(words),&reply)==0)nbt_rpc_reply_free(&reply);
        }
        if(vtable==0x0946e3d0u) {
            nbt_u32 widgets[9]={handler,nbt_read_word(handler+0x90u),0,
                nbt_read_word(handler+0x94u),0,nbt_read_word(handler+0x98u),0,
                nbt_read_word(handler+0x9cu),nbt_read_word(handler+0xa0u)};
            nbt_u32 index;
            for(index=1;index<=5;index+=2)
                if(widgets[index] && !(widgets[index]&3u))widgets[index+1]=nbt_read_word(widgets[index]);
            if(nbt_rpc_call(51,widgets,sizeof(widgets),&reply)==0)nbt_rpc_reply_free(&reply);
        }
    }
}

static void describe_database_providers(nbt_u32 manager) {
    nbt_u32 head=nbt_read_word(manager+0x28u),node,count=0;
    struct nbt_rpc_reply reply;
    if(!head || (head&3u))return;
    node=nbt_read_word(head);
    while(node && node!=head && !(node&3u) && count++<32u) {
        nbt_u32 provider=nbt_read_word(node+8u);
        if(provider && !(provider&3u) && nbt_read_word(provider)==0x096a46e0u) {
            nbt_u32 body[7]={provider,nbt_read_word(provider),nbt_read_word(provider+0x2cu),
                nbt_read_word(provider+0x8cu),nbt_read_word(provider+0xb4u),
                nbt_read_word(provider+0x4b8u),node};
            if(nbt_rpc_call(46,body,sizeof(body),&reply)==0)nbt_rpc_reply_free(&reply);
        }
        node=nbt_read_word(node);
    }
}

static void describe_string_cache(nbt_u32 manager,nbt_u32 phase) {
    nbt_u32 cache=nbt_read_word(manager+0x60u),body[9]={manager,cache,0,0,0,0,
        nbt_read_word(0x09908908u),nbt_read_word(0x09908914u),phase};
    struct nbt_rpc_reply reply;
    if(cache && !(cache&3u)) {
        body[2]=nbt_read_word(cache);
        if(body[2]==0x096a5868u) {
            body[3]=nbt_read_word(cache+0x0cu);
            body[4]=nbt_read_word(cache+0x24u);
            body[5]=nbt_read_word(cache+0x28u);
        }
    }
    if(nbt_rpc_call(47,body,sizeof(body),&reply)==0)nbt_rpc_reply_free(&reply);
}
static int idle_arm_status=-1000;
static int idle_callback_reported;

/* Base bridge/smoke keep their existing swap-only behavior. The separately
 * linked controller DSO overrides this with the verified scoped wait hook.
 * Weak + noinline keeps this an overridable call in the final ELF. */
__attribute__((weak,noinline)) int nbt_idle_arm_after_swap(nbt_u32 success) {
    (void)success;
    return 1; /* Scoped idle hook was not linked into this DSO. */
}

static void initialize_vm_language(void) {
    nbt_u32 context=0,manager=0,body[5];
    nbt_u32 previous=0xffffffffu,current=0xffffffffu;
    int result=-1;
    char *requested;
    struct nbt_rpc_reply reply;
    if(language_checked) {
        ++text_observations;
        if(observed_manager && (text_observations==16u || text_observations==100u))
            describe_string_cache(observed_manager,text_observations==16u?1u:2u);
        return;
    }
    if(nbt_input_has_app_proc_unit(&context,0)!=NBT_INPUT_READY)return;
    if(context && nbt_read_word(context)==0x096217a0u) {
        manager=nbt_read_word(context+4u);
        if(manager && nbt_read_word(manager)==0x096a5170u) {
            previous=*(volatile const nbt_u8 *)(manager+0x20u);
            current=previous;result=0;
            requested=getenv("NBT_VM_LANGUAGE_ID");
            if(previous==0xffu && requested && requested[0]=='2' && !requested[1]
                    && nbt_read_word(0x096a5170u+8u)==0x08d10d66u) {
                typedef void (__attribute__((cdecl)) *set_language_fn)(void *,nbt_u32);
                set_language_fn volatile set_language=(set_language_fn)0x08d10d66u;
                /* Exact native English-UK ID, used only when no language was
                 * initialized. The original setter notifies its providers and
                 * listeners; no resource bytes or UI strings are replaced. */
                set_language((void *)manager,2u);
                current=*(volatile const nbt_u8 *)(manager+0x20u);
                result=1;
                language_refresh_pending=1;
            }
        }
    }
    body[0]=(nbt_u32)gettid();body[1]=manager;body[2]=previous;body[3]=current;body[4]=(nbt_u32)result;
    if(nbt_rpc_call(43,body,sizeof(body),&reply)==0)nbt_rpc_reply_free(&reply);
    if(manager && nbt_read_word(manager)==0x096a5170u) {
        describe_database_providers(manager);
        describe_string_cache(manager,0u);
        observed_manager=manager;
    }
    if(result==1) {
        nbt_u32 integrator=nbt_read_word(0x099a17ccu),owner=0;
        nbt_u32 old_engine=0xffffffffu,new_engine=0xffffffffu;
        int engine_status=-1;
        if(integrator && nbt_read_word(integrator)==0x0960bd00u
                && nbt_read_word(integrator+0x1cu)==context) {
            owner=nbt_read_word(integrator+0x198u);
            if(owner && nbt_read_word(owner)==0x0944a7f8u
                    && nbt_read_word(owner+0x28cu)==context
                    && nbt_read_word(0x0960bd00u+0x54u)==0x0891df02u) {
                old_engine=*(volatile const nbt_u8 *)(integrator+0x20u);
                new_engine=old_engine;engine_status=0;
                if(old_engine!=2u) {
                    typedef void (__attribute__((cdecl)) *engine_language_fn)(void *,nbt_u32);
                    engine_language_fn volatile set_engine=(engine_language_fn)0x0891df02u;
                    set_engine((void *)integrator,2u);
                    new_engine=*(volatile const nbt_u8 *)(integrator+0x20u);
                    engine_status=1;
                }
            }
        }
        body[1]=integrator;body[2]=old_engine;body[3]=new_engine;body[4]=(nbt_u32)engine_status;
        if(nbt_rpc_call(44,body,sizeof(body),&reply)==0)nbt_rpc_reply_free(&reply);
    }
    language_checked=1;
}

void nbt_controller_arm(void) {
    /* The runner independently hashes HmiMain3D inside its validated ImageFS. */
    verified_image=getenv("NBT_VM_INPUT_HMI_SHA256");
}

static void report(int status,nbt_u32 key) {
    nbt_u32 body[3]={(nbt_u32)gettid(),(nbt_u32)status,key};
    struct nbt_rpc_reply reply;
    if(nbt_rpc_call(42,body,sizeof(body),&reply)==0)nbt_rpc_reply_free(&reply);
}

static void report_idle(int status,nbt_u32 phase) {
    nbt_u32 body[3]={(nbt_u32)gettid(),(nbt_u32)status,phase};
    struct nbt_rpc_reply reply;
    if(nbt_rpc_call(45,body,sizeof(body),&reply)==0)nbt_rpc_reply_free(&reply);
}

static int controller_ready(void) {
    int status;
    if(!verified_image || !configured)return NBT_INPUT_DISABLED;
    status=nbt_input_on_app_thread(0);
    if(status!=last_status){report(status,0);last_status=status;}
    return status;
}

static void controller_poll(void) {
    struct nbt_rpc_reply reply;
    nbt_u32 *words,count,i;
    int status;
    if(controller_polling || controller_ready()!=NBT_INPUT_READY)return;
    controller_polling=1;
    initialize_vm_language();
    refresh_language_presentation();
    if(nbt_rpc_call(41,0,0,&reply)!=0){controller_polling=0;return;}
    if(reply.status || reply.length<4){nbt_rpc_reply_free(&reply);controller_polling=0;return;}
    words=reply.payload;count=words[0];
    if(count>4 || reply.length!=4+count*16){nbt_rpc_reply_free(&reply);controller_polling=0;return;}
    for(i=0;i<count;i++) {
        struct nbt_input_event event={words[1+i*4],words[2+i*4],(nbt_i32)words[3+i*4],words[4+i*4]};
        status=nbt_input_on_app_thread(&event);
        if(status==NBT_INPUT_SUBMITTED)++input_generation;
        report(status,event.key);
    }
    nbt_rpc_reply_free(&reply);
    controller_polling=0;
}

/* Called only by the separately scoped wait interposer on the verified app
 * thread, while its native event-queue mutex is temporarily unlocked. */
void nbt_controller_poll_idle(void) {
    int status=controller_ready();
    if(!idle_callback_reported) {
        report_idle(status,1u);
        idle_callback_reported=1;
    }
    if(status==NBT_INPUT_READY)controller_poll();
}

void nbt_controller_after_swap(nbt_u32 success) {
    int status;
    if(!verified_image || success!=1)return;
    if(!configured) {
        status=nbt_input_configure_verified_image(verified_image,(nbt_u32)gettid());
        if(status<0){verified_image=0;return;}
        configured=1;
    }
    if(controller_ready()!=NBT_INPUT_READY)return;
    describe_last_wait();
    status=nbt_idle_arm_after_swap(success);
    if(status!=idle_arm_status) {
        if(status!=1)report_idle(status,0u);
        idle_arm_status=status;
    }
    controller_poll();
}
