/* VM-only entry bridge. The native NVIDIA hardware initialization is replaced
 * by a verified host-renderer connection. This does not initialize a KD event
 * system; the matching HMI imports only NvKdLaunch from KD directly, and its
 * eleven imported Wal operations are replaced by wal_adapter.c.
 *
 * Requires the matching firmware ABI proven by the diagnostic entry probe.
 * Does not imply that the HMI can run without its non-graphics services.
 */
#include "wal_adapter.h"
extern int write(int fd,const void *buffer,unsigned int length);
extern void nbt_controller_arm(void);
typedef int (*nbt_kd_entry)(int argc,char **argv);

__attribute__((visibility("default")))
int NvKdLaunch(nbt_kd_entry entry,int argc,char **argv) {
    static const char ready[]="NBT_VM_GRAPHICS: real host renderer connected; entering native kdMain\n";
    static const char failed[]="NBT_VM_GRAPHICS: entry or renderer unavailable; kdMain not called\n";
    static const char returned[]="NBT_VM_GRAPHICS: native kdMain returned\n";
    int result;
    if(!entry || nbt_bridge_ready()!=0) {
        (void)write(2,failed,sizeof(failed)-1);return -1;
    }
    (void)write(2,ready,sizeof(ready)-1);
    nbt_controller_arm();
    result=entry(argc,argv);
    (void)write(2,returned,sizeof(returned)-1);return result;
}
