/* Explicit VM-only kernel tick setter, loaded only by the WHPX profile. */
struct clockperiod { unsigned int nsec; int fract; };
extern int ClockPeriod(int,const struct clockperiod *,struct clockperiod *,int);
extern int snprintf(char *,unsigned int,const char *,...);
extern int write(int,const void *,unsigned int);
extern void _exit(int);
_Static_assert(sizeof(struct clockperiod)==8,"QNX ILP32 ClockPeriod ABI");
__attribute__((visibility("default")))
void nbt_vm_probe_init(void) {
    struct clockperiod wanted={10000000u,0},old={0,0},actual={0,0};
    int rc=ClockPeriod(0,&wanted,&old,0);char text[160];
    if(!rc)rc=ClockPeriod(0,0,&actual,0);
    if(!rc && (actual.nsec<10000000u || actual.nsec>10000100u || actual.fract))rc=-1;
    int n=snprintf(text,sizeof(text),"NBT_VM_TICK_10MS rc=%d old_nsec=%u actual_nsec=%u\n",rc,old.nsec,actual.nsec);
    if(n>0 && (unsigned)n<sizeof(text))write(1,text,(unsigned)n);
    if(rc)_exit(77);
}
