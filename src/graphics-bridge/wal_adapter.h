#ifndef NBT_VM_WAL_ADAPTER_H
#define NBT_VM_WAL_ADAPTER_H

/* Experimental VM bridge ABI, derived from matching x86 HMI disassembly.
 * A real host renderer must implement every hook below. There are no default
 * success stubs. Public Wal objects are one pointer (4 bytes on this target).
 */
#if !defined(__i386__)
#error This guest adapter requires the verified QNX i386 ABI.
#endif
typedef unsigned int nbt_u32;
typedef unsigned char nbt_u8;
typedef struct { nbt_u32 id; unsigned short order; unsigned short padding; } nbt_wal_order;
typedef struct { void *state; } nbt_wal_public;
_Static_assert(sizeof(nbt_wal_order)==8 && sizeof(nbt_wal_public)==4,
    "Wal ABI layout differs from the matching firmware");

/* Return zero only after the real host operation succeeds. Native/EGL tokens
 * are guest-visible 32-bit IDs, never truncated host pointers. create must
 * return nonzero tokens representing a real render surface/window resource.
 * Geometry/alpha/visibility/order may precede surface creation for logical
 * layer IDs; keep that metadata and apply it when a surface is attached.
 * Hooks run under the adapter operation lock; they must not reenter Wal.
 * Listener creation/destruction and dispatch are expected on the HMI thread.
 */
int nbt_bridge_ready(void);
int nbt_bridge_select_zone(nbt_u32 zone);
int nbt_bridge_window_create(nbt_u32 id, nbt_u32 display, nbt_u32 config,
    nbt_u32 width, nbt_u32 height, nbt_u32 *native, nbt_u32 *surface);
int nbt_bridge_window_destroy(nbt_u32 id);
int nbt_bridge_window_geometry(nbt_u32 id, nbt_u32 x, nbt_u32 y,
    nbt_u32 width, nbt_u32 height);
int nbt_bridge_window_alpha(nbt_u32 id, nbt_u8 alpha);
int nbt_bridge_window_visible(nbt_u32 id, nbt_u8 visible);
int nbt_bridge_window_zorder(const nbt_wal_order *orders, nbt_u32 count);

/* Guest ABI entry points. C callers use the same exact native symbol names. */
void nbt_wal_app_construct(nbt_wal_public *object) __asm__("_ZN3wal23WalApplicationInterfaceC1Ev");
void nbt_wal_app_destruct(nbt_wal_public *object) __asm__("_ZN3wal23WalApplicationInterfaceD1Ev");
nbt_u8 nbt_wal_select_zone(nbt_wal_public *object, nbt_u32 zone) __asm__("_ZN3wal23WalApplicationInterface10selectZoneEm");
void nbt_wal_create_window(nbt_wal_public *object, nbt_u32 id,
    void *display, void *config, void **native, void **surface, void *listener) __asm__("_ZN3wal23WalApplicationInterface12createWindowEmPvS1_PP8KDWindowPS1_PNS_11WalListenerE");
void nbt_wal_hmi_construct(nbt_wal_public *object, void *listener) __asm__("_ZN3wal15WalHmiInterfaceC1ERNS_11WalListenerE");
void nbt_wal_hmi_destruct(nbt_wal_public *object) __asm__("_ZN3wal15WalHmiInterfaceD1Ev");
int nbt_wal_process_event(nbt_wal_public *object) __asm__("_ZN3wal15WalHmiInterface12processEventEv");
void nbt_wal_set_geometry(nbt_wal_public *object, nbt_u32 id,
    nbt_u32 x, nbt_u32 y, nbt_u32 width, nbt_u32 height) __asm__("_ZN3wal15WalHmiInterface24setWindowPositionAndSizeEmmmmm");
void nbt_wal_set_alpha(nbt_wal_public *object, nbt_u32 id, nbt_u8 alpha) __asm__("_ZN3wal15WalHmiInterface8setAlphaEmh");
void nbt_wal_set_visible(nbt_wal_public *object, nbt_u32 id, nbt_u8 visible) __asm__("_ZN3wal15WalHmiInterface10setVisibleEmb");
void nbt_wal_set_zorder(nbt_wal_public *object, const nbt_wal_order *orders, nbt_u32 count) __asm__("_ZN3wal15WalHmiInterface9setZOrderEPKNS0_12OrderTypeDefEm");
#endif
