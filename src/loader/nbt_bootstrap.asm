; Experimental VM-only BIOS-to-QNX bootstrap. This is not an NBT IPL.
; Inputs are supplied by build_bootstrap.py after validating the original IFS.
; NASM -f bin. QEMU must preload the unchanged IFS at IFS_SOURCE.
BITS 16
ORG 0x7c00

%macro MARK 1
    mov al, %1
    out 0xe9, al
    mov dx, 0x3f8
    out dx, al
%endmacro

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7c00
    cld
    ; COM1 115200 8N1; serial is only a VM log, never host hardware passthrough.
    mov dx, 0x3f9
    out dx, al
    mov dx, 0x3fb
    mov al, 0x80
    out dx, al
    mov dx, 0x3f8
    mov al, 1
    out dx, al
    mov dx, 0x3f9
    xor al, al
    out dx, al
    mov dx, 0x3fb
    mov al, 3
    out dx, al
    MARK 'R'
    ; Supply genuine BIOS E820 records through the standard Multiboot v1 ABI.
    ; startup-ids02 recognizes saved EAX=0x2badb002 and saved EBX=info pointer.
    xor ax, ax
    mov di, 0x6000
    mov cx, 64
    rep stosw
    xor ebx, ebx
    mov di, 0x5004
.map_next:
    cmp di, 0x5f00
    jae .map_done
    mov dword [di-4], 20
    mov eax, 0xe820
    mov edx, 0x534d4150
    mov ecx, 20
    int 0x15
    jc .map_done
    cmp eax, 0x534d4150
    jne .map_done
    cmp ecx, 20
    jb .map_done
    add di, 24
    test ebx, ebx
    jnz .map_next
.map_done:
    movzx eax, di
    sub eax, 0x5004
    test eax, eax
    jz real_error
    mov dword [0x6000], 0x40
    mov [0x602c], eax
    mov dword [0x6030], 0x5000
    MARK 'M'
    ; Enable A20 through the standard PC fast-A20 port, preserving other bits.
    in al, 0x92
    and al, 0xfe
    or al, 2
    out 0x92, al
    lgdt [gdt_descriptor]
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    jmp 0x08:protected
real_error:
    MARK 'E'
.halt:
    cli
    hlt
    jmp .halt

BITS 32
protected:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax
    mov esp, 0x90000
    MARK 'P'
    mov al, 0xff
    out 0x21, al
    out 0xa1, al
    cmp dword [IFS_SOURCE], 0x00ff7eeb
    jne error
    mov esi, IFS_SOURCE
    mov edi, IFS_DEST
    mov ecx, COPY_SIZE
    rep movsb
    ; image_paddr is the destination image base; imagefs_paddr supplies the
    ; existing filesystem bytes (compressed input when compression is set).
    ; startup computes decompression destination = image_paddr + startup_size.
    ; Patch only the disposable RAM copy, not the original IFS file.
    mov dword [IFS_DEST + 20], IFS_DEST
    mov dword [IFS_DEST + 40], RUNTIME_IMAGE_SOURCE + STARTUP_SIZE
    ; This board's memory routine reads QNX STARTUP_INFO_MEM before any
    ; generic Multiboot fallback. Translate one actual E820 usable high-RAM
    ; range into the standard 12-byte startup_info_mem record in RAM only.
    mov esi, 0x5000
    mov ecx, [0x602c]
.ram_next:
    cmp ecx, 24
    jb error
    cmp dword [esi+20], 1
    jne .ram_skip
    cmp dword [esi+8], 0
    jne .ram_skip
    cmp dword [esi+16], 0
    jne .ram_skip
    cmp dword [esi+4], 0x100000
    jne .ram_skip
    cmp dword [esi+12], 0x1000000
    jb .ram_skip
    mov dword [IFS_DEST+64], 0x000c0001
    mov eax, [esi+4]
    mov [IFS_DEST+68], eax
    mov eax, [esi+12]
    mov [IFS_DEST+72], eax
    jmp .ram_ready
.ram_skip:
    add esi, 24
    sub ecx, 24
    jmp .ram_next
.ram_ready:
%ifdef SINGLE_CPU_PATCH
    ; Explicit VM profile: change only the existing startup argument -P2 to
    ; documented -P1 in the temporary RAM copy, avoiding board SMP handshake.
    cmp byte [IFS_DEST+SINGLE_CPU_PATCH], '2'
    jne error
    mov byte [IFS_DEST+SINGLE_CPU_PATCH], '1'
%endif
%ifdef QEMU_CLOCKS
    ; Only for QEMU TCG icount: elapsed TSC and APIC bus ticks are nanoseconds.
    ; Board chipset discovery cannot infer these clocks from a PC host bridge.
    mov eax, QEMU_TSC_HZ
    mov [0x219c10], eax ; CPU/TSC frequency
    mov [0x219bcc], eax ; cycles frequency
%if QEMU_TSC_HZ = 1000000000
    mov [0x219b70], eax ; bus frequency used by local APIC timer initialization
%else
    mov dword [0x219b70], 1000000000 ; emulated userspace APIC counts nanoseconds
%endif
%endif
%ifndef QEMU_TSC_HZ
%define QEMU_TSC_HZ 1000000000
%endif
%if QEMU_TSC_HZ = 1000000000
    MARK 'C'
    MARK 'J'
%endif
    ; Standard Multiboot v1 handoff, with BIOS-derived memory map only.
    ; A successful transfer here does not mean startup or the kernel can run.
    mov eax, 0x2badb002
    mov ebx, 0x6000
%ifdef ROOTFS_RESERVE_PATCH
    ; New VM-only profile reserves physical 1..2 GiB for a secondary IFS.
    ; Source argument and its byte offset were verified by the builder.
    ; Multiboot defines only EAX/EBX; other general registers are unspecified.
    mov word [IFS_DEST+ROOTFS_RESERVE_PATCH], 0x4731 ; "1G" replaces "0M"
%else
    xor ecx, ecx
    xor edx, edx
    xor esi, esi
    xor edi, edi
    xor ebp, ebp
%endif
    jmp IFS_ENTRY
error:
    MARK 'E'
halt:
    cli
    hlt
    jmp halt

align 8
gdt:
    dq 0
    dq 0x00cf9a000000ffff
    dq 0x00cf92000000ffff
gdt_end:
gdt_descriptor:
    dw gdt_end - gdt - 1
    dd gdt

times 510-($-$$) db 0
dw 0xaa55
