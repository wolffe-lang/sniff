/* R-sn02-3 on macOS: the Mach-O core layouts sniff reads come from this compiled probe, not from header text.
 * Built with the SDK's clang for arm64 (tools/check-abi.py capture --platform macos); its output is
 * tests/evidence/macos-s3/abi.txt, which tools/check-abi.py check holds src/readers/macho_core.lu's constants to.
 * One fact a line: "machcore NAME VALUE". */
#include <mach-o/loader.h>
#include <mach/machine.h>
#include <mach/thread_status.h>
#include <stddef.h>
#include <stdio.h>

#define P(name, value) printf("machcore %s %llu\n", name, (unsigned long long)(value))

int main(void) {
    P("mh_magic_64", MH_MAGIC_64);
    P("mh_core", MH_CORE);
    P("cpu_type_arm64", CPU_TYPE_ARM64);
    P("header_size", sizeof(struct mach_header_64));
    P("header_cputype", offsetof(struct mach_header_64, cputype));
    P("header_cpusubtype", offsetof(struct mach_header_64, cpusubtype));
    P("header_filetype", offsetof(struct mach_header_64, filetype));
    P("header_ncmds", offsetof(struct mach_header_64, ncmds));
    P("header_sizeofcmds", offsetof(struct mach_header_64, sizeofcmds));
    P("lc_segment_64", LC_SEGMENT_64);
    P("lc_thread", LC_THREAD);
    P("lc_note", LC_NOTE);
    P("segment_size", sizeof(struct segment_command_64));
    P("segment_vmaddr", offsetof(struct segment_command_64, vmaddr));
    P("segment_vmsize", offsetof(struct segment_command_64, vmsize));
    P("segment_fileoff", offsetof(struct segment_command_64, fileoff));
    P("segment_filesize", offsetof(struct segment_command_64, filesize));
    P("segment_initprot", offsetof(struct segment_command_64, initprot));
    P("note_size", sizeof(struct note_command));
    P("note_owner", offsetof(struct note_command, data_owner));
    P("note_owner_size", sizeof(((struct note_command *)0)->data_owner));
    P("note_offset", offsetof(struct note_command, offset));
    P("note_payload_size", offsetof(struct note_command, size));
    P("thread_state64", ARM_THREAD_STATE64);
    P("thread_state64_count", ARM_THREAD_STATE64_COUNT);
    P("exception_state64", ARM_EXCEPTION_STATE64);
    P("exception_state64_count", ARM_EXCEPTION_STATE64_COUNT);
    P("state_fp", offsetof(arm_thread_state64_t, __fp));
    P("state_lr", offsetof(arm_thread_state64_t, __lr));
    P("state_sp", offsetof(arm_thread_state64_t, __sp));
    P("state_pc", offsetof(arm_thread_state64_t, __pc));
    P("state_cpsr", offsetof(arm_thread_state64_t, __cpsr));
    P("exception_far", offsetof(arm_exception_state64_t, __far));
    P("exception_esr", offsetof(arm_exception_state64_t, __esr));
    P("exception_exception", offsetof(arm_exception_state64_t, __exception));
    return 0;
}
