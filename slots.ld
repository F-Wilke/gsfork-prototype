/* Stable entry addresses, each function has room for instruction growth.
   No entry trampolines and no ELF program-header surgery in this prototype. */
SECTIONS {
 .gsfork_sum ALIGN(4096) : { *(.gsfork.sum) . = ALIGN(4096); }
 .gsfork_update ALIGN(4096) : { *(.gsfork.update) . = ALIGN(4096); }
 .gsfork_avx2 ALIGN(4096) : { *(.gsfork.avx2) . = ALIGN(4096); }
 .gsfork_chase ALIGN(4096) : { *(.gsfork.chase) . = ALIGN(4096); }
} INSERT BEFORE .text;
