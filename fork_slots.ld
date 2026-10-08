/* Dedicated growth slots for the fork-policy runtime probes. */
SECTIONS {
 .gsfork_fork_memory ALIGN(4096) : {
  *(.gsfork.fork_memory)
  . = ALIGN(4096);
 }
 .gsfork_fork_call ALIGN(4096) : {
  *(.gsfork.fork_call)
  . = ALIGN(4096);
 }
 .gsfork_fork_jump ALIGN(4096) : {
  *(.gsfork.fork_jump)
  . = ALIGN(4096);
 }
 .gsfork_fork_rip ALIGN(4096) : {
  *(.gsfork.fork_rip)
  . = ALIGN(4096);
 }
} INSERT BEFORE .text;
