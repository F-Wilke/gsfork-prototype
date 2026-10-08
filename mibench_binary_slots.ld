/* Reserve growth room for unchanged MiBench functions rewritten after link. */
SECTIONS {
 .gsfork_mibench_crc ALIGN(4096) : {
  *(.text.crc32buf)
  . = ALIGN(4096);
 }
 .gsfork_mibench_fft ALIGN(4096) : {
  *(.text.fft_float)
  . = ALIGN(4096);
 }
 .gsfork_mibench_adpcm ALIGN(4096) : {
  *(.text.adpcm_coder)
  . = ALIGN(4096);
 }
} INSERT BEFORE .text;
