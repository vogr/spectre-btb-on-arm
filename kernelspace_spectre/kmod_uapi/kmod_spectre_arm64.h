#define REQ_GADGET_DESC 10000
#define REQ_SPEC        20000

struct synth_gadget_desc {
  unsigned long kbr_dst;
  unsigned long kbr_src;
};

#define PROC_SPECTRE_ARM64 "spectre_arm64"