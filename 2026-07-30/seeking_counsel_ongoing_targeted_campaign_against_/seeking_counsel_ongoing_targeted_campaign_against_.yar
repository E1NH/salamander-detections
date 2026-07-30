import "hash"
// Salamander CTI  //  https://salacti.com
// Seeking Counsel: Ongoing Targeted Campaign Against US Law Firms

rule Salamander_UNC3753
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "UNC3753"
    malware = "LOCKBIT.BLACK, BAZARLOADER, TrickBot - S0266, Totbrick, TSPY_TRICKLOAD, Ursnif - S0386, Gozi-ISFB, PE_URSNIF, Dreambot, SILENTNIGHT"
  condition:
    false  // no file hashes in this brief
}
