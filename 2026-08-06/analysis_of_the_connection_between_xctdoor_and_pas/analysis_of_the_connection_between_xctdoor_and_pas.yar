import "hash"
// Salamander CTI  //  https://salacti.com
// Analysis of the Connection Between Xctdoor and Past CRAT Attack Cases

rule Salamander_Larva_26005
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Larva-26005"
    malware = "Xctdoor, Hydraq - S0203, Roarur, MdmBot, HomeUnix, Homux, HidraQ, HydraQ, McRat, Aurora, 9002 RAT, XcLoader, Hansom, Ngrok - S9000, ThreatNeedle - S0665"
  condition:
    hash.md5(0, filesize) == "0d2e61c8a5e6280e065b61e75b848c68" or
    hash.md5(0, filesize) == "12391f66ee33d379108fd649a999e1a0" or
    hash.md5(0, filesize) == "01b58f2ff2c14feed46a0768ea46686d" or
    hash.md5(0, filesize) == "07766e6e9d9f86775ad564a65af292c1" or
    hash.md5(0, filesize) == "08e19a0d516d14e564359ee111ed2586"
}
