import "hash"
// Salamander CTI  //  https://salacti.com
// macOS.Gaslight | Rust Backdoor Turns Prompt Injection on the Analyst, Not the Sandbox

rule Salamander_DPRK_aligned
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "DPRK-aligned"
    malware = "macOS.Gaslight, BONZAI, AIRPIPE"
  condition:
    hash.sha1(0, filesize) == "5555494492fc075f441637fb9d894913dde3a2ea" or
    hash.sha256(0, filesize) == "6328567511d88fdc2ae0939c5ef17b7a63d2a833881900de018a4f12f4982525" or
    hash.sha256(0, filesize) == "77b4fd46994992f0e57302cfe76ed23c0d90101381d2b89fc2ddf5c4536e77ca" or
    hash.sha256(0, filesize) == "b3c56d689414343589f38394d19ba2fe9a518133281200faa0556ba4e4136394" or
    hash.sha256(0, filesize) == "baabf249c77bc54c54ab0e66e15af798bd28aa5b4683554456a8b73ab8741239"
}
