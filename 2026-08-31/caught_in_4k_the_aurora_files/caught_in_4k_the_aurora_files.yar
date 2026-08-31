import "hash"
// Salamander CTI  //  https://salacti.com
// Caught in 4K: The Aurora Files

rule Salamander_Aurora
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Aurora"
    malware = "Hydraq - S0203, Roarur, MdmBot, HomeUnix, Homux, HidraQ, HydraQ, McRat, Aurora, 9002 RAT"
  condition:
    hash.sha256(0, filesize) == "a4af136d159a8eb96b54924fa80355ca52874913301300f55af7d67ae97edcfe" or
    hash.sha256(0, filesize) == "eb0aab1e892d7e09e2c7bcf1d21fd83c1743ed9196b3efac6c78482fb0d99207"
}
