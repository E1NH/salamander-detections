import "hash"
// Salamander CTI  //  https://salacti.com
// DeadLock ransomware: Breaking down a Rust-based encryptor with decentralized recovery infrastructure

rule Salamander_DeadLock
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "DeadLock"
    malware = "DeadLock, Lynx, Brave Prince - S0252"
  condition:
    hash.sha256(0, filesize) == "a1fdf65020ce4a0f0940c793c6425baf8a0b994ec48b9baaf72788661a9d29f4"
}
