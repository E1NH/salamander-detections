import "hash"
// Salamander CTI  //  https://salacti.com
// Malicious Twitch Browser Extension Exposes 30,000 Users' OAuth Tokens to Russian Bot Service

rule Salamander_JeetBot
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "JeetBot"
    malware = "Unknown malware"
  condition:
    hash.sha256(0, filesize) == "141c35607dc0e8e400deb380126b3052bd0495b4d37c8dd979c6aa0204b142fc" or
    hash.sha256(0, filesize) == "e17e1e671b597da19b89c5b2d0fa821e90e627860e756ae4947ed27c035330a8"
}
