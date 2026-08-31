import "hash"
// Salamander CTI  //  https://salacti.com
// ‘The Gentlemen’ Profile: Why This Ransomware Group Wants In Before It Locks You Out

rule Salamander_The_Gentlemen
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "The Gentlemen"
    malware = "Gentlemen"
  condition:
    hash.md5(0, filesize) == "30b49ae2f685d4403d3013410f80c2e2" or
    hash.sha1(0, filesize) == "68225c5613afe2174ed46e074147676b0f9a3915" or
    hash.sha256(0, filesize) == "8c87134c1b45e990e9568f0a3899b0076f94be16d3c40fa824ac1e6c6ee892db" or
    hash.md5(0, filesize) == "1ecaf7098bedaa4ffae0fff3e077f937" or
    hash.md5(0, filesize) == "ff709591615a26f037a465ce97cc59d6"
}
