import "hash"
// Salamander CTI  //  https://salacti.com
// Suspected Chinese Operators Use Claude Code and DeepSeek to Breach Government Systems Across Four Countries

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "TencShell, HSEWH-Ur, Vshell, Gshell"
  condition:
    hash.sha256(0, filesize) == "90b7b2c6f3d05234dc55678243039d7e51f0d54190239e5234a0005533337dc8" or
    hash.md5(0, filesize) == "050b84a0d6105a98f443f0165368cc1c" or
    hash.md5(0, filesize) == "4da236de055bfaf08ee21fb6b88442b4" or
    hash.sha1(0, filesize) == "1cac633d290a876fc1ead63c58de48575b67b1fc" or
    hash.sha1(0, filesize) == "66049dd42a29dde7481d5ca2951efec27214ce15" or
    hash.sha256(0, filesize) == "03f26cbfa3ca15fcb43f512aa4041732beeec267f9d1dc74a11f7b0bb32e86bb" or
    hash.sha256(0, filesize) == "2954639be599f23c2229a9743aba09a1d9d11bf2becc62bf353384437db37dee" or
    hash.sha256(0, filesize) == "64107e3e0a333f685d1be6386426223a030c4126ac7c295aa7b1d54c508bbace" or
    hash.sha256(0, filesize) == "643de2a1cf9148b896efecf560c9476fa56118ec477c4e15eb5c2da4b318061f" or
    hash.sha256(0, filesize) == "ad1a0b3e22a10a2bd680b773b178a0d3824cfcbdf3551016f3d052a0b823079f"
}
