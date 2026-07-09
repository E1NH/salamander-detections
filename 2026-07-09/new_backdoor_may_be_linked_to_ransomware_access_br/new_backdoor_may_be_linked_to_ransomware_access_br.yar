import "hash"
// Salamander CTI  //  https://salacti.com
// New Backdoor May be Linked to Ransomware Access Broker

rule Salamander_Woodgnat
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Woodgnat"
    malware = "Havoc, KongTuke, MintsLoader"
  condition:
    hash.sha256(0, filesize) == "3f797a639bc855bc6d5471f327924b62d10900ddec49b970eca6604142bbb4be" or
    hash.sha256(0, filesize) == "fb3630822b70bacb56aa4cec29b5a0e3e9acb3920809e70310a4003385a6d34a" or
    hash.sha256(0, filesize) == "59e3c4cb06331b4f2d78a9a0592f3747e573bd01c5a7650c26361d1e25520712" or
    hash.sha256(0, filesize) == "afd5f1ed45a9867daf3bc64152cef460a06b164c8183e490db39146d4749a82c" or
    hash.md5(0, filesize) == "347a3f5f2ed2f503a22f68c4951c78c7" or
    hash.md5(0, filesize) == "6b8ec32dc76fa3138f00616156962f4f" or
    hash.sha1(0, filesize) == "deb10789274bf903060d700b3472fdf094a14763" or
    hash.sha1(0, filesize) == "fd8e880cc32377af08327c9d187f6220c6ac449f" or
    hash.md5(0, filesize) == "b148626849c11dd5b3230632a38a6302" or
    hash.sha1(0, filesize) == "e5c4e634b2f443f783cae1b5e8247a1069df0c9f" or
    hash.sha256(0, filesize) == "1e41c7bfaa6aa3b93b6cc024274a10e33f3e12fe7c98c1db387ef8927f9d1984" or
    hash.md5(0, filesize) == "dc96668d007df0a545bf1334e10e80fa" or
    hash.sha1(0, filesize) == "48d4872e8463d1ede1b93e3f6a6a8cc8c2cecde3" or
    hash.sha256(0, filesize) == "34d798a6c55e57ed0932b6499f4fbcb5454bdfca903307be101a0594b0ac07bc" or
    hash.sha256(0, filesize) == "8c935feec4bd05d5d918df308be417532fb42608fb989a08eab183e0ae699235" or
    hash.sha256(0, filesize) == "db972979d508e75fe730d3b72c2701470fbdaeaf8ebdd674744754fa44438ca5" or
    hash.sha256(0, filesize) == "f591275a8f014b29e567529d67c54eb7bb4473db1c38737d6bfd5b3d52c9344e"
}
