import "hash"
// Salamander CTI  //  https://salacti.com
// Reverse Engineering the Six Stages of MacSync Stealer and RAT

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "MacSync, AMOS, Atomic Stealer, SectopRAT"
  condition:
    hash.md5(0, filesize) == "9dd465d26c7d86b4a6f514a4b46b2295" or
    hash.sha256(0, filesize) == "071bd109208eb1080ef525b5be394244cec467c59ffef5b8782cfb5e4850401d" or
    hash.sha256(0, filesize) == "230dff4bf9442a951dcd6898b2110924969a20668c20a43e3ceed6fcef65963e" or
    hash.sha256(0, filesize) == "31566a1df7070f30cb990aa5eab310c1d4e0266c8776e9438138e5438ec1cff8" or
    hash.sha256(0, filesize) == "3ae26ed89d3a1a140edc89ca78513aba2895789ed0d0f64cad6605b6f2347c7e" or
    hash.sha256(0, filesize) == "3db8befc08dc02ab7a76b5193abd81653775e8f3ceac5864c7c2188b2dbd3c54" or
    hash.sha256(0, filesize) == "78dea0693ac2d70bdf8be7588667a75910e43fd84397ad484e710e37369a30f7" or
    hash.sha256(0, filesize) == "9c09c303fa058c2d3e179969bd58ca5523775ff2d310fb2f8266ac74cb21ee81"
}
