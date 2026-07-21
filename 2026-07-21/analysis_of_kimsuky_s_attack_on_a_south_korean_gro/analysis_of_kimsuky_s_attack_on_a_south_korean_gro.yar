import "hash"
// Salamander CTI  //  https://salacti.com
// Analysis of Kimsuky's Attack on a South Korean Groupware Vendor Using a New Gomir Family Variant

rule Salamander_Kimsuky
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Kimsuky"
    malware = "Gomir, HttpTroy, BirdTroy, DriveTroy, TrollStealer, GoBear, Endoor, HttpSpy"
  condition:
    hash.md5(0, filesize) == "84e9b066bebd49036b7fc71b5f5f8d83" or
    hash.md5(0, filesize) == "a452a860f973c7a43ea804c17e9427d2" or
    hash.md5(0, filesize) == "aa61e76255a6e13313439655bc02bdf5" or
    hash.md5(0, filesize) == "b1c72139f2cdd9419562369fc6ced4fc" or
    hash.md5(0, filesize) == "bf215181b5140522137b3d4f6b73544a" or
    hash.md5(0, filesize) == "c2e37232556357944a04edf1dec3934b" or
    hash.md5(0, filesize) == "ca98a51cebdc802d255030b4baa44ca0" or
    hash.md5(0, filesize) == "dff787bce68c7653495f153c0534cb96" or
    hash.md5(0, filesize) == "e6c6fa32da47d9341b778bfa424abb4c" or
    hash.md5(0, filesize) == "e911f8f7c49476806ada37f3ebb7a28a" or
    hash.sha1(0, filesize) == "3fb6111490cac9f5c4b34f9fed459f01c10d2314" or
    hash.sha1(0, filesize) == "f3ed0bcc692555fea83c6556abaa5dc2b91bcb38" or
    hash.sha256(0, filesize) == "01b1c767f62e48efeb86410fd014fed4295ccb084bfcd6d5b9197638b615a648" or
    hash.sha256(0, filesize) == "073d9dd98a9ca3cd03901c31ba57811a1632e316923022640670ce00622cd8a9"
}
