import "hash"
// Salamander CTI  //  https://salacti.com
// The Crown Prince, Nezha

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "China Chopper - S0020, AntSword, Nezha, Ghost RAT, gh0st RAT - S0032, Mydoor, Moudoor"
  condition:
    hash.md5(0, filesize) == "d757ec4d5350843c44dd34a95dcb3a50" or
    hash.sha1(0, filesize) == "ad5e5b00f58396f5a518680e7084dc7dd5f2cc2b" or
    hash.sha256(0, filesize) == "7b2599ed54b72daec0acfd32744c7a9a77b19e6cf4e1651837175e4606dbc958" or
    hash.sha256(0, filesize) == "35e0b22139fb27d2c9721aedf5770d893423bf029e1f56be92485ff8fce210f3" or
    hash.sha256(0, filesize) == "9f33095a24471bed55ce11803e4ebbed5118bfb5d3861baf1c8214efcd9e7de6" or
    hash.sha256(0, filesize) == "f3570bb6e0f9c695d48f89f043380b43831dd0f6fe79b16eda2a3ffd9fd7ad16" or
    hash.md5(0, filesize) == "6f336f372c5a642b57413363265e7d7e" or
    hash.md5(0, filesize) == "89cb9c926e136c54011f3e0792b4a28c" or
    hash.sha1(0, filesize) == "1c948822cb57763c1d343542ee4ade212d8f4fbb"
}
