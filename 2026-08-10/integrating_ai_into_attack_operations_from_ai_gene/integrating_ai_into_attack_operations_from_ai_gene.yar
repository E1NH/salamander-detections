import "hash"
// Salamander CTI  //  https://salacti.com
// Integrating AI into Attack Operations, From AI-Generated Decoy Documents to a Local LLM

rule Salamander_Kimsuky
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Kimsuky"
    malware = "AsyncRAT"
  condition:
    hash.md5(0, filesize) == "30d5f17d5e3f85be18220a7cab0b9fff" or
    hash.sha256(0, filesize) == "a4f72ce8b5736fe3ca2083cfe21bd51697f12e900e307c357cb8523b8f86e3ec" or
    hash.sha256(0, filesize) == "22180919f562fb9f6e50d7f20b2eb3f94eb009c212b74b45cf77659fe8274d5b" or
    hash.sha256(0, filesize) == "4453b9e985f452365995c399f5292c92764570f03e6a066d7845320dd4ad09a1" or
    hash.md5(0, filesize) == "aa9d5dd632bb90addca480eaa5ff4382" or
    hash.sha1(0, filesize) == "5746f3e78351439caebfa3721e8feea36b67263f" or
    hash.sha256(0, filesize) == "4b0358c7e4afa54bc489a6199cca132b5f4a330892eb15bf06c0c4da9e020df2" or
    hash.sha256(0, filesize) == "9be8f2be7ad882e8423c269a0540b7c73d6470311ddfcfcd318ff9d1983e2935" or
    hash.sha256(0, filesize) == "e34d73a1da492c9a79a9729f2f7d9d4b5a2448f44934bd5552bd0bbbe1586767" or
    hash.sha256(0, filesize) == "7bc61d1bbc90d66d9988fd3baacd7834b1d2dfefe6d4ac999a194bccb9ba7dfc" or
    hash.md5(0, filesize) == "02ebc2356f9f700bbdac444cdefa0da2" or
    hash.md5(0, filesize) == "0d8ceb7dea7d471afa2f8e753b13d2d6" or
    hash.md5(0, filesize) == "1f378c0efc13669dada1fe340c6837bd" or
    hash.md5(0, filesize) == "2669731cb5ff664dfb5fbfc37637876d" or
    hash.md5(0, filesize) == "2ab3df4762fbde5d86e99a1ad147850e" or
    hash.md5(0, filesize) == "2e76d5316663a3dc472398b1c01cb9a8" or
    hash.md5(0, filesize) == "2eb77109cce1e8afca6245c2963e52a6" or
    hash.md5(0, filesize) == "302725413076d1aeaee2d7f2b3692646" or
    hash.md5(0, filesize) == "30792a0c0dfad55fb2b19d3e30e9a7d4" or
    hash.md5(0, filesize) == "37cec428257cd41153cf43d7f1a12652" or
    hash.md5(0, filesize) == "3b9d40f3d620ec87960b4350d42ccc03" or
    hash.md5(0, filesize) == "3e2110d233d4543830e14c78d53900f4" or
    hash.md5(0, filesize) == "422a221851ea6ad15f53cd3aea51c8af" or
    hash.md5(0, filesize) == "49bdbe7e6cbb88842afcce3a9fe60e9b" or
    hash.md5(0, filesize) == "4d87fef16790cbe1df72007d99149665" or
    hash.md5(0, filesize) == "5577fffb5b5acd3771ef9dc696498f1e" or
    hash.md5(0, filesize) == "5af95590a33b9bc64d95808f1fc71b78" or
    hash.md5(0, filesize) == "5c5672bb14e1d2f07a8318ffec19b213" or
    hash.md5(0, filesize) == "6add815cd61d6514f81a23ab8c23405a" or
    hash.md5(0, filesize) == "73ff669fc282653bd6c42cf87ade9337" or
    hash.md5(0, filesize) == "7f12fa589f56f6203c692715b3958d30" or
    hash.md5(0, filesize) == "8406075af0a1e9ec09bafdc0de01f138" or
    hash.md5(0, filesize) == "8c859a03814443c6f0da341ee594c352" or
    hash.md5(0, filesize) == "a1c07ac866fb6b388e38c6bb1d4bbe94" or
    hash.md5(0, filesize) == "a343d8bcf02a0554fa271452a512f3ce" or
    hash.md5(0, filesize) == "a435292106026e257789036a70ee1a14" or
    hash.md5(0, filesize) == "a5701848f82c65a55765dc534111899f" or
    hash.md5(0, filesize) == "af3fa7f22f6e97901f20326cc12bdb49" or
    hash.md5(0, filesize) == "b406ea5b8628cb7801f47c0189b96182" or
    hash.md5(0, filesize) == "b50dad56d891ef230656b37ce62cdada" or
    hash.md5(0, filesize) == "b516ec6c6b37618ad65080a063270ea4" or
    hash.md5(0, filesize) == "ba0238423b5c29667cd760ccd7b000aa" or
    hash.md5(0, filesize) == "ba8e682a72c6a3e634c070f0fb057bf5" or
    hash.md5(0, filesize) == "bbf1b0ab9fc27439de4386ed7b8fc151" or
    hash.md5(0, filesize) == "c410055bfa198937825dfd7e41000e7a" or
    hash.md5(0, filesize) == "c63d021de798034cbf933e1c99bcb83f" or
    hash.md5(0, filesize) == "c7723bf166ef08ff3112257a1244f584" or
    hash.md5(0, filesize) == "ca0b57807f79f26e7f59cab2a2542da0" or
    hash.md5(0, filesize) == "e0e4aec6d494fe68cdaa52d6878a8366" or
    hash.md5(0, filesize) == "e22367800e9d39bc865bd50cddd0537d" or
    hash.md5(0, filesize) == "ead95793528572e7b89679860e2f2116" or
    hash.md5(0, filesize) == "ed2f8dd9b96d706d833b7aa545b8e621" or
    hash.md5(0, filesize) == "f4e7ca8c1de252840c1f0e957cd4b717" or
    hash.md5(0, filesize) == "f73e07efb8707e3561e9cbff74557acb" or
    hash.sha1(0, filesize) == "215343916d101c6bbe287871816e063c78103dd1" or
    hash.sha1(0, filesize) == "263efd45e5cedce553c25cf2c49dbcf28c352cd8"
}
