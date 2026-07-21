import "hash"
// Salamander CTI  //  https://salacti.com
// The TTF Trap: A Global Campaign of a Low-Detection Lua Loader

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "AgentTesla, MASS Logger, Remcos, RemcosRAT, XWorm"
  condition:
    hash.md5(0, filesize) == "511ba918e1781ff38310530801b8cec5" or
    hash.sha1(0, filesize) == "c029ceede8f8f8c8a4f58687e6681536fe4cc97b" or
    hash.sha256(0, filesize) == "41ad1f28134f4b4a443b53af04aeb3fa57a2f72a3cc58a6466e84fc3225f38be" or
    hash.sha256(0, filesize) == "2b1248d89fd9a7c716816f9688402942827fc1bfa89d5dccd741521725104279" or
    hash.sha256(0, filesize) == "417fc4d6119dac40f276b563498a0ad3f9bf42262ec650a4463cbdbe78da388b" or
    hash.sha256(0, filesize) == "619d2628dcf0c8e15a6febb0e562609556ca57f9f8216800ee77a39e336b8bf4" or
    hash.sha256(0, filesize) == "96e22da4d5c0ea4b0efde0ad3eaa8fdedc60228f84fb3c56899afbb9338da2a1" or
    hash.md5(0, filesize) == "ba2793c45a12e96683a8b1b7cb5a5c3e" or
    hash.md5(0, filesize) == "c5724b86aae0e637b8b0b6f3c8d31168" or
    hash.md5(0, filesize) == "efd92efb0321bf811e74717974b14897" or
    hash.md5(0, filesize) == "ff3db8cc2d38ca5878a32fe40d7a8ba5" or
    hash.sha1(0, filesize) == "409f57557a91d2a7a424d122aef4e73f2b533b18" or
    hash.sha1(0, filesize) == "425ba7d4138a0e72e0e32db5438ee4bd88aa2982" or
    hash.sha1(0, filesize) == "9d8a4d41058d5d7934d55f2c97d032124a0d74e3" or
    hash.sha1(0, filesize) == "f17ee43fda3735a0eea7330774ed6c10c0749fa5" or
    hash.sha256(0, filesize) == "05390dd0d2c84f77475c0c6aa082638e23977da591302e911cbcb071c42a9451" or
    hash.sha256(0, filesize) == "1539468a21a439dd4f8d72a6c34ce503f0585281fc2e88535c3c33727bfdc717" or
    hash.sha256(0, filesize) == "16516e3298278719123068bf0ed808ea4e00f73c970a8a83377066b4e3c3c950" or
    hash.sha256(0, filesize) == "16f9692debe0d4e35d76b48312979e5a90a85ce066e7375269ce78f43da52769" or
    hash.sha256(0, filesize) == "1c4419d687bf45bdc5474b6347e41e89459fc0f5115f0d012c46c57280b242bf" or
    hash.sha256(0, filesize) == "1d9dd914cf623dcae4b88834744a005e5e3eae827ded1aafd23ed1d7be57b90a" or
    hash.sha256(0, filesize) == "2fe30eccd36f4346cb117af0cf626c2bca84b50c658b0c9af09110b9f86a53f4" or
    hash.sha256(0, filesize) == "3ace400380bd1fc51e83d008dbbe9ceb70b2572da95264be09d85979a6276a37" or
    hash.sha256(0, filesize) == "4c001e107a42d65c1b1e6092e4aa6932dbd1544d097d1a432ba27e3b4bddfcc1" or
    hash.sha256(0, filesize) == "5409b3fa21dcc2f854697ec731f9574603dd0b6bdfd892e968a2b412ed85f52c" or
    hash.sha256(0, filesize) == "5b271a1b1ffe2716ae420f8e9d40dbc8e9e682f6e4125d4f174a335bf070ac29" or
    hash.sha256(0, filesize) == "6700e6d2a0c285d3ebf1a55aecec63b1e42d7d581f691331c667a8920dac7029" or
    hash.sha256(0, filesize) == "775ae9a8c7363e2368cbb559f9c2d26a6c479d4e7998fe71d45830885ccde429" or
    hash.sha256(0, filesize) == "7df42fc54f053d1bb65f43d4386a75be02770f7923b66e713fb04631582e864e" or
    hash.sha256(0, filesize) == "81edd5e740bea0fefb5c1bbd14a671bd1daff37bf3641e34f3a1f7e93559184a" or
    hash.sha256(0, filesize) == "8c28bc87eb4f2613117d41a716e78f62d55c19edaeea573c2c96e787da055167" or
    hash.sha256(0, filesize) == "9674da676ee226ee456d35c774715d9b58655423806f281de19dc9ef899e9532" or
    hash.sha256(0, filesize) == "986d1d5270822af7d7744762ecd8fc4e9b2886c85b3660e9fdf0b5906d6c4117" or
    hash.sha256(0, filesize) == "b12b743d4ecc0fe7320b6c1533e2a60bb89f94ca39a5be37143e7af27daacf04" or
    hash.sha256(0, filesize) == "bbeb74e6af12536ecb6761a65ed893fbddd1b86a17cd4a61b616e5fc6106ec9a" or
    hash.sha256(0, filesize) == "be4fcf88a287f783a3d199e889f9f088f77338eafe0dce70a38ade01192fb223" or
    hash.sha256(0, filesize) == "c7159e589e29f9c866cc9983839ae9c9a1457df542a2dcd5103baf38636e08fd" or
    hash.sha256(0, filesize) == "c92740b6b90582a4bf73fef979ca047b9e6ae432e892a97f71e70b45c09e478e" or
    hash.sha256(0, filesize) == "ca9639f7db6c3d1b37a004493f44aaa4e1282ea9333bc8ca5eac5d263d899e6a" or
    hash.sha256(0, filesize) == "cc041def6013da331f025e12f21f43677cea08073018d6be037f15a343a9cc24" or
    hash.sha256(0, filesize) == "e2a95dd038a153dfb463c94554912f992cd04cf0f420552a95f4aea3d6f31e18" or
    hash.sha256(0, filesize) == "ec494785f243f5f1b516b31d8455fadafe5495e11d47a5ce2bd50b1b3791fec6" or
    hash.sha256(0, filesize) == "fbf9a87d351ef702d87e0cd9e0148baa44c6d619f50fbf91d79a1c5e37719a77"
}
