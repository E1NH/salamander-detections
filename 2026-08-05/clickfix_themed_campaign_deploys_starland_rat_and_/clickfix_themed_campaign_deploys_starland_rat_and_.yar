import "hash"
// Salamander CTI  //  https://salacti.com
// ClickFix-Themed Campaign Deploys Starland RAT and WLDR Framework

rule Salamander_UAT_11795
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "UAT-11795"
    malware = "Starland RAT, WLDR, CastleStealer, Remcos RAT"
  condition:
    hash.sha256(0, filesize) == "a6821c7e9bfe2e6af0f690d906ec6a26161e2198c256fb60f3b4731c317f3ad9" or
    hash.md5(0, filesize) == "c33f097fdb2b69b4cbb1c3f29ae88b43" or
    hash.sha1(0, filesize) == "650e751e8ee5f5958c6a70288a24a4e3d19904a2" or
    hash.sha256(0, filesize) == "1b46f761719dce44baa2d7b417c5214fc41c080f7f9ba485e7e489d949097f1f" or
    hash.sha256(0, filesize) == "2a27b3415114b874da295c19cce5227a8b8d9525cc2da331034a1f45528eecae" or
    hash.sha256(0, filesize) == "2c7a99f137efd718f89cf8b260379c99af89ea1939568df09314918f2c5999a3" or
    hash.sha256(0, filesize) == "365024336c7681ac0854321ac6c140a245b9593285da02d2a590124cdc592370" or
    hash.sha256(0, filesize) == "36e3838d07978f49ebe6546d57d2f311b8d6566558bcd58448e921c988cc346a" or
    hash.sha256(0, filesize) == "451ac8ca34d5bcdfe476465f69eb517b2608f267c7e8d69f8ef36197a6f1d949" or
    hash.sha256(0, filesize) == "575ce92c473e6d47810321e309a4e29dd7f52f4152526b0bdca80f54b53aed2f" or
    hash.sha256(0, filesize) == "5b9bf7957a9f8869c87ace1a6d76b48e2623073e72739ad0636b5dfa4bb2e0c3" or
    hash.sha256(0, filesize) == "603fd9724de346a06e00c1b8502c2ac1180812a18bbf30032dab8d469e5c18e1" or
    hash.sha256(0, filesize) == "6ca7a458985350ac082a9c9820d7f8d39128a4c4bda2f5d32f169a45b7b22bc6" or
    hash.sha256(0, filesize) == "7dc77a5abab119960fbe42b1535c957020cce1b8e0a3cf58d4eddc51b5bf9940" or
    hash.sha256(0, filesize) == "896185a89bd7eb0520b03fdcfb8db0be98b43cf15f14041d73b23d3988c1bcab" or
    hash.sha256(0, filesize) == "964256d3259b6e0c701ec04116c45cf0ec381c1c209dc29b09a7930cd7a4810b" or
    hash.sha256(0, filesize) == "a080b5380ccc8fc40b24c02151d305efc32d931dc547881e01a2e6f2b070c7dc" or
    hash.sha256(0, filesize) == "a1835d333ac3db961a8ff1f4864e3c10a6f73a872c040599091390a009ac7804" or
    hash.sha256(0, filesize) == "a32ac345e39cb7606322e2155bd7b4d6941c1678619e48d1f14d9301ee53e6c0" or
    hash.md5(0, filesize) == "0ddc62ec74a816a8a0607b16f2be9073" or
    hash.md5(0, filesize) == "3111f846b1cb76de775eabb62625cdda" or
    hash.md5(0, filesize) == "38167e35c0ceb08f2d11dc271243db3c" or
    hash.md5(0, filesize) == "57c6617c205f8dc296c41606ccc5cc16" or
    hash.md5(0, filesize) == "6337c9dcd6b6c7c122e26b008032e8ba" or
    hash.md5(0, filesize) == "7ed31a99036b9aecb028707ae082b108" or
    hash.md5(0, filesize) == "844c462e920593242594050f82643f7b" or
    hash.md5(0, filesize) == "9000b4d28f2736cf84147ddc0ff3b59e" or
    hash.md5(0, filesize) == "90dc1e26741120859d97cd287da38a78" or
    hash.md5(0, filesize) == "a86b42c731d12b5a4fb156ee3175fe86" or
    hash.md5(0, filesize) == "b099fe4c46c53403b7657cbfe18b8ac4" or
    hash.md5(0, filesize) == "b2b25a59e1e0cc74804344d631629fd2"
}
