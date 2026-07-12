import "hash"
// Salamander CTI  //  https://salacti.com
// Inside Banana RAT: From Build Server to Banking Fraud

rule Salamander_SHADOW_WATER_063
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "SHADOW-WATER-063"
    malware = "Banana RAT, Grandoreiro - S0531, Mekotio, Metamorfo - S0455, Casbaneiro, Astaroth - S0373, Guildma, CHAVECLOAK"
  condition:
    hash.sha256(0, filesize) == "38dfeb772afbd01c04eddda120d283acfb1147a6dc3d54ac62fe23ad06e39d8f" or
    hash.sha256(0, filesize) == "4912b1134e69ade7266e8508eec33ccb2d80ad693f1dbc4f1f4344c6dfcf2ff1" or
    hash.sha256(0, filesize) == "d7545b6dacebdae27effb3c778c5e349027ec789c76ae4f777bd9ba56a70cdaa" or
    hash.sha256(0, filesize) == "ecdc8fade561a75d68235859ad8b1fe131db2c458b4894268e38e90ecab1c47f"
}
