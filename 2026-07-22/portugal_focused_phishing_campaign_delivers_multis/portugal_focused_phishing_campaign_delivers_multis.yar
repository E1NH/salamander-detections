import "hash"
// Salamander CTI  //  https://salacti.com
// Portugal-focused phishing campaign delivers multistage malware

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Lampion, ChePro"
  condition:
    hash.sha256(0, filesize) == "036c8f32012abdcb9a389ae9c284da89505e830bca74eb1aa9ea3794b067aab6" or
    hash.sha256(0, filesize) == "050e84d134a32ed7c4885a9d57ce37f8ae5f910960b67e2156941961bd5781ba" or
    hash.sha256(0, filesize) == "1541c23f34eb05dfcbede3830741427681d719cee1dfd397a2c04110e0fa81b2" or
    hash.sha256(0, filesize) == "1bd347ce5deee3d783a038e2d2d224bc30cc074e0471a3897c5409ce99816dc9" or
    hash.sha256(0, filesize) == "643c0093baec45952a46b0210f7a6f8fb26883b396b66f1cb609c5b55e6dae1e" or
    hash.sha256(0, filesize) == "7ad89fb0a4a5449a381b8f540238193019673adc7cfb1c008dcd14a745891551" or
    hash.sha256(0, filesize) == "87efeada5fe39a94cefc6151fd84af223d0e0e2b070daec606274481ed87b87b" or
    hash.sha256(0, filesize) == "ab46f7c4d3f717bb1e61d2f236917976d2a85be6958ae099fee79ea6e9031e37" or
    hash.sha256(0, filesize) == "b1c101bd1ba134ffbea61f9fac2b7c8fbd13ca113a37944abdc131ef86da92ac" or
    hash.sha256(0, filesize) == "c6618bb692fb3f5d7959f8db1fedaaac5e8a36fb901397a008aa2b88874448fd" or
    hash.sha256(0, filesize) == "d25d32478ae67403484a309591b6409224d26ca3d094c5ccd8428ebef7efcfd1" or
    hash.sha256(0, filesize) == "fe769fd85a7440751e1508614c8d9ef0de00bece803329bf3318ff863a146216"
}
