# GogetaFS atop SSD Code Base

This repository contains the code base for GogetaFS atop SSD. The overall artifact evaluation steps can be obtained from [GogetaFS-AE](https://github.com/GogetaFS/GogetaFS-AE). We now introduce the code base and the branches corresponding to the paper.

- [GogetaFS atop SSD Code Base](#gogetafs-atop-ssd-code-base)
  - [Code Organization](#code-organization)
  - [Branches Corresponding to the Paper](#branches-corresponding-to-the-paper)


## Code Organization

The main modifications are listed below:

- `gogeta.c/gogeta.h`: the core deduplication logic implementation, which is nearly the same as [table.c](https://github.com/GogetaFS/Light-Dedup-J/blob/light-fs-dedup/table.c)/[table.h](https://github.com/GogetaFS/Light-Dedup-J/blob/light-fs-dedup/table.c) in GogetaFS atop PM. We rename the core function to `gogeta_dedup_one_page_acc` for GogetaFS atop SSD, to deduplicate data block(s) in the page granularity.

- `xatable.c/xatable.h/wyhash.h/fingerprint.h`: simple copy from GogetaFS atop PM.

- `f2fs_fs.h`: modify f2fs_entry structure to store the LFP entries. The corresponding macros and functions that use/access the f2fs_entry are also modified.

## Branches Corresponding to the Paper

- *main*: GogetaFS for SSD.

- *lightdedup*: Light-Dedup ported to SSD, which uses non-cryptographic hash and prefetch-based content-comparison, incurs metadata writes

- *hfdedup*: HF-Dedupe reproduced on SSD, which uses non-cryptographic hash and non-prefetch content-comparison, incurs metadata writes

- *SmartDedup*: SmartDedup reproduced on SSD, which uses cryptographic hash.