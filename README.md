# ntool

## Requirements
- Python3
- pycryptodome: `pip install pycryptodome`

## Usage

- **For the example commands, those in brackets are optional**
- Use **python** instead of **python3** if using Windows
- "CCI" is equivalent to a .3ds file

### Re-sign and re-encrypt CIA/CCI for retail/dev:
```py
python3 ntool.py cia_dev2retail <path_to_cia> (--out <path_to_output_file>)
python3 ntool.py cia_retail2dev <path_to_cia> (--out <path_to_output_file>)
python3 ntool.py cci_dev2retail <path_to_cci> (--out <path_to_output_file>)
python3 ntool.py cci_retail2dev <path_to_cci> (--out <path_to_output_file>)
```

### Run dev firmware on a retail 3DS (with Luma3DS)
- **WARNING: Only perform this on SysNAND if you are able to use ntrboot to recover from a brick!**
- First, obtain the SystemUpdaterForCTR zip file from NDP if you have a o3DS/o3DS XL/2DS. For n3DS/n3DS XL/n2DS XL, obtain the SystemUpdaterForSNAKE zip file instead
- Extract the zip file, and choose the appropriate .csu file for your 3DS's region
- Run `python3 ntool.py csu2retailcias <path_to_csu> updates/`
- Place the `updates` folder in the root of your 3DS's SD
- Install [sysUpdater](https://github.com/profi200/sysUpdater), launch it and follow the on-screen instructions
- You may need to enable `Set developer UNITINFO` in Luma3DS settings

### Convert CCI to CIA
- Pass `--cci-dev` if the CCI is dev-crypted/signed, pass `--cia-dev` if you want to build a dev-signed CIA
```py
python3 ntool.py cci2cia <path_to_cci> (--out <path_to_output_file>) (--cci_dev) (--cia-dev)
```

### Convert CDN contents to CIA
- If `--title-ver` is not provided and there are multiple TMD versions in the CDN folder, the latest TMD will be used
- Pass `--cdn-dev` if the CDN contents are dev-crypted/signed, pass `--cia-dev` if you want to build a dev-signed CIA
```py
python3 ntool.py cdn2cia <path_to_cdn_folder> (--out <path_to_output_file>) (--title-ver <ver>) (--cdn-dev) (--cia-dev)
```

### Convert CIA to CDN contents
- Pass `--titlekey` to use a custom titlekey to encrypt the content files (this field will be ignored if the ticket in the CIA is signed)
- Pass `--cia-dev` if the CIA is dev-signed
- Note that clean CDN contents are not guaranteed as the CIA may have improper contents (e.g. due to being decrypted)
```py
python3 ntool.py cia2cdn <path_to_cia> (--out <path_to_output_folder>) (--titlekey <titlekey>) (--cia-dev)
```

### Full extraction and rebuild of NCCH/CIA/CCI:
- First, use `ncch_extractall`/`cia_extractall`/`cci_extractall` to extract the NCCH/CIA/CCI to a folder
    - Pass the `--dev` flag to use dev crypto
- Next, modify the files in the folder as necessary
    - Note: do not modify the `exefs.bin`, `romfs.bin`, or `.ncch` files directly; modify the extracted contents
- Then, use `ncch_rebuildall`/`cia_rebuildall`/`cci_rebuildall` to rebuild the NCCH/CIA/CCI.
    - Pass the `--dev` flag to use dev crypto
```py
python3 ntool.py ncch_extractall <path_to_ncch> (--dev)
python3 ntool.py ncch_rebuildall <path_to_folder> (--dev)
python3 ntool.py cia_extractall <path_to_cia> (--dev)
python3 ntool.py cia_rebuildall <path_to_folder> (--dev)
python3 ntool.py cci_extractall <path_to_cci> (--dev)
python3 ntool.py cci_rebuildall <path_to_folder> (--dev)
```