# JBFMod Unpacker
A utility for unpacking/extracting tracker modules packed using Martin Rijks' ToPack utility (included with 
[jbfmod](https://web.archive.org/web/20080113222231/http:/gmc.yoyogames.com/index.php?showtopic=108103)
).
This packing tool worked with `jbfmod.dll` (a dll interface connecting 
[legacy gamemaker](https://web.archive.org/web/20060218132040/http:/www.gamemaker.nl/) 
with 
[fmod](https://www.fmod.com/)
) to allow users to package and encrypt tracker files that could later be 
loaded and played in their gamemaker titles. Typically, these packages have the `.pak` extension. 

## Background
Back in the legacy (pre-studio) [gamemaker community](https://web.archive.org/web/20080113080157/http:/gmc.yoyogames.com/) 
(encompassing the years roughly 2005-2015) it was popular to develop titles that used 
[tracker modules](https://en.wikipedia.org/wiki/Module_file) 
as their soundtrack (e.g., 
[seiklus](https://web.archive.org/web/20180313061901/http:/autofish.net/clysm/art/video_games/seiklus/index.html),
[uin](https://web.archive.org/web/20150330092808/https:/www.tigsource.com/2010/04/20/uin/), 
etc.). 
These modules were typically loaded and played using [fmod](https://www.fmod.com/) at runtime. 
However, as [legacy gamemaker](https://web.archive.org/web/20060218132040/http:/www.gamemaker.nl/) 
lacked native bindings with fmod, most titles relied on an intermediary library, 
[jbfmod](https://web.archive.org/web/20080113222231/http:/gmc.yoyogames.com/index.php?showtopic=108103),
developed by Martin Rijks ("smarty"). 

One particular feature introduced by Rijks was the ability to package and obfuscate multiple tracker modules into a single 
package using a utility called ToPack. The modules from these packages could then be loaded into fmod for playback using 
Rijks' jbfmod (see games such as 
[purple](https://web.archive.org/web/20210227182925/https:/www.yygarchive.org/game/92136)
). As an added layer of security, these packages could be 'locked' to a particular application binary. This prohibited 
applications other than the title for which the package was 'locked' from decrypting and loading the package. 

This utility is capable of decrypting and extracting modules packaged using Rijks' ToPack utility. For packages which 
were 'locked' to specific titles, the application binary of that title will also be needed for decryption. 
It should usually be obvious for which title the package is locked, however, the package format includes metadata with
the filename of the executable it has been 'locked' to. This metadata will be displayed to the user of this utility in
a prompt to include it as a command line argument.


## Installation
### Prerequisites
This tool requires [Python 3](https://www.python.org/download/releases/3.0/)
to be installed and added to the user's `PATH`. 
Often times, installing python will not automatically add these programs to the system `PATH`. 
Searching Google for questions like 'how to add python to my PATH' etc. usually yields good explanations 
on this process.

To confirm `python` is in your system's PATH, open an instance of command prompt and type `python --version` 
(sometimes it will be installed as `python3`, in which case - every time `python` is encountered in this 
document, it should be replaced with python3). If present, python should respond with its version number.

### Installing
Download the contents of this repo and extract them to a convenient place on your machine. 
Open an instance of command prompt and navigate to the location you extracted the repo. 
You should now be in the folder with `setup.py` and the `jbfmod_unpacker` directory. Enter the command (note the period!),

```
python -m pip install .
```

to install `jbfmod_unpacker` to your python package library.

Finally, confirm that `jbfmod_unpacker` has been installed properly by entering the command,

```
python -m jbfmod_unpacker --help
```

If successfully installed, `jbfmod_unpacker` should respond with an explanation of its command usage.


### Updating
To update these scripts having already previously installed an older version, 
download the latest version from the github repo, open a command prompt/shell window in the directory 
in which you downloaded the repo and run the command (note the period!),

```
python -m pip install .
```

## Usage

The basic structure for calling `jbfmod_unpacker` command is

```
python -m jbfmod_unpacker [pack_file] [destination] [-p [program]]
```


- `pack_file`: Path of the package file to be extracted.
- `destination`: Path of the output directory to place the extracted tracker modules (optional).
    The default value is the current working directory.
- `program`: Path of the application binary to which the module package is 'locked' (optional).
    Specified using the `-p` argument switch.

To display *help* for `jbfmod_unpacker`, call the command

```
python -m jbfmod_unpacker --help
```


### Extracting modules from a package

Consider the scenario in which one wishes to extract the package `packs/music.pak` to the 
folder `output/` (where both paths are given relative to the current directory). 
This would be accomplished with the command

```
python -m jbfmod_unpacker "packs/music.pak" "output/"
```

`jbfmod_unpacker` will then scan the contents of the package and extract the tracker
modules it finds within. Each package can contain up to 64 tracker modules, as well as an optional
info block which contains information specified by the creator of the package.
For each tracker module found within the package, `jbfmod_unpacker` will attempt to detect the
module name and tracker type. Currently, this utility can distinguish the `.mod`, `.s3m`, `.xm` and
`.it` module types.
The filename of each module extracted will be the module name
prepended with the index number (0-63) of the module within the pack. 
If the filetype cannot be determined, the extracted module will be given the `.bin` file extension.


### Packages locked to application binaries

Consider the scenario in which one wishes to extract the package `ost.pak`, which is 'locked'
to the application `bulletcurtain.exe`.
If the user attempts to run the command 

```
python -m jbfmod_unpacker "ost.pak" 
```

`jbfmod_unpacker` will return the following error

```
Failed to decrypt header - package locked to BULLETCURTAIN.EXE.
Run this utility again with the option '-p {path to BULLETCURTAIN.EXE}'.
```

Assuming `bulletcurtain.exe` is in the working directory alongside `ost.pak`,
the user should then rerun `jbfmod_unpacker` using the `-p` switch

```
python -m jbfmod_unpacker "ost.pak" -p "bulletcurtain.exe"
```

This will enable `jbfmod_unpacker` to properly extract `ost.pak`.

## Technical

Each package consists of an encrypted `0x588` byte header followed by the (encrypted) 
contents of each tracker module contained within the package. 

The encryption method used to encrypt both the header and module entries is a variant of the 
[Twofish](https://en.wikipedia.org/wiki/Twofish) cipher configured to operate as a stream cipher
(see `TfDecrypt` in the source). Additionally, the header is also encrypted using the Delphi Linear 
Congruential Generator (LCG) (see `LgcDecrypt` and `RandIntGenDelphi` in the source).

The header is first decrypted using the LCG (with a custom starting seed, `0x135C80A1`) followed by 
the Twofish stream variant (with the key `[0xF0, 0x3E, 0xC8, 0x34, 0xB7, 0xA0, 0x54, 0x72]`).
At this point, the final 68 bytes of the header are completely decrypted. These bytes contain
metadata which encode the application (if any) to which this package is 'locked'.

If the package is 'locked' to a given executable, a new Twofish key will be generated based on the
binary contents of this executable (see `compute_key_from_executable` in the source). If the package
is not 'locked' to any particular executable, a key of 8 NULL bytes is used.

The first `0x544` bytes of the header are again decrypted with the Twofish cipher variant using this 
new key. At this point, the entire header is completely decrypted.

The header has the following format

```
0x000 - 0x400: Table of module records (64 entries each 16 bytes long).
0x401 - 0x440: Unknown/unused.
0x441        : Length of the package info string (0-255).
0x442 - 0x542: Package info string.
0x543        : String terminator (always NULL).
0x544        : Length of the executable name to which this package is locked (0-68).
0x545 - 0x588: Executable name to which this package is locked (if applicable).
```

Each module record has the format

```
0x00 - 0x07: (char[8]) Twofish encryption key.
0x08 - 0x0B: (uint32_t) Offset of the module content (in bytes) from the start of the file.
0x0C - 0x0F: (uint32_t) Size of the module content (in bytes).
```

This utility then cycles through each valid module entry, decrypting the current module's contents 
using the Twofish cipher variant with the key given in the record entry.

## External dependencies 

This project uses the [python-twofish](https://github.com/keybase/python-twofish/) library
which itself relies on the [Twofish](https://en.wikipedia.org/wiki/Twofish) implementation 
by Niels Ferguson, [libtwofish-dev](https://packages.debian.org/sid/libtwofish-dev).

## Development and contributing
This utility only been rigorously tested in Windows 10. 
If a bug is found, please report it as an issue. Feature requests are welcome, 
but there is no guarantee I will be able to implement it.

## Support Me
`jbfmod_unpacker` is an open-source tool for extracting tracker modules packaged with Martin Rijks' ToPack utility.
If you like the work I've contributed to this project, you can support me by buying me a coffee!

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/counselor.chip)

## License
Copyright (c) 2022-present Counselor Chip.
`jbfmod_unpacker` is free and open-source software licensed under the [MIT License](/LICENSE).

### Third Party Licenses
 - [python-twofish](https://github.com/keybase/python-twofish/blob/master/LICENSE)

