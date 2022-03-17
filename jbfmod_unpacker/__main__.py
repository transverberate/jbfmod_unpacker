from argparse import ArgumentParser, FileType
import sys

from jbfmod_unpacker.jbfmod_unpacker import FailedDecryptHeader, extract_pak


def main(argv):

    arg_parser = ArgumentParser(
        prog="jbfmod_unpacker",
        description=(
        "JBFMod Unpacker - A utility for unpacking/extracting tracker "
        "modules packed using Martin Rijks' (smarty's) ToPack.exe for "
        "use with jbfmod.dll. Typically, these packages have the "
        ".pak extension. This utility will attempt to detect the name "
        "and filetype of each tracker module found within the package. "
        "The filename of each module found will be prepended with the "
        "index number (0-63) of the module within the pack. If the "
        "filetype cannot be determined the extracted module will be given "
        "the .bin file extension. Some packages are 'locked' to the "
        "program/executable which loads them. This utility can detect "
        "this scenario, and will prompt the user to run it again with the "
        "'-p {path to program}' option."
    ))
    arg_parser.add_argument(
        "pack_file",
        type=FileType(mode="rb"),
        help=(
            "The jbfmod pack (.pak) file to extract."
        )
    )
    arg_parser.add_argument(
        "destination",
        type=str, 
        default=".",
        nargs="?",
        help=(
            "The destination directory to place extracted modules."
            "The default is the current working directory."
        )
    )
    arg_parser.add_argument(
        "-p",
        "--program",
        type=FileType(mode="rb"), 
        default=None,
        nargs="?",
        help=(
            "The path to program/executable the package is locked "
            "to. Needed for some packages."
        )
    )

    args_namespace = arg_parser.parse_args(argv)
    try:
        extract_pak(
            args_namespace.pack_file, 
            args_namespace.destination,
            args_namespace.program
        )
    except FailedDecryptHeader as e:
        print(e)
    

if __name__ == "__main__":
    argv = sys.argv[1:]
    main(argv)

