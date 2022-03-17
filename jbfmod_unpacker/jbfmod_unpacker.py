import io
import os
import copy
import struct
import re
import textwrap
from typing import Tuple, Union
from dataclasses import dataclass
from twofish import Twofish


JBF_PAK_NUM_INDICES = 64
JBF_PAK_HEADER_TOTAL_LEN = 0x588  
JBF_PAK_HEADER_MAIN_LEN = 0x544 
JBF_PAK_INIT_VECTOR = (
    b"\x11\x22\x33\x44\x55\x66\x77\x88"
    b"\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00"
)
# The big secret...
JBF_PAK_HEADER_KEY = (
    b"\xF0\x3E\xC8\x34\xB7\xA0\x54\x72"
)


def copy_sized(data: bytes, size: int) -> bytes:
    result = copy.copy(data).ljust(size, b"\x00")
    return result


class RandIntGenDelphi:
    def __init__(
            self, 
            seed = 0, 
            multiplier = 0x8088405,
            increment = 1
    ) -> None:
        self.seed = seed
        self.multiplier = multiplier
        self.increment = increment


    def get_next(self, x = 255)->int:
        self.seed = self.multiplier * self.seed + self.increment
        self.seed &= 0xFFFFFFFF
        result = (self.seed * x)  # requires python 3 for big integers
        result = (result >> 32) & 0xFF
        return result


class LgcDecrypt:
    def __init__(self) -> None:
        self.rand_gen = RandIntGenDelphi()
        self.reset()


    def reset(self):
        # initial seed manually set by jbfmod
        self.rand_gen.seed = 0x135C80A1  


    def get_next(self, x: int) -> int:
        # Notice that rather than using rand_gen.get_next(255)
        # get_next(254) + 1 is used, thus ensuring that no byte
        # remains unaltered (xored with 0).
        lgc_result = self.rand_gen.get_next(254) + 1
        y = x ^ lgc_result
        return y


    def decrypt_block(self, data: bytes, size = None)->bytes:
        size = size or len(data)
        if size > len(data):
            raise IndexError
        result = bytes((self.get_next(x) for x in data[:size])) + data[size:]
        return result


class TfDecrypt(LgcDecrypt):
    VECTOR_SIZE = 16
    

    def __init__(self, key: bytes, init_vector: bytes = JBF_PAK_INIT_VECTOR):
        self.reset(key, init_vector)


    def reset(self, key: bytes, init_vector: bytes = JBF_PAK_INIT_VECTOR):
        self.data_block = copy_sized(init_vector, self.VECTOR_SIZE)
        self.key = copy.copy(key)
        self.tf = Twofish(self.key)


    def get_next(self, x: int) -> int:
        # Twofish configured as a stream cipher.
        tf_result = self.tf.encrypt(self.data_block)  
        self.data_block = self.data_block[1:] + bytes([x])
        y = x ^ tf_result[0]
        return y


@dataclass
class FileEntry:
    offset: int
    size: int 
    key: bytes  # TODO: how are these generated?

    @classmethod
    def from_bytes(cls, data: bytes):
        items = struct.unpack("<IIII", data)  # should've used construct 
        result = FileEntry(items[2], items[3], data[0:8])
        return result

    def read_from_file(self, file: io.BufferedReader):
        file.seek(self.offset, io.SEEK_SET)
        buffer = file.read1(self.size)
        tf = TfDecrypt(self.key)
        buffer_decrypted = tf.decrypt_block(buffer)
        return buffer_decrypted


def compute_key_from_executable(f: io.BufferedReader) -> bytes:
    f.seek(0, io.SEEK_END)
    eof = f.tell()

    key = b"\x00"*8
    offset = 1  # interestingly, not 0...
    while offset < eof:
        f.seek(offset, io.SEEK_SET)
        block = f.read1(8)
        key = bytes((x ^ y for x, y in zip(key, block)))
        offset += 0x4000

    return key


class FailedDecryptHeader(Exception):
    pass


def decrypt_header(
        f: io.BufferedReader, 
        program_stream: Union[io.BufferedReader, None] = None
    ):
    lgc_decrypt = LgcDecrypt()
    tf_decrypt = TfDecrypt(JBF_PAK_HEADER_KEY)
    
    f.seek(0, io.SEEK_SET)
    header = f.read1(JBF_PAK_HEADER_TOTAL_LEN)
    header = lgc_decrypt.decrypt_block(header)
    header = tf_decrypt.decrypt_block(header)

    key = b"\x00"*8

    program_lock_name_len = min(header[0x544], 0x43)
    if program_lock_name_len > 0:
        program_lock_name = \
            decode_as_ascii(header[0x545:0x545+program_lock_name_len])
        
        if not program_stream:
            raise FailedDecryptHeader((
                "Failed to decrypt header - "
                f"package locked to {program_lock_name}.\n"
                "Run this utility again with the option '"
                f"-p {{path to {program_lock_name}}}'."
            ))
        
        key = compute_key_from_executable(program_stream)

    tf_decrypt.reset(key)
    header = tf_decrypt.decrypt_block(header, JBF_PAK_HEADER_MAIN_LEN)
    return header


def decode_as_ascii(data: bytes) -> str:
    result = data.decode("ascii")
    result = re.sub(r"[\x00-\x1f]", "", result)
    result = result.strip()
    return result


class FailedModuleTypecheck(Exception): 
    pass


def decode_protracker(module_buffer) -> Tuple[str, str]:
    try:
        magic_sequence = decode_as_ascii(module_buffer[1080:1084])
    except UnicodeDecodeError as e:
        raise FailedModuleTypecheck from e

    VALID_MAGICS = {
        "M.K.",
        "M!K!",
        "FLT4",
        "FLT8",
        "6CHN",
        "8CHN"
    }

    if magic_sequence not in VALID_MAGICS:
        raise FailedModuleTypecheck

    try:
        name = decode_as_ascii(module_buffer[:20])
    except UnicodeDecodeError as e:
        raise FailedModuleTypecheck from e

    return name, "mod"


def decode_screamtracker(module_buffer) -> Tuple[str, str]:
    try:
        magic_byte = module_buffer[28]
    except IndexError as e:
        raise FailedModuleTypecheck from e

    if magic_byte != 0x1A:
        raise FailedModuleTypecheck

    try:
        name = decode_as_ascii(module_buffer[:28])
    except UnicodeDecodeError as e:
        raise FailedModuleTypecheck from e

    return name, "s3m"


def decode_fasttracker(module_buffer) -> Tuple[str, str]:
    try:
        magic_sequence = decode_as_ascii(module_buffer[:16])
    except UnicodeDecodeError as e:
        raise FailedModuleTypecheck from e

    if magic_sequence.lower() != "extended module:":
        raise FailedModuleTypecheck

    try:
        name = decode_as_ascii(module_buffer[17:37])
    except UnicodeDecodeError as e:
        raise FailedModuleTypecheck from e

    return name, "xm"


def decode_impulsetracker(module_buffer) -> Tuple[str, str]:
    try:
        magic_sequence = decode_as_ascii(module_buffer[0:4])
    except UnicodeDecodeError as e:
        raise FailedModuleTypecheck from e

    # "IMPM" as a magic number was inferred through observation.
    # I couldn't locate the spec (though I certainly didn't try too hard).
    if magic_sequence != "IMPM":  
        raise FailedModuleTypecheck

    try:
        name = decode_as_ascii(module_buffer[4:30])
    except UnicodeDecodeError as e:
        raise FailedModuleTypecheck from e

    return name, "it"


def determine_module_type(module_buffer: bytes):
    # All of the methods here are incredibly naive and could
    # stand to be improved. Stripped XM files will fail to 
    # be detected as such. 
    # Only includes MOD, S3M, XM and IT
    decode_functions = (
        decode_protracker,
        decode_screamtracker,
        decode_fasttracker,
        decode_impulsetracker
    )

    name = ""
    module_type = ""

    for decode_function in decode_functions:
        success_flag = True 
        try:
            name, module_type = decode_function(module_buffer)
        except FailedModuleTypecheck:
            success_flag = False
            name = ""
            module_type = "bin"  # TODO: make extensionless by default?

        if success_flag:
            break

    return name, module_type


def save_module(module_buffer: bytes, index: int, directory: str = "") -> str:
    filename, filetype = determine_module_type(module_buffer)
    # kill invalid filename chars
    filename = re.sub(r"[\\./*?:\"<>|!\x00-\x1f]", "", filename).strip()

    # there is likely a cleaner way to do this without branching...
    if filename: 
        filename = f"{index} {filename}" 
    else:
        filename = f"{index}"

    if filetype:
        filename = ".".join((filename, filetype))
    
    if not os.path.exists(directory):
        os.makedirs(directory)

    filepath = os.path.join(directory, filename)
    with open(filepath, "wb") as f_out:
        f_out.write(module_buffer)

    return filename


def extract_pak(
        f: io.BufferedReader, 
        directory = "",
        program_stream: Union[io.BufferedReader, None] = None
    ):
    # get the filesize
    f.seek(0, io.SEEK_END)
    eof = f.tell()
    f.seek(0, io.SEEK_SET)

    header = decrypt_header(f, program_stream)

    header_info_len = header[0x441]
    header_info = ""
    try:
        header_info = decode_as_ascii(header[0x442:0x442+header_info_len])
    except UnicodeDecodeError:
        header_info = ""
    if len(header_info) > 0:
        print("Pack Info:")  # should use logging not print...
        print(f"{textwrap.fill(header_info, 80)}")
        print("")

    num_modules_found = 0

    for index in range(JBF_PAK_NUM_INDICES):
        # this whole routine could eventually be done using construct...
        offset = 16 * index
        entry_raw = header[offset:offset+16]
        entry = FileEntry.from_bytes(entry_raw)
        if entry.size != 0 and entry.offset + entry.size <= eof:
            module_buffer = entry.read_from_file(f)
            filename = save_module(module_buffer, index, directory)
            print(f"Extracted: {filename}")  
            num_modules_found += 1

    print("")  # grug newline
    print(f"Search complete. Extracted {num_modules_found} modules.")

