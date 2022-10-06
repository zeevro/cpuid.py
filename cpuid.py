#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#     Copyright (c) 2018 Anders Høst
#

from __future__ import print_function

import ctypes
from ctypes import c_uint32, c_int, c_long, c_ulong, c_size_t, c_void_p, POINTER, CFUNCTYPE
import os
import platform
import struct


VERSION = '20221006'


# Posix x86_64:
# Three first call registers : RDI, RSI, RDX
# Volatile registers         : RAX, RCX, RDX, RSI, RDI, R8-11

# Windows x86_64:
# Three first call registers : RCX, RDX, R8
# Volatile registers         : RAX, RCX, RDX, R8-11

# cdecl 32 bit:
# Three first call registers : Stack (%esp)
# Volatile registers         : EAX, ECX, EDX

_POSIX_64_OPC = [
        0x53,                    # push   %rbx
        0x89, 0xf0,              # mov    %esi,%eax
        0x89, 0xd1,              # mov    %edx,%ecx
        0x0f, 0xa2,              # cpuid
        0x89, 0x07,              # mov    %eax,(%rdi)
        0x89, 0x5f, 0x04,        # mov    %ebx,0x4(%rdi)
        0x89, 0x4f, 0x08,        # mov    %ecx,0x8(%rdi)
        0x89, 0x57, 0x0c,        # mov    %edx,0xc(%rdi)
        0x5b,                    # pop    %rbx
        0xc3                     # retq
]

_WINDOWS_64_OPC = [
        0x53,                    # push   %rbx
        0x89, 0xd0,              # mov    %edx,%eax
        0x49, 0x89, 0xc9,        # mov    %rcx,%r9
        0x44, 0x89, 0xc1,        # mov    %r8d,%ecx
        0x0f, 0xa2,              # cpuid
        0x41, 0x89, 0x01,        # mov    %eax,(%r9)
        0x41, 0x89, 0x59, 0x04,  # mov    %ebx,0x4(%r9)
        0x41, 0x89, 0x49, 0x08,  # mov    %ecx,0x8(%r9)
        0x41, 0x89, 0x51, 0x0c,  # mov    %edx,0xc(%r9)
        0x5b,                    # pop    %rbx
        0xc3                     # retq
]

_CDECL_32_OPC = [
        0x53,                    # push   %ebx
        0x57,                    # push   %edi
        0x8b, 0x7c, 0x24, 0x0c,  # mov    0xc(%esp),%edi
        0x8b, 0x44, 0x24, 0x10,  # mov    0x10(%esp),%eax
        0x8b, 0x4c, 0x24, 0x14,  # mov    0x14(%esp),%ecx
        0x0f, 0xa2,              # cpuid
        0x89, 0x07,              # mov    %eax,(%edi)
        0x89, 0x5f, 0x04,        # mov    %ebx,0x4(%edi)
        0x89, 0x4f, 0x08,        # mov    %ecx,0x8(%edi)
        0x89, 0x57, 0x0c,        # mov    %edx,0xc(%edi)
        0x5f,                    # pop    %edi
        0x5b,                    # pop    %ebx
        0xc3                     # ret
]

is_windows = os.name == "nt"
is_64bit   = ctypes.sizeof(ctypes.c_voidp) == 8


class CPUID_struct(ctypes.Structure):
    _fields_ = [(r, c_uint32) for r in ("eax", "ebx", "ecx", "edx")]


class CPUID(object):
    def __init__(self):
        if platform.machine() not in ("AMD64", "x86_64", "x86", "i686"):
            raise SystemError("Only available for x86")

        if is_windows:
            if is_64bit:
                # VirtualAlloc seems to fail under some weird
                # circumstances when ctypes.windll.kernel32 is
                # used under 64 bit Python. CDLL fixes this.
                self.win = ctypes.CDLL("kernel32.dll")
                opc = _WINDOWS_64_OPC
            else:
                # Here ctypes.windll.kernel32 is needed to get the
                # right DLL. Otherwise it will fail when running
                # 32 bit Python on 64 bit Windows.
                self.win = ctypes.windll.kernel32
                opc = _CDECL_32_OPC
        else:
            opc = _POSIX_64_OPC if is_64bit else _CDECL_32_OPC

        size = len(opc)
        code = (ctypes.c_ubyte * size)(*opc)

        if is_windows:
            self.win.VirtualAlloc.restype = c_void_p
            self.win.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
            self.addr = self.win.VirtualAlloc(None, size, 0x1000, 0x40)
            if not self.addr:
                raise MemoryError("Could not allocate RWX memory")
        else:
            self.libc = ctypes.cdll.LoadLibrary(None)
            self.libc.valloc.restype = ctypes.c_void_p
            self.libc.valloc.argtypes = [ctypes.c_size_t]
            self.addr = self.libc.valloc(size)
            if not self.addr:
                raise MemoryError("Could not allocate memory")

            self.libc.mprotect.restype = c_int
            self.libc.mprotect.argtypes = [c_void_p, c_size_t, c_int]
            ret = self.libc.mprotect(self.addr, size, 1 | 2 | 4)
            if ret != 0:
                raise OSError("Failed to set RWX")


        ctypes.memmove(self.addr, code, size)

        func_type = CFUNCTYPE(None, POINTER(CPUID_struct), c_uint32, c_uint32)
        self.func_ptr = func_type(self.addr)

    def __call__(self, eax, ecx=0):
        s = CPUID_struct()
        self.func_ptr(s, eax, ecx)
        return s.eax, s.ebx, s.ecx, s.edx

    def __del__(self):
        if is_windows:
            self.win.VirtualFree.restype = c_long
            self.win.VirtualFree.argtypes = [c_void_p, c_size_t, c_ulong]
            self.win.VirtualFree(self.addr, 0, 0x8000)
        elif self.libc:
            # Seems to throw exception when the program ends and
            # libc is cleaned up before the object?
            self.libc.free.restype = None
            self.libc.free.argtypes = [c_void_p]
            self.libc.free(self.addr)


cpuid = CPUID()


WORD_EAX, WORD_EBX, WORD_ECX, WORD_EDX = 0, 1, 2, 3

VENDOR_UNKNOWN = 0
VENDOR_INTEL = 1
VENDOR_AMD = 2
VENDOR_CYRIX = 3
VENDOR_VIA = 4
VENDOR_TRANSMETA = 5
VENDOR_UMC = 6
VENDOR_NEXGEN = 7
VENDOR_RISE = 8
VENDOR_SIS = 9
VENDOR_NSC = 10
VENDOR_VORTEX = 11
VENDOR_RDC = 12
VENDOR_HYGON = 13
VENDOR_ZHAOXIN = 14

VENDORS = {
    b'GenuineIntel': VENDOR_INTEL,
    b'AuthenticAMD': VENDOR_AMD,
    b'CyrixInstead': VENDOR_CYRIX,
    b'CentaurHauls': VENDOR_VIA,
    b'UMC UMC UMC ': VENDOR_TRANSMETA,
    b'NexGenDriven': VENDOR_UMC,
    b'RiseRiseRise': VENDOR_NEXGEN,
    b'GenuineTMx86': VENDOR_RISE,
    b'SiS SiS SiS ': VENDOR_SIS,
    b'Geode by NSC': VENDOR_NSC,
    b'Vortex86 SoC': VENDOR_VORTEX,
    b'Genuine  RDC': VENDOR_RDC,
    b'HygonGenuine': VENDOR_HYGON,
    b'  Shanghai  ': VENDOR_ZHAOXIN,
}

HYPERVISOR_UNKNOWN = 0
HYPERVISOR_VMWARE = 1
HYPERVISOR_XEN = 2
HYPERVISOR_KVM = 3
HYPERVISOR_MICROSOFT = 4
HYPERVISOR_ACRN = 5

HYPERVISORS = {
    b'VMwareVMware': HYPERVISOR_VMWARE,
    b'XenVMMXenVMM': HYPERVISOR_XEN,
    b'KVMKVMKVM\0\0\0': HYPERVISOR_KVM,
    b'Microsoft Hv': HYPERVISOR_MICROSOFT,
    b'ACRNACRNACRN': HYPERVISOR_ACRN,
}


def IS_HYPERVISOR_LEAF(reg, want):
   return 0x4000000 <= reg < 0x40010000 and reg & 0xff == want


def get_named_id(words, d):
    return d.get(struct.pack('<III', words[WORD_EBX], words[WORD_EDX], words[WORD_ECX]), 0)


def print_reg(reg, words, try_, stash):
    if reg == 0:
        stash['vendor'] = get_named_id(words, VENDORS)
    elif reg == 1:
        stash['val_1_eax'] = words[WORD_EAX]
        stash['val_1_ebx'] = words[WORD_EBX]
        stash['val_1_ecx'] = words[WORD_ECX]
        stash['val_1_edx'] = words[WORD_EDX]
    elif reg == 4:
        stash['saw_4'] = True
        if try_ == 0:
            stash['val_4_eax'] = words[WORD_EAX]
    elif reg == 0xb:
        stash['saw_b'] = True
        if try_ < len(stash['val_b_eax']):
            stash['val_b_eax'][try_] = words[WORD_EAX]
        if try_ < len(stash['val_b_ebx']):
            stash['val_b_ebx'][try_] = words[WORD_EBX]
    elif reg == 0x1f:
        stash['saw_1f'] = True
        if try_ < len(stash['val_1f_eax']):
            stash['val_1f_eax'][try_] = words[WORD_EAX]
        if try_ < len(stash['val_1f_ebx']):
            stash['val_1f_ebx'][try_] = words[WORD_EBX]
        if try_ < len(stash['val_1f_ecx']):
            stash['val_1f_ecx'][try_] = words[WORD_ECX]
    elif IS_HYPERVISOR_LEAF(reg, 0):
        stash['hypervisor'] = get_named_id(words, HYPERVISORS)
    elif reg == 0x80000008:
        stash['val_80000008_ecx'] = words[WORD_ECX]
    elif reg == 0x8000001e:
        stash['val_8000001e_ebx'] = words[WORD_EBX]
    elif reg == 0x80860003:
        stash['transmeta_info'] = struct.pack('<IIII', *words) + stash['transmeta_info'][16:]
    elif reg == 0x80860004:
        stash['transmeta_info'] = stash['transmeta_info'][:16] + struct.pack('<IIII', *words) + stash['transmeta_info'][32:]
    elif reg == 0x80860005:
        stash['transmeta_info'] = stash['transmeta_info'][:32] + struct.pack('<IIII', *words) + stash['transmeta_info'][48:]
    elif reg == 0x80860006:
        stash['transmeta_info'] = stash['transmeta_info'][:48] + struct.pack('<IIII', *words)

    print('   0x{:08x} 0x{:02x}: eax=0x{:08x} ebx=0x{:08x} ecx=0x{:08x} edx=0x{:08x}'.format(reg, try_, *words))


def main():
    import argparse
    p = argparse.ArgumentParser(add_help=False)
    # p.add_argument('-1', '--one-cpu', action='store_true', help="display information only for the current CPU")
    # p.add_argument('-f', '--file', help="read raw hex information (-r output) from FILE instead of from executions of the cpuid instruction. If FILE is '-', read from stdin.")
    p.add_argument('-l', '--leaf', metavar='V', type=lambda s: int(s, 0), help="display information for the single specified leaf. If -s/--subleaf is not specified, 0 is assumed.")
    p.add_argument('-s', '--subleaf', metavar='V', type=lambda s: int(s, 0), help="display information for the single specified subleaf. It requires -l/--leaf.")
    p.add_argument('-h', '-H', '--help', action='help', help="display this help information")
    # p.add_argument('-i', '--inst', action='store_const', dest='method', const='inst', default='inst', help="use the CPUID instruction: The information it provides is reliable. It is not necessary to be root. (This option is the default.)")
    # p.add_argument('-k', '--kernel', action='store_const', dest='method', const='kernel', help="use the CPUID kernel module: The information does not seem to be reliable on all combinations of CPU type and kernel version. Typically, it is necessary to be root.")
    # p.add_argument('-r', '--raw', action='store_true', help="display raw hex information with no decoding")
    p.add_argument('-v', '--version', action='version', version='cpuid.py version {}'.format(VERSION), help="display cpuid.py version")
    args = p.parse_args()

    # if args.method == 'kernel':
    #     p.error("Using CPUID kernel module is not supported.")

    if args.subleaf is not None and args.leaf is None:
        p.error("-s/--subleaf requires that -l/--leaf also be specified")

    stash = {
        'vendor': 0,
        'saw_4': False,
        'saw_b': False,
        'saw_1f': False,
        'val_0_eax': 0,
        'val_1_eax': 0,
        'val_1_ebx': 0,
        'val_1_ecx': 0,
        'val_1_edx': 0,
        'val_4_eax': 0,
        'val_b_eax': [0, 0],
        'val_b_ebx': [0, 0],
        'val_1f_eax': [0, 0, 0, 0, 0, 0],
        'val_1f_ebx': [0, 0, 0, 0, 0, 0],
        'val_1f_ecx': [0, 0, 0, 0, 0, 0],
        'val_80000001_eax': 0,
        'val_80000001_ebx': 0,
        'val_80000001_ecx': 0,
        'val_80000001_edx': 0,
        'val_80000008_ecx': 0,
        'val_8000001e_ebx': 0,
        'transmeta_proc_rev': 0,
        'brand': '',
        'transmeta_info': b'\0'*64,
        'override_brand': '',
        'soc_brand': '',
        'hypervisor': 0,

        'mp': {
            'method': None,
            'cores': None,
            'hyperthreads': None,
        },

        'br': {
            'mobile': None,

            # Intel
            'celeron': False,
            'core': False,
            'pentium': False,
            'atom': False,
            'xeon_mp': False,
            'xeon': False,
            'pentium_m': False,
            'pentium_d': False,
            'extreme': False,
            'generic': False,
            'scalable': False,
            'u_line': False,
            'y_line': False,
            'g_line': False,
            'i_8000': False,
            'i_10000': False,
            'cc150': False,

            # AMD
            'athlon_lv': False,
            'athlon_xp': False,
            'duron': False,
            'athlon': False,
            'sempron': False,
            'phenom': False,
            'series': False,
            'a_series': False,
            'c_series': False,
            'e_series': False,
            'g_series': False,
            'r_series': False,
            'z_series': False,
            'geode': False,
            'turion': False,
            'neo': False,
            'athlon_fx': False,
            'athlon_mp': False,
            'duron_mp': False,
            'opteron': False,
            'fx': False,
            'firepro': False,
            'ultra': False,
            't_suffix': False,
            'ryzen': False,
            'threadripper': False,
            'epyc': False,
            'epyc_3000': False,
            'montage': False,

            'embedded': False,
            'embedded_V': False,
            'embedded_R': False,
            'cores': 0,

            # Cyrix
            'mediagx': False,

            # VIA
            'c7': False,
            'c7m': False,
            'c7d': False,
            'eden': False,
            'zhaoxin': False,
        },

        'bri': {
            'desktop_pentium': False,
            'desktop_celeron': False,
            'mobile_pentium': False,
            'mobile_pentium_m': False,
            'mobile_celeron': False,
            'xeon_mp': False,
            'xeon': False,
        },

        'L2_4w_1Mor2M': False,
        'L2_4w_512K': False,
        'L2_4w_256K': False,
        'L2_8w_1Mor2M': False,
        'L2_8w_512K': False,
        'L2_8w_256K': False,
        'L2_2M': False,
        'L2_6M': False,
        'L3': False,
        'L2_256K': False,
        'L2_512K': False,
    }

    print('CPU:')

    if args.leaf is not None:
        reg = args.leaf
        try_ = args.subleaf or 0
        words = cpuid(reg, try_)
        print_reg(reg, words, try_, stash)
        return

    max_ = 0
    reg = 0
    while reg <= max_:
        words = cpuid(reg)
        try_ = 0

        if reg == 0:
            max_ = words[WORD_EAX]

        if reg == 2:
            max_tries = words[WORD_EAX] & 0xff
            while 1:
                print_reg(reg, words, try_, stash)
                try_ += 1
                if try_ >= max_tries:
                    break
                words = cpuid(reg)
        elif reg == 4:
            while 1:
                print_reg(reg, words, try_, stash)
                if words[WORD_EAX] & 0x1f == 0:
                    break
                try_ += 1
                words = cpuid(reg, try_)
        elif reg == 7:
            max_tries = words[WORD_EAX] & 0xff
            while 1:
                print_reg(reg, words, try_, stash)
                try_ += 1
                if try_ > max_tries:
                    break
                words = cpuid(reg, try_)
        elif reg == 0xb:
            while 1:
                print_reg(reg, words, try_, stash)
                if (words[WORD_ECX] >> 8) & 0xff == 0:
                    break
                try_ += 1
                words = cpuid(reg, try_)
        elif reg == 0xd:
            print_reg(reg, words, 0, stash)
            valid_xcr0 = words[WORD_EDX] << 32 | words[WORD_EAX]
            words = cpuid(reg, 1)
            print_reg(reg, words, 1, stash)
            valid_xss = words[WORD_EDX] << 32 | words[WORD_ECX]
            valid_tries = valid_xcr0 | valid_xss
            for try_ in range(2, 63):
                if valid_tries & (1 << try_):
                    words = cpuid(reg, try_)
                    print_reg(reg, words, try_, stash)
        elif reg == 0xf:
            mask = words[WORD_EDX]
            print_reg(reg, words, 0, stash)
            if (mask >> 1) & 0x1:
                words = cpuid(reg, 1)
                print_reg(reg, words, 1, stash)
        elif reg == 0x10:
            mask = words[WORD_EBX]
            print_reg(reg, words, 0, stash)
            for try_ in range(1, 32):
                if mask & (1 << try_):
                    words = cpuid(reg, try_)
                    print_reg(reg, words, try_, stash)
        elif reg == 0x12:
            print_reg(reg, words, 0, stash)
            words = cpuid(reg, 1)
            print_reg(reg, words, 1, stash)
            try_ = 2
            while 1:
                words = cpuid(reg, try_)
                print_reg(reg, words, try_, stash)
                if words[WORD_EAX] & 0xf == 0:
                    break
                try_ += 1
        elif reg == 0x14:
            max_tries = words[WORD_EAX]
            while 1:
                print_reg(reg, words, try_, stash)
                try_ += 1
                if try_ > max_tries:
                    break
                words = cpuid(reg, try_)
        elif reg == 0x17:
            max_tries = words[WORD_EAX]
            while 1:
                print_reg(reg, words, try_, stash)
                try_ += 1
                if try_ > max_tries:
                    break
                words = cpuid(reg, try_)
        elif reg == 0x18:
            max_tries = words[WORD_EAX]
            while 1:
                print_reg(reg, words, try_, stash)
                try_ += 1
                if try_ > max_tries:
                    break
                words = cpuid(reg, try_)
        elif reg == 0x1b:
            print_reg(reg, words, 0, stash)
            try_ = 1
            while 1:
                words = cpuid(reg, try_)
                print_reg(reg, words, try_, stash)
                if words[WORD_EAX] & 0xfff == 0:
                    break
                try_ += 1
        elif reg == 0x1d:
            max_tries = words[WORD_EAX]
            while 1:
                print_reg(reg, words, try_, stash)
                try_ += 1
                if try_ > max_tries:
                    break
                words = cpuid(reg, try_)
        elif reg == 0x1f:
            print_reg(reg, words, 0, stash)
            for try_ in range(1, 256):
                words = cpuid(reg, try_)
                print_reg(reg, words, try_, stash)
                if (words[WORD_ECX] >> 8) & 0xff == 0:
                    break
        elif reg == 0x20:
            max_tries = words[WORD_EAX]
            while 1:
                print_reg(reg, words, try_, stash)
                try_ += 1
                if try_ > max_tries:
                    break
                words = cpuid(reg, try_)
        elif reg == 0x23:
            max_tries = words[WORD_EAX]
            while 1:
                print_reg(reg, words, try_, stash)
                try_ += 1
                if try_ > max_tries:
                    break
                words = cpuid(reg, try_)
        else:
            print_reg(reg, words, 0, stash)

        reg += 1

    max_ = 0x20000000
    reg = 0x20000000
    while reg <= max_:
        words = cpuid(reg)

        if reg == 0x20000000:
            max_ = words[WORD_EAX]
            if max_ > 0x20000100:
                max_ = 0x20000000

        print_reg(reg, words, 0, stash)

        reg += 1

    if (stash['val_1_ecx'] >> 31) & 0x1:
        for base in range(0x40000000, 0x40010000, 0x100):
            words = cpuid(base)

            print_reg(base, words, 0, stash)

            max_ = words[WORD_EAX]
            if stash['hypervisor'] == HYPERVISOR_KVM and max_ == 0:
                max_ = base + 1

            if stash['hypervisor'] == HYPERVISOR_UNKNOWN and max_ > base + 0x100:
                break
            if max_ < base:
                break

            for reg in range(base+1, max_):
                words = cpuid(reg)

                if IS_HYPERVISOR_LEAF(reg, 3) and stash['hypervisor'] == HYPERVISOR_XEN:
                    try_ = 0
                    while try_ <= 2:
                        print_reg(reg, words, try_, stash)
                        try_ += 1
                        words = cpuid(reg, try_)
                else:
                    print_reg(reg, words, 0, stash)


    max_ = 0x80000000
    reg = 0x80000000
    while reg <= max_:
        words = cpuid(reg)

        if reg == 0x80000000:
            max_ = words[WORD_EAX]

        if reg == 0x8000001d:
            try_ = 0
            while words[WORD_EAX] & 0x1f != 0:
                print_reg(reg, words, try_, stash)
                try_ += 1
                words = cpuid(reg, try_)
        elif reg == 0x80000020:
            mask = words[WORD_EBX]
            print_reg(reg, words, 0, stash)
            for try_ in range(1, 32):
                if mask & (1 << try_):
                    words = cpuid(reg, try_)
                    print_reg(reg, words, try_, stash)
        else:
            print_reg(reg, words, 0, stash)

        reg += 1

    max_ = 0x80860000
    reg = 0x80860000
    while reg <= max_:
        words = cpuid(reg)

        if reg == 0x80860000:
            max_ = words[WORD_EAX]

        print_reg(reg, words, 0, stash)

        reg += 1

    max_ = 0xc0000000
    reg = 0xc0000000
    while reg <= max_:
        words = cpuid(reg)

        if reg == 0xc0000000:
            max_ = words[WORD_EAX]

        if max_ > 0xc0001000:
            max_ = 0xc0000000

        print_reg(reg, words, 0, stash)

        reg += 1


if __name__ == "__main__":
    main()
