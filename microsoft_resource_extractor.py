#!/usr/bin/python3

import pefile
import nefile

# DETECT THE FILE TYPE.
# We will first assume this is a PE file, and if
# loading as a PE fails we will try reading as an
# NE file.
is_pe_file: bool = False
executable = None
filepath = '/home/npgentry/virt/shares/WINDOWS/SYSTEM/SHELL.DLL'
try:
    is_pe_file = True
    executable = pefile.PE(filepath)
except pefile.PEFormatError:
    try:
        executable = nefile.NE(filepath)
    except nefile.NEFormatError:
        # Print both the PE and NE errors.
        pass