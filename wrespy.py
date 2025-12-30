#!/usr/bin/python3

# The main purpose of this script is bulk-exporting resources (especially graphical resources)
# from old Windows executables (both PE and NE).

import argparse
import subprocess
import sys
import pefile
# For development purposes, we can install a local version of the library with this:
#  pipenv install -e ../nefile
import nefile

def extract_pe_resources(filepath, output_dir):
    """Extract resources from a PE file using wrestool."""
    try:
        subprocess.run(['wrestool', '--extract', '--raw', '--output', output_dir, filepath],
                     check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running wrestool: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print("Error: wrestool not found. Please install icoutils.", file=sys.stderr)
        sys.exit(1)

def extract_ne_resources(filepath, output_dir):
    """Extract resources from an NE file using nefile."""
    executable = nefile.NE(filepath)
    print(f"NE: {filepath}")
    executable.export_resources(output_dir)

def main():
    parser = argparse.ArgumentParser(description='Extract resources from Windows executables (PE or NE)')
    parser.add_argument('input_filepath', help='Path to the Windows executable')
    parser.add_argument('output_directory_path', help='Path to directory where resources should be extracted')
    args = parser.parse_args()

    input_filepath = args.input_filepath
    output_directory_path = args.output_directory_path

    # DETECT THE FILE TYPE.
    # We will first assume this is a PE file, and if loading as a PE fails we will try reading as an NE file.
    try:
        # Try to load as PE file. We are not currently using the pefile library to extract the resources; just
        # to check the format. But in the longer term, we should have our own extraction and not use wrestool
        # because of the well-known issues with it.
        executable = pefile.PE(input_filepath)
        print(f"PE: {input_filepath}")
        extract_pe_resources(input_filepath, output_directory_path)

    except pefile.PEFormatError:
        # Not a PE file, try NE.
        try:
            extract_ne_resources(input_filepath, output_directory_path)

        except nefile.NEFormatError:
            print(f"Skipping {input_filepath}: Not a valid PE or NE file", file = sys.stderr)

if __name__ == '__main__':
    main()