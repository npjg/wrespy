#!/usr/bin/python3

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
    print(f"Detected NE file: {filepath}")
    executable.export_resources(output_dir)

def main():
    parser = argparse.ArgumentParser(description='Extract resources from PE or NE files')
    parser.add_argument('input_file', help='Path to the PE or NE file')
    parser.add_argument('output_dir', help='Directory to extract resources to')
    args = parser.parse_args()

    filepath = args.input_file
    output_dir = args.output_dir

    # DETECT THE FILE TYPE.
    # We will first assume this is a PE file, and if loading as a PE fails we will try reading as an NE file.
    try:
        # Try to load as PE file. We are not currently using the
        executable = pefile.PE(filepath)
        print(f"Detected PE file: {filepath}")
        extract_pe_resources(filepath, output_dir)

    except pefile.PEFormatError:
        # Not a PE file, try NE.
        try:
            extract_ne_resources(filepath, output_dir)

        except nefile.NEFormatError:
            print(f"Skipping {filepath}: Not a valid PE or NE file", file = sys.stderr)

if __name__ == '__main__':
    main()