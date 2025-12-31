#!/usr/bin/python3

# The main purpose of this script is bulk-exporting resources (especially graphical resources)
# from old Windows executables (both PE and NE).

import argparse
import os
import subprocess
import sys
import pefile
import hashlib
import shutil
import tempfile

# Function to calculate the hash of the first 4096 bytes of a file.
# This should be sufficient to uniquely distinguish most things where the names are the same.
def calculate_file_hash(filepath):
    """Calculate the SHA256 hash of the first 4096 bytes of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        chunk = f.read(4096)
        sha256.update(chunk)
    return sha256.hexdigest()

# Updated extract_pe_resources function to handle hash collisions by appending a number to the directory name
def extract_with_wrestool(filepath, output_dir):
    """Extract resources from a PE file using wrestool."""
    try:
        # CREATE THE UNIQUE DIRECTORY PATH FOR RESOURCES FROM THIS FILE.
        # Calculate the hash of the start of the file.
        file_hash = calculate_file_hash(filepath)
        filename = os.path.basename(filepath)
        base_output_dir = os.path.join(output_dir, f"{filename} - {file_hash}")
        hash_output_dir = base_output_dir
        # Ensure the directory name is unique by appending a number if necessary.
        counter = 1
        while os.path.exists(hash_output_dir):
            hash_output_dir = f"{base_output_dir}-{counter}"
            counter += 1
        # Now, we can actually create the directory.
        os.makedirs(hash_output_dir, exist_ok=True)

        # DEFINE TYPES THAT WE WANT TO REMOVE.
        # These are not graphical types, and so I am not interested in them.
        resource_type_ids_to_exclude = [
            4, # RT_MENU
            5, # RT_DIALOG
            6, # RT_STRING
            7, # RT_FONTDIR
            8, # RT_FONT
            9, # RT_ACCELERATOR
            10, # RT_RCDATA
            11, # RT_MESSAGETABLE
            16, # RT_VERSION
        ]
        exclude_args = [f"--type=-{resource_type}" for resource_type in resource_type_ids_to_exclude]
        # TODO: This doesn't seem to be working as expected. Maybe wrestool doesn't handle the arguments
        # like I think it does?
        exclude_args = []

        # EXTRACT THE RESOURCES.
        # This gets all resources (including the ones that wrestool can't process). However,
        # bitmaps and icons and such don't have the proper icons written, so we need another pass.
        subprocess.run([
            'wrestool', '--extract', '--raw', *exclude_args, '--output', hash_output_dir, filepath],
            check=True)
        # This now gets the resources wrestool CAN process - we will overwrite the old raw
        # files for the images that wrestool can process.
        subprocess.run([
            'wrestool', '--extract', *exclude_args, '--output', hash_output_dir, filepath],
            check=True)

        # FIX AVI FILE NAMES.
        # Wrestool doesn't add these extensions appropriately, so we will add them after the fact.
        for root, dirs, files in os.walk(hash_output_dir):
            for file in files:
                if '_AVI_' in file and not file.lower().endswith('.avi'):
                    old_path = os.path.join(root, file)
                    new_path = f"{old_path}.avi"
                    os.rename(old_path, new_path)

        # REMOVE THE DIRECTORY IF IT IS EMPTY.
        if not os.listdir(hash_output_dir):
            shutil.rmtree(hash_output_dir)

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

# Updated process_file function to handle CAB files
def process_file(filepath, output_dir):
    """Process a single file and extract resources if it's a valid PE, NE, or CAB file."""
    # Check if the file is a CAB file
    # TODO: Handle other common installation archive types.
    if filepath.lower().endswith('.cab'):
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                # Extract the CAB file into a temporary directory
                subprocess.run(['cabextract', '-d', temp_dir, filepath], check=True)

                # Process each file inside the extracted CAB directory
                for root, dirs, files in os.walk(temp_dir):
                    for filename in files:
                        extracted_file_path = os.path.join(root, filename)
                        process_file(extracted_file_path, output_dir)
            except subprocess.CalledProcessError as e:
                print(f"Error extracting CAB file: {e}", file=sys.stderr)
                sys.exit(1)
            except FileNotFoundError:
                print("Error: cabextract not found. Please install it.", file=sys.stderr)
                sys.exit(1)
        return

    # Otherwise, attempt to extract any resources that might be in here.
    extract_resources(filepath, output_dir)

# Currently we are trying to extract just with wrestool and not using nefile for now.
# That might actually be sufficient for our needs.
def extract_resources(filepath, output_dir):
    extract_with_wrestool(filepath, output_dir)

# This is currently not used, as the issues with wrestool maybe were resolved? Not sure yet.
def extract_resources_with_wrestool_or_nefile(filepath, output_dir):
    # For development purposes, we can install a local version of the library with this:
    #  pipenv install -e ../nefile
    import nefile

    # DETECT THE FILE TYPE.
    # We will first assume this is a PE file, and if loading as a PE fails we will try reading as an NE file.
    try:
        # Try to load as PE file. We are not currently using the pefile library to extract the resources; just
        # to check the format. But in the longer term, we should have our own extraction and not use wrestool
        # because of the well-known issues with it.
        executable = pefile.PE(filepath)
        print(f"PE: {filepath}")
        extract_with_wrestool(filepath, output_dir)

    except pefile.PEFormatError:
        # Not a PE file, try NE.
        try:
            extract_ne_resources(filepath, output_dir)

        except:
            # Not a valid PE or NE file, so just skip it.
            print(f"Skipped: {filepath}")

def process_path(input_path, output_dir):
    """Process a file or directory recursively."""
    if os.path.isfile(input_path):
        process_file(input_path, output_dir)

    elif os.path.isdir(input_path):
        for root, dirs, files in os.walk(input_path):
            for filename in files:
                filepath = os.path.join(root, filename)
                process_file(filepath, output_dir)
    else:
        print(f"Error: {input_path} is not a valid file or directory", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Extract resources from Windows executables (PE or NE)')
    parser.add_argument('input_filepath', help='Path to a Windows executable or directory containing such executables. Files that are not PE or NE files will be ignored.')
    # TODO: Maybe the path should be the name of the file and the hash of the file? So we can put everything into
    # one directory to make things easier to find.
    parser.add_argument('output_directory_path', help='Path to directory where resources should be extracted.')
    args = parser.parse_args()

    input_filepath = args.input_filepath
    output_directory_path = args.output_directory_path
    process_path(input_filepath, output_directory_path)

if __name__ == '__main__':
    main()