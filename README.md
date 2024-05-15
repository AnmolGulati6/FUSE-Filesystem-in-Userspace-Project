### FUSE (Filesystem in Userspace) Project

#### Short Description:
FUSE (Filesystem in Userspace) is a framework enabling the development of custom filesystems in user space, eliminating the need for kernel modifications. This project provides a comprehensive guide and codebase for creating a FUSE-based filesystem in C. It covers filesystem operations like creating files and directories, reading and writing data, removing files and directories, and retrieving file attributes.

#### Readme File:

## FUSE (Filesystem in Userspace) Project

Welcome to the FUSE project! This repository contains everything you need to get started with creating your custom filesystem using FUSE in C.

### Getting Started
To begin, clone this repository to your local machine:

```
git clone https://github.com/AnmolGulati6/FUSE-Filesystem-in-Userspace-Project/
```

### Project Structure
- **mkfs.c**: Initializes a file to an empty filesystem.
- **wfs.c**: Contains the implementation for the FUSE filesystem.
- **wfs.h**: Provides the structures used in the filesystem (do not modify).
- **create_disk.sh**: Script to create a disk image file.
- **umount.sh**: Script to unmount a mount point.
- **Makefile**: Template makefile for compiling your code.

### Usage
1. **Compile**: Use the provided makefile to compile the code.
   ```
   make
   ```
2. **Create Disk**: Run the `create_disk.sh` script to create a disk image.
   ```
   ./create_disk.sh
   ```
3. **Initialize Filesystem**: Use `mkfs` to initialize the disk image with the desired parameters.
   ```
   ./mkfs -d disk.img -i 32 -b 200
   ```
4. **Mount Filesystem**: Create a mount point and mount the filesystem.
   ```
   mkdir mnt
   ./wfs disk.img -f -s mnt
   ```
5. **Interact**: You can now interact with your filesystem in the `mnt` directory.

### Features
- Create empty files and directories
- Read and write to files
- Read directory contents (e.g., `ls`)
- Remove files and empty directories
- Retrieve file attributes

### Debugging
- **Inspect Superblock**: Use `xxd` to inspect the disk image before mounting.
  ```
  xxd -e -g 4 disk.img | less
  ```
- **Printing**: Your filesystem will print to stdout if running in the foreground (`-f`).
- **Debugger**: Run the filesystem in gdb for debugging.
  ```
  gdb --args ./wfs disk.img -f -s mnt
  ```

### Error Handling
Make sure to handle errors appropriately by returning the respective error codes.

### Testing
Manually inspect your filesystem before running tests. Experiment using simple utilities like `mkdir`, `ls`, `touch`, `echo`, `rm`, etc.

### Notes
- Directories will not use the indirect block.
- Valid file/directory names consist of letters (uppercase and lowercase), numbers, and underscores.
- Maximum file name length is 28 characters.

### Contribution
Feel free to contribute to this project by submitting pull requests.

### License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
