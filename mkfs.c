#include "wfs.h"
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdlib.h>

int main(int argc, char *argv[]){
    int mayb;
    int N = 0;
    int mul = 32;
    char *storage_device = NULL;
    int B = 0;
    while ((mayb = getopt(argc, argv, "d:i:b:")) != -1){
        switch (mayb) {
        case 'b':
            B = atoi(optarg);
            if ((B%mul) != 0) {
                B += mul - (B%mul);
            }
            break;
        case 'i':
            N = atoi(optarg);
            if ((N % mul) != 0){
                N += mul - (N % mul);
            }
            break;
        case 'd':
            storage_device = optarg;
            break;
        }
    }
    int df = open(storage_device, O_RDWR | O_CREAT, 0644);
    size_t storeSize, totalBytes, totalBlocks, totalBits;
    storeSize = sizeof(struct wfs_sb);
    size_t stsize = sizeof(unsigned char);
    totalBytes = (N + 7)/8;
    size_t bbblocks = B*BLOCK_SIZE;
    totalBlocks = (N*BLOCK_SIZE);
    size_t tb = B/8;
    totalBits = (B+7)/8;
    struct stat holdInfo;
    fstat(df, &holdInfo);
    size_t m = storeSize+totalBytes+totalBits+totalBlocks+bbblocks;
    if (m > holdInfo.st_size) {
       close(df); 
       return -ENOSPC;
    }
    struct wfs_sb filesystem_info = {
        .d_bitmap_ptr = storeSize + totalBytes, .num_data_blocks = B,
        .i_blocks_ptr = storeSize + totalBytes + totalBits, .num_inodes = N,
        .d_blocks_ptr = storeSize + totalBytes + totalBits + totalBlocks, .i_bitmap_ptr = storeSize
    };

    lseek(df, 0, SEEK_SET);
    write(df, &filesystem_info, storeSize);
    lseek(df, filesystem_info.i_bitmap_ptr, SEEK_SET);
    unsigned char *all = (unsigned char *)calloc(totalBytes, stsize);
    all[0] |= 0x01;
    write(df, all, totalBytes);
    free(all);
    lseek(df, filesystem_info.d_bitmap_ptr, SEEK_SET);
    unsigned char *dall = (unsigned char *)calloc(tb, stsize);
    dall[0] |= 0x01;
    write(df, dall, tb);
    free(dall);

    lseek(df, filesystem_info.i_blocks_ptr, SEEK_SET);
    struct wfs_inode main_directory_inode = {
        .size = BLOCK_SIZE, .atim = time(NULL), .nlinks = 2, .ctim = time(NULL),
        .mode = __S_IFDIR | 0755, .gid = getgid(), .num = 0, .mtim = time(NULL),
        .uid = getuid()};

    main_directory_inode.blocks[0] = filesystem_info.d_blocks_ptr;
    write(df, &main_directory_inode, sizeof(struct wfs_inode));
    off_t i = filesystem_info.i_blocks_ptr + BLOCK_SIZE;
    off_t j = lseek(df, 0, SEEK_END);
    lseek(df, i, SEEK_SET);

    size_t done = j - i;
    void *last = calloc(1, done);
    write(df, last, done);
    free(last);
    close(df);
    return 0;
}
