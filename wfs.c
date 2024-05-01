#include "wfs.h"
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

char *disk;
struct wfs_sb *sb;

off_t make_block()
{
    int i;
    char *bitmap_offset;
    int bit_index;
    int bit_status;
    int total_data_blocks = sb->num_data_blocks;

    for (i = 0; i < total_data_blocks; i++)
    {
        bitmap_offset = disk + sb->d_bitmap_ptr + (i >> 3);
        bit_index = i & 7;

        bit_status = (*bitmap_offset >> bit_index) & 1;

        if (!bit_status)
        {
            int new_value = 1 << bit_index;
            *bitmap_offset = *bitmap_offset | new_value;

            off_t block_address = sb->d_blocks_ptr + i * BLOCK_SIZE;
            return block_address;
        }
    }

    return (off_t)(-1);
}

void free_block(off_t block)
{
    int blockIndex = (block - sb->d_blocks_ptr) / BLOCK_SIZE;
    char *bitmapOffset = disk + sb->d_bitmap_ptr + (blockIndex >> 3);
    char *zeroedBlock = calloc(1, BLOCK_SIZE);

    if (zeroedBlock)
    {
        write(block, zeroedBlock, BLOCK_SIZE);
        free(zeroedBlock);
    }

    int bitMask = 1 << (blockIndex & 7);
    *bitmapOffset &= ~bitMask;
}

int resize_inode(int newSize, struct wfs_inode *inode)
{
    int requiredBlocks = (newSize + BLOCK_SIZE - 1) / BLOCK_SIZE;
    int existingBlocks = (inode->size + BLOCK_SIZE - 1) / BLOCK_SIZE;

    if (requiredBlocks == existingBlocks)
        return 0;

    if (requiredBlocks < existingBlocks)
    {
        for (int i = requiredBlocks; i < existingBlocks; i++)
        {
            free_block(inode->blocks[i]);
            inode->blocks[i] = 0;
        }
    }
    else
    {
        if (requiredBlocks > D_BLOCK)
        {
            if (inode->blocks[D_BLOCK] == 0)
            {
                off_t newBlock = make_block();
                if (newBlock == -1)
                    return -1;

                inode->blocks[D_BLOCK] = newBlock;
            }
        }
        for (int i = existingBlocks; i < requiredBlocks; i++)
        {
            off_t newBlock = make_block();
            if (newBlock == -1)
                return -1;

            if (i < D_BLOCK)
                inode->blocks[i] = newBlock;
            else
            {
                char *indirectBlock = disk + inode->blocks[D_BLOCK];
                off_t *indirectBlockPtr = (off_t *)indirectBlock;
                indirectBlockPtr[i - D_BLOCK] = newBlock;
            }
        }
    }

    inode->size = newSize;
    return 0;
}

void remove_inode(int inodeIndex)
{
    char *bitmapOffset = disk + sb->i_bitmap_ptr + (inodeIndex >> 3);
    int bitPosition = inodeIndex & 7;
    struct wfs_inode *inode = (struct wfs_inode *)(disk + sb->i_blocks_ptr + inodeIndex * BLOCK_SIZE);

    for (int i = 0; i < (inode->size + BLOCK_SIZE - 1) / BLOCK_SIZE; i++)
    {
        free_block(inode->blocks[i]);
    }

    char *zeroedMemory = calloc(1, BLOCK_SIZE);
    if (zeroedMemory)
    {
        write(sb->i_blocks_ptr + inodeIndex * BLOCK_SIZE, zeroedMemory, BLOCK_SIZE);
        free(zeroedMemory);
    }

    *bitmapOffset &= ~(1 << bitPosition);
}

struct wfs_inode *get_inode(const char *path)
{
    struct wfs_inode *baseInode = (struct wfs_inode *)(disk + sb->i_blocks_ptr);
    struct wfs_inode *currentInode = baseInode;
    char *pathDup = strdup(path);

    if (strcmp(pathDup, "/") == 0)
    {
        free(pathDup);
        return currentInode;
    }

    char *segment = strtok(pathDup, "/");

    while (segment != NULL)
    {
        if ((currentInode->mode & __S_IFMT) != __S_IFDIR)
        {
            free(pathDup);
            return NULL;
        }

        int found = 0;

        for (int i = 0; i < (currentInode->size + BLOCK_SIZE - 1) / BLOCK_SIZE; i++)
        {
            struct wfs_dentry *dentryBlock = (struct wfs_dentry *)(disk + currentInode->blocks[i]);
            for (int j = 0; j < BLOCK_SIZE / sizeof(struct wfs_dentry); j++)
            {
                if (strcmp(dentryBlock[j].name, segment) == 0)
                {
                    currentInode = (struct wfs_inode *)(disk + sb->i_blocks_ptr + dentryBlock[j].num * BLOCK_SIZE);
                    found = 1;
                    break;
                }
            }
            if (found)
                break;
        }

        if (!found)
        {
            free(pathDup);
            return NULL;
        }

        segment = strtok(NULL, "/");
    }

    free(pathDup);
    return currentInode;
}

struct wfs_inode *get_parent_inode(const char *path)
{
    if (strcmp(path, "/") == 0 || path[0] == '\0')
    {
        return NULL;
    }

    char *duplicatePath = strdup(path);
    char *finalSlash = strrchr(duplicatePath, '/');

    if (finalSlash == duplicatePath)
    {
        free(duplicatePath);
        return get_inode("/");
    }
    else if (finalSlash != NULL)
    {
        *finalSlash = '\0';
    }

    struct wfs_inode *parent = get_inode(duplicatePath);
    free(duplicatePath);
    return parent;
}

int find_free_inode()
{
    for (int i = 1; i < sb->num_inodes; i++)
    {
        char *bitmapOffset = disk + sb->i_bitmap_ptr + (i >> 3);
        int bitPosition = i & 7;
        if (!((*bitmapOffset >> bitPosition) & 1))
        {
            *bitmapOffset |= 1 << bitPosition;
            return i;
        }
    }
    return -1;
}

int register_inode(struct wfs_inode *parentInode, char *name, int inodeIndex)
{
    for (int i = 0; i < D_BLOCK; i++)
    {
        if (parentInode->blocks[i] == 0)
            resize_inode(parentInode->size + BLOCK_SIZE, parentInode);

        struct wfs_dentry *dentry = (struct wfs_dentry *)(disk + parentInode->blocks[i]);
        for (int j = 0; j < BLOCK_SIZE / sizeof(struct wfs_dentry); j++)
        {
            if (dentry[j].num == 0)
            {
                dentry[j].num = inodeIndex;
                strcpy(dentry[j].name, name);
                return 1;
            }
        }
    }
    return 0;
}

struct wfs_inode *initialize_new_inode(void *inodeAddress, int size, int num)
{
    struct wfs_inode *inode = (struct wfs_inode *)inodeAddress;
    inode->num = num;
    inode->size = size;
    inode->uid = getuid();
    inode->gid = getgid();
    inode->nlinks = 1;
    inode->atim = time(NULL);
    inode->mtim = time(NULL);
    inode->ctim = time(NULL);
    return inode;
}

int allocate_blocks_to_inode(struct wfs_inode *inode, int size)
{
    int numBlocks = (size + BLOCK_SIZE - 1) / BLOCK_SIZE;
    for (int i = 0; i < numBlocks; i++)
    {
        off_t block = make_block();
        if (block == -1)
            return 0;
        inode->blocks[i] = block;
    }
    return 1;
}

struct wfs_inode *allocate_inode(int size, const char *path)
{
    struct wfs_inode *rootInode = (struct wfs_inode *)(disk + sb->i_blocks_ptr);
    char *pathDup = strdup(path);

    char *token = strtok(pathDup, "/");
    struct wfs_inode *currentInode = rootInode;

    while (token)
    {
        char *nextToken = strtok(NULL, "/");
        if (!nextToken)
            break;

        if ((currentInode->mode & __S_IFMT) != __S_IFDIR)
        {
            free(pathDup);
            return NULL;
        }

        int found = 0;
        for (int i = 0; i < (currentInode->size + BLOCK_SIZE - 1) / BLOCK_SIZE; i++)
        {
            struct wfs_dentry *dentry = (struct wfs_dentry *)(disk + currentInode->blocks[i]);
            for (int j = 0; j < BLOCK_SIZE / sizeof(struct wfs_dentry); j++)
            {
                if (!strcmp(dentry[j].name, token))
                {
                    currentInode = (struct wfs_inode *)(disk + sb->i_blocks_ptr + dentry[j].num * BLOCK_SIZE);
                    found = 1;
                    break;
                }
            }
            if (found)
                break;
        }

        if (!found)
        {
            free(pathDup);
            return NULL;
        }

        token = nextToken;
    }

    if ((currentInode->mode & __S_IFMT) != __S_IFDIR || !token)
    {
        free(pathDup);
        return NULL;
    }

    int inodeIndex = find_free_inode();
    if (inodeIndex == -1)
    {
        free(pathDup);
        return NULL;
    }

    if (!register_inode(currentInode, token, inodeIndex))
    {
        free(pathDup);
        return NULL;
    }

    struct wfs_inode *newInode = initialize_new_inode(disk + sb->i_blocks_ptr + inodeIndex * BLOCK_SIZE, size, inodeIndex);
    if (!allocate_blocks_to_inode(newInode, size))
    {
        free(pathDup);
        return NULL;
    }

    free(pathDup);
    return newInode;
}

static int wfs_getattr(const char *path, struct stat *statBuf)
{
    memset(statBuf, 0, sizeof(struct stat));
    struct wfs_inode *currentInode = get_inode(path);
    if (!currentInode)
    {
        return -ENOENT;
    }

    statBuf->st_mode = currentInode->mode;
    statBuf->st_uid = currentInode->uid;
    statBuf->st_gid = currentInode->gid;
    statBuf->st_size = currentInode->size;
    statBuf->st_nlink = currentInode->nlinks;
    statBuf->st_atime = currentInode->atim;
    statBuf->st_mtime = currentInode->mtim;
    statBuf->st_ctime = currentInode->ctim;

    return 0;
}

static int wfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
    struct wfs_inode *newInode = get_inode(path);
    if (newInode != NULL)
    {
        return -EEXIST;
    }

    newInode = allocate_inode(0, path);
    if (newInode == NULL)
    {
        return -ENOSPC;
    }

    newInode->mode = mode;

    return 0;
}

static int wfs_mkdir(const char *path, mode_t mode)
{
    struct wfs_inode *targetInode = get_inode(path);
    if (targetInode)
    {
        return -EEXIST;
    }

    targetInode = allocate_inode(0, path);
    if (!targetInode)
    {
        return -ENOSPC;
    }

    targetInode->mode = __S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR;

    return 0;
}

static int wfs_unlink(const char *path)
{
    struct wfs_inode *targetInode = get_inode(path);
    if (!targetInode)
    {
        return -ENOENT;
    }

    if ((targetInode->mode & __S_IFMT) == __S_IFDIR)
    {
        return -EISDIR;
    }

    struct wfs_inode *parentInode = get_parent_inode(path);
    if (!parentInode)
    {
        return -ENOENT;
    }

    for (int i = 0; i < D_BLOCK; i++)
    {
        if (parentInode->blocks[i] == 0)
        {
            continue;
        }
        struct wfs_dentry *dentry = (struct wfs_dentry *)(disk + parentInode->blocks[i]);
        for (int j = 0; j < BLOCK_SIZE / sizeof(struct wfs_dentry); j++)
        {
            if (dentry[j].num == targetInode->num)
            {
                dentry[j].num = 0;
                dentry[j].name[0] = '\0';
                break;
            }
        }
    }

    resize_inode(parentInode->size - sizeof(struct wfs_dentry), parentInode);

    remove_inode(targetInode->num);

    return 0;
}

static int wfs_rmdir(const char *path)
{
    struct wfs_inode *directoryInode = get_inode(path);
    if (!directoryInode)
    {
        return -ENOENT;
    }

    if ((directoryInode->mode & __S_IFMT) != __S_IFDIR)
    {
        return -ENOTDIR;
    }

    remove_inode(directoryInode->num);

    return 0;
}

static int min(int a, int b)
{
    return (a < b) ? a : b;
}

static int wfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    printf("read\n");
    struct wfs_inode *fileInode = get_inode(path);
    if (!fileInode)
    {
        return -ENOENT;
    }

    if (offset >= fileInode->size)
    {
        return 0;
    }

    int firstBlock = offset / BLOCK_SIZE;
    int lastBlock = (offset + size - 1) / BLOCK_SIZE;
    int startIndex = offset % BLOCK_SIZE;

    int remainingSize = size, totalCopied = 0;

    for (int blockNum = firstBlock; blockNum <= lastBlock && blockNum < (fileInode->size + BLOCK_SIZE - 1) / BLOCK_SIZE; blockNum++)
    {
        int copyOffset = (blockNum == firstBlock) ? startIndex : 0;
        int maxBlockSize = (blockNum < D_BLOCK) ? BLOCK_SIZE : (BLOCK_SIZE / sizeof(off_t));
        int copyAmount = min(BLOCK_SIZE - copyOffset, remainingSize);

        char *sourceBlock;
        if (blockNum < D_BLOCK)
        {
            sourceBlock = disk + fileInode->blocks[blockNum];
        }
        else
        {
            char *indirectBlock = disk + fileInode->blocks[D_BLOCK];
            off_t *indirectBlockPointers = (off_t *)indirectBlock;

            if (blockNum - D_BLOCK >= maxBlockSize)
            {
                continue;
            }

            sourceBlock = disk + indirectBlockPointers[blockNum - D_BLOCK];
        }

        if (!sourceBlock)
        {
            continue;
        }

        memcpy(buf + totalCopied, sourceBlock + copyOffset, copyAmount);
        remainingSize -= copyAmount;
        totalCopied += copyAmount;
    }

    return totalCopied;
}

static int wfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    struct wfs_inode *targetInode = get_inode(path);
    if (!targetInode)
    {
        return -ENOENT;
    }

    if (offset + size > targetInode->size)
    {
        if (resize_inode(offset + size, targetInode) != 0)
        {
            return -ENOSPC;
        }
    }

    int firstBlock = offset / BLOCK_SIZE;
    int lastBlock = (offset + size - 1) / BLOCK_SIZE;
    int writtenBytes = 0;

    for (int i = firstBlock; i <= lastBlock; i++)
    {
        int blockStart = (i == firstBlock) ? (offset % BLOCK_SIZE) : 0;
        int blockLimit = (i == lastBlock) ? ((offset + size) % BLOCK_SIZE) : BLOCK_SIZE;
        if (blockLimit == 0 && i == lastBlock)
            blockLimit = BLOCK_SIZE;

        char *blockAddress;
        if (i < D_BLOCK)
            blockAddress = disk + targetInode->blocks[i];
        else
        {
            char *indirectBlock = disk + targetInode->blocks[D_BLOCK];
            off_t *blockPointers = (off_t *)indirectBlock;
            blockAddress = disk + blockPointers[i - D_BLOCK];
        }

        char buffer[BLOCK_SIZE];
        memcpy(buffer, blockAddress, BLOCK_SIZE);

        int copyLength = blockLimit - blockStart;
        if (i == lastBlock)
        {
            copyLength = size - writtenBytes;
        }

        memcpy(buffer + blockStart, buf + writtenBytes, copyLength);
        memcpy(blockAddress, buffer, BLOCK_SIZE);
        writtenBytes += copyLength;
    }

    return writtenBytes;
}

static int wfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    struct wfs_inode *dirInode = get_inode(path);
    if (!dirInode)
    {
        return -ENOENT;
    }

    if ((dirInode->mode & __S_IFMT) != __S_IFDIR)
    {
        return -ENOTDIR;
    }

    int numBlocks = (dirInode->size + BLOCK_SIZE - 1) / BLOCK_SIZE;
    for (int i = 0; i < numBlocks; i++)
    {
        struct wfs_dentry *entries = (struct wfs_dentry *)(disk + dirInode->blocks[i]);
        int entriesPerBlock = BLOCK_SIZE / sizeof(struct wfs_dentry);
        for (int j = 0; j < entriesPerBlock; j++)
        {
            if (entries[j].num != 0)
            {
                if (filler(buf, entries[j].name, NULL, 0))
                {
                    break;
                }
            }
        }
    }

    return 0;
}

static struct fuse_operations ops = {
    .getattr = wfs_getattr,
    .mknod = wfs_mknod,
    .mkdir = wfs_mkdir,
    .unlink = wfs_unlink,
    .rmdir = wfs_rmdir,
    .read = wfs_read,
    .write = wfs_write,
    .readdir = wfs_readdir,
};

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        return -1; // Ensure disk path is provided
    }

    char *disk_path = argv[1];
    int fd = open(disk_path, O_RDWR);
    if (fd == -1)
    {
        return -1; // Check file descriptor validity
    }

    struct stat st;
    if (fstat(fd, &st) == -1)
    {
        close(fd);
        return -1; // Check status of file
    }

    disk = (char *)mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (disk == MAP_FAILED)
    {
        close(fd);
        return -1; // Handle memory mapping failure
    }

    close(fd);                  // Close file descriptor after successful mapping
    sb = (struct wfs_sb *)disk; // Set global superblock pointer

    return fuse_main(argc - 1, argv + 1, &ops, NULL); // Launch FUSE
}
