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
#include <stdbool.h>

char *disk;
struct wfs_sb *sb;

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

static int calculate_required_blocks(int size)
{
    return (size + BLOCK_SIZE - 1) / BLOCK_SIZE;
}

static void free_excess_blocks(struct wfs_inode *inode, int requiredBlocks, int existingBlocks)
{
    for (int i = requiredBlocks; i < existingBlocks; i++)
    {
        free_block(inode->blocks[i]);
        inode->blocks[i] = 0;
    }
}

static int allocate_additional_blocks(struct wfs_inode *inode, int existingBlocks, int requiredBlocks)
{
    if (requiredBlocks > D_BLOCK && inode->blocks[D_BLOCK] == 0)
    {
        off_t newBlock = make_block();
        if (newBlock == -1)
            return -1;
        inode->blocks[D_BLOCK] = newBlock;
    }

    for (int i = existingBlocks; i < requiredBlocks; i++)
    {
        off_t newBlock = make_block();
        if (newBlock == -1)
            return -1;

        if (i < D_BLOCK)
        {
            inode->blocks[i] = newBlock;
        }
        else
        {
            char *indirectBlock = disk + inode->blocks[D_BLOCK];
            off_t *indirectBlockPtr = (off_t *)indirectBlock;
            indirectBlockPtr[i - D_BLOCK] = newBlock;
        }
    }
    return 0;
}

int resize_inode(int newSize, struct wfs_inode *inode)
{
    int requiredBlocks = calculate_required_blocks(newSize);
    int existingBlocks = calculate_required_blocks(inode->size);

    if (requiredBlocks == existingBlocks)
        return 0;

    if (requiredBlocks < existingBlocks)
    {
        free_excess_blocks(inode, requiredBlocks, existingBlocks);
    }
    else
    {
        int status = allocate_additional_blocks(inode, existingBlocks, requiredBlocks);
        if (status != 0)
            return -1;
    }

    inode->size = newSize;
    return 0;
}

void remove_inode(int inodeIndex)
{
    char *bitmapOffset = disk + sb->i_bitmap_ptr + (inodeIndex >> 3);
    int bitPosition = inodeIndex & 7;
    struct wfs_inode *inode = (struct wfs_inode *)(disk + sb->i_blocks_ptr + inodeIndex * BLOCK_SIZE);
    int numBlocks = (inode->size + BLOCK_SIZE - 1) / BLOCK_SIZE;

    for (int i = 0; i < numBlocks; i++)
    {
        off_t block = inode->blocks[i];
        free_block(block);
    }

    char *zeroedMemory = calloc(1, BLOCK_SIZE);
    off_t blockAddress = sb->i_blocks_ptr + inodeIndex * BLOCK_SIZE;

    if (zeroedMemory)
    {
        write(blockAddress, zeroedMemory, BLOCK_SIZE);
        free(zeroedMemory);
    }

    *bitmapOffset = *bitmapOffset & ~(1 << bitPosition);
}

struct wfs_inode *get_base_inode()
{
    off_t inodeBlocksPtr = (off_t)(disk + sb->i_blocks_ptr);
    return (struct wfs_inode *)inodeBlocksPtr;
}

int is_root_path(const char *path)
{
    return strcmp(path, "/") == 0;
}

int is_directory(struct wfs_inode *inode)
{
    return (inode->mode & __S_IFMT) == __S_IFDIR;
}

struct wfs_inode *search_directory_entries(struct wfs_inode *currentInode, const char *segment)
{
    for (int i = 0; i < (currentInode->size + BLOCK_SIZE - 1) / BLOCK_SIZE; i++)
    {
        struct wfs_dentry *dentryBlock = (struct wfs_dentry *)(disk + currentInode->blocks[i]);
        for (int j = 0; j < BLOCK_SIZE / sizeof(struct wfs_dentry); j++)
        {
            if (strcmp(dentryBlock[j].name, segment) == 0)
            {
                currentInode = (struct wfs_inode *)(disk + sb->i_blocks_ptr + dentryBlock[j].num * BLOCK_SIZE);
                return currentInode;
            }
        }
    }

    return NULL;
}

struct wfs_inode *get_inode(const char *path)
{
    struct wfs_inode *baseInode = get_base_inode();
    struct wfs_inode *currentInode = baseInode;
    char *pathDup = strdup(path);

    if (is_root_path(pathDup))
    {
        free(pathDup);
        return currentInode;
    }

    char *segment = strtok(pathDup, "/");
    while (segment != NULL)
    {
        if (!is_directory(currentInode))
        {
            free(pathDup);
            return NULL;
        }

        currentInode = search_directory_entries(currentInode, segment);
        if (currentInode == NULL)
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

int register_inode(struct wfs_inode *parentInode, const char *name, int inodeIndex)
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

struct wfs_inode *find_target_directory(const char *path)
{
    struct wfs_inode *rootInode = (struct wfs_inode *)(disk + sb->i_blocks_ptr);
    char *pathDup = strdup(path);
    char *token = strtok(pathDup, "/");
    struct wfs_inode *currentInode = rootInode;

    while (token)
    {
        char *nextToken = strtok(NULL, "/");
        if (!nextToken)
        {
            break;
        }

        if ((currentInode->mode & __S_IFMT) != __S_IFDIR)
        {
            free(pathDup);
            return NULL;
        }

        bool found = false;
        for (int i = 0; i < (currentInode->size + BLOCK_SIZE - 1) / BLOCK_SIZE; i++)
        {
            struct wfs_dentry *dentry = (struct wfs_dentry *)(disk + currentInode->blocks[i]);
            for (int j = 0; j < BLOCK_SIZE / sizeof(struct wfs_dentry); j++)
            {
                if (strcmp(dentry[j].name, token) == 0)
                {
                    currentInode = (struct wfs_inode *)(disk + sb->i_blocks_ptr + dentry[j].num * BLOCK_SIZE);
                    found = true;
                    break;
                }
            }
            if (found)
            {
                break;
            }
        }

        if (!found)
        {
            free(pathDup);
            return NULL;
        }

        token = nextToken;
    }

    free(pathDup);
    return (currentInode->mode & __S_IFMT) == __S_IFDIR ? currentInode : NULL;
}

struct wfs_inode *allocate_inode(int size, const char *path)
{
    struct wfs_inode *parentInode = find_target_directory(path);
    if (!parentInode)
    {
        return NULL;
    }

    const char *finalToken = strrchr(path, '/');
    finalToken = finalToken ? finalToken + 1 : path;

    int inodeIndex = find_free_inode();
    if (inodeIndex == -1)
    {
        return NULL;
    }

    if (!register_inode(parentInode, finalToken, inodeIndex))
    {
        return NULL;
    }

    struct wfs_inode *newInode = initialize_new_inode(disk + sb->i_blocks_ptr + inodeIndex * BLOCK_SIZE, size, inodeIndex);
    if (!allocate_blocks_to_inode(newInode, size))
    {
        return NULL;
    }

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

static int validate_inode_with_offset(struct wfs_inode *inode, off_t offset)
{
    if (!inode)
    {
        return -ENOENT;
    }
    if (offset >= inode->size)
    {
        return 0;
    }
    return 1;
}

static void calculate_block_range_and_start_index(off_t offset, size_t size, int *firstBlock, int *lastBlock, int *startIndex)
{
    *firstBlock = offset / BLOCK_SIZE;
    *lastBlock = (offset + size - 1) / BLOCK_SIZE;
    *startIndex = offset % BLOCK_SIZE;
}

char *resolve_block_address(struct wfs_inode *inode, int blockNum)
{
    if (blockNum < D_BLOCK)
    {
        return disk + inode->blocks[blockNum];
    }
    else
    {
        char *indirectBlock = disk + inode->blocks[D_BLOCK];
        off_t *indirectBlockPointers = (off_t *)indirectBlock;
        int maxBlockSize = (BLOCK_SIZE / sizeof(off_t));

        if (blockNum - D_BLOCK >= maxBlockSize)
        {
            return NULL;
        }
        return disk + indirectBlockPointers[blockNum - D_BLOCK];
    }
}

static int read_blocks(char *buf, size_t size, struct wfs_inode *inode, int firstBlock, int lastBlock, int startIndex)
{
    int remainingSize = size, totalCopied = 0;

    for (int blockNum = firstBlock; blockNum <= lastBlock && blockNum < (inode->size + BLOCK_SIZE - 1) / BLOCK_SIZE; blockNum++)
    {
        int copyOffset = (blockNum == firstBlock) ? startIndex : 0;
        char *sourceBlock = resolve_block_address(inode, blockNum);
        if (!sourceBlock)
            continue;

        int copyAmount = min(BLOCK_SIZE - copyOffset, remainingSize);
        memcpy(buf + totalCopied, sourceBlock + copyOffset, copyAmount);
        remainingSize -= copyAmount;
        totalCopied += copyAmount;
    }
    return totalCopied;
}

static int wfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    printf("read\n");
    struct wfs_inode *fileInode = get_inode(path);
    int valid = validate_inode_with_offset(fileInode, offset);
    if (valid <= 0)
    {
        return valid; // This will handle both -ENOENT and 0 cases.
    }

    int firstBlock, lastBlock, startIndex;
    calculate_block_range_and_start_index(offset, size, &firstBlock, &lastBlock, &startIndex);

    return read_blocks(buf, size, fileInode, firstBlock, lastBlock, startIndex);
}

static int validate_inode(struct wfs_inode *inode)
{
    if (!inode)
    {
        return -ENOENT;
    }
    return 0;
}

static int resize_if_needed(off_t new_size, struct wfs_inode *inode)
{
    if (new_size > inode->size)
    {
        return resize_inode(new_size, inode);
    }
    return 0;
}

static void calculate_block_range(off_t offset, size_t size, int *firstBlock, int *lastBlock)
{
    *firstBlock = offset / BLOCK_SIZE;
    *lastBlock = (offset + size - 1) / BLOCK_SIZE;
}

static int write_blocks(const char *buf, size_t size, off_t offset, struct wfs_inode *inode, int firstBlock, int lastBlock)
{
    int writtenBytes = 0;
    for (int i = firstBlock; i <= lastBlock; i++)
    {
        int blockStart = (i == firstBlock) ? (offset % BLOCK_SIZE) : 0;
        int blockLimit = (i == lastBlock) ? ((offset + size) % BLOCK_SIZE) : BLOCK_SIZE;
        if (blockLimit == 0 && i == lastBlock)
            blockLimit = BLOCK_SIZE;

        char *blockAddress = resolve_block_address(inode, i);

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

static int wfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    struct wfs_inode *targetInode = get_inode(path);
    int status = validate_inode(targetInode);
    if (status != 0)
        return status;

    status = resize_if_needed(offset + size, targetInode);
    if (status != 0)
        return -ENOSPC;

    int firstBlock, lastBlock;
    calculate_block_range(offset, size, &firstBlock, &lastBlock);

    return write_blocks(buf, size, offset, targetInode, firstBlock, lastBlock);
}

static int process_directory_entries(struct wfs_inode *dirInode, void *buf, fuse_fill_dir_t filler)
{
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
                    return 1;
                }
            }
        }
    }
    return 0;
}

static int wfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    struct wfs_inode *dirInode = get_inode(path);
    if (!dirInode)
    {
        return -ENOENT;
    }

    if (!is_directory(dirInode))
    {
        return -ENOTDIR;
    }

    if (process_directory_entries(dirInode, buf, filler))
    {
        return 0;
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

int validate_args(int argc)
{
    if (argc < 2)
    {
        return -1;
    }
    return 0;
}

int open_disk(const char *disk_path)
{
    int fd = open(disk_path, O_RDWR);
    if (fd == -1)
    {
        perror("Error opening disk file");
        return -1;
    }
    return fd;
}

int validate_fd(int fd)
{
    struct stat st;
    if (fstat(fd, &st) == -1)
    {
        perror("Error getting file statistics");
        close(fd);
        return -1;
    }
    return st.st_size;
}

char *map_disk(int fd, size_t size)
{
    char *mapped_disk = (char *)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapped_disk == MAP_FAILED)
    {
        perror("Error mapping file");
        close(fd);
        return NULL;
    }
    return mapped_disk;
}

int main(int argc, char *argv[])
{
    if (validate_args(argc) == -1)
        return -1;

    char *disk_path = argv[1];
    int fd = open_disk(disk_path);
    if (fd == -1)
        return -1;

    int size = validate_fd(fd);
    if (size == -1)
        return -1;

    disk = map_disk(fd, size);
    if (disk == NULL)
        return -1;

    close(fd);
    sb = (struct wfs_sb *)disk;

    return fuse_main(argc - 1, argv + 1, &ops, NULL);
}
