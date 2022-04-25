#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <getopt.h>
#include <filesystem>



struct __attribute__((packed)) tag {
    uint32_t tag_start = 0x14; //Always 0x14
    uint32_t size;
    uint32_t offset;
    uint32_t blocks;
    uint32_t tag_id; // 0x02 for kernel, 0x01 for cmdline, 0x00 for initramfs
};

struct __attribute__((packed)) __cmu_kernel_header {
    uint32_t magic_byes;
    uint32_t header_length;
    uint32_t padding[15];
    struct tag kernel;
    struct tag cmdline;
    struct tag initramfs;
};

typedef struct __cmu_kernel_header cmu_kernel_header;


void print_header(char *path) {
    FILE *img_file = fopen(path, "rb");
    cmu_kernel_header header;

    fread(&header, 1, sizeof(cmu_kernel_header), img_file);
    std::cout << "Header Magic Bytes: " << std::hex << header.magic_byes << std::endl;
    std::cout << "Kernel Size Bytes: " << std::dec << header.kernel.size << std::endl;
    std::cout << "Kernel Blocks: " << std::dec << header.kernel.blocks << std::endl;
    std::cout << "Kernel Offset in blocks: " << std::dec << header.kernel.offset << std::endl;
    std::cout << "Kernel Offset in bytes: " << std::dec << header.kernel.offset * 512 << std::endl;
    std::cout << "Kernel cmdline Size: " << std::dec << header.cmdline.size << std::endl;
    std::cout << "Kernel cmdline Blocks: " << std::dec << header.cmdline.blocks << std::endl;
    std::cout << "Kernel cmdline Offset in blocks: " << std::dec << header.cmdline.offset << std::endl;
    std::cout << "Kernel cmdline Offset in bytes: " << std::dec << header.cmdline.offset * 512 << std::endl;
    char *kernel_cmdline;
    kernel_cmdline = static_cast<char *>(malloc(header.cmdline.size));
    fseek(img_file, header.cmdline.offset * 512, 0);
    fread(kernel_cmdline, 1, header.cmdline.size, img_file);
    std::cout << "Kernel cmdline: " << kernel_cmdline << std::endl;
    std::cout << "initramfs Size Bytes: " << std::dec << header.initramfs.size << std::endl;
    std::cout << "initramfs Size blocks: " << std::dec << header.initramfs.blocks << std::endl;
    std::cout << "initramfs Offset in blocks: " << std::dec << header.initramfs.offset << std::endl;
    std::cout << "initramfs Offset in bytes: " << std::dec << header.initramfs.offset * 512 << std::endl;
    fclose(img_file);
}

void extract_file(FILE *in, uint32_t offset, uint32_t size, char *name) {
    char *buffer;
    buffer = static_cast<char *>(malloc(size));
    FILE *out = fopen(name, "wb");
    fseek(in, offset, 0);
    fread(buffer, 1, size, in);
    fwrite(buffer, 1, size, out);
    fclose(out);
    free(buffer);
}

void extract(char *path, char *kernel, char *cmdline, char *initramfs) {
    const char *basename = strrchr(path, '/');
    basename = basename ? basename + 1 : path;
    FILE *img_file = fopen(path, "rb");
    cmu_kernel_header header;
    char file_name[255];

    fread(&header, 1, sizeof(cmu_kernel_header), img_file);
    fseek(img_file, header.kernel.offset * 512, 0);

    strncpy(file_name, basename, sizeof file_name);
    strcat(file_name, "_kernel");
    std::cout << "Extracting kernel image to " << (kernel?kernel:file_name) << std::endl;
    extract_file(img_file, header.kernel.offset * 512, header.kernel.size, kernel?kernel:file_name);

    strncpy(file_name, basename, sizeof file_name);
    strcat(file_name, "_cmdline");
    std::cout << "Extracting cmdline to " <<  (cmdline?cmdline:file_name) << std::endl;
    extract_file(img_file, header.cmdline.offset * 512, header.cmdline.size-1, cmdline?cmdline:file_name);

    strncpy(file_name, basename, sizeof file_name);
    strcat(file_name, "_initramfs");
    std::cout << "Extracting initramfs image to " << (initramfs?initramfs:file_name) << std::endl;
    extract_file(img_file, header.initramfs.offset * 512, header.initramfs.size, initramfs?initramfs:file_name);

    fclose(img_file);

}

void write_file(const std::filesystem::path& file, FILE *out_file, uint32_t size){
    FILE *file_in = fopen(file.c_str(), "rb");

    char *buffer;
    buffer = static_cast<char *>(malloc(size));
    fread(buffer, 1, size, file_in);
    fclose(file_in);
    fwrite(buffer, 1, size, out_file);

    free(buffer);
}

void write(char *image, const std::filesystem::path& kernel, const std::filesystem::path& cmdline, const std::filesystem::path& initramfs){
    FILE *image_out = fopen(image, "wb");
    cmu_kernel_header header = { 0x424F4F54, 0x03 };
    header.kernel.size =  std::filesystem::file_size(kernel);
    header.kernel.offset = 1;
    header.kernel.blocks = (header.kernel.size/512)+1;
    header.kernel.tag_id = 0x02;
    header.cmdline.size = std::filesystem::file_size(cmdline)+1;
    header.cmdline.blocks = (header.cmdline.size/512)+1;
    header.cmdline.offset = header.kernel.blocks+1;
    header.cmdline.tag_id = 0x01;
    header.initramfs.size =  std::filesystem::file_size(initramfs);
    header.initramfs.blocks = (header.initramfs.size/512)+1;
    header.initramfs.offset = header.kernel.offset+header.cmdline.offset;
    header.initramfs.tag_id = 0x00;

    fwrite(&header, 1, sizeof(cmu_kernel_header), image_out);
    fseek(image_out, header.kernel.offset*512, 0);
    write_file(kernel, image_out, header.kernel.size);
    fseek(image_out, header.cmdline.offset*512, 0);
    write_file(cmdline, image_out, header.cmdline.size);
    fseek(image_out, header.initramfs.offset*512, 0);
    write_file(initramfs, image_out, header.initramfs.size);
    fseek(image_out, (header.initramfs.offset*512)+(header.initramfs.blocks*512)-1, 0);
    uint8_t padding = 0x00;
    fwrite(&padding, 1, 1,image_out);
    std::cout << "file is " << ftell(image_out) << std::endl;
    padding = 0xFF;
    while(ftell(image_out) < 7*1024*1024){
        fwrite(&padding, 1, 1,image_out);
    }
    fclose(image_out);




    std::cout << "The size of " << kernel.u8string() << " is " <<
              std::filesystem::file_size(kernel) << " bytes.\n";



}

void usage(FILE *fp, const char *path) {
    const char *basename = strrchr(path, '/');
    basename = basename ? basename + 1 : path;

    fprintf(fp, "usage: %s [OPTION]\n", basename);
    fprintf(fp, "  -h, --help\t\t"
                "Print this help and exit.\n");
    fprintf(fp, "  -m --mode\t\t"
                "create, read, extract\n");
    fprintf(fp, "  -i --image\t\t"
                "image file to read or save to\n");
    fprintf(fp, "  -k --kernel\t\t"
                "kernel file to use to create image, or where to extract kernel image\n");
    fprintf(fp, "  -c --cmdline\t\t"
                "cmdline file to use to create image, or where to extract cmdline\n");
    fprintf(fp, "  -r --initramfs\t"
                "initramfs file to use to create image, or where to extract initramfs\n");
}

int main(int argc, char **argv) {
    int opt;
    int help_flag = 0;
    char mode;
    char image_file[255] = { 0 };
    char kernel_file[255];
    char cmdline[255];
    char initramfs_file[255];
    struct option longopts[] = {
            {"help",  no_argument, &help_flag, 1},
            {"mode",  required_argument, nullptr, 'm'},
            {"image", required_argument, nullptr, 'i'},
            {"kernel", optional_argument, nullptr, 'k'},
            {"cmdline", optional_argument, nullptr, 'c'},
            {"initramfs", optional_argument, nullptr, 'r'},
            {nullptr}
    };

/* infinite loop, to be broken when we are done parsing options */
    if(argc == 1){
        usage(stdout, argv[0]);
        return 0;
    }
    while (true) {
        opt = getopt_long(argc, argv, "hk::c::r::m:i:", longopts, nullptr);

        if (opt == -1) {
            /* a return value of -1 indicates that there are no more options */
            break;
        }
        switch (opt) {
            case 'h':
                help_flag = 1;
                break;
            case 'm':
                if ((strcmp(optarg, "read") == 0) | (strcmp(optarg, "r") == 0)) {
                    mode = 'r';
                } else if ((strcmp(optarg, "extract") == 0) | (strcmp(optarg, "e") == 0)) {
                    mode = 'e';
                } else if ((strcmp(optarg, "create") == 0) | (strcmp(optarg, "c") == 0)) {
                    mode = 'c';
                } else {
                    usage(stderr, argv[0]);
                }
                break;
            case 'i':
                strncpy(image_file, optarg, 255);
                break;
            case 'k':
                strncpy(kernel_file, optarg ? optarg : "", 255);
                break;
            case 'c':
                strncpy(cmdline, optarg ? optarg : "", 255);
                break;
            case 'r':
                strncpy(initramfs_file, optarg ? optarg : "", 255);
                break;
            case '?':
                return 1;
            default:
                break;
        }
    }

    switch (mode) {
        case 'r':
            print_header(image_file);
            break;
        case 'e':
            extract(image_file, kernel_file, cmdline, initramfs_file);
            break;
        case 'c':
            std::cout << "write" << std::endl;
            std::cout << kernel_file << std::endl;
            if((strlen(kernel_file) < 1 )| (strlen(cmdline) < 1) | (strlen(initramfs_file) < 1)){
                usage(stdout, argv[0]);
            }
            else {
                write(image_file, kernel_file, cmdline, initramfs_file);
            }
            break;
        default:
            break;
    }

    if (help_flag) {
        usage(stdout, argv[0]);
        return 0;
    }
    return 0;
}