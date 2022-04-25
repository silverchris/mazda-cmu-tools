#include <iostream>
#include <openssl/engine.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <sys/stat.h>
#include <cstdio>
#include <cstring>
#include <getopt.h>



int computeSHA256(unsigned char *hash, unsigned int total_size, FILE *update_handle) {
    unsigned int digest_size;
    EVP_MD_CTX *emd_md_ctx;
    unsigned int processed;
    int ret;
    void *buffer;

    ENGINE_load_builtin_engines();
    ENGINE_register_all_complete();
    OpenSSL_add_all_digests();
    emd_md_ctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(emd_md_ctx, EVP_sha256(), nullptr);
    buffer = malloc(0x20000);

    processed = 0;
    unsigned int to_read;
    while (processed != total_size) {

        to_read = total_size - processed;
        if (to_read > 0x20000) {
            to_read = 0x20000;
        }
        size_t read_bytes = fread(buffer, 1, to_read, update_handle);
        if (to_read != read_bytes) {
            std::cout << "Only read " << read_bytes << " of " << to_read << " byte(s)" << std::endl;
            break;
        }
        processed = read_bytes + processed;
        ret = EVP_DigestUpdate(emd_md_ctx, buffer, read_bytes);
        if (ret != 1) {
            std::cout << "EVP_DigestUpdate() failed" << std::endl;
            break;
        }
    }
    if (processed == total_size) {
        if (EVP_DigestFinal_ex(emd_md_ctx, hash, &digest_size)) {
            ret = 0;
        } else {
            std::cout << "EVP_DigestFinal_ex() failed" << std::endl;
            ret = -1;
        }
    }

    free(buffer);
    EVP_MD_CTX_destroy(emd_md_ctx);
    return ret;
}


void create_signature(char *publisher_private_key_file, char *update_file) {
    rsa_st *rsa;
    unsigned char *update_signature;
    unsigned int update_signature_len;
    unsigned char hash[EVP_MAX_MD_SIZE];
    int ret;
    FILE *update_handle;
    EVP_PKEY *publisher_private_key;
    FILE *local_2c;

    update_handle = fopen(update_file, "rb");
    struct stat64 *structstat;
    structstat = static_cast<struct stat64 *>(malloc(sizeof(struct stat64)));
    stat64(update_file, structstat);

    memset(hash, 0, EVP_MAX_MD_SIZE);

    computeSHA256(hash, structstat->st_size, update_handle);
    free(structstat);

    local_2c = fopen(publisher_private_key_file, "rb");
    publisher_private_key = PEM_read_PrivateKey(local_2c, nullptr, nullptr, nullptr);

    rsa = EVP_PKEY_get1_RSA(publisher_private_key);
    update_signature = static_cast<unsigned char *>(malloc(RSA_size(rsa)));
    ret = RSA_sign(0x2a0, hash, 0x20, update_signature, &update_signature_len, rsa);

    if (ret) {
        std::cout << "signature generated len: " << std::dec << update_signature_len << std::endl;

        fclose(update_handle);
        update_handle = fopen(update_file, "a");
        fwrite(update_signature, 1, 256, update_handle);
    }
    fclose(update_handle);
    EVP_PKEY_free(publisher_private_key);
    free(update_signature);

}

void usage(FILE *fp, const char *path) {
    const char *basename = strrchr(path, '/');
    basename = basename ? basename + 1 : path;

    fprintf(fp, "usage: %s [OPTION]\n", basename);
    fprintf(fp, "  -h, --help\t\t"
                "Print this help and exit.\n");
    fprintf(fp, "  -p --privatekey\t"
                "private key to use to sign update file\n");
    fprintf(fp, "  -u --update\t\t"
                "update file to sign\n");
}


int main(int argc, char **argv) {
    int opt;
    int help_flag = 0;
    char privatekey[255] = {0};
    char update[255];
    struct option longopts[] = {
            {"help",       no_argument,       &help_flag, 1},
            {"privatekey", required_argument, nullptr,    'p'},
            {"update",     required_argument, nullptr,    'u'},
            {nullptr}
    };

/* infinite loop, to be broken when we are done parsing options */
    if (argc == 1) {
        usage(stdout, argv[0]);
        return 0;
    }
    while (true) {
        opt = getopt_long(argc, argv, "hp:u:", longopts, nullptr);

        if (opt == -1) {
            /* a return value of -1 indicates that there are no more options */
            break;
        }
        switch (opt) {
            case 'h':
                help_flag = 1;
                break;
            case 'p':
                strncpy(privatekey, optarg, 255);
                break;
            case 'u':
                strncpy(update, optarg, 255);
                break;
            case '?':
                return 1;
            default:
                break;
        }
    }

    if (help_flag) {
        usage(stdout, argv[0]);
        return 0;
    }

    SSL_library_init();
    SSL_load_error_strings();

    create_signature(privatekey, update);

    return 0;
}