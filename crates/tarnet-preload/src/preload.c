/*
 * libtarnet_preload.so — LD_PRELOAD shim for tarify.
 *
 * Intercepts connect() and getaddrinfo() to redirect traffic through
 * a SOCKS5 proxy (tarnet-socks). Uses sentinel IPs (127.44.x.y) to
 * preserve hostname information through the connect() call.
 *
 * Env vars:
 *   TARIFY_PROXY_ADDR — SOCKS5 proxy address (e.g., "127.0.0.1:1080")
 */

#include <dlfcn.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>

/* Sentinel IP range: 127.44.x.y */
#define SENTINEL_PREFIX_A 127
#define SENTINEL_PREFIX_B 44

/* Maximum hostnames we track. */
#define MAX_SENTINELS 4096

/* Sentinel map entry. */
struct sentinel_entry {
    uint16_t key;       /* x*256+y from 127.44.x.y */
    char hostname[256];
};

static struct sentinel_entry sentinel_map[MAX_SENTINELS];
static int sentinel_count = 0;
static pthread_mutex_t sentinel_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Proxy address parsed from TARIFY_PROXY_ADDR. */
static struct sockaddr_in proxy_addr;
static int proxy_addr_valid = 0;
static pthread_once_t init_once = PTHREAD_ONCE_INIT;

/* Identity label from TARIFY_IDENTITY (for SOCKS5 username/password auth). */
static char identity_label[256];
static int identity_set = 0;

/* Original libc functions. */
typedef int (*connect_fn)(int, const struct sockaddr *, socklen_t);
typedef int (*getaddrinfo_fn)(const char *, const char *,
                              const struct addrinfo *,
                              struct addrinfo **);

static connect_fn real_connect = NULL;
static getaddrinfo_fn real_getaddrinfo = NULL;

/* Simple hash of hostname to 16-bit key. */
static uint16_t hash_hostname(const char *name) {
    uint32_t h = 5381;
    while (*name) {
        h = ((h << 5) + h) + (unsigned char)*name++;
    }
    return (uint16_t)(h & 0xFFFF);
}

static void init_proxy_addr(void) {
    const char *env = getenv("TARIFY_PROXY_ADDR");
    if (!env) {
        fprintf(stderr, "tarnet-preload: TARIFY_PROXY_ADDR not set\n");
        return;
    }

    char buf[256];
    strncpy(buf, env, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *colon = strrchr(buf, ':');
    if (!colon) {
        fprintf(stderr, "tarnet-preload: invalid TARIFY_PROXY_ADDR: %s\n", env);
        return;
    }
    *colon = '\0';
    int port = atoi(colon + 1);

    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, buf, &proxy_addr.sin_addr) != 1) {
        fprintf(stderr, "tarnet-preload: invalid proxy IP: %s\n", buf);
        return;
    }

    proxy_addr_valid = 1;

    /* Read optional identity label. */
    const char *id_env = getenv("TARIFY_IDENTITY");
    if (id_env && id_env[0] != '\0') {
        strncpy(identity_label, id_env, sizeof(identity_label) - 1);
        identity_label[sizeof(identity_label) - 1] = '\0';
        identity_set = 1;
    }
}

static void ensure_init(void) {
    if (!real_connect) {
        real_connect = (connect_fn)dlsym(RTLD_NEXT, "connect");
    }
    if (!real_getaddrinfo) {
        real_getaddrinfo = (getaddrinfo_fn)dlsym(RTLD_NEXT, "getaddrinfo");
    }
    pthread_once(&init_once, init_proxy_addr);
}

/* Store a sentinel -> hostname mapping. */
static void sentinel_store(uint16_t key, const char *hostname) {
    pthread_mutex_lock(&sentinel_mutex);

    /* Check if key already exists. */
    for (int i = 0; i < sentinel_count; i++) {
        if (sentinel_map[i].key == key) {
            strncpy(sentinel_map[i].hostname, hostname, 255);
            sentinel_map[i].hostname[255] = '\0';
            pthread_mutex_unlock(&sentinel_mutex);
            return;
        }
    }

    if (sentinel_count < MAX_SENTINELS) {
        sentinel_map[sentinel_count].key = key;
        strncpy(sentinel_map[sentinel_count].hostname, hostname, 255);
        sentinel_map[sentinel_count].hostname[255] = '\0';
        sentinel_count++;
    }

    pthread_mutex_unlock(&sentinel_mutex);
}

/* Look up hostname from sentinel IP. Returns 1 if found. */
static int sentinel_lookup(uint16_t key, char *out, size_t out_len) {
    pthread_mutex_lock(&sentinel_mutex);

    for (int i = 0; i < sentinel_count; i++) {
        if (sentinel_map[i].key == key) {
            strncpy(out, sentinel_map[i].hostname, out_len - 1);
            out[out_len - 1] = '\0';
            pthread_mutex_unlock(&sentinel_mutex);
            return 1;
        }
    }

    pthread_mutex_unlock(&sentinel_mutex);
    return 0;
}

/* Check if an address is a sentinel IP (127.44.x.y). */
static int is_sentinel(const struct sockaddr *addr) {
    if (addr->sa_family != AF_INET) return 0;
    const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
    uint32_t ip = ntohl(sin->sin_addr.s_addr);
    return ((ip >> 24) == SENTINEL_PREFIX_A) &&
           (((ip >> 16) & 0xFF) == SENTINEL_PREFIX_B);
}

/* Check if an address is the proxy itself (anti-recursion). */
static int is_proxy_addr(const struct sockaddr *addr) {
    if (!proxy_addr_valid) return 0;
    if (addr->sa_family != AF_INET) return 0;
    const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
    return sin->sin_addr.s_addr == proxy_addr.sin_addr.s_addr &&
           sin->sin_port == proxy_addr.sin_port;
}

/* Temporarily set socket to blocking mode. Returns old flags, or -1 on error. */
static int set_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (flags & O_NONBLOCK) {
        fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    }
    return flags;
}

/* Restore original socket flags. */
static void restore_flags(int fd, int flags) {
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags);
    }
}

/* Perform SOCKS5 auth negotiation.
 * If identity_set, uses username/password (method 0x02) to carry identity label.
 * Otherwise uses no-auth (method 0x00).
 * Returns 0 on success, -1 on failure (sets errno). */
static int socks5_auth(int fd) {
    if (identity_set) {
        /* Offer username/password auth. */
        unsigned char auth_req[] = {0x05, 0x01, 0x02};
        if (write(fd, auth_req, sizeof(auth_req)) != sizeof(auth_req)) {
            errno = ECONNREFUSED;
            return -1;
        }

        unsigned char auth_resp[2];
        if (read(fd, auth_resp, 2) != 2 || auth_resp[0] != 0x05 || auth_resp[1] != 0x02) {
            errno = ECONNREFUSED;
            return -1;
        }

        /* RFC 1929 sub-negotiation: VER(1) ULEN(1) UNAME PLEN(1) PASSWD */
        int ulen = strlen(identity_label);
        unsigned char sub[3 + 255]; /* ver + ulen + username + plen */
        sub[0] = 0x01;              /* sub-negotiation version */
        sub[1] = (unsigned char)ulen;
        memcpy(sub + 2, identity_label, ulen);
        sub[2 + ulen] = 0x00;      /* password length = 0 */
        int sub_len = 3 + ulen;

        if (write(fd, sub, sub_len) != sub_len) {
            errno = ECONNREFUSED;
            return -1;
        }

        unsigned char sub_resp[2];
        if (read(fd, sub_resp, 2) != 2 || sub_resp[0] != 0x01 || sub_resp[1] != 0x00) {
            errno = ECONNREFUSED;
            return -1;
        }
    } else {
        /* No-auth. */
        unsigned char auth_req[] = {0x05, 0x01, 0x00};
        if (write(fd, auth_req, sizeof(auth_req)) != sizeof(auth_req)) {
            errno = ECONNREFUSED;
            return -1;
        }

        unsigned char auth_resp[2];
        if (read(fd, auth_resp, 2) != 2 || auth_resp[0] != 0x05 || auth_resp[1] != 0x00) {
            errno = ECONNREFUSED;
            return -1;
        }
    }
    return 0;
}

/* Perform SOCKS5 CONNECT through the proxy with a hostname. */
static int socks5_connect_hostname(int fd, const char *hostname, uint16_t port) {
    /* Force blocking for the SOCKS5 handshake. */
    int saved_flags = set_blocking(fd);

    /* Connect to proxy. */
    if (real_connect(fd, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) < 0) {
        restore_flags(fd, saved_flags);
        return -1;
    }

    if (socks5_auth(fd) < 0) {
        restore_flags(fd, saved_flags);
        return -1;
    }

    /* CONNECT request with domain name. */
    size_t hlen = strlen(hostname);
    if (hlen > 255) hlen = 255;

    size_t req_len = 4 + 1 + hlen + 2;
    unsigned char *req = alloca(req_len);
    req[0] = 0x05;          /* VER */
    req[1] = 0x01;          /* CMD: CONNECT */
    req[2] = 0x00;          /* RSV */
    req[3] = 0x03;          /* ATYP: domain */
    req[4] = (unsigned char)hlen;
    memcpy(req + 5, hostname, hlen);
    req[5 + hlen] = (port >> 8) & 0xFF;
    req[5 + hlen + 1] = port & 0xFF;

    if (write(fd, req, req_len) != (ssize_t)req_len) {
        restore_flags(fd, saved_flags);
        errno = ECONNREFUSED;
        return -1;
    }

    /* Read reply (minimum 10 bytes for IPv4 reply). */
    unsigned char reply[10];
    if (read(fd, reply, 10) != 10) {
        restore_flags(fd, saved_flags);
        errno = ECONNREFUSED;
        return -1;
    }

    if (reply[0] != 0x05 || reply[1] != 0x00) {
        restore_flags(fd, saved_flags);
        errno = ECONNREFUSED;
        return -1;
    }

    /* Restore original flags (e.g. non-blocking) for the application. */
    restore_flags(fd, saved_flags);
    return 0;
}

/* Perform SOCKS5 CONNECT with an IPv4 address. */
static int socks5_connect_ipv4(int fd, struct in_addr addr, uint16_t port) {
    int saved_flags = set_blocking(fd);

    if (real_connect(fd, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) < 0) {
        restore_flags(fd, saved_flags);
        return -1;
    }

    if (socks5_auth(fd) < 0) {
        restore_flags(fd, saved_flags);
        return -1;
    }

    unsigned char req[10];
    req[0] = 0x05;
    req[1] = 0x01;
    req[2] = 0x00;
    req[3] = 0x01; /* ATYP: IPv4 */
    memcpy(req + 4, &addr.s_addr, 4);
    req[8] = (port >> 8) & 0xFF;
    req[9] = port & 0xFF;

    if (write(fd, req, 10) != 10) {
        restore_flags(fd, saved_flags);
        errno = ECONNREFUSED;
        return -1;
    }

    unsigned char reply[10];
    if (read(fd, reply, 10) != 10) {
        restore_flags(fd, saved_flags);
        errno = ECONNREFUSED;
        return -1;
    }

    if (reply[0] != 0x05 || reply[1] != 0x00) {
        restore_flags(fd, saved_flags);
        errno = ECONNREFUSED;
        return -1;
    }

    restore_flags(fd, saved_flags);
    return 0;
}

/* ── Intercepted functions ── */

int connect(int fd, const struct sockaddr *addr, socklen_t len) {
    ensure_init();

    if (!proxy_addr_valid || !real_connect) {
        return real_connect ? real_connect(fd, addr, len) : -1;
    }

    /* Pass through AF_UNIX. */
    if (addr->sa_family == AF_UNIX) {
        return real_connect(fd, addr, len);
    }

    /* Pass through non-IPv4. */
    if (addr->sa_family != AF_INET) {
        return real_connect(fd, addr, len);
    }

    /* Check socket type — pass through UDP. */
    int sock_type = 0;
    socklen_t optlen = sizeof(sock_type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &sock_type, &optlen) == 0) {
        if (sock_type == SOCK_DGRAM) {
            return real_connect(fd, addr, len);
        }
    }

    /* Anti-recursion: pass through connections to the proxy itself. */
    if (is_proxy_addr(addr)) {
        return real_connect(fd, addr, len);
    }

    const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
    uint16_t port = ntohs(sin->sin_port);

    /* Sentinel IP → look up hostname, SOCKS5 with hostname. */
    if (is_sentinel(addr)) {
        uint32_t ip = ntohl(sin->sin_addr.s_addr);
        uint16_t key = ip & 0xFFFF;
        char hostname[256];

        if (sentinel_lookup(key, hostname, sizeof(hostname))) {
            return socks5_connect_hostname(fd, hostname, port);
        }
    }

    /* Real IP → SOCKS5 with IP address. */
    return socks5_connect_ipv4(fd, sin->sin_addr, port);
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints,
                struct addrinfo **res) {
    ensure_init();

    /* Pass through if no node or numeric-only request. */
    if (!node || !proxy_addr_valid) {
        return real_getaddrinfo ? real_getaddrinfo(node, service, hints, res) : EAI_SYSTEM;
    }

    /* If hints request numeric-only, pass through. */
    if (hints && (hints->ai_flags & AI_NUMERICHOST)) {
        return real_getaddrinfo(node, service, hints, res);
    }

    /* Generate sentinel IP. */
    uint16_t key = hash_hostname(node);
    uint8_t x = (key >> 8) & 0xFF;
    uint8_t y = key & 0xFF;

    sentinel_store(key, node);

    /* Build a fake addrinfo with sentinel IP. */
    struct addrinfo *ai = calloc(1, sizeof(struct addrinfo));
    struct sockaddr_in *sin = calloc(1, sizeof(struct sockaddr_in));
    if (!ai || !sin) {
        free(ai);
        free(sin);
        return EAI_MEMORY;
    }

    sin->sin_family = AF_INET;
    uint32_t sentinel_ip = ((uint32_t)SENTINEL_PREFIX_A << 24) |
                           ((uint32_t)SENTINEL_PREFIX_B << 16) |
                           ((uint32_t)x << 8) |
                           (uint32_t)y;
    sin->sin_addr.s_addr = htonl(sentinel_ip);

    /* Parse port from service string. */
    if (service) {
        int p = atoi(service);
        if (p > 0) {
            sin->sin_port = htons(p);
        } else {
            /* Try getservbyname for named services. */
            struct servent *se = getservbyname(service, "tcp");
            if (se) {
                sin->sin_port = se->s_port;
            }
        }
    }

    ai->ai_family = AF_INET;
    ai->ai_socktype = SOCK_STREAM;
    ai->ai_protocol = IPPROTO_TCP;
    ai->ai_addrlen = sizeof(struct sockaddr_in);
    ai->ai_addr = (struct sockaddr *)sin;
    ai->ai_canonname = NULL;
    ai->ai_next = NULL;

    *res = ai;
    return 0;
}

void freeaddrinfo(struct addrinfo *res) {
    /* Check if this is one of our sentinel results. */
    if (res && res->ai_addr) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)res->ai_addr;
        if (sin->sin_family == AF_INET && is_sentinel(res->ai_addr)) {
            free(res->ai_addr);
            free(res);
            return;
        }
    }

    /* Call real freeaddrinfo. */
    typedef void (*freeaddrinfo_fn)(struct addrinfo *);
    static freeaddrinfo_fn real_freeaddrinfo = NULL;
    if (!real_freeaddrinfo) {
        real_freeaddrinfo = (freeaddrinfo_fn)dlsym(RTLD_NEXT, "freeaddrinfo");
    }
    if (real_freeaddrinfo) {
        real_freeaddrinfo(res);
    }
}

struct hostent *gethostbyname(const char *name) {
    ensure_init();

    if (!name || !proxy_addr_valid) {
        typedef struct hostent *(*gethostbyname_fn)(const char *);
        static gethostbyname_fn real_gethostbyname = NULL;
        if (!real_gethostbyname) {
            real_gethostbyname = (gethostbyname_fn)dlsym(RTLD_NEXT, "gethostbyname");
        }
        return real_gethostbyname ? real_gethostbyname(name) : NULL;
    }

    uint16_t key = hash_hostname(name);
    uint8_t x = (key >> 8) & 0xFF;
    uint8_t y = key & 0xFF;

    sentinel_store(key, name);

    /* Return a static hostent with sentinel IP. */
    static struct hostent he;
    static struct in_addr addr;
    static char *addr_list[2] = {NULL, NULL};

    uint32_t sentinel_ip = ((uint32_t)SENTINEL_PREFIX_A << 24) |
                           ((uint32_t)SENTINEL_PREFIX_B << 16) |
                           ((uint32_t)x << 8) |
                           (uint32_t)y;
    addr.s_addr = htonl(sentinel_ip);
    addr_list[0] = (char *)&addr;

    he.h_name = (char *)name;
    he.h_aliases = NULL;
    he.h_addrtype = AF_INET;
    he.h_length = sizeof(struct in_addr);
    he.h_addr_list = addr_list;

    return &he;
}
