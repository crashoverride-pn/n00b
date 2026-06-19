#include "net/dns.h"

#if defined(_WIN32) && !defined(__CYGWIN__)

n00b_string_t *
n00b_dns_resolve(n00b_string_t *host)
{
    (void)host;
    return n00b_string_empty();
}

int
n00b_dns_resolve_addrs(n00b_string_t        *host,
                       uint16_t              port,
                       n00b_resolved_addr_t *out,
                       int                   cap)
{
    (void)host;
    (void)port;
    (void)out;
    (void)cap;
    return 0;
}

#else

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#define N00B_DNS_PORT 53u
#define N00B_DNS_PACKET_CAP 1500u
#define N00B_DNS_NAME_CAP 256u
#define N00B_DNS_OUT_CAP 4096u
#define N00B_DNS_NAMESERVER_CAP 4u
#define N00B_DNS_TIMEOUT_MS 250
#define N00B_DNS_TYPE_A 1u
#define N00B_DNS_TYPE_CNAME 5u
#define N00B_DNS_TYPE_AAAA 28u
#define N00B_DNS_CLASS_IN 1u
#define N00B_DNS_HEADER_LEN 12u
#define N00B_DNS_NAME_PTR_DEPTH_MAX 8u

typedef struct {
    size_t                  count;
    struct sockaddr_storage addr[N00B_DNS_NAMESERVER_CAP];
    socklen_t               len[N00B_DNS_NAMESERVER_CAP];
} n00b_dns_nameservers_t;

static bool
n00b_dns_is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static uint16_t
n00b_dns_get_u16(const uint8_t *buf, size_t pos)
{
    return (uint16_t)(((uint16_t)buf[pos] << 8) | (uint16_t)buf[pos + 1u]);
}

static uint32_t
n00b_dns_get_u32(const uint8_t *buf, size_t pos)
{
    return ((uint32_t)buf[pos] << 24) |
           ((uint32_t)buf[pos + 1u] << 16) |
           ((uint32_t)buf[pos + 2u] << 8) |
           (uint32_t)buf[pos + 3u];
}

static void
n00b_dns_put_u16(uint8_t *buf, size_t pos, uint16_t value)
{
    buf[pos] = (uint8_t)(value >> 8);
    buf[pos + 1u] = (uint8_t)(value & 0xffu);
}

static uint16_t
n00b_dns_host_to_be16(uint16_t value)
{
    return (uint16_t)((value >> 8) | (value << 8));
}

static bool
n00b_dns_parse_ipv4(const char *ip, uint8_t out[4])
{
    if (ip == nullptr || out == nullptr) {
        return false;
    }

    size_t pos = 0;
    for (size_t part = 0; part < 4u; part++) {
        if (ip[pos] < '0' || ip[pos] > '9') {
            return false;
        }
        uint32_t value = 0;
        size_t digits = 0;
        while (ip[pos] >= '0' && ip[pos] <= '9') {
            value = value * 10u + (uint32_t)(ip[pos] - '0');
            if (value > 255u || ++digits > 3u) {
                return false;
            }
            pos++;
        }
        out[part] = (uint8_t)value;
        if (part == 3u) {
            return ip[pos] == '\0';
        }
        if (ip[pos] != '.') {
            return false;
        }
        pos++;
    }

    return false;
}

static size_t
n00b_dns_append_decimal(char *out, size_t cap, size_t pos, uint8_t value)
{
    char tmp[3] = {};
    size_t n = 0;
    do {
        tmp[n++] = (char)('0' + (value % 10u));
        value /= 10u;
    } while (value != 0 && n < sizeof(tmp));

    while (n != 0) {
        if (pos + 1u >= cap) {
            return cap;
        }
        out[pos++] = tmp[--n];
    }
    return pos;
}

static bool
n00b_dns_format_ipv4(const uint8_t in[4], char *out, size_t cap)
{
    if (in == nullptr || out == nullptr || cap == 0) {
        return false;
    }
    size_t pos = 0;
    for (size_t i = 0; i < 4u; i++) {
        if (i != 0) {
            if (pos + 1u >= cap) {
                return false;
            }
            out[pos++] = '.';
        }
        pos = n00b_dns_append_decimal(out, cap, pos, in[i]);
        if (pos >= cap) {
            return false;
        }
    }
    out[pos] = '\0';
    return true;
}

static bool
n00b_dns_format_ipv6(const uint8_t in[16], char *out, size_t cap)
{
    static const char hex[] = "0123456789abcdef";
    if (in == nullptr || out == nullptr || cap < 40u) {
        return false;
    }

    size_t pos = 0;
    for (size_t i = 0; i < 8u; i++) {
        if (i != 0) {
            out[pos++] = ':';
        }
        uint16_t word = (uint16_t)(((uint16_t)in[i * 2u] << 8)
                                   | in[i * 2u + 1u]);
        bool emitted = false;
        for (int shift = 12; shift >= 0; shift -= 4) {
            uint8_t nibble = (uint8_t)((word >> shift) & 0x0fu);
            if (nibble != 0 || emitted || shift == 0) {
                out[pos++] = hex[nibble];
                emitted = true;
            }
        }
    }
    out[pos] = '\0';
    return true;
}

static bool
n00b_dns_nameserver_add(n00b_dns_nameservers_t *servers, const char *ip)
{
    if (servers == nullptr || ip == nullptr ||
        servers->count >= N00B_DNS_NAMESERVER_CAP) {
        return false;
    }

    struct sockaddr_in v4 = {
        .sin_family = AF_INET,
        .sin_port   = n00b_dns_host_to_be16((uint16_t)N00B_DNS_PORT),
    };
    if (n00b_dns_parse_ipv4(ip, (uint8_t *)&v4.sin_addr)) {
        memcpy(&servers->addr[servers->count], &v4, sizeof(v4));
        servers->len[servers->count] = (socklen_t)sizeof(v4);
        servers->count++;
        return true;
    }
    return false;
}

static void
n00b_dns_nameserver_parse_line(n00b_dns_nameservers_t *servers,
                               const char             *line,
                               size_t                  len)
{
    static const char key[] = "nameserver";
    size_t key_len = sizeof(key) - 1u;
    size_t pos = 0;
    while (pos < len && n00b_dns_is_space(line[pos])) {
        pos++;
    }
    if (pos + key_len > len || memcmp(line + pos, key, key_len) != 0) {
        return;
    }
    pos += key_len;
    if (pos < len && !n00b_dns_is_space(line[pos])) {
        return;
    }
    while (pos < len && n00b_dns_is_space(line[pos])) {
        pos++;
    }

    char ip[96] = {};
    size_t out = 0;
    while (pos < len && !n00b_dns_is_space(line[pos]) &&
           line[pos] != '#' && out + 1u < sizeof(ip)) {
        ip[out++] = line[pos++];
    }
    ip[out] = '\0';
    (void)n00b_dns_nameserver_add(servers, ip);
}

static void
n00b_dns_nameservers_load(n00b_dns_nameservers_t *servers)
{
    *servers = (n00b_dns_nameservers_t){};

    int fd = open("/etc/resolv.conf", O_RDONLY);
    if (fd >= 0) {
        char buf[4096] = {};
        ssize_t got = read(fd, buf, sizeof(buf) - 1u);
        close(fd);
        if (got > 0) {
            size_t start = 0;
            size_t len = (size_t)got;
            for (size_t i = 0; i <= len; i++) {
                if (i == len || buf[i] == '\n') {
                    n00b_dns_nameserver_parse_line(servers,
                                                   buf + start,
                                                   i - start);
                    start = i + 1u;
                    if (servers->count >= N00B_DNS_NAMESERVER_CAP) {
                        return;
                    }
                }
            }
        }
    }

    if (servers->count == 0) {
        (void)n00b_dns_nameserver_add(servers, "1.1.1.1");
    }
}

static bool
n00b_dns_encode_name(uint8_t *buf, size_t cap, size_t *pos, const char *host)
{
    if (buf == nullptr || pos == nullptr || host == nullptr) {
        return false;
    }

    size_t i = 0;
    while (host[i] != '\0') {
        if (host[i] == '.') {
            i++;
            continue;
        }

        size_t label_start = i;
        while (host[i] != '\0' && host[i] != '.') {
            i++;
        }
        size_t label_len = i - label_start;
        if (label_len == 0 || label_len > 63u || *pos + 1u + label_len >= cap) {
            return false;
        }

        buf[(*pos)++] = (uint8_t)label_len;
        memcpy(buf + *pos, host + label_start, label_len);
        *pos += label_len;
    }

    if (*pos >= cap) {
        return false;
    }
    buf[(*pos)++] = 0;
    return true;
}

static bool
n00b_dns_build_query(const char *host, uint16_t qtype, uint8_t *out, size_t *out_len)
{
    if (host == nullptr || out == nullptr || out_len == nullptr) {
        return false;
    }

    memset(out, 0, N00B_DNS_PACKET_CAP);
    uint16_t id = (uint16_t)(0x4e30u ^ qtype ^ (uint16_t)strlen(host));
    n00b_dns_put_u16(out, 0, id);
    n00b_dns_put_u16(out, 2, 0x0100u);
    n00b_dns_put_u16(out, 4, 1u);

    size_t pos = N00B_DNS_HEADER_LEN;
    if (!n00b_dns_encode_name(out, N00B_DNS_PACKET_CAP, &pos, host) ||
        pos + 4u > N00B_DNS_PACKET_CAP) {
        return false;
    }

    n00b_dns_put_u16(out, pos, qtype);
    pos += 2u;
    n00b_dns_put_u16(out, pos, N00B_DNS_CLASS_IN);
    pos += 2u;
    *out_len = pos;
    return true;
}

static bool
n00b_dns_decode_name(const uint8_t *buf,
                     size_t         len,
                     size_t        *offset,
                     char          *out_name,
                     size_t         out_cap)
{
    size_t cur = *offset;
    size_t out_len = 0;
    size_t depth = 0;
    bool advanced = false;
    size_t advanced_to = 0;

    if (out_cap == 0) {
        return false;
    }
    out_name[0] = '\0';

    while (cur < len) {
        uint8_t b = buf[cur];
        if ((b & 0xc0u) == 0xc0u) {
            if (cur + 1u >= len) {
                return false;
            }
            size_t ptr = (((size_t)b & 0x3fu) << 8) | (size_t)buf[cur + 1u];
            if (ptr >= len || ++depth > N00B_DNS_NAME_PTR_DEPTH_MAX) {
                return false;
            }
            if (!advanced) {
                advanced = true;
                advanced_to = cur + 2u;
            }
            cur = ptr;
            continue;
        }
        if ((b & 0xc0u) != 0) {
            return false;
        }

        cur++;
        if (b == 0) {
            if (out_len == 0) {
                if (out_cap < 2u) {
                    return false;
                }
                out_name[0] = '.';
                out_name[1] = '\0';
            }
            else {
                if (out_len >= out_cap) {
                    return false;
                }
                out_name[out_len] = '\0';
            }
            *offset = advanced ? advanced_to : cur;
            return true;
        }
        if (b > 63u || cur + (size_t)b > len) {
            return false;
        }
        if (out_len != 0) {
            if (out_len + 1u >= out_cap) {
                return false;
            }
            out_name[out_len++] = '.';
        }
        if (out_len + (size_t)b >= out_cap) {
            return false;
        }
        memcpy(out_name + out_len, buf + cur, (size_t)b);
        out_len += (size_t)b;
        cur += (size_t)b;
    }

    return false;
}

static bool
n00b_dns_skip_questions(const uint8_t *buf, size_t len, size_t *offset, uint16_t qdcount)
{
    for (uint16_t i = 0; i < qdcount; i++) {
        char name[N00B_DNS_NAME_CAP] = {};
        if (!n00b_dns_decode_name(buf, len, offset, name, sizeof(name)) ||
            *offset + 4u > len) {
            return false;
        }
        *offset += 4u;
    }
    return true;
}

static bool
n00b_dns_output_has_ip(const char *out, size_t out_len, const char *ip)
{
    size_t ip_len = strlen(ip);
    size_t pos = 0;
    while (pos < out_len) {
        size_t start = pos;
        while (pos < out_len && out[pos] != '\n') {
            pos++;
        }
        if (pos - start == ip_len && memcmp(out + start, ip, ip_len) == 0) {
            return true;
        }
        if (pos < out_len) {
            pos++;
        }
    }
    return false;
}

static bool
n00b_dns_output_add_ip(char *out, size_t *out_len, const char *ip)
{
    size_t ip_len = strlen(ip);
    if (ip_len == 0 || n00b_dns_output_has_ip(out, *out_len, ip)) {
        return true;
    }
    size_t need = ip_len + (*out_len == 0 ? 0u : 1u);
    if (*out_len + need + 1u > N00B_DNS_OUT_CAP) {
        return false;
    }
    if (*out_len != 0) {
        out[(*out_len)++] = '\n';
    }
    memcpy(out + *out_len, ip, ip_len);
    *out_len += ip_len;
    out[*out_len] = '\0';
    return true;
}

static void
n00b_dns_collect_answers(const uint8_t *buf, size_t len, char *out, size_t *out_len)
{
    if (len < N00B_DNS_HEADER_LEN || (n00b_dns_get_u16(buf, 2) & 0x8000u) == 0) {
        return;
    }
    if ((n00b_dns_get_u16(buf, 2) & 0x000fu) != 0) {
        return;
    }

    uint16_t qdcount = n00b_dns_get_u16(buf, 4);
    uint16_t ancount = n00b_dns_get_u16(buf, 6);
    size_t offset = N00B_DNS_HEADER_LEN;
    if (!n00b_dns_skip_questions(buf, len, &offset, qdcount)) {
        return;
    }

    for (uint16_t i = 0; i < ancount; i++) {
        char name[N00B_DNS_NAME_CAP] = {};
        if (!n00b_dns_decode_name(buf, len, &offset, name, sizeof(name)) ||
            offset + 10u > len) {
            return;
        }
        uint16_t rrtype = n00b_dns_get_u16(buf, offset);
        uint16_t rrclass = n00b_dns_get_u16(buf, offset + 2u);
        uint16_t rdlen = n00b_dns_get_u16(buf, offset + 8u);
        size_t rdata = offset + 10u;
        if (rdata + (size_t)rdlen > len) {
            return;
        }

        char ip[40] = {};
        if (rrclass == N00B_DNS_CLASS_IN &&
            rrtype == N00B_DNS_TYPE_A &&
            rdlen == 4u &&
            n00b_dns_format_ipv4(buf + rdata, ip, sizeof(ip))) {
            (void)n00b_dns_output_add_ip(out, out_len, ip);
        }
        else if (rrclass == N00B_DNS_CLASS_IN &&
                 rrtype == N00B_DNS_TYPE_AAAA &&
                 rdlen == 16u &&
                 n00b_dns_format_ipv6(buf + rdata, ip, sizeof(ip))) {
            (void)n00b_dns_output_add_ip(out, out_len, ip);
        }
        else if (rrtype == N00B_DNS_TYPE_CNAME) {
            /* CNAME is intentionally ignored here; address RRs elsewhere in
             * the same answer section are still collected. */
        }
        offset = rdata + (size_t)rdlen;
    }
}

static void
n00b_dns_query_one(const struct sockaddr *server,
                   socklen_t             server_len,
                   const char           *host,
                   uint16_t              qtype,
                   char                 *out,
                   size_t               *out_len)
{
    uint8_t query[N00B_DNS_PACKET_CAP] = {};
    uint8_t response[N00B_DNS_PACKET_CAP] = {};
    size_t query_len = 0;
    if (!n00b_dns_build_query(host, qtype, query, &query_len)) {
        return;
    }

    int family = server->sa_family;
    int fd = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        return;
    }

    ssize_t sent = sendto(fd, query, query_len, 0, server, server_len);
    if (sent == (ssize_t)query_len) {
        struct pollfd pfd = {
            .fd = fd,
            .events = POLLIN,
        };
        int pr = poll(&pfd, 1, N00B_DNS_TIMEOUT_MS);
        if (pr > 0 && (pfd.revents & POLLIN) != 0) {
            ssize_t got = recvfrom(fd, response, sizeof(response), 0, nullptr, nullptr);
            if (got > 0) {
                n00b_dns_collect_answers(response, (size_t)got, out, out_len);
            }
        }
    }

    close(fd);
}

n00b_string_t *
n00b_dns_resolve(n00b_string_t *host)
{
    if (host == nullptr || host->data == nullptr || host->u8_bytes == 0) {
        return n00b_string_empty();
    }
    if (host->u8_bytes >= N00B_DNS_NAME_CAP) {
        return n00b_string_empty();
    }

    n00b_dns_nameservers_t servers = {};
    n00b_dns_nameservers_load(&servers);
    if (servers.count == 0) {
        return n00b_string_empty();
    }

    char out[N00B_DNS_OUT_CAP] = {};
    char host_buf[N00B_DNS_NAME_CAP] = {};
    size_t out_len = 0;
    memcpy(host_buf, host->data, host->u8_bytes);
    host_buf[host->u8_bytes] = '\0';

    for (size_t i = 0; i < servers.count; i++) {
        n00b_dns_query_one((const struct sockaddr *)&servers.addr[i],
                           servers.len[i],
                           host_buf,
                           N00B_DNS_TYPE_A,
                           out,
                           &out_len);
        n00b_dns_query_one((const struct sockaddr *)&servers.addr[i],
                           servers.len[i],
                           host_buf,
                           N00B_DNS_TYPE_AAAA,
                           out,
                           &out_len);
        if (out_len != 0) {
            break;
        }
    }

    return n00b_string_from_raw(out, (int64_t)out_len);
}

/* Fill out[count] from a NUL-terminated IP literal; returns true on success.
 * inet_pton parses in place (no allocation), so this is worker-thread safe. */
static bool
n00b_dns_fill_sockaddr(n00b_resolved_addr_t *slot, const char *ip, uint16_t nport)
{
    struct in_addr  a4;
    struct in6_addr a6;

    if (inet_pton(AF_INET, ip, &a4) == 1) {
        struct sockaddr_in *s = (struct sockaddr_in *)&slot->ss;
        memset(s, 0, sizeof(*s));
        s->sin_family = AF_INET;
        s->sin_port   = nport;
        s->sin_addr   = a4;
        slot->len     = (socklen_t)sizeof(struct sockaddr_in);
        return true;
    }
    if (inet_pton(AF_INET6, ip, &a6) == 1) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&slot->ss;
        memset(s, 0, sizeof(*s));
        s->sin6_family = AF_INET6;
        s->sin6_port   = nport;
        s->sin6_addr   = a6;
        slot->len      = (socklen_t)sizeof(struct sockaddr_in6);
        return true;
    }
    return false;
}

int
n00b_dns_resolve_addrs(n00b_string_t        *host,
                       uint16_t              port,
                       n00b_resolved_addr_t *out,
                       int                   cap)
{
    if (host == nullptr || host->data == nullptr || host->u8_bytes == 0
        || out == nullptr || cap <= 0) {
        return 0;
    }

    uint16_t nport = htons(port);

    /* A literal IP address needs no DNS round-trip. host->data is NUL
     * terminated (n00b strings guarantee the trailing NUL). */
    if (n00b_dns_fill_sockaddr(&out[0], (const char *)host->data, nport)) {
        return 1;
    }

    /* Otherwise resolve via the libc-free UDP resolver and parse each
     * newline-delimited literal it returns. */
    n00b_string_t *ips = n00b_dns_resolve(host);
    if (ips == nullptr || ips->data == nullptr || ips->u8_bytes == 0) {
        return 0;
    }

    int         count = 0;
    const char *p     = (const char *)ips->data;
    const char *end   = p + ips->u8_bytes;

    while (p < end && count < cap) {
        const char *nl = p;
        while (nl < end && *nl != '\n') {
            nl++;
        }
        size_t line_len = (size_t)(nl - p);
        /* Drop a trailing CR if the resolver ever emits CRLF. */
        if (line_len > 0 && p[line_len - 1u] == '\r') {
            line_len--;
        }

        char ip[64];
        if (line_len > 0 && line_len < sizeof(ip)) {
            memcpy(ip, p, line_len);
            ip[line_len] = '\0';
            if (n00b_dns_fill_sockaddr(&out[count], ip, nport)) {
                count++;
            }
        }
        p = (nl < end) ? nl + 1 : end;
    }

    return count;
}

#endif
