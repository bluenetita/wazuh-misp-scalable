/*
 ____  _            _   _      _                      _        
|  _ \| |          | \ | |    | |                    | |       
| |_) | |_   _  ___|  \| | ___| |___      _____  _ __| | _____ 
|  _ <| | | | |/ _ \ . ` |/ _ \ __\ \ /\ / / _ \| '__| |/ / __|
| |_) | | |_| |  __/ |\  |  __/ |_ \ V  V / (_) | |  |   <\__ \
|____/|_|\__,_|\___|_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\___/
                                                               
-= Scalable MISP Integration :: Wazuh Forwarder =- 
Github @bluenetita
Version: 1.0
License: AGPL v3.0 https://www.gnu.org/licenses/agpl-3.0.html
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <hiredis/hiredis.h>
#include <sys/stat.h>

#define DEFAULT_STREAM "wazuh:misp:in"
#define DEFAULT_MAXLEN 200000
#define MAX_ALERT_BYTES (1024 * 1024)   // 1 MiB default

static char *read_file(const char *path, size_t *out_len) {
    struct stat st;
    if (stat(path, &st) != 0) return NULL;
    if (st.st_size <= 0 || st.st_size > MAX_ALERT_BYTES) return NULL;

    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    size_t n = (size_t)st.st_size;
    char *buf = (char *)malloc(n + 1);
    if (!buf) { fclose(f); return NULL; }

    size_t r = fread(buf, 1, n, f);
    fclose(f);
    if (r != n) { free(buf); return NULL; }

    buf[n] = '\0';
    *out_len = n;
    return buf;
}

static redisContext *redis_connect(void) {
    const char *sock = getenv("REDIS_UNIX_SOCK");   // es: /run/redis/redis-server.sock
    struct timeval tv = {0, 80000};                 // 80ms timeout

    if (sock && sock[0]) {
        redisContext *c = redisConnectUnixWithTimeout(sock, tv);
        if (c && !c->err) return c;
        if (c) redisFree(c);
        // TCP fallback
    }

    const char *host = getenv("REDIS_HOST"); if (!host) host = "127.0.0.1";
    const char *port_s = getenv("REDIS_PORT"); int port = port_s ? atoi(port_s) : 6379;

    redisContext *c = redisConnectWithTimeout(host, port, tv);
    if (c && !c->err) return c;
    if (c) redisFree(c);
    return NULL;
}

int main(int argc, char **argv) {
    // Wazuh integrator will pass this as argv[1]
    if (argc < 2) return 1;

    const char *stream = getenv("REDIS_STREAM");
    if (!stream || !stream[0]) stream = DEFAULT_STREAM;

    const char *maxlen_s = getenv("REDIS_STREAM_MAXLEN");
    long maxlen = maxlen_s ? atol(maxlen_s) : DEFAULT_MAXLEN;
    if (maxlen < 1000) maxlen = DEFAULT_MAXLEN;

    size_t alert_len = 0;
    char *alert = read_file(argv[1], &alert_len);
    if (!alert) return 0; // fail-closed: non bloccare Wazuh

    redisContext *c = redis_connect();
    if (!c) { free(alert); return 0; }

    // XADD stream MAXLEN ~ <maxlen> * alert "<json>"
    redisReply *r = (redisReply *)redisCommand(
        c,
        "XADD %s MAXLEN ~ %ld * alert %b",
        stream, maxlen, alert, (size_t)alert_len
    );

    if (r) freeReplyObject(r);
    redisFree(c);
    free(alert);
    return 0;
}
