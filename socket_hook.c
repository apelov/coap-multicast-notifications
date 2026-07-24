#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <dlfcn.h>
#include <stdio.h>

int bind(int socket, const struct sockaddr *address, socklen_t address_len) {
    static int (*real_bind)(int, const struct sockaddr *, socklen_t) = NULL;
    if (!real_bind) {
        real_bind = dlsym(RTLD_NEXT, "bind");
    }

    if (address) {
        if (address->sa_family == AF_INET) {
            struct sockaddr_in *addr4 = (struct sockaddr_in *)address;
            if (ntohs(addr4->sin_port) == 56830) {
                int reuse = 1;
                setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
                setsockopt(socket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
            }
        } else if (address->sa_family == AF_INET6) {
            struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)address;
            if (ntohs(addr6->sin6_port) == 56830) {
                int reuse = 1;
                setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
                setsockopt(socket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
            }
        }
    }

    return real_bind(socket, address, address_len);
}
