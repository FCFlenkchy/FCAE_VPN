#include <windows.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern int hev_socks5_tunnel_main_from_str(const unsigned char *, unsigned int, int);
extern void hev_socks5_tunnel_quit(void);
extern void hev_socks5_tunnel_stats(size_t *, size_t *, size_t *, size_t *);

struct control {
    HANDLE stop;
    HANDLE done;
};

static void *monitor(void *argument)
{
    struct control *control = argument;
    HANDLE events[] = {control->done, control->stop};
    for (;;) {
        DWORD result = WaitForMultipleObjects(2, events, FALSE, 1000);
        if (result == WAIT_OBJECT_0)
            return NULL;
        if (result == WAIT_OBJECT_0 + 1 || result == WAIT_FAILED) {
            hev_socks5_tunnel_quit();
            return NULL;
        }
        size_t tx_packets = 0, tx_bytes = 0, rx_packets = 0, rx_bytes = 0;
        hev_socks5_tunnel_stats(&tx_packets, &tx_bytes, &rx_packets, &rx_bytes);
        printf("FCAE_HEV_STATS %zu %zu %zu %zu\n", tx_packets, tx_bytes, rx_packets, rx_bytes);
    }
}

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0)
        return 2;
    struct control control = {OpenEventA(SYNCHRONIZE, FALSE, argv[1]), CreateEventW(NULL, TRUE, FALSE, NULL)};
    if (!control.stop || !control.done) {
        fprintf(stderr, "cannot open HEV control events: %lu\n", GetLastError());
        if (control.stop) CloseHandle(control.stop);
        if (control.done) CloseHandle(control.done);
        return 2;
    }
    unsigned char *config = malloc(65537);
    if (!config) {
        CloseHandle(control.stop);
        CloseHandle(control.done);
        return 2;
    }
    size_t length = fread(config, 1, 65537, stdin);
    if (ferror(stdin) || length == 0 || length > 65536) {
        fprintf(stderr, "invalid HEV configuration input\n");
        free(config);
        CloseHandle(control.stop);
        CloseHandle(control.done);
        return 2;
    }
    pthread_t thread;
    if (pthread_create(&thread, NULL, monitor, &control) != 0) {
        free(config);
        CloseHandle(control.stop);
        CloseHandle(control.done);
        return 2;
    }
    int result = hev_socks5_tunnel_main_from_str(config, (unsigned int)length, -1);
    SetEvent(control.done);
    pthread_join(thread, NULL);
    free(config);
    CloseHandle(control.stop);
    CloseHandle(control.done);
    if (result != 0)
        fprintf(stderr, "HEV engine exited with code %d\n", result);
    return result == 0 ? 0 : 1;
}
