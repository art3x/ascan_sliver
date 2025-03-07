#include "pch.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <process.h>  // for _beginthreadex
#include <stdio.h>    // for snprintf, sscanf
#include <ctype.h>    // for isdigit()

#include "output.h"
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")  // Provides IcmpSendEcho and related functions.

// Global output pointer.
Output* output = NULL;

// Global configuration variables (with defaults)
int g_threadLimit = 20; // default number of concurrent threads
static int g_ctimeout = 100; // port scan timeout in msec (default: 100)
int g_rechecks = 0;     // default extra rechecks if a port is closed

// Globals for ping functionality:
static int g_pingEnabled = 1; // if nonzero, perform ping check (default ON)
static int g_isPingOnly = 0;  // if nonzero, perform ping-only scan

// Global flag for NetBIOS name lookup. Default is OFF.
static int g_netbiosEnabled = 0;

// ----------------------
// Global Structures for Grouping Results
// ----------------------
typedef struct _IPResult {
    char ip[INET_ADDRSTRLEN];
    char netbiosName[256]; // To store NETBIOS (hostname) name
    char** details;        // Array of detailed message strings for each open port or ping result.
    int detailCount;
    int detailCapacity;
    int* openPorts;        // Array of open port numbers (for summary). In ping-only mode, a dummy value (0) is added.
    int openCount;
    int openCapacity;
    CRITICAL_SECTION cs;   // To protect updates to this IP's result.
    int responded;         // set to 1 if the IP responded to ping.
} IPResult;

static IPResult* g_ipResults = NULL;
static int g_ipCount = 0;  // Number of IPs in the range

// ----------------------
// Helper: Append a result for an IP (thread-safe)
// ----------------------
void add_ip_result(int ipIndex, int port, const char* message) {
    if (ipIndex < 0 || ipIndex >= g_ipCount)
        return;
    IPResult* ipRes = &g_ipResults[ipIndex];
    EnterCriticalSection(&ipRes->cs);
    // Append the detailed message.
    if (ipRes->detailCount >= ipRes->detailCapacity) {
        int newCapacity = (ipRes->detailCapacity == 0) ? 4 : ipRes->detailCapacity * 2;
        char** newDetails = (char**)realloc(ipRes->details, newCapacity * sizeof(char*));
        if (!newDetails) {
            LeaveCriticalSection(&ipRes->cs);
            return;
        }
        ipRes->details = newDetails;
        ipRes->detailCapacity = newCapacity;
    }
    ipRes->details[ipRes->detailCount] = _strdup(message);
    ipRes->detailCount++;

    // Also add the port number to the openPorts list.
    if (ipRes->openCount >= ipRes->openCapacity) {
        int newCapacity = (ipRes->openCapacity == 0) ? 4 : ipRes->openCapacity * 2;
        int* newPorts = (int*)realloc(ipRes->openPorts, newCapacity * sizeof(int));
        if (!newPorts) {
            LeaveCriticalSection(&ipRes->cs);
            return;
        }
        ipRes->openPorts = newPorts;
        ipRes->openCapacity = newCapacity;
    }
    ipRes->openPorts[ipRes->openCount++] = port;
    LeaveCriticalSection(&ipRes->cs);
}


// ----------------------
// Helper: For sorting
// ----------------------
int cmp_int(const void* a, const void* b) {
    int int_a = *(const int*)a;
    int int_b = *(const int*)b;
    return int_a - int_b;
}

// ----------------------
// Ping Functionality
// ----------------------

// Define echo data and reply size constants.
#define ICMP_ECHO_DATA "abcdefghijklmnopqrstuvwabdcefghi"
#define ICMP_REPLY_SIZE (sizeof(ICMP_ECHO_REPLY) + sizeof(ICMP_ECHO_DATA))
#define ICMP_TIMEOUT 800 // in milliseconds

// ping_ip() uses the ICMP API (via iphlpapi/icmpapi) to send an echo request.
DWORD ping_ip(HANDLE hIcmpFile, IPAddr ip, PICMP_ECHO_REPLY reply) {
    IP_OPTION_INFORMATION options = { 0 };
    options.Ttl = 128; // Use a typical TTL value.
    return IcmpSendEcho(
        hIcmpFile,
        ip,
        (LPVOID)ICMP_ECHO_DATA,
        sizeof(ICMP_ECHO_DATA) - 1,
        &options,
        reply,
        ICMP_REPLY_SIZE,
        ICMP_TIMEOUT
    );
}

// ----------------------
// Ping Thread Data Structure
// ----------------------
typedef struct _PingThreadData {
    char ip[INET_ADDRSTRLEN];
    int ipIndex;
} PingThreadData;

// ----------------------
// Ping Thread Function
// ----------------------
unsigned __stdcall ping_thread(void* param) {
    PingThreadData* data = (PingThreadData*)param;
    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) {
        free(data);
        return 0;
    }
    struct in_addr addr;
    if (inet_pton(AF_INET, data->ip, &addr) != 1) {
        free(data);
        IcmpCloseHandle(hIcmp);
        return 0;
    }
    IPAddr ipAddr = addr.s_addr;
    char replyBuffer[ICMP_REPLY_SIZE];
    PICMP_ECHO_REPLY reply = (PICMP_ECHO_REPLY)replyBuffer;
    DWORD dwRetVal = ping_ip(hIcmp, ipAddr, reply);
    if (dwRetVal != 0) {
        // Atomically mark this IP as having responded.
        InterlockedExchange((volatile LONG*)&g_ipResults[data->ipIndex].responded, 1);
        if (g_isPingOnly) {
            char message[256];
            snprintf(message, sizeof(message), "%s responded to ping", data->ip);
            add_ip_result(data->ipIndex, 0, message);
        }
    }
    IcmpCloseHandle(hIcmp);
    free(data);
    return 0;
}

// ----------------------
// Port and IP Parsing Functions
// ----------------------
int parse_ports(const char* input, int** ports, int* count) {
    if (!input || !ports || !count) return 0;
    if (strchr(input, ',') != NULL) {
        char* copy = _strdup(input);
        if (!copy) return 0;
        int tokenCount = 0;
        char* token = strtok(copy, ",");
        while (token) {
            tokenCount++;
            token = strtok(NULL, ",");
        }
        free(copy);
        int* arr = (int*)malloc(sizeof(int) * tokenCount);
        if (!arr) return 0;
        copy = _strdup(input);
        if (!copy) { free(arr); return 0; }
        int idx = 0;
        token = strtok(copy, ",");
        while (token) {
            char* endptr;
            long port = strtol(token, &endptr, 10);
            if (port <= 0 || port > 65535) {
                free(copy);
                free(arr);
                return 0;
            }
            arr[idx++] = (int)port;
            token = strtok(NULL, ",");
        }
        free(copy);
        *ports = arr;
        *count = tokenCount;
        return 1;
    }
    else {
        const char* p = input;
        char* endptr;
        long first = strtol(p, &endptr, 10);
        if (first <= 0 || first > 65535) return 0;
        while (*endptr && !isdigit((unsigned char)*endptr) && *endptr != '-') {
            endptr++;
        }
        if (*endptr == '-') {
            const char* dashPos = endptr + 1;
            if (!isdigit((unsigned char)*dashPos)) {
                int* arr = (int*)malloc(sizeof(int));
                if (!arr) return 0;
                arr[0] = (int)first;
                *ports = arr;
                *count = 1;
                return 1;
            }
            else {
                long second = strtol(dashPos, &endptr, 10);
                if (second <= 0 || second > 65535 || second < first)
                    return 0;
                int cnt = (int)(second - first + 1);
                int* arr = (int*)malloc(sizeof(int) * cnt);
                if (!arr) return 0;
                for (int i = 0; i < cnt; i++) {
                    arr[i] = (int)first + i;
                }
                *ports = arr;
                *count = cnt;
                return 1;
            }
        }
        else {
            int* arr = (int*)malloc(sizeof(int));
            if (!arr) return 0;
            arr[0] = (int)first;
            *ports = arr;
            *count = 1;
            return 1;
        }
    }
}

int parse_ip_range(const char* input, char* startIp, char* endIp) {
    const char* dash = strchr(input, '-');
    if (!dash) {
        strncpy(startIp, input, INET_ADDRSTRLEN);
        startIp[INET_ADDRSTRLEN - 1] = '\0';
        strncpy(endIp, input, INET_ADDRSTRLEN);
        endIp[INET_ADDRSTRLEN - 1] = '\0';
    }
    else {
        size_t len = dash - input;
        if (len >= INET_ADDRSTRLEN)
            return 0;
        strncpy(startIp, input, len);
        startIp[len] = '\0';
        if (strchr(dash + 1, '.') == NULL) {
            // For shorthand notation like "192.168.1.1-100"
            strncpy(endIp, startIp, INET_ADDRSTRLEN);
            endIp[INET_ADDRSTRLEN - 1] = '\0';
            char* lastDot = strrchr(endIp, '.');
            if (!lastDot)
                return 0;
            size_t remain = INET_ADDRSTRLEN - (lastDot - endIp + 1);
            snprintf(lastDot + 1, remain, "%s", dash + 1);
        }
        else {
            strncpy(endIp, dash + 1, INET_ADDRSTRLEN);
            endIp[INET_ADDRSTRLEN - 1] = '\0';
        }
    }
    return 1;
}

uint32_t ip_to_int(const char* ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1)
        return 0;
    return ntohl(addr.s_addr);
}

void int_to_ip(uint32_t ipInt, char* buffer) {
    struct in_addr addr;
    addr.s_addr = htonl(ipInt);
    inet_ntop(AF_INET, &addr, buffer, INET_ADDRSTRLEN);
}

// ----------------------
// Multithreaded Port Scanner Functions
// ----------------------
typedef struct _ThreadData {
    char ip[INET_ADDRSTRLEN];
    int port;
    int ipIndex; // Index into the global IP results array.
} ThreadData;

int scan_port(const char* ip, int port, int ipIndex) {
    int totalAttempts = 1 + g_rechecks;
    int attempt;
    int success = 0;
    char message[1024] = { 0 };

    for (attempt = 0; attempt < totalAttempts; attempt++) {
        SOCKET sock;
        struct sockaddr_in server;
        char buffer[1024];
        int result;
        int ctimeout = g_ctimeout; // use configurable timeout
        fd_set writefds;
        struct timeval tv;

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET)
            continue;

        DWORD timeout = 100;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

        // Set non-blocking mode.
        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);

        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        server.sin_port = htons(port);
        inet_pton(AF_INET, ip, &server.sin_addr);

        if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEWOULDBLOCK) {
                FD_ZERO(&writefds);
                FD_SET(sock, &writefds);
                tv.tv_sec = ctimeout / 1000;
                tv.tv_usec = (ctimeout % 1000) * 1000;
                int res = select(0, NULL, &writefds, NULL, &tv);
                if (!(res > 0 && FD_ISSET(sock, &writefds))) {
                    closesocket(sock);
                    continue;
                }
            }
            else {
                closesocket(sock);
                continue;
            }
        }

        // Restore blocking mode.
        mode = 0;
        ioctlsocket(sock, FIONBIO, &mode);

        // Try to receive an initial banner.
        result = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (result > 0) {
            buffer[result] = '\0';
            char* newline = strpbrk(buffer, "\r\n");
            if (newline) {
                *newline = '\0';
            }
            snprintf(message, sizeof(message), "%s:%d is open. %s", ip, port, buffer);
            success = 1;
            closesocket(sock);
            add_ip_result(ipIndex, port, message);
            break;
        }
        else {
            // No banner received. Send an HTTP GET request.
            const char* httpRequestTemplate = "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n";
            char httpRequest[256];
            snprintf(httpRequest, sizeof(httpRequest), httpRequestTemplate, ip);
            int sendResult = send(sock, httpRequest, (int)strlen(httpRequest), 0);
            if (sendResult == SOCKET_ERROR) {
                closesocket(sock);
                continue;
            }
            else {
                char httpResponse[4096];
                int totalReceived = 0;
                int recvResult;
                while ((recvResult = recv(sock, httpResponse + totalReceived, sizeof(httpResponse) - totalReceived - 1, 0)) > 0) {
                    totalReceived += recvResult;
                    if (totalReceived >= (int)sizeof(httpResponse) - 1)
                        break;
                }
                httpResponse[totalReceived] = '\0';

                if (totalReceived > 0) {
                    int responseCode = 0;
                    char protocol[16] = { 0 };
                    char statusMessage[64] = { 0 };
                    if (sscanf(httpResponse, "%15s %d %63[^\r\n]", protocol, &responseCode, statusMessage) == 3) {
                        int contentLength = 0;
                        char* clHeader = strstr(httpResponse, "Content-Length:");
                        if (clHeader) {
                            clHeader += strlen("Content-Length:");
                            while (*clHeader == ' ') clHeader++;
                            contentLength = atoi(clHeader);
                        }
                        else {
                            contentLength = totalReceived;
                        }
                        char title[256] = { 0 };
                        char* titleStart = strstr(httpResponse, "<title>");
                        if (titleStart) {
                            titleStart += strlen("<title>");
                            char* titleEnd = strstr(titleStart, "</title>");
                            if (titleEnd && (titleEnd - titleStart) < (int)sizeof(title)) {
                                size_t titleLen = titleEnd - titleStart;
                                strncpy(title, titleStart, titleLen);
                                title[titleLen] = '\0';
                            }
                        }
                        if (responseCode == 200)
                            snprintf(message, sizeof(message), "%s:%d is open.\033[92m code:%d len:%d title:%s\033[0m", ip, port, responseCode, contentLength, title);
                        else
                            snprintf(message, sizeof(message), "%s:%d is open.\033[31m code:%d len:%d title:%s\033[0m", ip, port, responseCode, contentLength, title);
                        success = 1;
                        closesocket(sock);
                        add_ip_result(ipIndex, port, message);
                        break;
                    }
                }
            }
        }

        snprintf(message, sizeof(message), "%s:%d is open.", ip, port);
        closesocket(sock);
        add_ip_result(ipIndex, port, message);
        break;
    }
    return success;
}

unsigned __stdcall port_thread(void* param) {
    ThreadData* data = (ThreadData*)param;
    scan_port(data->ip, data->port, data->ipIndex);
    free(data);
    return 0;
}

// ----------------------
// run_port_scan: Main scanning function.
// ----------------------
int run_port_scan(const char* ipRange, const char* portRange) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        append(output, "WSAStartup failed\n");
        return -1;
    }

    // Record start time.
    DWORD startTime = GetTickCount();

    char startIp[INET_ADDRSTRLEN], endIp[INET_ADDRSTRLEN];
    if (!parse_ip_range(ipRange, startIp, endIp)) {
        append(output, "Invalid IP range\n");
        WSACleanup();
        return -1;
    }

    int* portList = NULL;
    int portCount = 0;
    if (!g_isPingOnly) {
        if (!parse_ports(portRange, &portList, &portCount)) {
            append(output, "Invalid port specification\n");
            WSACleanup();
            return -1;
        }
    }

    int isRangeScan = (strchr(ipRange, '-') != NULL);
    uint32_t ipStart = ip_to_int(startIp);
    uint32_t ipEnd = ip_to_int(endIp);
    if (ipStart == 0 || ipEnd == 0) {
        append(output, "IP conversion failed\n");
        WSACleanup();
        if (portList) free(portList);
        return -1;
    }

    // Initialize the global IP results array.
    g_ipCount = (int)(ipEnd - ipStart + 1);
    g_ipResults = (IPResult*)malloc(sizeof(IPResult) * g_ipCount);
    if (!g_ipResults) {
        append(output, "Memory allocation failed for IP results\n");
        WSACleanup();
        if (portList) free(portList);
        return -1;
    }
    for (uint32_t i = 0; i < (uint32_t)g_ipCount; i++) {
        IPResult* ipRes = &g_ipResults[i];
        int_to_ip(ipStart + i, ipRes->ip);
        ipRes->netbiosName[0] = '\0';
        ipRes->details = NULL;
        ipRes->detailCount = 0;
        ipRes->detailCapacity = 0;
        ipRes->openPorts = NULL;
        ipRes->openCount = 0;
        ipRes->openCapacity = 0;
        ipRes->responded = 0; // Initialize as not responded.
        InitializeCriticalSection(&ipRes->cs);
    }

    // If ping is enabled, spawn ping threads for all IPs.
    if (g_pingEnabled) {
        int pingThreadCount = 0;
        int pingThreadCapacity = g_threadLimit;
        HANDLE* pingHandles = (HANDLE*)malloc(sizeof(HANDLE) * pingThreadCapacity);
        if (!pingHandles) {
            append(output, "Memory allocation failed for ping handles\n");
            WSACleanup();
            if (portList) free(portList);
            return -1;
        }
        for (uint32_t ip = ipStart; ip <= ipEnd; ip++) {
            char ipStr[INET_ADDRSTRLEN];
            int_to_ip(ip, ipStr);
            int ipIndex = (int)(ip - ipStart);

            PingThreadData* data = (PingThreadData*)malloc(sizeof(PingThreadData));
            if (!data)
                continue;
            strncpy(data->ip, ipStr, INET_ADDRSTRLEN);
            data->ip[INET_ADDRSTRLEN - 1] = '\0';
            data->ipIndex = ipIndex;

            uintptr_t hThread = _beginthreadex(NULL, 0, ping_thread, data, 0, NULL);
            if (hThread != 0) {
                if (pingThreadCount >= pingThreadCapacity) {
                    WaitForMultipleObjects(pingThreadCount, pingHandles, TRUE, INFINITE);
                    for (int i = 0; i < pingThreadCount; i++)
                        CloseHandle(pingHandles[i]);
                    pingThreadCount = 0;
                }
                pingHandles[pingThreadCount++] = (HANDLE)hThread;
            }
            else {
                free(data);
            }
        }
        if (pingThreadCount > 0) {
            WaitForMultipleObjects(pingThreadCount, pingHandles, TRUE, INFINITE);
            for (int i = 0; i < pingThreadCount; i++) {
                CloseHandle(pingHandles[i]);
            }
        }
        free(pingHandles);
    }

    // If in ping-only mode, no further scanning is needed.
    if (g_isPingOnly) {
        WSACleanup();
    }
    else {
        // For each IP that responded (if ping enabled) or for all IPs (if ping disabled),
        // spawn port scanning threads.
        int threadCount = 0;
        int capacity = g_threadLimit;
        HANDLE* handles = (HANDLE*)malloc(sizeof(HANDLE) * capacity);
        if (!handles) {
            append(output, "Memory allocation failed for port scan handles\n");
            WSACleanup();
            if (portList) free(portList);
            return -1;
        }
        for (uint32_t ip = ipStart; ip <= ipEnd; ip++) {
            char ipStr[INET_ADDRSTRLEN];
            int_to_ip(ip, ipStr);
            int ipIndex = (int)(ip - ipStart);

            // If ping is enabled, skip IPs that did not respond.
            if (g_pingEnabled && !g_ipResults[ipIndex].responded)
                continue;

            for (int i = 0; i < portCount; i++) {
                int port = portList[i];
                ThreadData* data = (ThreadData*)malloc(sizeof(ThreadData));
                if (!data)
                    continue;
                strncpy(data->ip, ipStr, INET_ADDRSTRLEN);
                data->ip[INET_ADDRSTRLEN - 1] = '\0';
                data->port = port;
                data->ipIndex = ipIndex;
                uintptr_t hThread = _beginthreadex(NULL, 0, port_thread, data, 0, NULL);
                if (hThread != 0) {
                    if (threadCount >= capacity) {
                        WaitForMultipleObjects(threadCount, handles, TRUE, INFINITE);
                        for (int i = 0; i < threadCount; i++)
                            CloseHandle(handles[i]);
                        threadCount = 0;
                    }
                    handles[threadCount++] = (HANDLE)hThread;
                }
                else {
                    free(data);
                }
            }
        }
        if (threadCount > 0) {
            WaitForMultipleObjects(threadCount, handles, TRUE, INFINITE);
            for (int i = 0; i < threadCount; i++) {
                CloseHandle(handles[i]);
            }
        }
        free(handles);
        WSACleanup();
        if (portList) free(portList);
    }

    // Lookup NETBIOS names only if enabled.
    if (g_netbiosEnabled) {
        for (int i = 0; i < g_ipCount; i++) {
            IPResult* ipRes = &g_ipResults[i];
            if (ipRes->openCount > 0) {
                struct sockaddr_in sa;
                memset(&sa, 0, sizeof(sa));
                sa.sin_family = AF_INET;
                inet_pton(AF_INET, ipRes->ip, &sa.sin_addr);
                char host[NI_MAXHOST] = { 0 };
                if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), NULL, 0, NI_NAMEREQD) == 0) {
                    strncpy(ipRes->netbiosName, host, sizeof(ipRes->netbiosName) - 1);
                    ipRes->netbiosName[sizeof(ipRes->netbiosName) - 1] = '\0';
                }
            }
        }
    }

    // Output detailed results.
    for (int i = 0; i < g_ipCount; i++) {
        IPResult* ipRes = &g_ipResults[i];
        if (ipRes->detailCount > 0) {
            for (int j = 0; j < ipRes->detailCount; j++) {
                append(output, "%s\n", ipRes->details[j]);
            }
            if (isRangeScan && (i != g_ipCount - 1)) {
                append(output, "\033[97m------------------\033[0m\n");
            }
        }
    }

    // Print summary.
    append(output, "\n\033[33mSummary:\033[0m\n");
    for (int i = 0; i < g_ipCount; i++) {
        IPResult* ipRes = &g_ipResults[i];
        if (ipRes->openCount > 0) {
            if (g_isPingOnly) {
                append(output, "%s responded to ping\n", ipRes->ip);
            }
            else {
                // Sort the ports array in ascending order.
                qsort(ipRes->openPorts, ipRes->openCount, sizeof(int), cmp_int);

                char portsStr[512] = { 0 };
                size_t offset = 0;
                for (int j = 0; j < ipRes->openCount; j++) {
                    int n = snprintf(portsStr + offset, sizeof(portsStr) - offset, "%d%s",
                        ipRes->openPorts[j], (j < ipRes->openCount - 1 ? "," : ""));
                    if (n < 0 || (size_t)n >= sizeof(portsStr) - offset)
                        break;
                    offset += n;
                }
                if (ipRes->netbiosName[0] != '\0') {
                    append(output, "%s: %s (%s)\n", ipRes->ip, portsStr, ipRes->netbiosName);
                }
                else {
                    append(output, "%s: %s\n", ipRes->ip, portsStr);
                }
            }
        }
    }

    // Record end time and print scan duration.
    DWORD endTime = GetTickCount();
    DWORD elapsedTime = endTime - startTime;
    double seconds = elapsedTime / 1000.0;
    append(output, "\nScan Duration: %.2f s\n", seconds);

    // Free allocated IP results.
    for (int i = 0; i < g_ipCount; i++) {
        IPResult* ipRes = &g_ipResults[i];
        DeleteCriticalSection(&ipRes->cs);
        for (int j = 0; j < ipRes->detailCount; j++) {
            free(ipRes->details[j]);
        }
        free(ipRes->details);
        free(ipRes->openPorts);
    }
    free(g_ipResults);
    return 0;
}

extern "C" {
    __declspec(dllexport) int __cdecl Execute(char* argsBuffer, uint32_t bufferSize, goCallback callback);
}

int Execute(char* argsBuffer, uint32_t bufferSize, goCallback callback) {
    output = NewOutput(128, callback);

    g_threadLimit = 20; // default number of concurrent threads
    g_ctimeout = 100; // port scan timeout in msec (default: 100)
    g_rechecks = 0;     // default extra rechecks if a port is closed
    g_pingEnabled = 1;  // if nonzero, perform ping check (default ON)
    g_isPingOnly = 0;   // if nonzero, perform ping-only scan
    g_netbiosEnabled = 0; // if nonzero, perform NetBIOS lookup
    int isNoPorts = 0;
    append(output, "\033[36m");
    append(output, " _____     _   _____             \n");
    append(output, "|  _  |___| |_|   __|___ ___ ___ \n");
    append(output, "|     |  _|  _|__   |  _| .'|   |\n");
    append(output, "|__|__|_| |_| |_____|___|__,|_|_|\n");
    append(output, "\033[32m");
    append(output, "ArtScan by @art3x\033[0m         ver 1.1\n");

    if (bufferSize < 1) {
        append(output, "[!] Usage: <ipRange> [portRange] [-T threadLimit] [-t timeout] [-r rechecks] [-Pn] [-i] [-Nb] [-h]\n");
        return failure(output);
    }

    char* buf = (char*)malloc(bufferSize + 1); // +1 to null-terminate
    if (buf == NULL) {
        append(output, "[!] Memory allocation error.\n");
        return failure(output);
    }

    memcpy(buf, argsBuffer, bufferSize);
    buf[bufferSize] = '\0'; // explicitly null-terminate

    // Remove trailing CRLF
    buf[strcspn(buf, "\r\n")] = '\0';

    // Check if help is requested.
    if (strcmp(buf, "-h") == 0 || strstr(buf, " -h") != NULL) {
        append(output, "Usage: <ipRange> [portRange] [-T threadLimit] [-t timeout] [-r rechecks] [-Pn] [-i] [-Nb] [-h]\n");
        append(output, "  ipRange:   Single IP or range (e.g., 192.168.1.1-100 or 192.168.1.1-192.168.1.100)\n");
        append(output, "  portRange: Single port, range (80-90), or comma-separated list (22,80,443)\n");
        append(output, "  -T:        Set thread limit (default: 20, max: 50)\n");
        append(output, "  -t:        Set port scan timeout in msec (default: 100)\n");
        append(output, "  -r:        Set extra rechecks for unanswered ports (default: 0, max: 10)\n");
        append(output, "  -Pn:       Disable ping (skip host availability check)\n");
        append(output, "  -i:        Perform ping scan only (skip port scan)\n");
        append(output, "  -Nb:       Enable hostname resolution during ICMP (like ping -a)\n");
        append(output, "  -h:        Display this help message\n");
        return success(output);
    }

    // Parse the first token as the target IP range.
    char* targetRange = strtok(buf, " ");
    if (!targetRange) {
        append(output, "[!] Usage: <ipRange> [portRange] [-t threadLimit] [-r rechecks] [-Pn] [-i] [-Nb] [-h]\n");
        return failure(output);
    }

    char* portRange = NULL;
    bool pingOnlyFlag = false;
    // Process all remaining tokens.
    char* token = NULL;
    while ((token = strtok(NULL, " ")) != NULL) {
        if (token[0] == '-') {
            if (strncmp(token, "-T", 2) == 0) {
                const char* valueStr = token + 2;
                if (*valueStr == '\0') {
                    valueStr = strtok(NULL, " ");
                }
                if (valueStr)
                    g_threadLimit = atoi(valueStr);
                if (g_threadLimit > 50 || g_threadLimit < 1)
                    g_threadLimit = 50;
            }
            else if (strncmp(token, "-t", 2) == 0) {
                const char* valueStr = token + 2;
                if (*valueStr == '\0') {
                    valueStr = strtok(NULL, " ");
                }
                if (valueStr)
                    g_ctimeout = atoi(valueStr);
                if (g_ctimeout < 10) g_ctimeout = 10; // set a reasonable minimum
                if (g_ctimeout > 10000) g_ctimeout = 10000; // set a reasonable max
            }
            else if (strncmp(token, "-r", 2) == 0) {
                const char* valueStr = token + 2;
                if (*valueStr == '\0') {
                    valueStr = strtok(NULL, " ");
                }
                if (valueStr)
                    g_rechecks = atoi(valueStr);
                if (g_rechecks > 10 || g_rechecks < 0)
                    g_rechecks = 10;
            }
            else if (strncmp(token, "-Pn", 3) == 0) {
                g_pingEnabled = 0;
            }
            else if (strncmp(token, "-i", 2) == 0) {
                pingOnlyFlag = true;
            }
            else if (strncmp(token, "-Nb", 3) == 0) {
                g_netbiosEnabled = 1;
            }
        }
        else {
            // The first non-flag token after the IP is considered the port range.
            if (portRange == NULL) {
                char filtered[128] = { 0 };
                int j = 0;
                // Copy characters as long as they are digits or '-'
                for (int i = 0; token[i] != '\0' && j < (int)sizeof(filtered) - 1; i++) {
                    if (isdigit((unsigned char)token[i]) || token[i] == '-' || token[i] == ',') {
                        filtered[j++] = token[i];
                    }
                    else {
                        break;
                    }
                }
                filtered[j] = '\0';
                portRange = _strdup(filtered);
            }
        }
    }

    // If -i flag is provided, force ping-only mode and ignore any port range.
    if (pingOnlyFlag) {
        g_isPingOnly = 1;
        if (portRange) {
            free(portRange);
            portRange = NULL;
        }
    }
    else {
        // If no port range is provided, default to a common port list.
        if (portRange == NULL) {
            portRange = _strdup("20,21,22,23,25,53,65,66,69,80,88,110,111,135,139,143,194,389,443,445,464,465,587,593,636,993,995,1194,1433,1494,1521,1540,1666,1801,1812,1813,2049,2179,2222,2383,2598,3000,3268,3269,3306,3333,3389,4444,4848,5000,5044,5060,5061,5432,5555,5601,5631,5666,5671,5672,5693,5900,5931,5938,5984,5985,5986,6160,6200,6379,6443,6600,6771,7001,7474,7687,7777,7990,8000,8006,8080,8081,8082,8086,8088,8090,8091,8200,8443,8444,8500,8529,8530,8531,8600,8888,8912,9000,9042,9080,9090,9092,9160,9200,9300,9389,9443,9999,10000,10001,10011,10050,10051,11211,15672,17990,27015,27017,30033,47001");
            isNoPorts = 1;
        }
        g_isPingOnly = 0;
    }

    append(output, "\033[97m");
    append(output, "[.] Scanning IP(s): %s\n", targetRange);
    if (!g_isPingOnly)
        if (!isNoPorts)
            append(output, "[.] PORT(s): %s\n", portRange);
        else
            append(output, "[.] PORT(s): TOP 120\n");
    else
        append(output, "[.] Ping-only scan mode\n");
    append(output, "[.] Threads: %d   Rechecks: %d   Timeout: %d\n", g_threadLimit, g_rechecks, g_ctimeout);
    if (!g_pingEnabled)
        append(output, "[.] Ping disabled (-Pn flag used)\n");
    append(output, "\033[0m");
        
    // run_port_scan() will perform the ping scan and, if not in ping-only mode, the port scan.
    run_port_scan(targetRange, portRange);

    free(buf);
    // Free allocated portRange.
    if (portRange != NULL) {
        free(portRange);
    }

    return success(output);
}