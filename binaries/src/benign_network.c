/**
 * SENTINEL Test Binary - Benign Network Demo
 * 
 * Contains network-related strings but in completely benign context.
 * Tests if detector correctly identifies legitimate network usage.
 * May produce LOW severity warnings but not HIGH.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Common HTTP status codes (educational/documentation)
typedef struct {
    int code;
    const char* message;
    const char* description;
} HttpStatus;

const HttpStatus http_statuses[] = {
    {200, "OK", "Request succeeded"},
    {201, "Created", "Resource created successfully"},
    {204, "No Content", "Request succeeded with no response body"},
    {301, "Moved Permanently", "Resource has been moved"},
    {302, "Found", "Temporary redirect"},
    {304, "Not Modified", "Resource has not changed"},
    {400, "Bad Request", "Invalid request syntax"},
    {401, "Unauthorized", "Authentication required"},
    {403, "Forbidden", "Access denied"},
    {404, "Not Found", "Resource does not exist"},
    {405, "Method Not Allowed", "HTTP method not supported"},
    {500, "Internal Server Error", "Server encountered an error"},
    {502, "Bad Gateway", "Invalid response from upstream server"},
    {503, "Service Unavailable", "Server is temporarily unavailable"},
};

// Common HTTP headers (for documentation)
const char* common_headers[] = {
    "Content-Type",
    "Content-Length",
    "Accept",
    "Accept-Language",
    "Accept-Encoding",
    "User-Agent",
    "Host",
    "Connection",
    "Cache-Control",
    "Authorization",
    "Cookie",
    "Set-Cookie",
    "Location",
    "Referer",
    "Origin"
};

// Content types
const char* content_types[] = {
    "text/html",
    "text/plain",
    "text/css",
    "text/javascript",
    "application/json",
    "application/xml",
    "application/pdf",
    "image/png",
    "image/jpeg",
    "image/gif",
    "audio/mpeg",
    "video/mp4"
};

// Well-known ports (educational)
typedef struct {
    int port;
    const char* service;
    const char* protocol;
} WellKnownPort;

const WellKnownPort common_ports[] = {
    {20, "FTP Data", "TCP"},
    {21, "FTP Control", "TCP"},
    {22, "SSH", "TCP"},
    {23, "Telnet", "TCP"},
    {25, "SMTP", "TCP"},
    {53, "DNS", "TCP/UDP"},
    {80, "HTTP", "TCP"},
    {110, "POP3", "TCP"},
    {143, "IMAP", "TCP"},
    {443, "HTTPS", "TCP"},
    {993, "IMAPS", "TCP"},
    {995, "POP3S", "TCP"},
    {3306, "MySQL", "TCP"},
    {5432, "PostgreSQL", "TCP"},
    {6379, "Redis", "TCP"},
    {8080, "HTTP Alternate", "TCP"},
    {27017, "MongoDB", "TCP"}
};

// URL parser (simple)
typedef struct {
    char protocol[16];
    char host[256];
    int port;
    char path[512];
} ParsedUrl;

int parse_url(const char* url, ParsedUrl* result) {
    memset(result, 0, sizeof(ParsedUrl));
    
    // Check for protocol
    const char* proto_end = strstr(url, "://");
    if (!proto_end) return -1;
    
    int proto_len = proto_end - url;
    strncpy(result->protocol, url, proto_len);
    
    // Parse host
    const char* host_start = proto_end + 3;
    const char* path_start = strchr(host_start, '/');
    const char* port_start = strchr(host_start, ':');
    
    if (port_start && (!path_start || port_start < path_start)) {
        strncpy(result->host, host_start, port_start - host_start);
        result->port = atoi(port_start + 1);
    } else {
        int host_len = path_start ? (path_start - host_start) : strlen(host_start);
        strncpy(result->host, host_start, host_len);
        result->port = strcmp(result->protocol, "https") == 0 ? 443 : 80;
    }
    
    // Parse path
    if (path_start) {
        strcpy(result->path, path_start);
    } else {
        strcpy(result->path, "/");
    }
    
    return 0;
}

// IP address validator (simple)
int is_valid_ipv4(const char* ip) {
    int parts[4];
    int count = sscanf(ip, "%d.%d.%d.%d", &parts[0], &parts[1], &parts[2], &parts[3]);
    if (count != 4) return 0;
    
    for (int i = 0; i < 4; i++) {
        if (parts[i] < 0 || parts[i] > 255) return 0;
    }
    return 1;
}

// CIDR notation parser
typedef struct {
    unsigned int network;
    int prefix_length;
} CidrBlock;

// Convert IP string to integer
unsigned int ip_to_int(const char* ip) {
    int parts[4];
    sscanf(ip, "%d.%d.%d.%d", &parts[0], &parts[1], &parts[2], &parts[3]);
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
}

// Check if IP is in private range
int is_private_ip(const char* ip) {
    unsigned int addr = ip_to_int(ip);
    
    // 10.0.0.0/8
    if ((addr & 0xFF000000) == 0x0A000000) return 1;
    
    // 172.16.0.0/12
    if ((addr & 0xFFF00000) == 0xAC100000) return 1;
    
    // 192.168.0.0/16
    if ((addr & 0xFFFF0000) == 0xC0A80000) return 1;
    
    return 0;
}

void print_url_info(const char* url) {
    ParsedUrl parsed;
    if (parse_url(url, &parsed) == 0) {
        printf("  Protocol: %s\n", parsed.protocol);
        printf("  Host: %s\n", parsed.host);
        printf("  Port: %d\n", parsed.port);
        printf("  Path: %s\n", parsed.path);
    }
}

int main(int argc, char* argv[]) {
    printf("=== Network Concepts Demo ===\n\n");
    
    // HTTP Status codes
    printf("Common HTTP Status Codes:\n");
    for (int i = 0; i < 5; i++) {
        printf("  %d %s - %s\n", 
               http_statuses[i].code,
               http_statuses[i].message,
               http_statuses[i].description);
    }
    
    // Well-known ports
    printf("\nWell-Known Ports:\n");
    for (int i = 0; i < 5; i++) {
        printf("  Port %d: %s (%s)\n",
               common_ports[i].port,
               common_ports[i].service,
               common_ports[i].protocol);
    }
    
    // URL parsing examples
    printf("\nURL Parsing Examples:\n");
    printf("\nParsing: https://www.example.com/path/to/page\n");
    print_url_info("https://www.example.com/path/to/page");
    
    printf("\nParsing: http://api.service.io:8080/v1/data\n");
    print_url_info("http://api.service.io:8080/v1/data");
    
    // IP validation
    printf("\nIP Address Validation:\n");
    const char* test_ips[] = {"192.168.1.1", "10.0.0.1", "8.8.8.8", "256.1.1.1"};
    for (int i = 0; i < 4; i++) {
        printf("  %s: %s", test_ips[i], is_valid_ipv4(test_ips[i]) ? "Valid" : "Invalid");
        if (is_valid_ipv4(test_ips[i]) && is_private_ip(test_ips[i])) {
            printf(" (Private)");
        }
        printf("\n");
    }
    
    printf("\nDemo completed successfully!\n");
    return 0;
}
