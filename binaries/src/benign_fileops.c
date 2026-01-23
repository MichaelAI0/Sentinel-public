/**
 * SENTINEL Test Binary - Benign File Operations
 * 
 * A program that does legitimate file I/O operations.
 * Uses file APIs but in completely benign ways.
 * Should produce ZERO or minimal detections.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

// Configuration file paths (standard locations)
const char* config_locations[] = {
    "./config.txt",
    "./settings.ini",
    "./app.conf",
    "~/.myapp/config",
    "/etc/myapp.conf"
};

// Log levels
typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR
} LogLevel;

const char* log_level_names[] = {
    "DEBUG", "INFO", "WARNING", "ERROR"
};

// Simple logging function
void log_message(LogLevel level, const char* message) {
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    printf("[%02d:%02d:%02d] [%s] %s\n", 
           t->tm_hour, t->tm_min, t->tm_sec,
           log_level_names[level], message);
}

// Read entire file into memory
char* read_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        return NULL;
    }
    
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char* content = malloc(size + 1);
    if (content) {
        fread(content, 1, size, file);
        content[size] = '\0';
    }
    
    fclose(file);
    return content;
}

// Write content to file
int write_file(const char* filename, const char* content) {
    FILE* file = fopen(filename, "w");
    if (!file) {
        return -1;
    }
    
    fprintf(file, "%s", content);
    fclose(file);
    return 0;
}

// Append to file
int append_to_file(const char* filename, const char* content) {
    FILE* file = fopen(filename, "a");
    if (!file) {
        return -1;
    }
    
    fprintf(file, "%s\n", content);
    fclose(file);
    return 0;
}

// Count lines in file
int count_lines(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) return -1;
    
    int lines = 0;
    int ch;
    while ((ch = fgetc(file)) != EOF) {
        if (ch == '\n') lines++;
    }
    
    fclose(file);
    return lines;
}

// Copy file
int copy_file(const char* src, const char* dst) {
    FILE* source = fopen(src, "rb");
    if (!source) return -1;
    
    FILE* dest = fopen(dst, "wb");
    if (!dest) {
        fclose(source);
        return -1;
    }
    
    char buffer[4096];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), source)) > 0) {
        fwrite(buffer, 1, bytes, dest);
    }
    
    fclose(source);
    fclose(dest);
    return 0;
}

// Get file size
long get_file_size(const char* filename) {
    struct stat st;
    if (stat(filename, &st) == 0) {
        return st.st_size;
    }
    return -1;
}

// Check if file exists
int file_exists(const char* filename) {
    return access(filename, F_OK) == 0;
}

// List directory contents
void list_directory(const char* path) {
    DIR* dir = opendir(path);
    if (!dir) {
        printf("Cannot open directory: %s\n", path);
        return;
    }
    
    struct dirent* entry;
    printf("Contents of %s:\n", path);
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] != '.') {  // Skip hidden files
            printf("  %s\n", entry->d_name);
        }
    }
    
    closedir(dir);
}

// CSV parser (simple)
void parse_csv_line(const char* line, char fields[][256], int* field_count) {
    *field_count = 0;
    const char* start = line;
    const char* p = line;
    
    while (*p) {
        if (*p == ',' || *p == '\n' || *p == '\0') {
            int len = p - start;
            strncpy(fields[*field_count], start, len);
            fields[*field_count][len] = '\0';
            (*field_count)++;
            start = p + 1;
        }
        p++;
    }
}

// Text statistics
typedef struct {
    int characters;
    int words;
    int lines;
    int paragraphs;
} TextStats;

TextStats analyze_text(const char* text) {
    TextStats stats = {0, 0, 0, 0};
    int in_word = 0;
    int blank_line = 1;
    
    while (*text) {
        stats.characters++;
        
        if (*text == ' ' || *text == '\t') {
            in_word = 0;
        } else if (*text == '\n') {
            stats.lines++;
            if (blank_line) {
                stats.paragraphs++;
            }
            blank_line = 1;
            in_word = 0;
        } else {
            if (!in_word) {
                stats.words++;
                in_word = 1;
            }
            blank_line = 0;
        }
        text++;
    }
    
    return stats;
}

int main(int argc, char* argv[]) {
    printf("=== Benign File Operations Demo ===\n\n");
    
    log_message(LOG_INFO, "Application started");
    
    // Create a test file
    const char* test_file = "/tmp/benign_test.txt";
    const char* content = "Hello, World!\nThis is a test file.\nLine 3\nLine 4\n";
    
    log_message(LOG_INFO, "Writing test file...");
    if (write_file(test_file, content) == 0) {
        printf("Created: %s\n", test_file);
        printf("Size: %ld bytes\n", get_file_size(test_file));
        printf("Lines: %d\n", count_lines(test_file));
    }
    
    // Read and analyze
    char* read_content = read_file(test_file);
    if (read_content) {
        TextStats stats = analyze_text(read_content);
        printf("\nText Statistics:\n");
        printf("  Characters: %d\n", stats.characters);
        printf("  Words: %d\n", stats.words);
        printf("  Lines: %d\n", stats.lines);
        free(read_content);
    }
    
    // List current directory
    printf("\n");
    list_directory(".");
    
    // Cleanup
    remove(test_file);
    log_message(LOG_INFO, "Cleaned up test file");
    
    log_message(LOG_INFO, "Application finished successfully");
    return 0;
}
