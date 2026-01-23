/**
 * SENTINEL Test Binary - Benign Hello World
 * 
 * A completely clean binary with no suspicious patterns.
 * Should produce ZERO detections.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

// Simple greeting messages
const char* greetings[] = {
    "Hello, World!",
    "Good morning!",
    "Welcome to the program",
    "Have a nice day",
    "Thank you for using this software"
};

// Days of the week
const char* days[] = {
    "Sunday", "Monday", "Tuesday", "Wednesday", 
    "Thursday", "Friday", "Saturday"
};

// Months
const char* months[] = {
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"
};

// Simple math operations
double calculate_area(double radius) {
    return 3.14159265359 * radius * radius;
}

double calculate_perimeter(double radius) {
    return 2 * 3.14159265359 * radius;
}

int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

int fibonacci(int n) {
    if (n <= 1) return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

// String utilities
void reverse_string(char* str) {
    int len = strlen(str);
    for (int i = 0; i < len / 2; i++) {
        char temp = str[i];
        str[i] = str[len - 1 - i];
        str[len - 1 - i] = temp;
    }
}

int count_vowels(const char* str) {
    int count = 0;
    while (*str) {
        char c = *str;
        if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u' ||
            c == 'A' || c == 'E' || c == 'I' || c == 'O' || c == 'U') {
            count++;
        }
        str++;
    }
    return count;
}

// Temperature conversion
double celsius_to_fahrenheit(double c) {
    return (c * 9.0 / 5.0) + 32.0;
}

double fahrenheit_to_celsius(double f) {
    return (f - 32.0) * 5.0 / 9.0;
}

// Simple data structure
typedef struct {
    char name[64];
    int age;
    double height;
} Person;

void print_person(Person* p) {
    printf("Name: %s, Age: %d, Height: %.2f\n", p->name, p->age, p->height);
}

int main(int argc, char* argv[]) {
    printf("=== Benign Test Application ===\n\n");
    
    // Print greeting
    printf("%s\n\n", greetings[0]);
    
    // Show date info
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    printf("Today is %s, %s %d\n", 
           days[t->tm_wday], 
           months[t->tm_mon], 
           t->tm_mday);
    
    // Math examples
    printf("\nMath Examples:\n");
    printf("  Circle area (r=5): %.2f\n", calculate_area(5.0));
    printf("  Factorial of 6: %d\n", factorial(6));
    printf("  Fibonacci(10): %d\n", fibonacci(10));
    
    // Temperature conversion
    printf("\nTemperature Conversions:\n");
    printf("  20°C = %.1f°F\n", celsius_to_fahrenheit(20.0));
    printf("  68°F = %.1f°C\n", fahrenheit_to_celsius(68.0));
    
    // String example
    char test[] = "Hello";
    printf("\nString Examples:\n");
    printf("  Vowels in 'Hello': %d\n", count_vowels(test));
    
    // Person example
    Person person = {"Alice", 30, 5.6};
    printf("\nPerson Info:\n  ");
    print_person(&person);
    
    printf("\nProgram completed successfully!\n");
    return 0;
}
