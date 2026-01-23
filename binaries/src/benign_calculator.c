/**
 * SENTINEL Test Binary - Benign Calculator
 * 
 * A simple calculator with no suspicious patterns.
 * Should produce ZERO detections.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// Calculator operations
typedef enum {
    OP_ADD,
    OP_SUBTRACT,
    OP_MULTIPLY,
    OP_DIVIDE,
    OP_POWER,
    OP_SQRT,
    OP_MOD
} Operation;

const char* operation_names[] = {
    "Addition",
    "Subtraction", 
    "Multiplication",
    "Division",
    "Power",
    "Square Root",
    "Modulus"
};

// Basic arithmetic
double add(double a, double b) {
    return a + b;
}

double subtract(double a, double b) {
    return a - b;
}

double multiply(double a, double b) {
    return a * b;
}

double divide(double a, double b) {
    if (b == 0) {
        printf("Error: Division by zero!\n");
        return 0;
    }
    return a / b;
}

double power(double base, double exp) {
    return pow(base, exp);
}

double square_root(double a) {
    if (a < 0) {
        printf("Error: Cannot calculate square root of negative number!\n");
        return 0;
    }
    return sqrt(a);
}

int modulus(int a, int b) {
    if (b == 0) {
        printf("Error: Modulus by zero!\n");
        return 0;
    }
    return a % b;
}

// Advanced math functions
double calculate_hypotenuse(double a, double b) {
    return sqrt(a * a + b * b);
}

double calculate_average(double* values, int count) {
    if (count == 0) return 0;
    double sum = 0;
    for (int i = 0; i < count; i++) {
        sum += values[i];
    }
    return sum / count;
}

double calculate_variance(double* values, int count) {
    if (count == 0) return 0;
    double avg = calculate_average(values, count);
    double variance = 0;
    for (int i = 0; i < count; i++) {
        double diff = values[i] - avg;
        variance += diff * diff;
    }
    return variance / count;
}

double calculate_std_dev(double* values, int count) {
    return sqrt(calculate_variance(values, count));
}

// Unit conversions
double meters_to_feet(double m) {
    return m * 3.28084;
}

double kilos_to_pounds(double kg) {
    return kg * 2.20462;
}

double liters_to_gallons(double l) {
    return l * 0.264172;
}

// Prime number check
int is_prime(int n) {
    if (n <= 1) return 0;
    if (n <= 3) return 1;
    if (n % 2 == 0 || n % 3 == 0) return 0;
    for (int i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) return 0;
    }
    return 1;
}

// GCD using Euclidean algorithm
int gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// LCM
int lcm(int a, int b) {
    return (a * b) / gcd(a, b);
}

int main(int argc, char* argv[]) {
    printf("=== Simple Calculator ===\n\n");
    
    // Basic operations
    printf("Basic Operations:\n");
    printf("  10 + 5 = %.2f\n", add(10, 5));
    printf("  10 - 5 = %.2f\n", subtract(10, 5));
    printf("  10 * 5 = %.2f\n", multiply(10, 5));
    printf("  10 / 5 = %.2f\n", divide(10, 5));
    printf("  10 %% 3 = %d\n", modulus(10, 3));
    
    // Advanced math
    printf("\nAdvanced Math:\n");
    printf("  2^8 = %.0f\n", power(2, 8));
    printf("  sqrt(144) = %.0f\n", square_root(144));
    printf("  Hypotenuse(3,4) = %.2f\n", calculate_hypotenuse(3, 4));
    
    // Statistics
    double values[] = {10, 20, 30, 40, 50};
    printf("\nStatistics for [10,20,30,40,50]:\n");
    printf("  Average: %.2f\n", calculate_average(values, 5));
    printf("  Std Dev: %.2f\n", calculate_std_dev(values, 5));
    
    // Number theory
    printf("\nNumber Theory:\n");
    printf("  Is 17 prime? %s\n", is_prime(17) ? "Yes" : "No");
    printf("  Is 18 prime? %s\n", is_prime(18) ? "Yes" : "No");
    printf("  GCD(48, 18) = %d\n", gcd(48, 18));
    printf("  LCM(4, 6) = %d\n", lcm(4, 6));
    
    // Unit conversions
    printf("\nUnit Conversions:\n");
    printf("  10 meters = %.2f feet\n", meters_to_feet(10));
    printf("  70 kg = %.2f lbs\n", kilos_to_pounds(70));
    printf("  3.8 liters = %.2f gallons\n", liters_to_gallons(3.8));
    
    printf("\nCalculator finished.\n");
    return 0;
}
