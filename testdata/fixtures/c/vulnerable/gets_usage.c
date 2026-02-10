/* VULN: gets() usage - banned function, always a buffer overflow.
 * Should trigger GTSS-MEM-001 (Banned Functions: gets).
 */

#include <stdio.h>
#include <string.h>

void read_username(void) {
    char username[32];

    printf("Enter username: ");

    /* Vulnerable: gets() reads unlimited input into a 32-byte buffer.
     * This function was banned in C11.
     */
    gets(username);

    printf("Hello, %s!\n", username);
}

int main(void) {
    read_username();
    return 0;
}
