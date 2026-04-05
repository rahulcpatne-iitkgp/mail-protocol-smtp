#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>

#define MAX_LINE 512
#define MAX_BODY 65536

char server_ip[64];
int server_port;

// DJB2 hash function
unsigned long djb2(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

// Connect to server
int connect_to_server() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sockfd);
        return -1;
    }
    
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return -1;
    }
    
    return sockfd;
}

// Send a line to server
void send_line(int sockfd, const char *line) {
    char buf[MAX_LINE + 3];
    snprintf(buf, sizeof(buf), "%s\r\n", line);
    send(sockfd, buf, strlen(buf), 0);
}

// Read a line from server (blocking)
int read_line(int sockfd, char *buf, size_t size) {
    size_t pos = 0;
    while (pos < size - 1) {
        char c;
        int n = recv(sockfd, &c, 1, 0);
        if (n <= 0) return -1;
        
        if (c == '\r') continue;
        if (c == '\n') {
            buf[pos] = '\0';
            return pos;
        }
        buf[pos++] = c;
    }
    buf[pos] = '\0';
    return pos;
}

// Read input line from user
void read_input(const char *prompt, char *buf, size_t size) {
    printf("%s", prompt);
    fflush(stdout);
    
    if (fgets(buf, size, stdin) == NULL) {
        buf[0] = '\0';
        return;
    }
    
    // Remove trailing newline
    buf[strcspn(buf, "\r\n")] = '\0';
}

// Send mail flow - sockfd already connected
// Returns 0 on success, -1 on connection error
int send_mail(int sockfd) {
    char line[MAX_LINE];
    
    // Set mode
    send_line(sockfd, "MODE SEND");
    if (read_line(sockfd, line, sizeof(line)) < 0) {
        return -1;
    }
    if (strncmp(line, "OK", 2) != 0) {
        printf("Server error: %s\n", line);
        return 0;
    }
    
    // Get sender name
    char from_name[256];
    read_input("From (your name): ", from_name, sizeof(from_name));
    
    char cmd[MAX_LINE];
    snprintf(cmd, sizeof(cmd), "FROM %s", from_name);
    send_line(sockfd, cmd);
    if (read_line(sockfd, line, sizeof(line)) < 0) return -1;
    
    // Get recipients
    int valid_recipients = 0;
    while (1) {
        char recipient[64];
        read_input("To (recipient username, empty line to finish): ", recipient, sizeof(recipient));
        
        if (strlen(recipient) == 0) {
            if (valid_recipients == 0) {
                printf("Error: At least one valid recipient is required.\n");
                continue;
            }
            break;
        }
        
        snprintf(cmd, sizeof(cmd), "TO %s", recipient);
        send_line(sockfd, cmd);
        if (read_line(sockfd, line, sizeof(line)) < 0) return -1;
        
        if (strncmp(line, "OK", 2) == 0) {
            printf("-> Recipient '%s' accepted.\n", recipient);
            valid_recipients++;
        } else {
            printf("-> Error: user '%s' does not exist on this server.\n", recipient);
        }
    }
    
    // Get subject
    char subject[256];
    read_input("Subject: ", subject, sizeof(subject));
    
    snprintf(cmd, sizeof(cmd), "SUB %s", subject);
    send_line(sockfd, cmd);
    if (read_line(sockfd, line, sizeof(line)) < 0) return -1;
    
    // Get body
    printf("Body (type '.' on a line by itself to finish):\n");
    
    send_line(sockfd, "BODY");
    if (read_line(sockfd, line, sizeof(line)) < 0) return -1;
    
    while (1) {
        char body_line[MAX_LINE];
        read_input("", body_line, sizeof(body_line));
        
        if (strcmp(body_line, ".") == 0) {
            send_line(sockfd, ".");
            break;
        }
        
        // Dot-stuffing: if line starts with '.', prepend another '.'
        if (body_line[0] == '.') {
            char stuffed[MAX_LINE + 1];
            snprintf(stuffed, sizeof(stuffed), ".%s", body_line);
            send_line(sockfd, stuffed);
        } else {
            send_line(sockfd, body_line);
        }
    }
    
    // Read delivery confirmation
    if (read_line(sockfd, line, sizeof(line)) < 0) return -1;
    if (strncmp(line, "OK Delivered to ", 16) == 0) {
        int count;
        sscanf(line + 16, "%d", &count);
        printf("Mail delivered to %d recipient%s.\n", count, count == 1 ? "" : "s");
    } else {
        printf("Error: %s\n", line);
    }
    
    // Quit and close
    send_line(sockfd, "QUIT");
    read_line(sockfd, line, sizeof(line));
    return 0;
}

// Check mailbox flow - sockfd already connected
// Returns 0 on success, -1 on connection error
int check_mailbox(int sockfd) {
    char line[MAX_LINE];
    
    // Set mode
    send_line(sockfd, "MODE RECV");
    if (read_line(sockfd, line, sizeof(line)) < 0) {
        return -1;
    }
    if (strncmp(line, "OK", 2) != 0) {
        printf("Server error: %s\n", line);
        return 0;
    }
    
    // Read AUTH REQUIRED with nonce
    if (read_line(sockfd, line, sizeof(line)) < 0) return -1;
    
    char nonce[32];
    if (sscanf(line, "AUTH REQUIRED %s", nonce) != 1) {
        printf("Protocol error: expected AUTH REQUIRED\n");
        return 0;
    }
    
    int auth_attempts = 0;
    int authenticated = 0;
    char username[64];
    
    while (auth_attempts < 3 && !authenticated) {
        read_input("Username: ", username, sizeof(username));
        
        char password[64];
        read_input("Password: ", password, sizeof(password));
        
        // Compute hash
        char hash_input[128];
        snprintf(hash_input, sizeof(hash_input), "%s%s", password, nonce);
        unsigned long hash = djb2(hash_input);
        
        char cmd[MAX_LINE];
        snprintf(cmd, sizeof(cmd), "AUTH %s %lu", username, hash);
        send_line(sockfd, cmd);
        if (read_line(sockfd, line, sizeof(line)) < 0) return -1;
        
        if (strncmp(line, "OK Welcome", 10) == 0) {
            authenticated = 1;
            printf("Welcome, %s!\n", username);
        } else if (strncmp(line, "ERR Too many", 12) == 0) {
            printf("Too many authentication failures. Connection closed.\n");
            return 0;
        } else {
            printf("Authentication failed. Please try again.\n");
            auth_attempts++;
            
            // Read new AUTH REQUIRED
            if (read_line(sockfd, line, sizeof(line)) < 0) return -1;
            if (sscanf(line, "AUTH REQUIRED %s", nonce) != 1) {
                printf("Protocol error.\n");
                return 0;
            }
        }
    }
    
    if (!authenticated) {
        return 0;
    }
    
    // Count messages for initial display
    send_line(sockfd, "COUNT");
    if (read_line(sockfd, line, sizeof(line)) < 0) return -1;
    
    int msg_count = 0;
    sscanf(line + 3, "%d", &msg_count);
    
    // Mailbox menu loop
    while (1) {
        printf("\nMailbox for %s (%d message%s)\n", username, msg_count, msg_count == 1 ? "" : "s");
        printf("1. List all messages\n");
        printf("2. Read a message\n");
        printf("3. Delete a message\n");
        printf("4. Count messages\n");
        printf("5. Logout\n");
        printf("> ");
        fflush(stdout);
        
        char choice[16];
        if (fgets(choice, sizeof(choice), stdin) == NULL) break;
        
        int opt = atoi(choice);
        
        if (opt == 1) {
            // List messages
            send_line(sockfd, "LIST");
            read_line(sockfd, line, sizeof(line));
            
            if (strncmp(line, "OK", 2) == 0) {
                sscanf(line + 3, "%d", &msg_count);
                
                if (msg_count > 0) {
                    printf("\n%-6s %-20s %-30s %s\n", "ID", "From", "Subject", "Date");
                    printf("%-6s %-20s %-30s %s\n", "---", "----", "-------", "----");
                }
                
                // Read listing lines until dot
                while (1) {
                    read_line(sockfd, line, sizeof(line));
                    if (strcmp(line, ".") == 0) break;
                    
                    // Parse tab-separated fields
                    char *id_str = strtok(line, "\t");
                    char *from = strtok(NULL, "\t");
                    char *subject = strtok(NULL, "\t");
                    char *date = strtok(NULL, "\t");
                    
                    if (id_str && from && subject && date) {
                        printf("%-6s %-20.20s %-30.30s %s\n", id_str, from, subject, date);
                    }
                }
                
                if (msg_count == 0) {
                    printf("No messages in mailbox.\n");
                }
            }
        }
        else if (opt == 2) {
            // Read a message
            char id_str[16];
            read_input("Enter message ID: ", id_str, sizeof(id_str));
            
            char cmd[MAX_LINE];
            snprintf(cmd, sizeof(cmd), "READ %s", id_str);
            send_line(sockfd, cmd);
            read_line(sockfd, line, sizeof(line));
            
            if (strncmp(line, "OK", 2) == 0) {
                printf("\n");
                // Read and display message content until dot
                while (1) {
                    read_line(sockfd, line, sizeof(line));
                    if (strcmp(line, ".") == 0) break;
                    
                    // De-stuff lines starting with ..
                    if (line[0] == '.' && line[1] == '.') {
                        printf("%s\n", line + 1);
                    } else {
                        printf("%s\n", line);
                    }
                }
            } else {
                printf("Error: Message not found.\n");
            }
        }
        else if (opt == 3) {
            // Delete a message
            char id_str[16];
            read_input("Enter message ID: ", id_str, sizeof(id_str));
            
            char cmd[MAX_LINE];
            snprintf(cmd, sizeof(cmd), "DELETE %s", id_str);
            send_line(sockfd, cmd);
            read_line(sockfd, line, sizeof(line));
            
            if (strncmp(line, "OK Deleted", 10) == 0) {
                printf("Message %s deleted.\n", id_str);
                msg_count--;
            } else {
                printf("Error: Message not found.\n");
            }
        }
        else if (opt == 4) {
            // Count messages
            send_line(sockfd, "COUNT");
            read_line(sockfd, line, sizeof(line));
            
            if (strncmp(line, "OK", 2) == 0) {
                sscanf(line + 3, "%d", &msg_count);
                printf("You have %d message%s.\n", msg_count, msg_count == 1 ? "" : "s");
            }
        }
        else if (opt == 5) {
            // Logout
            send_line(sockfd, "QUIT");
            read_line(sockfd, line, sizeof(line));
            printf("Logged out.\n");
            break;
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: ./smclient <server_ip> <port>\n");
        exit(1);
    }
    
    strncpy(server_ip, argv[1], sizeof(server_ip) - 1);
    server_port = atoi(argv[2]);
    
    while (1) {
        // Connect to server at start of each iteration
        int sockfd = connect_to_server();
        if (sockfd < 0) {
            printf("Cannot connect to server at %s:%d\n", server_ip, server_port);
            exit(1);
        }
        
        char line[MAX_LINE];
        if (read_line(sockfd, line, sizeof(line)) < 0) {
            printf("Connection closed by server.\n");
            close(sockfd);
            continue;
        }
        printf("Connected to SimpleMail server.\n");
        
        printf("1. Send a mail\n");
        printf("2. Check my mailbox\n");
        printf("3. Quit\n");
        printf("> ");
        fflush(stdout);
        
        char choice[16];
        if (fgets(choice, sizeof(choice), stdin) == NULL) {
            close(sockfd);
            break;
        }
        
        int opt = atoi(choice);
        
        if (opt == 1) {
            if (send_mail(sockfd) < 0) {
                printf("Connection closed by server.\n");
            }
            close(sockfd);
        }
        else if (opt == 2) {
            if (check_mailbox(sockfd) < 0) {
                printf("Connection closed by server.\n");
            }
            close(sockfd);
        }
        else if (opt == 3) {
            printf("Goodbye.\n");
            close(sockfd);
            break;
        }
        else {
            close(sockfd);
        }
    }
    
    return 0;
}
