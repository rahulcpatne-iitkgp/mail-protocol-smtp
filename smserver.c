#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>
#include <dirent.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdarg.h>

#define MAX_LINE 513
#define MAX_BODY 65536
#define FILE_NAME_SIZE 50
#define USERNAME_SIZE 21
#define PASSWORD_SIZE 31
#define MAX_USERS 100
#define MAX_CLIENTS 100
#define MAX_RECIPIENTS 50
#define MAILBOX_PATH_SIZE 64
#define NONCE_SIZE 9
#define MODE_TIMEOUT 30

int strncmp_nocase(char* s1, char* s2, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        unsigned char ca = (unsigned char)s1[i];
        unsigned char cb = (unsigned char)s2[i];

        int la = tolower(ca);
        int lb = tolower(cb);

        if (la != lb) return la - lb;
        if (ca == '\0') return 0;
    }
    return 0;
}

// User structure
typedef struct user_t {
    char username[USERNAME_SIZE];
    char password[PASSWORD_SIZE];
    char mailbox_dir[MAILBOX_PATH_SIZE];
    int next_mail_idx;
} user_t;

user_t reg_users[MAX_USERS];
int n_users;

// Client session modes
typedef enum {
    MODE_NONE,
    MODE_SEND,
    MODE_RECV
} session_mode_t;

// SMTP2 states
typedef enum {
    SMTP2_INIT,
    SMTP2_FROM_DONE,
    SMTP2_TO_DONE,
    SMTP2_SUB_DONE,
    SMTP2_BODY_STARTED
} smtp2_state_t;

// SMP states
typedef enum {
    SMP_AUTH_WAIT,
    SMP_AUTHENTICATED
} smp_state_t;

// Per-client state
typedef struct client_state {
    int fd;
    int active;
    char ip[INET_ADDRSTRLEN];
    int port;
    time_t connect_time;
    session_mode_t mode;
    
    char recv_buf[MAX_LINE * 2 - 1];
    int recv_len;
    
    // SMTP2 state
    smtp2_state_t smtp2_state;
    char from_name[512];
    int recipients[MAX_RECIPIENTS];
    int recipient_count;
    char subject[512];
    char body[MAX_BODY + 1];
    int body_len;
    
    // SMP state
    smp_state_t smp_state;
    int auth_user_idx;
    char nonce[NONCE_SIZE];
    int auth_attempts;
} client_state_t;

client_state_t clients[MAX_CLIENTS];

// Logging with timestamp
void server_log(const char *fmt, ...) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    printf("[%04d-%02d-%02d %02d:%02d:%02d] ",
           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
           t->tm_hour, t->tm_min, t->tm_sec);
    
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
    fflush(stdout);
}

// Get current timestamp string
void get_timestamp(char *buf, size_t size) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    snprintf(buf, size, "%04d-%02d-%02d %02d:%02d:%02d",
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
             t->tm_hour, t->tm_min, t->tm_sec);
}

// DJB2 hash function
unsigned long djb2(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    return hash;
}

// Generate random alphanumeric nonce (len includes '\0')
void generate_nonce(char *buf, size_t len) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (size_t i = 0; i < len - 1; i++) {
        buf[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    buf[len - 1] = '\0';
}

// Eead file and fill user data
void read_userfile(char *filename) {
    FILE* fp = fopen(filename, "r");
    if(fp == NULL) {
        perror("user file missing/corrupted");
        exit(1);
    }
    mkdir("mailbox", 0755);

    int lineno = 0;
    char line[256];
    
    n_users = 0;
    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) == 0) continue;
        
        char username[USERNAME_SIZE + 10];
        char password[PASSWORD_SIZE + 10];
        
        if (sscanf(line, "%s %s", username, password) != 2) {
            fprintf(stderr, "Invalid format on line %d, ignored\n", lineno);
            continue;
        }

        // Validate username and password
        int valid = 1;
        if (strlen(username) > 20) {
            valid = 0;
        } else {
            for (int i = 0; username[i]; i++) {
                if (username[i] < 'a' || username[i] > 'z') {
                    valid = 0;
                    break;
                }
            }
        }
        if (strlen(password) > 30) {
            valid = 0;
        } else {
            for (int i = 0; password[i]; i++) {
                char c = password[i];
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) {
                    valid = 0;
                    break;
                }
            }
        }

        if(!valid) {
            fprintf(stderr, "Invalid user credentials on line %d ignored\n", lineno);
            continue;
        }

        strncpy(reg_users[n_users].username, username, USERNAME_SIZE - 1);
        strncpy(reg_users[n_users].password, password, PASSWORD_SIZE - 1);
        snprintf(reg_users[n_users].mailbox_dir, MAILBOX_PATH_SIZE, "mailbox/%s", username);
        mkdir(reg_users[n_users].mailbox_dir, 0755);
        
        n_users++;
        lineno++;
        if(n_users >= MAX_USERS) {
            fprintf(stderr, "Too many users in file (max %d)\n", MAX_USERS);
            break;
        }
    }
    fclose(fp);
}

// Get next mail ID (max existing id + 1)
int get_next_mail_idx(int user_idx) {
    DIR *dir = opendir(reg_users[user_idx].mailbox_dir);
    if (!dir) return 1;
    int max_idx = 0;
    struct dirent* ent;
    while ((ent = readdir(dir))) {
        int id;
        if (sscanf(ent->d_name, "%d.txt", &id) == 1) {
            if (id > max_idx) max_idx = id;
        }
    }
    closedir(dir);
    return max_idx+1;
}

void close_client(int idx, fd_set* master_set_ptr) {
    if(clients[idx].active) {
        close(clients[idx].fd);
        server_log("Client disconnected from %s:%d", clients[idx].ip, clients[idx].port);
        clients[idx].active = 0;
        FD_CLR(clients[idx].fd, master_set_ptr);
    }
}

int find_user(const char *username) {
    char lower[USERNAME_SIZE];
    for (int i = 0; username[i] && i < USERNAME_SIZE - 1; i++) {
        lower[i] = tolower(username[i]);
        lower[i + 1] = '\0';
    }
    for (int i = 0; i < n_users; i++) {
        if (strcmp(reg_users[i].username, lower) == 0) {
            return i;
        }
    }
    return -1;
}

int deliver_mail(client_state_t *client, char* recipient_list) {
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));
    
    // Deliver to each recipient
    int del_cnt = 0;
    for (int i = 0; i < client->recipient_count; i++) {
        int user_idx = client->recipients[i];
        char filepath[256];
        int mail_id = reg_users[user_idx].next_mail_idx++;
        snprintf(filepath, sizeof(filepath), "%s/%d.txt", reg_users[user_idx].mailbox_dir, mail_id);
        
        FILE *fp = fopen(filepath, "w");
        if (!fp) {
            perror("Failed to create mail file");
            continue;
        }
        
        fprintf(fp, "From: %s\r\n", client->from_name);
        fprintf(fp, "To: %s\r\n", recipient_list);
        fprintf(fp, "Subject: %s\r\n", client->subject);
        fprintf(fp, "Date: %s\r\n", timestamp);
        fprintf(fp, "---\r\n");
        fprintf(fp, "%s", client->body);
        fclose(fp);
        del_cnt++;
    }
    
    return del_cnt;
}

// Send response to client (handles non-blocking with retry)
void send_response(int fd, const char *msg) {
    char buf[MAX_LINE];
    snprintf(buf, sizeof(buf), "%s\r\n", msg);
    size_t total = strlen(buf);
    size_t sent = 0;
    while (sent < total) {
        ssize_t n = send(fd, buf + sent, total - sent, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Would block, wait briefly and retry
                usleep(1000);
                continue;
            }
            // Real error, give up
            return;
        }
        sent += n;
    }
}

void handle_smtp2(int client_idx, char* line, fd_set* master_set_ptr) {
    client_state_t *client = &clients[client_idx];

    if (client->smtp2_state == SMTP2_BODY_STARTED) {
        if (strcmp(line, ".") == 0) {
            char recipient_list[MAX_RECIPIENTS * (USERNAME_SIZE+5)] = "";
            for (int i = 0; i < client->recipient_count; i++) {
                if (i > 0) strcat(recipient_list, ", ");
                strcat(recipient_list, reg_users[client->recipients[i]].username);
            }

            int n_delivered = deliver_mail(client, recipient_list);
            char response[64];
            snprintf(response, sizeof(response), "OK Delivered to %d mailboxes", n_delivered);
            send_response(client->fd, response);

            server_log("Mail delivered from \"%s\" to [%s] (%d recipient%s)",
                      client->from_name, recipient_list, n_delivered, n_delivered == 1 ? "" : "s");
            
            client->smtp2_state = SMTP2_INIT;
            client->recipient_count = 0;
            client->body_len = 0;
            client->body[0] = '\0';
            return;
        }

        if (line[0] == '.' && line[1] == '.') {
            line++;
        }

        size_t line_len = strlen(line);
        if (client->body_len + line_len + 2 > MAX_BODY) {
            send_response(client->fd, "ERR Body too large");
            client->smtp2_state = SMTP2_INIT;
            client->body_len = 0;
            client->body[0] = '\0';
            return;
        }

        strcat(client->body, line);
        strcat(client->body, "\r\n");
        client->body_len += line_len + 2;
        return;
    }

    char cmd[16] = "";
    char arg[512] = "";
    int i = 0;
    while (line[i] != '\0' && line[i] != ' ' && i < 15) {
        cmd[i] = toupper(line[i]);
        i++;
    }
    cmd[i] = '\0';
    if (line[i] == ' ') {
        strcpy(arg, line + i + 1);
    }

    if (strcmp(cmd, "FROM") == 0) {
        if (client->smtp2_state != SMTP2_INIT) {
            send_response(client->fd, "ERR Bad sequence");
            return;
        }
        strncpy(client->from_name, arg, sizeof(client->from_name) - 1);
        client->smtp2_state = SMTP2_FROM_DONE;
        client->recipient_count = 0;
        send_response(client->fd, "OK Sender accepted");
    } else if (strcmp(cmd, "TO") == 0) {
        if (client->smtp2_state != SMTP2_FROM_DONE && client->smtp2_state != SMTP2_TO_DONE) {
            send_response(client->fd, "ERR Bad sequence");
            return;
        }
        int user_idx = find_user(arg);
        if (user_idx < 0) {
            send_response(client->fd, "ERR No such user");
            return;
        }
        // Check for duplicate recipient
        for (int i = 0; i < client->recipient_count; i++) {
            if (client->recipients[i] == user_idx) {
                send_response(client->fd, "OK Recipient accepted");
                return;
            }
        }
        if (client->recipient_count < MAX_RECIPIENTS) {
            client->recipients[client->recipient_count++] = user_idx;
        } else {
            send_response(client->fd, "ERR Reached maximum recipients");
            return;
        }
        client->smtp2_state = SMTP2_TO_DONE;
        send_response(client->fd, "OK Recipient accepted");
    } else if (strcmp(cmd, "SUB") == 0) {
        if (client->smtp2_state != SMTP2_TO_DONE) {
            send_response(client->fd, "ERR Bad sequence");;
            return;
        }
        if (strlen(arg) == 0) {
            strcpy(client->subject, "(no subject)");
        } else {
            strncpy(client->subject, arg, sizeof(client->subject) - 1);
            client->subject[sizeof(client->subject) - 1] = '\0';
        }
        client->smtp2_state = SMTP2_SUB_DONE;
        send_response(client->fd, "OK Subject accepted");
    } else if (strcmp(cmd, "BODY") == 0) {
        if (client->smtp2_state != SMTP2_SUB_DONE) {
            send_response(client->fd, "ERR Bad sequence");
            return;
        }
        if (client->recipient_count == 0) {
            send_response(client->fd, "ERR No valid recipients");
            client->smtp2_state = SMTP2_INIT;
            return;
        }
        client->smtp2_state = SMTP2_BODY_STARTED;
        client->body_len = 0;
        client->body[0] = '\0';
        send_response(client->fd, "OK Send body, end with CRLF.CRLF");
    } else if (strcmp(cmd, "QUIT") == 0) {
        send_response(client->fd, "BYE");
        close_client(client_idx, master_set_ptr);
    } else {
        send_response(client->fd, "ERR Unknown command");
    }
}

// Count messages in mailbox
int count_messages(int user_idx) {
    DIR *dir = opendir(reg_users[user_idx].mailbox_dir);
    if (!dir) return 0;
    
    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        int id;
        if (sscanf(ent->d_name, "%d.txt", &id) == 1) {
            count++;
        }
    }
    closedir(dir);
    return count;
}

void handle_smp(int client_idx, char* line, fd_set* master_set_ptr) {
    client_state_t *client = &clients[client_idx];

    char cmd[16] = "";
    char arg1[128] = "";
    char arg2[128] = "";

    // Parse command and args
    int i = 0;
    while (line[i] != '\0' && line[i] != ' ' && i < 15) {
        cmd[i] = toupper(line[i]);
        i++;
    }
    cmd[i] = '\0';

    if (line[i] == ' ') {
        int j = 0;
        i++;
        while (line[i] && line[i] != ' ' && j < 127) {
            arg1[j++] = line[i++];
        }
        arg1[j] = '\0';
        
        if (line[i] == ' ') {
            i++;
            strcpy(arg2, line + i);
        }
    }

    // Handle authentication
    if (client->smp_state == SMP_AUTH_WAIT) {
        if (strcmp(cmd, "AUTH") != 0) {
            send_response(client->fd, "ERR Authentication required");
            return;
        }
        int user_idx = find_user(arg1);
        if (user_idx < 0) {
            client->auth_attempts++;
            if (client->auth_attempts >= 3) {
                send_response(client->fd, "ERR Too many failures");
                close_client(client_idx, master_set_ptr);
                return;
            }
            server_log("Authentication failed for client %s:%d", client->ip, client->port);
            send_response(client->fd, "ERR Authentication failed");
            
            // New nonce for retry
            generate_nonce(client->nonce, NONCE_SIZE);
            char auth_msg[64];
            snprintf(auth_msg, sizeof(auth_msg), "AUTH REQUIRED %s", client->nonce);
            send_response(client->fd, auth_msg);
            return;
        }

        // Compute expected hash (password + nonce per spec)
        char hash_input[64];
        snprintf(hash_input, sizeof(hash_input), "%s%s", reg_users[user_idx].password, client->nonce);
        unsigned long expected_hash = djb2(hash_input);
        unsigned long provided_hash = strtoul(arg2, NULL, 10);

        if (expected_hash != provided_hash) {
            client->auth_attempts++;
            if (client->auth_attempts >= 3) {
                send_response(client->fd, "ERR Too many failures");
                close_client(client_idx, master_set_ptr);
                return;
            }
            server_log("Authentication failed for client %s:%d", client->ip, client->port);
            send_response(client->fd, "ERR Authentication failed");
            
            // New nonce for retry
            generate_nonce(client->nonce, NONCE_SIZE);
            char auth_msg[64];
            snprintf(auth_msg, sizeof(auth_msg), "AUTH REQUIRED %s", client->nonce);
            send_response(client->fd, auth_msg);
            return;
        }

        client->smp_state = SMP_AUTHENTICATED;
        client->auth_user_idx = user_idx;
        server_log("Authentication successful for user %s", reg_users[user_idx].username);
        
        char welcome[64];
        snprintf(welcome, sizeof(welcome), "OK Welcome %s", reg_users[user_idx].username);
        send_response(client->fd, welcome);
        return;
    }

    // Handle authenticated clients
    int user_idx = client->auth_user_idx;

    if (strcmp(cmd, "LIST") == 0) {
        DIR *dir = opendir(reg_users[user_idx].mailbox_dir);
        
        // Collect messages
        struct {
            int id;
            char from[256];
            char subject[256];
            char date[32];
        } messages[1000];
        int msg_count = 0;
        
        if (dir) {
            struct dirent *ent;
            while ((ent = readdir(dir)) != NULL && msg_count < 1000) {
                int id;
                if (sscanf(ent->d_name, "%d.txt", &id) == 1) {
                    char filepath[512];
                    snprintf(filepath, sizeof(filepath), "%s/%s", reg_users[user_idx].mailbox_dir, ent->d_name);
                    
                    FILE *fp = fopen(filepath, "r");
                    if (fp) {
                        messages[msg_count].id = id;
                        messages[msg_count].from[0] = '\0';
                        messages[msg_count].subject[0] = '\0';
                        messages[msg_count].date[0] = '\0';
                        
                        char line_buf[512];
                        while (fgets(line_buf, sizeof(line_buf), fp)) {
                            line_buf[strcspn(line_buf, "\r\n")] = '\0';
                            if (strncmp(line_buf, "From: ", 6) == 0) {
                                strncpy(messages[msg_count].from, line_buf + 6, 255);
                            } else if (strncmp(line_buf, "Subject: ", 9) == 0) {
                                strncpy(messages[msg_count].subject, line_buf + 9, 255);
                            } else if (strncmp(line_buf, "Date: ", 6) == 0) {
                                strncpy(messages[msg_count].date, line_buf + 6, 31);
                            } else if (strcmp(line_buf, "---") == 0) {
                                break;
                            }
                        }
                        fclose(fp);
                        msg_count++;
                    }
                }
            }
            closedir(dir);
        }
        
        // Sort by ID (is it required?)
        for (int i = 0; i < msg_count - 1; i++) {
            for (int j = i + 1; j < msg_count; j++) {
                if (messages[i].id > messages[j].id) {
                    typeof(messages[0]) tmp = messages[i];
                    messages[i] = messages[j];
                    messages[j] = tmp;
                }
            }
        }
        
        char response[64];
        snprintf(response, sizeof(response), "OK %d messages", msg_count);
        send_response(client->fd, response);
        
        for (int i = 0; i < msg_count; i++) {
            char list_line[560];
            snprintf(list_line, sizeof(list_line), "%d\t%s\t%s\t%s",
                    messages[i].id, messages[i].from, messages[i].subject, messages[i].date);
            send_response(client->fd, list_line);
        }
        send_response(client->fd, ".");
        
        server_log("User %s LIST mailbox (%d messages)", reg_users[user_idx].username, msg_count);
    } else if (strcmp(cmd, "READ") == 0) {
        int msg_id = atoi(arg1);
        char filepath[256];
        snprintf(filepath, sizeof(filepath), "%s/%d.txt", reg_users[user_idx].mailbox_dir, msg_id);
        
        FILE *fp = fopen(filepath, "r");
        if (!fp) {
            send_response(client->fd, "ERR No such message");
            return;
        }
        
        send_response(client->fd, "OK");
        
        char line_buf[512];
        while (fgets(line_buf, sizeof(line_buf), fp)) {
            line_buf[strcspn(line_buf, "\r\n")] = '\0';
            
            // Dot-stuff lines starting with .
            if (line_buf[0] == '.') {
                char stuffed[514];
                snprintf(stuffed, sizeof(stuffed), ".%s", line_buf);
                send_response(client->fd, stuffed);
            } else {
                send_response(client->fd, line_buf);
            }
        }
        fclose(fp);
        send_response(client->fd, ".");
        
        server_log("User %s READ message %d", reg_users[user_idx].username, msg_id);
    } else if (strcmp(cmd, "DELETE") == 0) {
        int msg_id = atoi(arg1);
        char filepath[256];
        snprintf(filepath, sizeof(filepath), "%s/%d.txt", reg_users[user_idx].mailbox_dir, msg_id);
        
        if (unlink(filepath) == 0) {
            send_response(client->fd, "OK Deleted");
            server_log("User %s DELETE message %d", reg_users[user_idx].username, msg_id);
        } else {
            send_response(client->fd, "ERR No such message");
        }
    } else if (strcmp(cmd, "COUNT") == 0) {
        int count = count_messages(user_idx);
        char response[32];
        snprintf(response, sizeof(response), "OK %d", count);
        send_response(client->fd, response);
    } else if (strcmp(cmd, "QUIT") == 0) {
        send_response(client->fd, "BYE");
        client->active = 0;
    } else {
        send_response(client->fd, "ERR Unknown command");
    }
}

void process_line(int client_idx, char* line, fd_set* master_set_ptr) {
    client_state_t *client = &clients[client_idx];

    if (client->mode == MODE_NONE) {
        if (strncmp_nocase(line, "MODE SEND", 9) == 0) {
            client->mode = MODE_SEND;
            send_response(client->fd, "OK");
            server_log("Client %s:%d selected MODE SEND", client->ip, client->port);
        } else if (strncmp_nocase(line, "MODE RECV", 9) == 0) {
            client->mode = MODE_RECV;
            send_response(client->fd, "OK");
            server_log("Client %s:%d selected MODE RECV", client->ip, client->port);
            
            // initiate authentication
            generate_nonce(client->nonce, NONCE_SIZE);
            char auth_msg[64];
            snprintf(auth_msg, sizeof(auth_msg), "AUTH REQUIRED %s", client->nonce);
            send_response(client->fd, auth_msg);
        } else {
            send_response(client->fd, "ERR Unknown mode");
        }
        return;
    }

    // Handle protocol specific modes
    
    if (client->mode == MODE_SEND) {
        handle_smtp2(client_idx, line, master_set_ptr); // SMTP2
    } else {
        handle_smp(client_idx, line, master_set_ptr);   // SMP
    }
}

void handle_client(int client_idx, fd_set* master_set_ptr) {
    client_state_t *client = &clients[client_idx];

    char buf[MAX_LINE];
    int n = recv(client->fd, buf, sizeof(buf)-1, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Spurious wakeup, no data available
            return;
        }
        // Real error
        close_client(client_idx, master_set_ptr);
        return;
    }
    if (n == 0) {
        // Connection closed by client
        close_client(client_idx, master_set_ptr);
        return;
    }
    buf[n] = '\0';

    if (client->recv_len + n + 1 > (int)sizeof(client->recv_buf)) {
        // Buffer overflow
        close_client(client_idx, master_set_ptr);
    }

    memcpy(client->recv_buf + client->recv_len, buf, n+1);
    client->recv_len += n;

    // process each available complete line
    char* line_start = client->recv_buf;
    char* crlf;
    while((crlf = strstr(line_start, "\r\n")) != NULL) {
        *crlf = '\0';
        process_line(client_idx, line_start, master_set_ptr);
        if (!client->active) return; // connection may have been closed
        line_start = crlf + 2;
    }
    int remaining = client->recv_len - (line_start - client->recv_buf);
    if (remaining > 0) {
        memmove(client->recv_buf, line_start, remaining);
    }
    client->recv_len = remaining;
    client->recv_buf[remaining] = '\0';
}

int main(int argc, char* argv[]) {
    if(argc < 3) {
        fprintf(stderr, "Usage: ./smserver <port> <userfile>\n");
        exit(1);
    }
    srand(time(NULL));

    int port = atoi(argv[1]);
    char *filename = argv[2];
    
    read_userfile(filename);
    for (int i = 0; i < n_users; i++) {
        reg_users[i].next_mail_idx = get_next_mail_idx(i);
    }

    server_log("Server started on port %d", port);
    server_log("Loaded %d users from %s", n_users, filename);

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); exit(1); }
    
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port        = htons(port);

    if (bind(listen_fd, (struct sockaddr *)&server_addr,
             sizeof(server_addr)) < 0) {
        perror("bind");
        exit(1);
    }

    if (listen(listen_fd, 5) < 0) {
        perror("listen");
        exit(1);
    }

    // Set listen socket to non-blocking
    int flags = fcntl(listen_fd, F_GETFL, 0);
    fcntl(listen_fd, F_SETFL, flags | O_NONBLOCK);

    fd_set master_set, read_set;
    int max_fd;

    FD_ZERO(&master_set);
    FD_SET(listen_fd, &master_set);
    max_fd = listen_fd;

    // Initialise clients
    memset(clients, 0, sizeof(clients));

    while(1) {
        read_set = master_set;

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        int ready = select(max_fd + 1, &read_set, NULL, NULL, &tv);
        if (ready < 0) {
            perror("select");
            exit(1);
        }

        // Check for mode selection timeouts
        time_t now = time(NULL);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].active && clients[i].mode == MODE_NONE) {
                if (now - clients[i].connect_time > MODE_TIMEOUT) {
                    server_log("Mode selection timeout for %s:%d", clients[i].ip, clients[i].port);
                    close_client(i, &master_set);
                }
            }
        }

        if(ready == 0) continue;

        for (int fd = 0; fd <= max_fd; fd++) {
            if (!FD_ISSET(fd, &read_set)) continue;
        
            if (fd == listen_fd) {
                // New connection
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int conn_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
                if (conn_fd < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        // Spurious wakeup, no pending connection
                        continue;
                    }
                    perror("accept");
                    continue;
                }

                // Set client socket to non-blocking
                int flags = fcntl(conn_fd, F_GETFL, 0);
                fcntl(conn_fd, F_SETFL, flags | O_NONBLOCK);

                int idx = 0;
                for(; idx < MAX_CLIENTS; idx++) {
                    if (!clients[idx].active) break;
                }
                if (idx == MAX_CLIENTS) {
                    send(conn_fd, "ERR Server busy\r\n", 17, 0);
                    close(conn_fd);
                    continue;
                }

                memset(&clients[idx], 0, sizeof(client_state_t));
                clients[idx].active = 1;
                clients[idx].fd = conn_fd;
                inet_ntop(AF_INET, &client_addr.sin_addr, clients[idx].ip, INET_ADDRSTRLEN);
                clients[idx].port = ntohs(client_addr.sin_port);
                clients[idx].connect_time = time(NULL);
                clients[idx].mode = MODE_NONE;
                clients[idx].smtp2_state = SMTP2_INIT;
                clients[idx].smp_state = SMP_AUTH_WAIT;
                clients[idx].auth_user_idx = -1;
                
                FD_SET(conn_fd, &master_set);
                if (conn_fd > max_fd) max_fd = conn_fd;
                
                server_log("New connection from %s:%d", clients[idx].ip, clients[idx].port);
                send_response(conn_fd, "WELCOME SimpleMail v1.0");

            } else {
                int idx = 0;
                for (; idx < MAX_CLIENTS; idx++) {
                    if(clients[idx].active && clients[idx].fd == fd) break;
                }
                if (idx != MAX_CLIENTS) {
                    handle_client(idx, &master_set);
                }
            }
        
        }
    }
}