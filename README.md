# SimpleMail: A Command-Line Mail System

**Course:** CS39006 - Computer Networks Laboratory  
**Assignment:** Mini Project 2

## Overview

SimpleMail is a complete command-line email system implemented in C using TCP socket programming. The system comprises two components:

- **smserver**: A concurrent mail server that manages user mailboxes and handles multiple client connections
- **smclient**: An interactive client for composing, sending, and retrieving emails

Communication between the client and server follows two custom text-based protocols:
- **SMTP2** (SimpleMail Transfer Protocol 2) for sending mail
- **SMP** (SimpleMail Pickup Protocol) for retrieving mail

Both protocols operate over TCP with `\r\n` line terminators and dot-termination (`.`) for multi-line content.

## Building

```bash
make            # Build both smserver and smclient
make clean      # Remove executables and mailbox directory
```

## Usage

### Starting the Server

```bash
./smserver <port> <userfile>
```

**Example:**
```bash
./smserver 9000 users.txt
```

The server reads the user registry from `userfile`, creates mailbox directories under `mailbox/`, and begins listening for client connections.

### Running the Client

```bash
./smclient <server_ip> <port>
```

**Example:**
```bash
./smclient 127.0.0.1 9000
```

## Design Choices

### Concurrency Model

The server uses **I/O multiplexing with `select()`** to handle multiple concurrent client connections within a single-threaded event loop. This approach:

- Avoids multi-threading complexity and synchronization overhead
- Maintains per-client state in a fixed array (`MAX_CLIENTS = 100`)
- Uses a 1-second select timeout to periodically check for mode selection timeouts
- Each client has an independent receive buffer for handling partial TCP reads (TCP stream reassembly)

### Mailbox File ID Management

- Each user's mailbox is stored in `mailbox/<username>/`
- Mail files are named with monotonically increasing integers (`1.txt`, `2.txt`, etc.)
- On server startup, the highest existing ID is determined by scanning each user's directory
- The next ID is always `max_existing_id + 1`, ensuring **deleted IDs are never reused**
- This approach persists across server restarts

### Protocol State Machines

**SMTP2 (Send Mode):**
```
INIT → FROM_DONE → TO_DONE → SUB_DONE → BODY_STARTED → (delivery) → INIT
```
- Strict sequence enforcement with `ERR Bad sequence` for violations
- Duplicate recipients are silently accepted but stored only once
- Body size limit: 65,536 bytes with dot-stuffing support

**SMP (Receive Mode):**
```
AUTH_WAIT → (challenge-response) → AUTHENTICATED → (commands) → QUIT
```
- Challenge-response authentication using DJB2 hash
- Hash computed as: `DJB2(password + nonce)`
- Random 8-character alphanumeric nonce per authentication attempt
- Maximum 3 authentication attempts before disconnection

### Timeout Handling

- **Server-side:** 30-second timeout for mode selection after connection; client is disconnected if no `MODE SEND` or `MODE RECV` is received
- **Client-side:** Gracefully handles closed connections with informative messages and automatic reconnection

## Protocol Summary

### SMTP2 Commands (MODE SEND)

| Command | Response | Description |
|---------|----------|-------------|
| `FROM <name>` | `OK Sender accepted` | Set sender display name |
| `TO <user>` | `OK Recipient accepted` / `ERR No such user` | Add recipient |
| `SUB <subject>` | `OK Subject accepted` | Set subject (empty = "(no subject)") |
| `BODY` | `OK Send body, end with CRLF.CRLF` | Begin body transmission |
| `.` | `OK Delivered to N mailboxes` | End body, deliver mail |
| `QUIT` | `BYE` | Close connection |

### SMP Commands (MODE RECV)

| Command | Response | Description |
|---------|----------|-------------|
| `AUTH <user> <hash>` | `OK Welcome <user>` / `ERR Authentication failed` | Authenticate |
| `LIST` | `OK N messages` + listing + `.` | List all messages |
| `READ <id>` | `OK` + content + `.` / `ERR No such message` | Read message |
| `DELETE <id>` | `OK Deleted` / `ERR No such message` | Delete message |
| `COUNT` | `OK N` | Get message count |
| `QUIT` | `BYE` | Close connection |

## File Format

Mail files are stored with the following structure:

```
From: <display_name>
To: <comma-separated recipients>
Subject: <subject_text>
Date: <YYYY-MM-DD HH:MM:SS>
---
<body text>
```

## Assumptions and Constraints

| Parameter | Limit |
|-----------|-------|
| Maximum registered users | 100 |
| Maximum concurrent connections | 100 |
| Maximum recipients per email | 50 |
| Maximum line length | 512 bytes |
| Maximum body size | 65,536 bytes |
| Username length | 20 characters (lowercase a-z only) |
| Password length | 30 characters (alphanumeric) |
| Mode selection timeout | 30 seconds |
| Authentication attempts | 3 maximum |

## Files

| File | Description |
|------|-------------|
| `smserver.c` | Server implementation |
| `smclient.c` | Client implementation |
| `Makefile` | Build configuration |
| `users.txt` | Sample user registry (7 users) |
| `mailbox/` | Auto-created directory for user mailboxes |

## Testing

The implementation has been tested for:

- ✓ Basic send/receive workflow
- ✓ Multiple recipients with duplicate filtering
- ✓ Authentication success and failure cases
- ✓ Mode selection timeout (30 seconds)
- ✓ Out-of-sequence command rejection
- ✓ Non-existent user handling
- ✓ Dot-stuffing for body lines starting with `.`
- ✓ Empty subject handling
- ✓ Concurrent client connections

## Author

Computer Networks Laboratory - Mini Project 2
