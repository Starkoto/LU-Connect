# LU‑Connect Chat

A secure, real‑time chat app built in Python that supports user authentication, encrypted messaging, file transfers, and concurrent client management using the Observer pattern.

## Features

- **User Authentication:** Register and log in with secure password hashing (bcrypt).
- **Encrypted Messaging:** Messages are encrypted with Fernet before being stored.
- **File Transfers:** Send and receive files (e.g., .pdf, .docx, .jpeg) within the chat.
- **Real-Time Broadcasting:** Uses the Observer pattern to broadcast messages to all connected clients.
- **Concurrency:** Manages multiple clients concurrently with threading and semaphores.
- **Graphical User Interface:** A Tkinter-based client provides a user-friendly chat experience.
- **Sound Notifications:** Utilizes the Windows-only winsound library for message notifications.

## Requirements

- **Operating System:** Windows (due to the winsound library used for sound notifications)
- **Python Version:** Python 3.8+
- **Dependencies:** All required libraries are listed in `requirements.txt`.

## Usage

- **Starting the Server:**

  ```bash
  python server.py

- **Starting the Client:**

  ```bash
  python client.py

## Version Control

- This project uses Git for version control with regular, meaningful commits. Check the commit history for a detailed change log.

## License

- This project is licensed under the [MIT License](LICENSE).
