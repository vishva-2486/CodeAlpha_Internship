"""
CodeAlpha Cyber Security Internship
Task 3: Secure Coding Review

VULNERABLE APPLICATION
----------------------
This application intentionally contains security weaknesses
for educational security-audit purposes.

DO NOT use this code in production.
"""

import sqlite3
import subprocess
import hashlib


DATABASE = "users.db"

# VULNERABILITY 1:
# Hardcoded credentials / secret
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"


def create_database():
    """Create the users table."""

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def add_user(username, password):
    """
    Add a new user.

    VULNERABILITY 2:
    Password is stored using a fast general-purpose hash.
    Proper password hashing should use a password-specific
    algorithm such as PBKDF2, scrypt, or Argon2.
    """

    password_hash = hashlib.md5(
        password.encode()
    ).hexdigest()

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    # VULNERABILITY 3:
    # SQL Injection due to string concatenation.
    query = (
        "INSERT INTO users (username, password) "
        "VALUES ('"
        + username
        + "', '"
        + password_hash
        + "')"
    )

    cursor.execute(query)

    connection.commit()
    connection.close()


def find_user(username):
    """
    Search for a user.

    VULNERABILITY 4:
    SQL Injection caused by unsafely constructing SQL.
    """

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    query = (
        "SELECT id, username, password "
        "FROM users WHERE username = '"
        + username
        + "'"
    )

    cursor.execute(query)

    result = cursor.fetchall()

    connection.close()

    return result


def ping_host(host):
    """
    Ping a host.

    VULNERABILITY 5:
    Command Injection because user-controlled input is
    passed to a shell command.
    """

    command = "ping -n 1 " + host

    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True
    )

    return result.stdout


def login(username, password):
    """
    Basic login function.

    VULNERABILITY 6:
    Sensitive information may be exposed through
    overly detailed error messages.
    """

    if username == ADMIN_USERNAME:

        if password == ADMIN_PASSWORD:
            return "Login successful."

        return (
            "Login failed: administrator username exists "
            "but the supplied password is incorrect."
        )

    users = find_user(username)

    if not users:
        return "Login failed: username does not exist."

    stored_hash = users[0][2]

    supplied_hash = hashlib.md5(
        password.encode()
    ).hexdigest()

    if supplied_hash == stored_hash:
        return "Login successful."

    return "Login failed: password is incorrect."


def main():
    """Run the vulnerable demonstration application."""

    print("=" * 70)
    print("CODEALPHA - VULNERABLE USER MANAGEMENT APPLICATION")
    print("=" * 70)

    create_database()

    print("\n1. Adding demonstration user...")
    add_user("alice", "AlicePassword123")

    print("User added.")

    print("\n2. Searching for user...")
    username = input("Enter username to search: ")

    try:
        users = find_user(username)
        print("Search result:", users)

    except Exception as error:
        # VULNERABILITY 7:
        # Internal exception details are exposed.
        print("Database error:", error)

    print("\n3. Host connectivity test")

    host = input("Enter host to ping: ")

    try:
        output = ping_host(host)
        print(output)

    except Exception as error:
        print("Command execution error:", error)

    print("\n4. Login test")

    login_username = input("Username: ")
    login_password = input("Password: ")

    print(login(login_username, login_password))


if __name__ == "__main__":
    main()