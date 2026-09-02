"""
CodeAlpha Cyber Security Internship
Task 3: Secure Coding Review

SECURE APPLICATION
------------------
This version demonstrates remediation of the
security issues identified during the code review.
"""

import sqlite3
import subprocess
import hashlib
import secrets
import hmac
import getpass


DATABASE = "secure_users.db"


# ---------------------------------------------------------
# Database
# ---------------------------------------------------------

def create_database():
    """Create the users table."""

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


# ---------------------------------------------------------
# Secure Password Hashing
# ---------------------------------------------------------

def hash_password(password):
    """
    Securely hash a password using PBKDF2-HMAC-SHA256.

    A unique random salt is generated for every password.
    """

    salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200_000
    )

    return (
        salt.hex()
        + ":"
        + password_hash.hex()
    )


def verify_password(password, stored_value):
    """Verify a password against a stored PBKDF2 hash."""

    try:
        salt_hex, stored_hash_hex = stored_value.split(":")

        salt = bytes.fromhex(salt_hex)

        calculated_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            200_000
        )

        stored_hash = bytes.fromhex(
            stored_hash_hex
        )

        return hmac.compare_digest(
            calculated_hash,
            stored_hash
        )

    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------
# Input Validation
# ---------------------------------------------------------

def validate_username(username):
    """
    Validate usernames before processing them.
    """

    if not username:
        return False

    if len(username) > 50:
        return False

    allowed_characters = (
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789_-"
    )

    return all(
        character in allowed_characters
        for character in username
    )


def validate_host(host):
    """
    Basic hostname/IP validation.

    Shell metacharacters are rejected.
    """

    if not host:
        return False

    if len(host) > 253:
        return False

    dangerous_characters = (
        ";",
        "&",
        "|",
        "`",
        "$",
        "(",
        ")",
        "<",
        ">",
        "\n",
        "\r"
    )

    return not any(
        character in host
        for character in dangerous_characters
    )


# ---------------------------------------------------------
# User Management
# ---------------------------------------------------------

def add_user(username, password):
    """
    Add a user using a parameterized SQL query.
    """

    if not validate_username(username):
        raise ValueError("Invalid username.")

    if len(password) < 12:
        raise ValueError(
            "Password must contain at least 12 characters."
        )

    password_hash = hash_password(password)

    connection = sqlite3.connect(DATABASE)

    try:

        cursor = connection.cursor()

        # SECURITY FIX:
        # Parameterized query prevents SQL injection.
        cursor.execute(
            """
            INSERT INTO users
            (username, password_hash)
            VALUES (?, ?)
            """,
            (username, password_hash)
        )

        connection.commit()

    finally:
        connection.close()


def find_user(username):
    """
    Safely search for a user using a parameterized query.
    """

    if not validate_username(username):
        return []

    connection = sqlite3.connect(DATABASE)

    try:

        cursor = connection.cursor()

        # SECURITY FIX:
        # User input is passed as a parameter.
        cursor.execute(
            """
            SELECT id, username, password_hash
            FROM users
            WHERE username = ?
            """,
            (username,)
        )

        return cursor.fetchall()

    finally:
        connection.close()


# ---------------------------------------------------------
# Safe Host Connectivity Test
# ---------------------------------------------------------

def ping_host(host):
    """
    Ping a host without invoking a shell.

    SECURITY FIX:
    shell=False prevents shell command injection.
    """

    if not validate_host(host):
        raise ValueError("Invalid host.")

    try:

        result = subprocess.run(
            [
                "ping",
                "-n",
                "1",
                host
            ],
            shell=False,
            capture_output=True,
            text=True,
            timeout=5
        )

        return result.stdout

    except subprocess.TimeoutExpired:
        return "Ping operation timed out."


# ---------------------------------------------------------
# Secure Login
# ---------------------------------------------------------

def login(username, password):
    """
    Authenticate a user without revealing
    whether the username exists.
    """

    if not validate_username(username):
        return "Invalid credentials."

    users = find_user(username)

    if not users:
        # SECURITY FIX:
        # Generic authentication error prevents
        # username enumeration.
        return "Invalid credentials."

    stored_hash = users[0][2]

    if verify_password(
        password,
        stored_hash
    ):
        return "Login successful."

    return "Invalid credentials."


# ---------------------------------------------------------
# Main Application
# ---------------------------------------------------------

def main():

    print("=" * 70)
    print("CODEALPHA - SECURE USER MANAGEMENT APPLICATION")
    print("=" * 70)

    create_database()

    print("\n1. Creating demonstration user...")

    try:

        add_user(
            "alice",
            "AliceSecurePassword123"
        )

        print("User created successfully.")

    except sqlite3.IntegrityError:
        print("Demonstration user already exists.")

    except ValueError as error:
        print("Input validation failed.")

    print("\n2. Search user")

    username = input(
        "Enter username to search: "
    )

    users = find_user(username)

    if users:
        print("User found.")
    else:
        print("User not found.")

    print("\n3. Host connectivity test")

    host = input(
        "Enter hostname or IP address: "
    )

    try:

        output = ping_host(host)

        print(output)

    except ValueError:
        print("Invalid host.")

    except Exception:
        # SECURITY FIX:
        # Do not expose internal exception details.
        print("Unable to perform connectivity test.")

    print("\n4. Login test")

    login_username = input(
        "Username: "
    )

    login_password = getpass.getpass(
        "Password: "
    )

    print(
        login(
            login_username,
            login_password
        )
    )


if __name__ == "__main__":
    main()