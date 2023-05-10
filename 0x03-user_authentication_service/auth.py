#!/usr/bin/env python3
'''hash_password
'''
import bcrypt
from db import DB
from user import User
import uuid
from auth import _generate_uuid
from auth import _hash_password


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()


def update_password(self, reset_token: str, password: str) -> None:
        """Update the password for the user with the given reset token.

        Args:
            reset_token (str): Reset password token
            password (str): New password
        """
        user = self._db.find_user_by(reset_token=reset_token)
        if not user:
            raise ValueError("Invalid reset token")

        hashed_password = _hash_password(password)
        self._db.update_user(user.id, hashed_password=hashed_password, reset_token=None)


def get_reset_password_token(self, email: str) -> str:
        """Get the reset password token for the user with the given email.

        Args:
            email (str): User's email

        Returns:
            str: Reset password token
        """
        user = self._db.find_user_by(email=email)
        if not user:
            raise ValueError(f"User {email} does not exist")

        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token


def destroy_session(self, user_id: int) -> None:
        """Destroy the session for the user with the given user ID.

        Args:
            user_id (int): User ID
        """
        self._db.update_user(user_id, session_id=None)


def get_user_from_session_id(self, session_id: str) -> User or None:
        """Get the user corresponding to the given session ID.

        Args:
            session_id (str): Session ID

        Returns:
            User or None: Corresponding User object or None if not found
        """
        if session_id is None:
            return None

        user = self._db.find_user_by(session_id=session_id)
        if user:
            return user
        else:
            return None


def create_session(self, email: str) -> str:
        """Create a session for the user with the given email.

        Args:
            email (str): User's email

        Returns:
            str: Session ID
        """
        user = self._db.find_user_by(email=email)
        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id


def valid_login(self, email: str, password: str) -> bool:
        """Validate a user login.

        Args:
            email (str): User's email
            password (str): User's password

        Returns:
            bool: True if the login is valid, False otherwise
        """
        user = self._db.find_user_by(email=email)
        if user and bcrypt.checkpw(password.encode('utf-8'), user.hashed_password):
            return True
        return False

    def register_user(self, email: str, password: str) -> User:
        """Register a new user.

        Args:
            email (str): User's email
            password (str): User's password

        Returns:
            User: Registered User object

        Raises:
            ValueError: If a user already exists with the given email
        """
        existing_user = self._db.find_user_by(email=email)
        if existing_user:
            raise ValueError(f"User {email} already exists")

        hashed_password = self._hash_password(password)
        user = self._db.add_user(email=email, hashed_password=hashed_password)
        return user

class User:
    """User class
    """

    def _hash_password(self, password: str) -> bytes:
        """Hashes the input password using bcrypt

        Args:
            password (str): Password string

        Returns:
            bytes: Salted hash of the input password
        """
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password

def _generate_uuid() -> str:
    """Generate a new UUID.

    Returns:
        str: String representation of the generated UUID
    """
    new_uuid = uuid.uuid4()
    return str(new_uuid)
