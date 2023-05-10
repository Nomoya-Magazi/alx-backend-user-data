#!/usr/bin/env python3
"""A module for authentication-related routines.
"""
import bcrypt
from uuid import uuid4
from typing import Union
from sqlalchemy.orm.exc import NoResultFound

from db import DB
from user import User

<<<<<<< HEAD

class Auth:
    """Auth class to interact with the authentication database.
    """
=======
>>>>>>> 2772d296d96af14da297b370fce73deecf87c0a0

def _hash_password(password: str) -> bytes:
    """Hashes a password.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

<<<<<<< HEAD

def update_password(self, reset_token: str, password: str) -> None:
        """Update the password for the user with the given reset token.
=======
>>>>>>> 2772d296d96af14da297b370fce73deecf87c0a0

def _generate_uuid() -> str:
    """Generates a UUID.
    """
    return str(uuid4())

<<<<<<< HEAD

def get_reset_password_token(self, email: str) -> str:
        """Get the reset password token for the user with the given email.
=======
>>>>>>> 2772d296d96af14da297b370fce73deecf87c0a0

class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """Initializes a new Auth instance.
        """
<<<<<<< HEAD
        user = self._db.find_user_by(email=email)
        if not user:
            raise ValueError(f"User {email} does not exist")

        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token


def destroy_session(self, user_id: int) -> None:
        """Destroy the session for the user with the given user ID.
=======
        self._db = DB()
>>>>>>> 2772d296d96af14da297b370fce73deecf87c0a0

    def register_user(self, email: str, password: str) -> User:
        """Adds a new user to the database.
        """
<<<<<<< HEAD
        self._db.update_user(user_id, session_id=None)


def get_user_from_session_id(self, session_id: str) -> User or None:
        """Get the user corresponding to the given session ID.

        Args:
            session_id (str): Session ID
=======
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))
        raise ValueError("User {} already exists".format(email))

    def valid_login(self, email: str, password: str) -> bool:
        """Checks if a user's login details are valid.
        """
        user = None
        try:
            user = self._db.find_user_by(email=email)
            if user is not None:
                return bcrypt.checkpw(
                    password.encode("utf-8"),
                    user.hashed_password,
                )
        except NoResultFound:
            return False
        return False
>>>>>>> 2772d296d96af14da297b370fce73deecf87c0a0

    def create_session(self, email: str) -> str:
        """Creates a new session for a user.
        """
        user = None
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        if user is None:
            return None
<<<<<<< HEAD


def create_session(self, email: str) -> str:
        """Create a session for the user with the given email.

        Args:
            email (str): User's email

        Returns:
            str: Session ID
        """
        user = self._db.find_user_by(email=email)
=======
>>>>>>> 2772d296d96af14da297b370fce73deecf87c0a0
        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

<<<<<<< HEAD

def valid_login(self, email: str, password: str) -> bool:
        """Validate a user login.

        Args:
            email (str): User's email
            password (str): User's password

        Returns:
            bool: True if the login is valid, False otherwise
=======
    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Retrieves a user based on a given session ID.
>>>>>>> 2772d296d96af14da297b370fce73deecf87c0a0
        """
        user = None
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        return user

    def destroy_session(self, user_id: int) -> None:
        """Destroys a session associated with a given user.
        """
        if user_id is None:
            return None
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """Generates a password reset token for a user.
        """
        user = None
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            user = None
        if user is None:
            raise ValueError()
        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates a user's password given the user's reset token.
        """
        user = None
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            user = None
        if user is None:
            raise ValueError()
        new_password_hash = _hash_password(password)
        self._db.update_user(
            user.id,
            hashed_password=new_password_hash,
            reset_token=None,
        )
