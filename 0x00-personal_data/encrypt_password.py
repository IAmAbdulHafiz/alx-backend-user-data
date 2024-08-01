#!/usr/bin/env python3
"""
Module for encrypting and validating passwords.
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """ Generates a salted, hashed version of the input password
    and returns it as a byte string.
    """
    encoded = password.encode()
    hashed = bcrypt.hashpw(encoded, bcrypt.gensalt())

    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ Checks if the provided password matches the given
    hashed password.
    """
    valid = False
    encoded = password.encode()
    if bcrypt.checkpw(encoded, hashed_password):
        valid = True
    return valid
