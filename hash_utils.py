# Hashing utilities

import hmac
import random
import string
import hashlib

SECRET = 'imsosecret'


def hash_str(s):
    """Creates a hash of the string s.

    Args:
        s: An input string.

    Returns:
        A hash of the input string.
    """
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    """Given an input string, outputs a secure value, i.e. the string followed
    by a pipe followed by a hash of that string.

    Args:
        s: An input string

    Returns:
        A string of the form "s|hash_str(s)".
    """
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    """Given a secure value of the form "s|h(s)", checks that h(s) actually
    matches hash_str(s).


    Args:
        h: A string, expected to be of the form "s|h(s)"

    Returns:
        True if s == h(s), False otherwise.
    """
    if not h:
        return None

    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


def make_salt():
    return ''.join(random.choice(string.letters) for x in range(5))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()

    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)


def valid_pw(name, pw, h):
    hash_val, salt = h.split('|')

    return make_pw_hash(name, pw, salt) == h
