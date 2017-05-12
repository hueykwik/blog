# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import re

import random
import string
import hashlib

from google.appengine.ext import db

import webapp2
import jinja2

import hmac
import model

SECRET = 'imsosecret'

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    if not h:
        return None

    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


class Handler(webapp2.RequestHandler):
    """
    Base class for other Handlers we write. Handler takes care
    of rendering HTML from templates and writing them in the response.
    """
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class BlogHandler(Handler):
    def get(self):
        blog_posts = db.GqlQuery("SELECT * FROM BlogPost "
                                 "ORDER BY created DESC ")

        self.render("front.html", blog_posts=blog_posts)


class NewPostHandler(Handler):
    def render_post(self, subject="", content="", error=""):
        self.render("new_post.html", subject=subject, content=content, error=error)

    def get(self):
        self.render_post()

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            blog_post = model.BlogPost(subject=subject, content=content)
            blog_post.put()

            self.redirect("/blog/%d" % blog_post.key().id())
        else:
            error = "subject and content, please!"
            self.render_post(subject, content, error)


class ViewPostHandler(Handler):
    def get(self, post_id):
        blog_post = model.BlogPost.get_by_id(int(post_id))

        self.render("view_post.html", post=blog_post)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


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


def username_exists(username):
    users = db.GqlQuery("select * from User where username = '%s'" % username)

    return users.count(limit=1) != 0


class SignupHandler(Handler):
    """
    Handles user signup requests.
    """
    def valid_username(self, username):
        return USER_RE.match(username)

    def valid_password(self, password):
        return PASSWORD_RE.match(password)

    def valid_email(self, email):
        return not email or EMAIL_RE.match(email)

    def get(self):
        self.render('signup.html')

    def post(self):
        has_error = False

        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username=username, email=email)

        if not self.valid_username(username):
            params['username_error'] = "That's not a valid username."
            has_error = True
        elif username_exists(username):
            params['username_error'] = "That username already exists."
            has_error = True

        if not self.valid_password(password):
            params['password_error'] = "That wasn't a valid password."
            has_error = True
        elif password != verify:
            params['verify_error'] = "Your passwords didn't match."
            has_error = True

        if not self.valid_email(email):
            params['email_error'] = "That's not a valid email."
            has_error = True

        if has_error:
            self.render('signup.html', **params)
        else:
            hash_password = make_pw_hash(username, password)
            user = model.User(username=username, password=hash_password)
            user.put()

            cookie = ("user_id=%s; Path=/" %
                      make_secure_val(str(user.key().id())))

            self.response.headers.add_header("Set-Cookie", cookie)

            self.redirect("/welcome")


class WelcomeHandler(Handler):
    """
    Welcomes the new user.
    """
    def get(self):
        # things to check
        # 1. no cookie
        # 2. forged cookie
        # 3. user_id exists in DB
        user = None

        user_id = check_secure_val(self.request.cookies.get('user_id'))
        if user_id:
            user = model.User.get_by_id(int(user_id))

        if user:
            self.render('welcome.html', username=user.username)
        else:
            self.redirect("/signup")


class LoginHandler(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        error = None

        if not username_exists(username):
            error = "Invalid login"

        if error:
            self.render('login.html', error="Invalid login")


app = webapp2.WSGIApplication([
    ('/blog/?', BlogHandler),
    ('/blog/newpost', NewPostHandler),
    (r'/blog/(\d+)', ViewPostHandler),
    ('/signup', SignupHandler),
    ('/welcome', WelcomeHandler),
    ('/login', LoginHandler)
], debug=True)
