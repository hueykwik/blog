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

from google.appengine.ext import db

import webapp2
import jinja2

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


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


class BlogPost(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class NewPostHandler(Handler):
    def render_post(self, subject="", content="", error=""):
        self.render("new_post.html", subject=subject, content=content, error=error)

    def get(self):
        self.render_post()

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            blog_post = BlogPost(subject=subject, content=content)
            blog_post.put()

            self.redirect("/blog/%d" % blog_post.key().id())
        else:
            error = "subject and content, please!"
            self.render_post(subject, content, error)


class ViewPostHandler(Handler):
    def get(self, post_id):
        blog_post = BlogPost.get_by_id(int(post_id))

        self.render("view_post.html", post=blog_post)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


class SignupHandler(Handler):
    """
    Handles user signup requests.
    """
    def valid_username(self, username):
        return USER_RE.match(username)

    def username_error(self, username, username_exists=False):
        if username_exists:
            return "Username already exists."

        return None if username else "That's not a valid username."

    def valid_password(self, password):
        return PASSWORD_RE.match(password)

    def password_error(self, password):
        return None if password else "That wasn't a valid password."

    def verify_error(self, password, passwords_match):
        if self.valid_password(password) and not passwords_match:
            return "Your passwords didn't match."

    def valid_email(self, email):
        return EMAIL_RE.match(email)

    def email_error(self, email):
        return None if email else "That's not a valid email."

    def get(self):
        self.render('signup.html')

    def post(self):
        user_username = self.request.get('username')
        user_password = self.request.get('password')
        user_verify = self.request.get('verify')
        user_email = self.request.get('email')

        username = self.valid_username(user_username)
        password = self.valid_password(user_password)
        verify = self.valid_password(user_verify)
        email = self.valid_email(user_email) or (not user_email)

        passwords_match = (user_password == user_verify)

        # TODO: check username exists
        username_exists = False

        if (username and password and verify and passwords_match and email):
            # create a user
            self.redirect("/welcome?username=%s" % user_username)
        else:
            self.render('signup.html',
                        username=user_username,
                        username_error=self.username_error(username, username_exists),
                        password_error=self.password_error(password),
                        verify_error=self.verify_error(user_password, passwords_match),
                        email=user_email,
                        email_error=self.email_error(email))


class WelcomeHandler(Handler):
    """
    Welcomes the new user.
    """
    def get(self):
        username = self.request.get('username')

        if username:
            self.render('welcome.html', username=username)
        else:
            self.redirect("/signup")

app = webapp2.WSGIApplication([
    ('/blog/?', BlogHandler),
    ('/blog/newpost', NewPostHandler),
    (r'/blog/(\d+)', ViewPostHandler),
    ('/signup', SignupHandler),
    ('/welcome', WelcomeHandler)
], debug=True)
