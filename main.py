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

import model

import hash_utils


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def render_str(template, **params):
    """Renders a template with associated parameters.

    Args:
        template: The string filename of the template.
        **params: Keyword parameters used in the template.

    Returns:
        A string rendering of the template with the parameters.
    """
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

    def set_secure_cookie(self, name, val):
        """Make a secure string for a cookie name and value and sets it in the
        response header.


        Args:
            name: Name of the cookie.
            val: The value associated with the cookie.

        Returns:
            None.
        """
        cookie_val = hash_utils.make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        """Reads and validates the value for the cookie named `name.`

        Args:
            name: The name of the cookie.

        Returns:
            The cookie value if valid (see check_secure_val), None otherwise.
        """
        cookie_val = self.request.cookies.get(name)
        return cookie_val and hash_utils.check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def like_done(self, post_id=None):
        """Called when the user "like" action is completed.

        Args:
            post_id: Optional id for the associated blog post.

        Returns:
            Nothing, but it is expected that subclasses will redirect.
        """
        raise NotImplementedError

    def handle_like(self, blog_post):
        """Adds or removes a "like" for a given blog_post.

        Args:
            blog_post: The db.Model BlogPost

        Returns:
            No return value, but expected that subclasses implement
            `Handler.like_done()` to handle redirects.
        """
        if not blog_post.can_like_or_comment(self.user):
            self.response.out.write("Authors are not allowed to like")
            return

        if blog_post.has_liked(self.user):
            likes = [like for like in blog_post.likes if like.voter.key().id() == self.user.key().id()]
            db.delete(likes)
        else:
            like = model.Like(voter=self.user, post=blog_post)
            like.put()

        self.like_done(blog_post.key().id())

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and model.User.get_by_id(int(uid))


class FrontPage(Handler):
    """Shows all blog posts.
    """
    def get(self):
        blog_posts = db.GqlQuery("SELECT * FROM BlogPost "
                                 "ORDER BY created DESC ")

        self.render("front.html", blog_posts=blog_posts, user=self.user)

    def post(self):
        post_id = self.request.get("post_id")
        blog_post = model.BlogPost.get_by_id(int(post_id))

        if blog_post:
            self.handle_like(blog_post)

    def like_done(self, post_id=None):
        self.redirect("/blog")


class AddComment(Handler):
    """Handles adding a single comment.
    """
    def post(self, post_id):
        blog_post = model.BlogPost.get_by_id(int(post_id))

        if not blog_post.can_like_or_comment(self.user):
            self.error(404)
            self.response.out.write("Authors are not allowed to comment!")
            return

        comment_text = self.request.get("comment")

        if comment_text:
            comment = model.Comment(text=comment_text, author=self.user, post=blog_post)
            comment.put()

            self.redirect("/blog/%d" % blog_post.key().id())
        else:
            error = "comments cannot be blank"
            self.render("view_post.html", post=blog_post, user=self.user,
                        can_comment=True, error=error)


class AddLike(Handler):
    """Handles ading a single like.
    """
    def post(self, post_id):
        blog_post = model.BlogPost.get_by_id(int(post_id))

        self.handle_like(blog_post)

    def like_done(self, post_id):
        self.redirect("/blog/%d" % post_id)


class ViewPost(Handler):
    """Handles viewing a single post.
    """
    def render_post(self, blog_post):
        """Renders a blog post.

        This function call will result in the display of a blog post with
        its title, contents, number of likes, number of comments, as well
        as the comments in descending order.

        Args:
            blog_post: The db.Model BlogPost

        Returns:
            None
        """
        comments = blog_post.comments.order("-created")

        self.render("view_post.html", post=blog_post, user=self.user,
                    show_comments=True,
                    can_comment=blog_post.can_like_or_comment(self.user),
                    comments=comments)

    def get(self, post_id):
        blog_post = model.BlogPost.get_by_id(int(post_id))
        self.render_post(blog_post)


class NewPost(Handler):
    """Handles creating a new post.
    """
    def render_post(self, subject="", content="", error="",
                    title="new post", post_id=""):
        self.render("post_form.html", subject=subject, content=content, error=error, user=self.user, title=title, post_id=post_id)

    def get(self):
        if self.user:
            self.render_post()
        else:
            self.redirect("/login")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            blog_post = model.BlogPost(subject=subject, content=content, author=self.user)
            blog_post.put()

            self.redirect("/blog/%d" % blog_post.key().id())
        else:
            error = "subject and content, please!"
            self.render_post(subject, content, error)


class DeleteComment(Handler):
    """Handles deleting a comment.
    """
    def get(self, post_id, comment_id):
        comment = model.Comment.get_by_id(int(comment_id))

        if comment:
            comment.delete()

        self.redirect("/blog/%d" % int(post_id))


class EditComment(Handler):
    """Handles editing a comment.
    """
    def get(self, post_id, comment_id):
        comment = model.Comment.get_by_id(int(comment_id))
        self.render("comment_form.html", comment=comment.text, user=self.user)

    def post(self, post_id, comment_id):
        comment = model.Comment.get_by_id(int(comment_id))

        comment_text = self.request.get("comment")

        if comment_text:
            comment.text = comment_text
            comment.put()
        else:
            error = "comment cannot be blank"
            self.render("comment_form.html", user=self.user,
                        comment=comment_text, error=error)

        self.redirect("/blog/%d" % int(post_id))


class DeletePost(Handler):
    """Handles deleting a post.
    """
    def get(self, post_id):
        blog_post = model.BlogPost.get_by_id(int(post_id))

        if blog_post:
            blog_post.delete()

        self.redirect("/blog")


class EditPost(NewPost):
    """Handles editing a post.
    """
    def get(self, post_id):
        blog_post = model.BlogPost.get_by_id(int(post_id))

        if blog_post.author.key().id() != self.user.key().id():
            self.redirect("/blog/%d" % blog_post.key().id())

        self.render_post(subject=blog_post.subject, content=blog_post.content, title="edit post", post_id=post_id)

    def post(self, post_id):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            blog_post = model.BlogPost.get_by_id(int(post_id))
            blog_post.subject = subject
            blog_post.content = content

            blog_post.put()

            self.redirect("/blog/%d" % blog_post.key().id())
        else:
            error = "subject and content, please!"
            self.render_post(subject, content, error)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


def get_user(username):
    users = db.GqlQuery("select * from User where username = '%s'" % username)

    return users.get()


def user_cookie_string(user):
    return "user_id=%s; Path=/" % hash_utils.make_secure_val(str(user.key().id()))


class Signup(Handler):
    """Handles user signup requests.
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
        elif get_user(username):
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
            hash_password = hash_utils.make_pw_hash(username, password)
            user = model.User(username=username, hash_password=hash_password)
            user.put()

            self.login(user)

            self.redirect("/welcome")


class Welcome(Handler):
    """Welcomes a user.
    """
    def get(self):
        # Things to check:
        # 1. no cookie
        # 2. forged cookie
        # 3. user_id exists in DB
        user = None

        user_id = self.read_secure_cookie('user_id')
        if user_id:
            user = model.User.get_by_id(int(user_id))

        if user:
            self.render('welcome.html', user=user)
        else:
            self.redirect("/signup")


class Login(Handler):
    """Handles viewing a single post.
    """
    def check_password(self, username, password):
        # Assume that username exists in DB.
        query = db.GqlQuery("select * from User where username = '%s'" % username)
        user = query.get()

        return hash_utils.valid_pw(username, password, user.hash_password)

    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        user = get_user(username)

        if not user or not self.check_password(username, password):
            self.render('login.html', error='Invalid login')
        else:
            self.login(user)
            self.redirect("/welcome")


class Logout(Handler):
    """Handles logging out.
    """
    def get(self):
        self.logout()
        self.redirect("/signup")

app = webapp2.WSGIApplication([
    ('/blog/?', FrontPage),
    ('/blog/newpost', NewPost),
    (r'/blog/(\d+)/edit', EditPost),
    (r'/blog/(\d+)/delete', DeletePost),
    (r'/blog/(\d+)/add_comment', AddComment),
    (r'/blog/(\d+)/add_like', AddLike),
    (r'/blog/(\d+)/(\d+)/delete', DeleteComment),
    (r'/blog/(\d+)/(\d+)/edit', EditComment),
    (r'/blog/(\d+)', ViewPost),
    ('/signup', Signup),
    ('/welcome', Welcome),
    ('/login', Login),
    ('/logout', Logout)
], debug=True)
