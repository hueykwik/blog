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

from google.appengine.ext import db

import webapp2
import jinja2

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


class Handler(webapp2.RequestHandler):
    """
    Base class for other Handlers we write. Handler takes care
    of rendering HTML from templates and writing them in the response.
    """
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class BlogHandler(webapp2.RequestHandler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.write('Hello, Blog!')


class BlogPost(db.Model):
    subject = db.StringProperty(required=True)
    blog = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class NewPostHandler(Handler):
    def render_post(self, subject="", blog="", error=""):
        self.render("new_post.html", subject=subject, blog=blog, error=error)

    def get(self):
        self.render_post()

    def post(self):
        subject = self.request.get("subject")
        blog = self.request.get("blog")

        if subject and blog:
            blog_post = BlogPost(subject=subject, blog=blog)
            blog_post.put()

            self.redirect("/blog/%d" % blog_post.key().id())
        else:
            error = "subject and content, please!"
            self.render_post(subject, blog, error)


class ViewPostHandler(Handler):
    def get(self, post_id):
        blog_post = BlogPost.get_by_id(int(post_id))

        self.render("view_post.html", subject=blog_post.subject, blog=blog_post.blog, created=blog_post.created)

app = webapp2.WSGIApplication([
    ('/blog', BlogHandler),
    ('/newpost', NewPostHandler),
    (r'/blog/(\d+)', ViewPostHandler),
], debug=True)
