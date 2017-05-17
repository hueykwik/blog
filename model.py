from google.appengine.ext import db


class BlogPost(db.Model):
    """Models a blog post.

    Attributes:
        subject: The blog post title.
        content: The blog post text.
        created: When the blog post was created.
    """
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    def set_render_text(self):
        """Replaces newline characters from content with the <br> HTML tag,
        storing it in a _render_text instance variable.
        """
        self._render_text = self.content.replace('\n', '<br>')


class User(db.Model):
    """Models a user.

    Attributes:
        username: The user's username.
        password: The user's hashed and salted password.
        email: The user's email.
    """
    username = db.StringProperty(required=True)
    hash_password = db.StringProperty(required=True)
    email = db.EmailProperty()
