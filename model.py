from google.appengine.ext import db


class BlogPost(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    def set_render_text(self):
        """Replaces newline characters from content with the <br> HTML tag,
        storing it in a _render_text instance variable.
        """
        self._render_text = self.content.replace('\n', '<br>')


class User(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.EmailProperty()
