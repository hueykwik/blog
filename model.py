from google.appengine.ext import db


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

    @classmethod
    def get_by_name(cls, name):
        return User.all().filter("username = ", name).get()


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
    author = db.ReferenceProperty(User, required=True, collection_name="posts")

    def get_render_text(self):
        return self.content.replace('\n', '<br>')

    def has_liked(self, user):
        """Returns True if `user` has liked this post, False otherwise.
        """
        if user:
            for like in self.likes:
                if like.voter.key().id() == user.key().id():
                    return True
        return False

    def can_like_or_comment(self, user):
        return user and self.author.key().id() != user.key().id()


class Comment(db.Model):
    """Models a blog comment.

    Attributes:
        text: The comment text.
        created: When the commment was created.
        author: The user who wrote the comment.
        post: The comment's associated blog post.

    """
    text = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    author = db.ReferenceProperty(User, required=True, collection_name="comments")
    post = db.ReferenceProperty(BlogPost, required=True, collection_name="comments")


class Like(db.Model):
    """Models liking posts.
    """

    created = db.DateTimeProperty(auto_now_add=True)
    voter = db.ReferenceProperty(User, required=True, collection_name="likes")
    post = db.ReferenceProperty(BlogPost, required=True,
                                collection_name="likes")

