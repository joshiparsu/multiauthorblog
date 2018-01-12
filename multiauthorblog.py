import os
import re
from string import letters
import random
import hashlib
import hmac
import json
import logging
from functools import wraps

import jinja2
import webapp2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

"""Secret value for password encryption
Instead of creating a plain secret key, let's use a GUID
to make sure it is always unique
"""
SECRET = "ABB93A92-089A-4972-BAFF-59FF19DC2465"


def post_exists(function):
    """Decorator Method
    Through out code, we want to verify whether given post exists in our db
    or not. Instead of writing same piece of code every time, let's wrap it
    in a function and use that method as decorator to not to clutter actual
    code.
    """
    @wraps(function)
    def wrapper(self, post_id):
        key = db.Key.from_path("Post", int(post_id), parent=blog_key())
        post = db.get(key)
        if post:
            return function(self, post_id, post)
        else:
            self.error(404)
            return self.redirect("/404/%s" % post_id)
    return wrapper


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_value(value):
    return "%s|%s" % (value, hmac.new(SECRET, value).hexdigest())


def check_secure_value(cookie_value):
    value = cookie_value.split("|")[0]
    if cookie_value == make_secure_value(value):
        return value


def make_salt(length=5):
    return "".join(random.choice(letters) for x in xrange(length))


def make_password_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return "%s,%s" % (salt, h)


def validate_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and USER_RE.match(username)


def validate_password(password):
    PASS_RE = re.compile(r"^.{3,20}$")
    return password and PASS_RE.match(password)


def validate_email(email):
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
    return not email or EMAIL_RE.match(email)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_password_hash(name, password, salt)


def users_key(group="default"):
    return db.Key.from_path("users", group)


def blog_key(name="default"):
    return db.Key.from_path("blogs", name)


class User (db.Model):
    """User class represents a user from our blogging platform
    We're interested in storing user's username, password
    and email (optional)
    """
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        user = cls.all().filter("name =", name).get()
        return user

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_password_hash(name, pw)
        return cls(parent=users_key(),
                   name=name,
                   pw_hash=pw_hash,
                   email=email)

    @classmethod
    def signin(cls, name, password):
        user = cls.by_name(name)
        if user and valid_pw(name, password, user.pw_hash):
            return user


class Post(db.Model):
    """Post class is used to represent a blog post of any registered user
    We're interested in storing subject, post-content, last modified time,
    author of blog, image path associated with post (optional), number of
    comments for the post and number of likes for the post
    """
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    last_modified = db.DateTimeProperty(auto_now=True)
#    author = db.StringProperty(required=True)
    author = db.StringProperty(required=True)
    image_path = db.StringProperty()
    no_of_comments = db.IntegerProperty(required=True)
    no_of_likes = db.IntegerProperty(required=True)


class PostComment(db.Model):
    """PostComment class is used to represent a comment for given blog post
    We're interested in post id for which comment is stored, actual comment
    content and comment time
    """
    post_id = db.IntegerProperty(required=True)
    comment = db.TextProperty(required=True)
    author = db.StringProperty(required=True)
    commented_on = db.DateTimeProperty(auto_now=True)


class PostLike(db.Model):
    """PostLike class is used to represent user's choice for
    all the posts he/she has liked
    """
    post_id = db.IntegerProperty(required=True)
    username = db.StringProperty(required=True)


class BlogHandler(webapp2.RequestHandler):
    """Our HTTP Request handler class that will handle all the
    http request coming to our blog site
    """

    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.response.out.write(render_str(template, **kw))

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def set_secure_cookie(self, name, value):
        cookie_value = make_secure_value(value)
        self.response.headers.add_header("Set-Cookie",
                                         "%s=%s; Path=/" % (name, cookie_value))

    def read_secure_cookie(self, name):
        cookie_value = self.request.cookies.get(name)
        return cookie_value and check_secure_value(cookie_value)

    def signin(self, user):
        self.set_secure_cookie("user_id", str(user.key().id()))

    def signout(self):
        self.response.headers.add_header("Set-Cookie", "user_id=; Path=/")

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie("user_id")
        self.user = uid and User.by_id(int(uid))


class SigninHandler(BlogHandler):
    """Handle "signin" request for our blog site"""

    def get(self):
        message = ""
        if not self.user:
            message = "Please signin and continue writing post"
            self.render("signin.html",
                        userSignedIn="false",
                        message=message)
        else:
            message = "You are already logged in, %s" % self.user.name
            self.render("signin.html",
                        userSignedIn="true",
                        message=message)

    def post(self):
        self.username = self.request.get("username")
        self.password = self.request.get("password")

        params = {}
        params['password'] = self.password
        params['username'] = self.username
        user = User.by_name(self.username)
        if user and valid_pw(self.username, self.password, user.pw_hash):
            self.signin(user)
            return self.redirect("/welcome")
        else:
            params['error_signin'] = "Invalid signin credentials." \
                                     " Please try again."
            params['message'] = ""
            self.render("signin.html", **params)


class SignupHandler(BlogHandler):
    """Handle "signup" request for our blog site"""

    def get(self):
        if not self.user:
            self.render("signup.html",
                        userSignedIn="false")
        else:
            msg = "You are already signed in as %s" % self.user.name
            msg = msg + ". Do you want to signout first?"
            self.render("signup.html",
                        msg=msg,
                        userSignedIn="true")

    def post(self):
        self.username = self.request.get("username")
        self.password = self.request.get("password")
        self.verify = self.request.get("verify")
        self.email = self.request.get("email")

        params = {}
        params['email'] = self.email
        params['username'] = self.username
        params['error_username'] = ""
        params['error_password'] = ""
        params['error_verify'] = ""
        params['error_email'] = ""
        have_error = False

        if not validate_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not validate_password(self.password):
            params['error_password'] = "That's not a valid password."
            have_error = True

        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not validate_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render("signup.html", **params)
        else:
            user = User.by_name(self.username)
            if user:
                msg = "That user already exists. Please try with different." \
                    " username."
                self.render("signup.html", error_username=msg, u="")
            else:
                user = User.register(self.username, self.password, self.email)
                user.put()
                self.signin(user)
                user = self.username
                return self.redirect("/welcome")


class SignoutHandler(BlogHandler):
    """Handle "signout" request for our blog site"""

    def get(self):
        self.signout()
        return self.redirect("/signup")


class NewPostHandler(BlogHandler):
    """New post request handler
    Note that, we would serve "new post" request only when user
    is signed in. Otherwise we'll straight away ask user to sign
    in first and then proceed
    """

    def get(self):
        if not self.user:
            return self.redirect("/signin")

        user_id = self.read_secure_cookie("user_id")
        if User.by_id(int(user_id)).name == self.user.name:
            self.render("newpost.html",
                        userSignedIn="true",
                        username=self.user.name,
                        error="",
                        subject="",
                        content="")
        else:
            return self.redirect("/signin")

    def post(self):
        if not self.user:
            return self.redirect("/signin")

        cancel = self.request.get("button-submit")

        if cancel == "Cancel":
            return self.redirect("/")

        user_id = self.read_secure_cookie("user_id")
        if self.user:
            if User.by_id(int(user_id)).name == self.user.name:
                subject = self.request.get("subject")
                content = self.request.get("postcontent")
                image_path = self.request.get("postimage")
                user_id = self.read_secure_cookie("user_id")
                author = User.by_id(int(user_id)).name

                #
                # If user has not provided an image path associated with
                # post, we would use place-holder image
                #
                if image_path == "":
                    image_path = "http://via.placeholder.com/675x337/ebf4fe/"\
                                 "000000?text=%s" % subject
                if subject and content and author:
                    post = Post(parent=blog_key(),
                                subject=subject,
                                content=content,
                                author=author,
                                image_path=image_path,
                                no_of_comments=0,
                                no_of_likes=0)
                    post.put()
                    return self.redirect("/postdetail/" +
                                         str(post.key().id()))
                else:
                    #
                    # If required inputs are not provided by user, don't
                    # create a new post. Rather inform user about it and
                    # ask to provide those inputs
                    #
                    if not subject and not content:
                        error = "Subject and Content can't be empty"
                    elif not subject:
                        error = "Subject cannot be empty."
                    elif not content:
                        error = "Content cannot be empty.!"

                    self.render("newpost.html",
                                userSignedIn="true",
                                username=self.user.name,
                                error=error,
                                subject=subject,
                                content=content)
            else:
                return self.redirect("/signin")
        else:
            return self.redirect("/signin")


class EditPostHandler(BlogHandler):
    """Edit post request handler
    Note that, we would serve "edit post" request only when user
    is signed in. Otherwise we'll straight away ask user to sign
    in first and then proceed
    If edit request has come for a post not present in our db then
    we would return 404
    """
    @post_exists
    def get(self, post_id, post):
        if not self.user:
            return self.redirect("/signin")

        if post.author == self.user.name:
            self.render("editpost.html",
                        userSignedIn="true",
                        username=self.user.name,
                        post=post)
        else:
            return self.redirect("/")

    @post_exists
    def post(self, post_id, post):
        if not self.user:
            return self.redirect("/signin")

        cancel = self.request.get("button-submit")
        #
        # If user has clicked on "Cancel" button, no need to go ahead
        #
        if cancel == "Cancel":
            return self.redirect("/welcome")

        if self.user.name == post.author:
            subject = self.request.get("subject")
            content = self.request.get("postcontent")
            image_path = self.request.get("postimage")
            user_id = self.read_secure_cookie("user_id")

            if image_path == "":
                image_path = "http://via.placeholder.com/675x337/ebf4fe/" \
                             "000000?text=%s" % subject

            if subject and content:
                post.subject = subject
                post.content = content
                post.image_path = image_path
                post.put()
                return self.redirect("/postdetail/%s" % str(post.key().id()))
            else:
                error = "subject and content, please!"
                self.render("editpost.html", subject=subject,
                            content=content, error=error)
        else:
            return self.redirect("/signin")


class PostDetailHandler(BlogHandler):
    """Post details request handler
    We would show post details even when user has not signed-in
    But in that case, user cannot alter post content or write any
    comment for the post
    """
    @post_exists
    def get(self, post_id, post):
        if not self.user:
            username = ""
            userSignedIn = "false"
        else:
            username = self.user.name
            userSignedIn = "true"

        comments = db.GqlQuery("SELECT * FROM PostComment " +
                               "WHERE post_id = :1 " +
                               "ORDER BY commented_on DESC", int(post_id))

        liked_post = False
        post_likes = db.GqlQuery(
            "SELECT * FROM PostLike WHERE post_id = :1", int(post_id))

        if self.user:
            for post_like in post_likes:
                if self.user.name == post_like.username:
                    liked_post = True
                    break
        self.render("postdetail.html",
                    userSignedIn=userSignedIn,
                    username=username,
                    post=post,
                    comments=comments,
                    liked_post=liked_post)


class DeletePostHandler(BlogHandler):
    """Delete Post request handler
    If we receive a delete request for a post that doesn't exist
    we would return 404
    """
    @post_exists
    def post(self, post_id, post):
        if not self.user:
            return self.redirect("/signin")

        if post.author == self.user.name:
            post.delete()
            comments = db.GqlQuery("SELECT * FROM PostComment WHERE "
                                   "post_id = :1", int(post_id))
            for comment in comments:
                comment.delete()
        return self.redirect("/welcome")


class LikePostHandler(BlogHandler):
    """Like Post request handler
    If we receive a like request for a post that doesn't exist
    we would return 404
    """
    @post_exists
    def post(self, post_id, post):
        if not self.user:
            return self.redirect("/signin")

        #
        # We already have a check on frontend to make sure user cannot like
        # his/her post. However, double check here to me make sure someone
        # is not trying to do so by directly using url to like his/her own
        # post.
        #
        if self.user.name == post.author:
            return self.redirect("/postdetail/" + post_id)

        liked_post = False
        post_likes = db.GqlQuery("SELECT * FROM PostLike WHERE "
                                 "post_id = :1", int(post_id))

        for post_like in post_likes:
            if self.user.name == post_like.username:
                liked_post = True
                break

        if liked_post is False:
            new_like = PostLike(parent=blog_key(),
                                username=self.user.name,
                                post_id=int(post_id))
            new_like.put()
            post.no_of_likes = 1
            post.put()
        else:
            like = PostLike(parent=blog_key(),
                            username=self.user.name,
                            post_id=int(post_id))
            like.put()
            post.no_of_likes = post.no_of_likes + 1
            post.put()
        return self.redirect("/postdetail/" + post_id)


class UnlikePostHandler(BlogHandler):
    """Unlike Post request handler
    If we receive a unlike request for a post that doesn't exist
    we would return 404
    """
    @post_exists
    def post(self, post_id, post):
        if not self.user:
            return self.redirect("/signin")

        #
        # We already have a check on frontend to make sure user cannot
        # unlike his/her post. However, double check here to me make
        # sure someone is not trying to do so by directly using url to
        # like his/her own post.
        #
        if self.user.name == post.author:
            return self.redirect("/postdetail/" + post_id)

        liked_post = False
        post_likes = db.GqlQuery("SELECT * FROM PostLike WHERE post_id = :1 "
                                 "AND username = :2",
                                 int(post_id), self.user.name)
        post_like = post_likes.get()

        if post_like is not None:
            post_like.delete()
            post.no_of_likes = post.no_of_likes - 1
            post.put()
        return self.redirect("/postdetail/" + post_id)


class AddCommentHandler(BlogHandler):
    """Add comment to post request handler
    If we receive request for a post that doesn't exist
    we would return 404
    """
    @post_exists
    def post(self, post_id, post):
        if not self.user:
            return self.redirect("/signin")

        comment = self.request.get("comment")
        post_comment = PostComment(parent=blog_key(),
                                   post_id=int(post_id),
                                   comment=comment,
                                   author=self.user.name)
        post_comment.put()
        if post.no_of_comments is None:
            post.no_of_comments = 1
        else:
            post.no_of_comments = int(post.no_of_comments) + 1
        post.put()
        return self.redirect("/postdetail/%s" % post_id)


class EditCommentHandler(BlogHandler):
    """Edit comment to post request handler
    If we receive request for a post that doesn't exist
    we would return 404
    """
    @post_exists
    def post(self, post_id, post):
        if not self.user:
            return self.redirect("/signin")

        comment_data = self.request.get("comment")
        comment_id = self.request.get("comment-id")
        if comment_data and comment_id and self.user:
            key = db.Key.from_path("PostComment", int(
                comment_id), parent=blog_key())
            comment = db.get(key)

            if comment and comment.author == self.user.name:
                comment.comment = comment_data
                comment.put()
        return self.redirect("/postdetail/%s" % str(post.key().id()))


class DeleteCommentHandler(BlogHandler):
    """Delete comment to post request handler
    If we receive request for a post that doesn't exist
    we would return 404
    """
    @post_exists
    def post(self, post_id, post):
        if not self.user:
            return self.redirect("/signin")

        comment_id = self.request.get("commentid")
        comment_key = db.Key.from_path("PostComment",
                                       int(comment_id),
                                       parent=blog_key())
        comment = db.get(comment_key)
        if comment:
            if comment_id and comment.author == self.user.name:
                comment.delete()
                post.no_of_comments = int(post.no_of_comments) - 1
                post.put()
            return self.redirect("/postdetail/%s" % post_id)
        else:
            return self.redirect("/")


class ByAuthorPostsHandler(BlogHandler):
    """Handle a request to see posts by a specific user"""

    def get(self):
        author = self.request.get("author")
        if author:
            posts = db.GqlQuery("SELECT * FROM Post WHERE author = :1 "
                                "ORDER BY last_modified DESC", author)
            post = posts.get()
            message = ""
            if post is None:
                message = "The author has not posted anything yet!!!"
            self.render("author_posts.html",
                        userSignedIn="false",
                        username="",
                        message=message,
                        posts=posts)
        else:
            self.redirect("/")


class NotFoundErrorHandler(BlogHandler):
    """Requested resource not found error handler"""

    def get(self, error_id):
        self.render("error_404.html",
                    error_id=404)


class ContactusHandler(BlogHandler):
    """Contact us request. Right now, we don't do anything with this
    but going ahead maintain a database of all the requests that
    has come to use
    """

    def get(self):
        if not self.user:
            userSignedIn = "false"
        else:
            userSignedIn = "true"
        self.render("contactus.html",
                    userSignedIn=userSignedIn)

    def post(self):
        return self.redirect("/")


class WelcomeHandler(BlogHandler):
    """User home page that lists all his/her posts"""

    def get(self):
        message = ""
        if not self.user:
            return self.redirect("/signin")
        else:
            posts_query = Post.all().ancestor(blog_key())
            posts_query.filter("author =", self.user.name)
            posts_query.order("-last_modified")
            posts = posts_query.run()

            if not posts_query.get():
                message = "You don't have written any post." \
                          "Why don't you start with your first post now?"
            self.render("welcome.html",
                        userSignedIn="true",
                        message=message,
                        posts=posts,
                        username=self.user.name)


class MainPage(BlogHandler):
    """Home page of the blog site"""

    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY last_modified DESC")
        post = posts.get()
        message = ""

        if not self.user:
            if post is None:
                message = "Please signin or signup and get started."
            self.render("home.html",
                        userSignedIn="false",
                        username="",
                        message=message,
                        posts=posts)
        else:
            if post is None:
                message = "You can start writing your post now."
            self.render("home.html",
                        userSignedIn="true",
                        username=self.user.name,
                        message=message,
                        posts=posts)


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/signin', SigninHandler),
                               ('/signup', SignupHandler),
                               ('/signout', SignoutHandler),
                               ('/welcome', WelcomeHandler),
                               ('/newpost', NewPostHandler),
                               ('/postdetail/([0-9]+)', PostDetailHandler),
                               ('/postdetail/([0-9]+)/editpost',
                                EditPostHandler),
                               ('/postdetail/([0-9]+)/deletepost',
                                DeletePostHandler),
                               ('/postdetail/([0-9]+)/likepost',
                                LikePostHandler),
                               ('/postdetail/([0-9]+)/unlikepost',
                                UnlikePostHandler),
                               ('/postdetail/([0-9]+)/addcomment',
                                AddCommentHandler),
                               ('/postdetail/([0-9]+)/editcomment',
                                EditCommentHandler),
                               ('/postdetail/([0-9]+)/deletecomment',
                                DeleteCommentHandler),
                               ('/byauthor', ByAuthorPostsHandler),
                               ('/404/([0-9]+)', NotFoundErrorHandler),
                               ('/contactus', ContactusHandler),
                               ],
                              debug=True)
