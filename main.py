from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_gravatar import Gravatar
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import Integer, String, Text, ForeignKey, or_
from sqlalchemy.exc import IntegrityError
from typing import List
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
import os
# App Configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("secreat_key")
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI",'sqlite:///posts.db')
ckeditor = CKEditor(app)
Bootstrap5(app)

# Database Setup
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
db.init_app(app)

# Login Manager Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Gravatar Setup
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=True)

# Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(100), nullable=False)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)

    # Relationships
    blog_posts: Mapped[List["BlogPost"]] = relationship("BlogPost", back_populates="author", cascade="all, delete")
    comments: Mapped[List["Comment"]] = relationship("Comment", back_populates="author", cascade="all, delete")


class BlogPost(db.Model):
    __tablename__ = 'blog_posts'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))

    # Relationship
    author: Mapped["User"] = relationship("User", back_populates="blog_posts")
    comments: Mapped[List["Comment"]] = relationship("Comment", back_populates="post", cascade="all, delete")


class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(String(5000), nullable=False)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    post_id: Mapped[int] = mapped_column(ForeignKey("blog_posts.id"), nullable=False)

    # Relationships
    author: Mapped["User"] = relationship("User", back_populates="comments")
    post: Mapped["BlogPost"] = relationship("BlogPost", back_populates="comments")

with app.app_context():
    db.create_all()

# User Loader
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

# Context Processor
@app.context_processor
def inject_user():
    return dict(logged_in=current_user.is_authenticated)

# Admin-Only Decorator
def admin_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if current_user.is_authenticated and current_user.get_id() == "1":  # Admin ID
            return function(*args, **kwargs)
        else:
            abort(403)
    return wrapper

# Decorator for deleting comments
def only_commenter(function):
    @wraps(function)
    def check(*args, **kwargs):
        comment_id = kwargs.get('comment_id')
        comment = db.get_or_404(Comment, comment_id)
        if not current_user.is_authenticated or current_user.id != comment.author_id:
            return abort(403)
        return function(*args, **kwargs)
    return check

# Routes
@app.route('/')
def get_all_posts():
    results = db.session.execute(db.select(BlogPost))
    posts = results.scalars().all()
    user_id = str(current_user.get_id()) if current_user.is_authenticated else None
    return render_template("index.html", all_posts=posts, user_id=user_id)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
        new_user = User(email=form.email.data, password=hashed_password, username=form.username.data)
        try:
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            flash("Registered successfully!", "success")
            return redirect(url_for("get_all_posts"))
        except IntegrityError:
            db.session.rollback()
            flash("Email or username already exists. Please login instead.", "info")
            return redirect(url_for("login"))
    return render_template("register.html", form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = db.session.execute(
            db.select(User).where(or_(User.email == email, User.username == email))
        ).scalar_one_or_none()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash("Successfully logged in!", "success")
            return redirect(url_for("get_all_posts"))
        else:
            flash("Invalid credentials. Please try again.", "warning")
    return render_template("login.html", form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "warning")
    return redirect(url_for("get_all_posts"))

@app.route('/post/<int:post_id>', methods=["POST", "GET"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                text=form.comment.data,
                author_id=current_user.get_id(),
                post_id=post_id
            )
            db.session.add(new_comment)
            db.session.commit()
            form.comment.data = ""  # Clear form input
            flash("Comment added!", "success")
        else:
            flash("You have to log in to post comments", "warning")
            return redirect(url_for("login"))
    return render_template("post.html", post=requested_post, form=form)

@app.route('/new-post', methods=['GET', 'POST'])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)

@app.route('/edit-post/<int:post_id>', methods=['GET', 'POST'])
@login_required
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if form.validate_on_submit():
        post.title = form.title.data
        post.subtitle = form.subtitle.data
        post.img_url = form.img_url.data
        post.body = form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=form, is_edit=True)

@app.route('/delete/<int:post_id>')
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    flash("Post deleted successfully.", "success")
    return redirect(url_for("get_all_posts"))

@app.route("/delete/comment/<int:comment_id>/<int:post_id>")
@only_commenter
def delete_comment(post_id, comment_id):
    comment_to_delete = db.get_or_404(Comment, comment_id)
    db.session.delete(comment_to_delete)
    db.session.commit()
    flash("Comment deleted successfully.", "success")
    return redirect(url_for('show_post', post_id=post_id))

@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/contact')
def contact():
    return render_template("contact.html")

@app.errorhandler(403)
def forbidden(error):
    return render_template("403.html"), 403

if __name__ == "__main__":
    app.run(debug=False, port=5000)
