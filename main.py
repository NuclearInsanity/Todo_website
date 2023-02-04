from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, RadioField
from wtforms.validators import DataRequired, Length, Email
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
import hashlib
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite://todo.db")
app.config['SECRET_KEY'] = "RBudY8Kem1lDlq9eTykb3kDQw7ge2wt1+tmrGpNdgYA"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)

# Login Manager
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)


# Forms
class RegistrationForm(FlaskForm):
    email = StringField(label='Username', validators=[DataRequired(), Length(min=6, max=30)])
    password = PasswordField(label='Password', validators=[DataRequired(), Length(min=6, max=20)])
    submit = SubmitField('Register 💥')


class LoginForm(FlaskForm):
    email = StringField(label='Username', validators=[DataRequired(), Length(min=6, max=30)])
    password = PasswordField(label='Password', validators=[DataRequired(), Length(min=6, max=20)])
    submit = SubmitField('Login ✅')

class TodoForm(FlaskForm):
    todo = StringField(label='Type your todo', validators=[DataRequired()])
    due_date = RadioField(label='Due date', choices=[('now', 'Now'), ('soon', 'Soon'), ('later', 'Later')])
    submit = SubmitField('Add Todo 👌')

# Configure database
class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    hashed_email = db.Column(db.String(200), unique=True)
    password = db.Column(db.String(100))
    # name = db.Column(db.String(80))
    todos = relationship("Todos", back_populates='author')


class Todos(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.String(200), db.ForeignKey("users.id"))
    todo_item = db.Column(db.String(200))
    todo_due_date = db.Column(db.String(200))
    author = relationship("Users", back_populates='todos')


with app.app_context():
    db.create_all()


@app.route('/')
def homepage():
    return render_template('index.html')


@app.route('/todos', methods=['POST', 'GET'])
@login_required
def todos():
    form = TodoForm()
    all_todos = current_user.todos

    if form.validate_on_submit():
        new_todo = Todos(
            todo_item=form.todo.data,
            todo_due_date=form.due_date.data,
            author=current_user,
        )
        db.session.add(new_todo)
        db.session.commit()
        return redirect(url_for('todos'))

    return render_template('todos.html', form=form, all_todos=all_todos)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()

        if user:
            flash("Your email is already registered in our database! Please sign in.")
            return redirect(url_for('login'))

        else:
            hash_and_salted_password = generate_password_hash(
                form.password.data,
                method='pbkdf2:sha256',
                salt_length=8
            )

            hashed_email = hashlib.md5(str.strip(str.lower(form.email.data)).encode()).hexdigest()

            new_user = Users(
                email=form.email.data,
                hashed_email=hashed_email,
                password=hash_and_salted_password
            )
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)

            return redirect(url_for('todos'))

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():

        user = Users.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                flash('Login Successful!')
                return redirect(url_for('todos'))
            else:
                flash('Sorry, either your email or password are incorrect, try again! 👾')
        else:
            flash('Sorry, either your email or password are incorrect, try again! 👾')
    return render_template('login.html', form=form)


@app.route('/delete_todo/<int:todo_id>')
@login_required
def delete_todo(todo_id):
    todo_to_delete = Todos.query.get(todo_id)
    db.session.delete(todo_to_delete)
    db.session.commit()
    return redirect(url_for('todos'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('homepage'))

if __name__ == '__main__':
    app.run(debug=True)
