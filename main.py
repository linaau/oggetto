# на все странички, которые не могут просматриваться неавторизованным человеком накладывается декоратор @login_required
import os.path
import pathlib

import cachecontrol
import google.auth.transport.requests
import requests
from flask import Flask, render_template, url_for, request, redirect, flash, Response, session, abort
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from werkzeug.security import check_password_hash, generate_password_hash
import cv2

site = Flask(__name__)
site.secret_key = 'bara bara bara bere bere bere'
site.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
GOOGLE_CLIENT_ID = "1008911753425-pveobv95mm7o9685o3ijgtbb5tl7ht8j.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
db = SQLAlchemy(site)
manager = LoginManager(site)
camera = cv2.VideoCapture(0)

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"


flow = Flow.from_client_secrets_file(client_secrets_file=client_secrets_file,
                                     scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
                                     redirect_uri="http://127.0.0.1:5000/callback")


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    # loguser = db.Column(db.Integer, nullable=False)
    # guest = db.Column(db.Integer, nullable=False)
    # admin = db.Column(db.Integer, nullable=False)
    # lector = db.Column(db.Integer, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    login = db.Column(db.String(255), nullable=False, unique=True)


def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)
        else:
            return function()

    return wrapper


def generate_frames():
    while True:
        #  read the camera frame
        success, frame = camera.read()
        if not success:
            break
        else:
            ret, buffer = cv2.imencode('.jpg', frame)
            frame = buffer.tobytes()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')


@manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)


@site.route('/main')
@site.route('/')
def main_page():
    with site.app_context():
        db.create_all()
    return render_template("main.html")


@site.route('/login')
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@site.route('/logout')
def logout():
    session.clear()
    return redirect('/')


@site.route('/callback')
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)


    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    return redirect("/protected_area")


@site.route('/protected_area')
@login_is_required
def protected_area():
    return render_template("protected_area.html")


# @site.route('/login', methods=['GET', 'POST'])
# def login_page():
#     login = request.form.get('login')
#     password = request.form.get('password')
#
#     if login and password:
#         user = Users.query.filter_by(login=login).first()
#
#         if user and check_password_hash(user.password, password):
#             login_user(user)
#
#             next_page = request.args.get('next')
#
#             return redirect(next_page)
#         else:
#             flash('Login or password is not correct')
#     else:
#         flash('Please fill login and password fields')
#     return render_template('login.html')
#
#
# @site.route('/logout', methods=['GET', 'POST'])
# @login_required
# def logout_page():
#     logout_user()
#     return redirect(url_for('main_page'))  # ну например
#
#
# @site.after_request
# def redirect_to_signin(response):
#     if response.status_code == 401:
#         return redirect(url_for('login_page') + '?next=' + request.url)
#
#     return response
#
#
# @site.route('/registration', methods=['GET', 'POST'])
# def registration_page():
#     login = request.form.get('login')
#     password = request.form.get('password')
#     password2 = request.form.get('password2')
#
#     if request.method == 'POST':
#         if not (login or password or password2):
#             flash('Please, fill all fields!')
#         elif password != password2:
#             flash('Passwords do not equal ')
#         else:
#             hash_pwd = generate_password_hash(password)
#             new_user = Users(login=login, password=hash_pwd)
#             db.session.add(new_user)
#             db.session.commit()
#
#             return redirect(url_for('login_page'))
#     return render_template('registration.html')

@site.route('/meeting')
def meeting():
    return render_template('meeting.html')


@site.route('/video')
def video():
    return Response(generate_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')


# @site.route('/posts')
# def posts():
#     articles = Article.query.order_by(Article.date.desc()).all() #Обращение через определённый класс к базе данных (first - первый, all - все и т.д.).order_by(Article.date) - сортировка по date из Article.
#
#     return render_template("posts.html", articles=articles)


# @site.route('/posts/<int:id>')
# def post_detail(id):
#     article = Article.query.get(id) #Обращение через определённый класс к базе данных (first - первый, all - все и т.д.).order_by(Article.date) - сортировка по date из Article.
#     return render_template("post_detail.html", article=article)


# @site.route('/create-article', methods=['POST', 'GET'])
# def create_article():
#     if request.method == "POST":
#         title = request.form['title']
#         intro = request.form['intro']
#         text = request.form['text']
#
#         article = Article(title=title, intro=intro, text=text)
#
#         try:
#             db.session.add(article)
#             db.session.commit()
#             return redirect('/posts')
#         except:
#             return "при добавлении статьи произошла ошибка, попроуйте позже"
#     else:
#         return render_template("create-article.html")

if __name__ == "__main__":
    site.run(debug=True)
