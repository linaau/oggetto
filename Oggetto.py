# на все странички, которые не могут просматриваться неавторизованным человеком накладывается декоратор @login_required
import os
import pathlib
import cachecontrol
import requests
import google.auth.transport.requests
from flask import Flask, render_template, url_for, request, redirect, flash, session, abort
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from werkzeug.security import check_password_hash, generate_password_hash
# import cv2


site = Flask(__name__)
# site.static_folder = "static"
site.secret_key = 'bara bara bara bere bere bere'
site.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lectors.db'
db = SQLAlchemy(site)
GOOGLE_CLIENT_ID = "1008911753425-pveobv95mm7o9685o3ijgtbb5tl7ht8j.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
manager = LoginManager(site)


os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"


flow = Flow.from_client_secrets_file(client_secrets_file=client_secrets_file,
                                     scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
                                     redirect_uri="http://127.0.0.1:5000/callback")


class Lectors(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    lector_name = db.Column(db.String(120), nullable=False)
    discipline = db.Column(db.String(128), nullable=False)
    description = db.Column(db.String(255), nullable=False, unique=True)


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String(128), nullable=False)
    login = db.Column(db.String(255), nullable=False, unique=True)


class Courses(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    course = db.Column(db.String(128), nullable=False)
    lector = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(128), nullable=False)
    data = db.Column(db.String(128), nullable=False)
    descr = db.Column(db.String(300), nullable=False)
    url = db.Column(db.Text, nullable=False)


def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)
        else:
            return function()

    return wrapper


@manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)


@site.route('/main')
@site.route('/')
def main_page():
    with site.app_context():
        db.create_all()
    return render_template("main.html")


@site.route('/lectors')
def posts():
    lectors = Lectors.query.order_by(Lectors.lector_name).all() #Обращение через определённый класс к базе данных (first - первый, all - все и т.д.).order_by(Article.date) - сортировка по lectors_name из Lectors.

    return render_template("lectors.html", lectors=lectors)


@site.route('/lectors/<int:id>')
def post_detail(id):
    lector = Lectors.query.get(id) #Обращение через определённый класс к базе данных (first - первый, all - все и т.д.).order_by(Article.date) - сортировка по date из Article.
    return render_template("Kurator_index.html", lector=lector)


@site.route('/login')
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@site.route('/logout')
@login_is_required
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
def protected_area():
    return render_template("protected_area.html")


@site.route('/profile')
def profile():
    return render_template('profile.html')


@site.route('/courses')
def courses():
    return render_template('courses.html')


@site.route('/add_course', methods=["POST", "GET"])
def add_course():
    if request.method == "POST":
        course = request.form['course']
        lector = request.form['lector']
        name = request.form['name']
        data = request.form['data']
        descr = request.form['descr']
        url_adr = request.form['url_adr']

        course = Courses(course=course, lector=lector, name=name, data=data, descr=descr, url_adr=url_adr)

        try:
            db.session.add(course)
            db.session.commit()
            return redirect('/courses')
        except:
            return "при добавлении статьи произошла ошибка, попробуйте позже"
    else:
        return render_template("admin.html")


if __name__ == "__main__":
    site.run(debug=True)