import time
import requests
import os
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone, date
from functools import wraps
from urllib.parse import urlencode

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, create_engine, text
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, login_user, logout_user, current_user, login_required, UserMixin
from flask_migrate import Migrate

# ─── FLASK APP ───────────────────────────────────────────
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = "ma_cle_ultra_secrete"

# ─── UPLOAD CONFIG ───────────────────────────────────────
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

UPLOAD_FOLDER_PROFILE = 'static/uploads/profiles'
UPLOAD_FOLDER_VLOGS = 'static/vlogs'
UPLOAD_FOLDER_APPS = os.path.join(os.getcwd(), "static", "uploads", "apps")

# Création des dossiers si inexistant
os.makedirs(UPLOAD_FOLDER_PROFILE, exist_ok=True)
os.makedirs(UPLOAD_FOLDER_APPS, exist_ok=True)
os.makedirs(UPLOAD_FOLDER_VLOGS, exist_ok=True)

# Configuration Flask
app.config['UPLOAD_FOLDER_PROFILE'] = UPLOAD_FOLDER_PROFILE
app.config['UPLOAD_FOLDER_VLOGS'] = UPLOAD_FOLDER_VLOGS
app.config['UPLOAD_FOLDER_APPS'] = UPLOAD_FOLDER_APPS

def allowed_file(filename):
    """
    Vérifie si le fichier uploadé est autorisé.
    Retourne True si l'extension est dans ALLOWED_EXTENSIONS.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ─── DATABASE CONFIG ─────────────────────────────────────
DATABASE_URL = "postgresql://neondb_owner:npg_4NUwvZ9BdFAs@ep-ancient-waterfall-absumywn-pooler.eu-west-2.aws.neon.tech/neondb?sslmode=require"

engine = create_engine(
    DATABASE_URL,
    pool_size=10,
    max_overflow=20,
    pool_timeout=30,
    pool_recycle=1800,
)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True,
    "pool_recycle": 280,
    "pool_timeout": 20
}

# ─── INITIALISATION DE LA BASE DE DONNÉES ───────────────
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# ─── FLASK-LOGIN CONFIG ─────────────────────────────────
from flask_login import LoginManager, UserMixin, current_user

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "connexion_page"  # ta route login

# Fonction pour charger un utilisateur via Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  # classique

# Avant chaque requête, on force current_user à utiliser ta session
@app.before_request
def load_logged_in_user():
    from flask import g
    user_id = session.get("user_id")
    if user_id:
        g.logged = User.query.get(user_id)
    else:
        g.logged = None


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.String(50), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))

    # Informations principales
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(300), nullable=False)

    # Parrainage — maintenant basé sur le username
    parrain = db.Column(db.String(50), db.ForeignKey('user.username'), nullable=True)

    downlines = db.relationship(
    'User',
    backref=db.backref('parent', remote_side=[username]),
    lazy='dynamic'
    )
    commission_total = db.Column(db.Float, default=0.0)
    has_seen_pay_ok = db.Column(db.Boolean, default=False)
    # Informations du portefeuille
    wallet_country = db.Column(db.String(50))
    wallet_operator = db.Column(db.String(50))
    wallet_number = db.Column(db.String(30))

    # Soldes
    solde_total = db.Column(db.Float, default=0.0)
    solde_depot = db.Column(db.Float, default=0.0)
    solde_parrainage = db.Column(db.Float, default=0.0)
    solde_revenu = db.Column(db.Float, default=0.0)
    total_retrait = db.Column(db.Float, default=0.0)

    premier_depot = db.Column(db.Boolean, default=False)

    is_admin = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)

    country = db.Column(db.String(50), default='')

    # Points divers
    points = db.Column(db.Integer, default=0)
    points_video = db.Column(db.Integer, default=0)
    points_youtube = db.Column(db.Integer, default=0)
    points_tiktok = db.Column(db.Integer, default=0)
    points_instagram = db.Column(db.Integer, default=0)
    points_ads = db.Column(db.Integer, default=0)
    points_spin = db.Column(db.Integer, default=0)
    points_games = db.Column(db.Integer, default=0)
    last_instagram_date = db.Column(db.String(10), default=None)
    last_youtube_date = db.Column(db.String(10), default=None)
    last_tiktok_date = db.Column(db.String(20), default=None)
    last_login = db.Column(db.DateTime, nullable=True)
    login_count = db.Column(db.Integer, default=0)
    has_spun_wheel = db.Column(db.Boolean, default=False)
    has_spun = db.Column(db.Boolean, default=False)
    date_creation = db.Column(db.DateTime, default=datetime.utcnow)
    date_update = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    whatsapp_number = db.Column(db.String(30), nullable=True)
    profile_pic = db.Column(db.String(200), nullable=True)

    def __repr__(self):
        return f"<User {self.username} | {self.phone}>"

# ==============================
# 📦 MODELS
# ==============================
class Depot(db.Model):
    __tablename__ = "depot"

    id = db.Column(db.Integer, primary_key=True)

    # 🔗 Lien vers l'utilisateur via username (nom d'utilisateur)
    user_name = db.Column(
        db.String(50),
        db.ForeignKey("user.username", ondelete="CASCADE"),
        nullable=False
    )

    # 📱 Informations utilisateur
    phone = db.Column(db.String(30), nullable=False)

    # 🛠 Informations paiement
    operator = db.Column(db.String(50), nullable=False)
    country = db.Column(db.String(50), nullable=False)

    # 💰 Montant déposé
    montant = db.Column(db.Float, nullable=False)

    # 🔖 Référence transaction
    reference = db.Column(db.String(200), nullable=True)

    # 📌 Statut du dépôt
    statut = db.Column(db.String(20), default="pending")

    email = db.Column(db.String(120), nullable=True)
    # ⏱ Date création
    date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Depot {self.id} | User: {self.user_name} | Montant: {self.montant}>"

class Commission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    parrain_uid = db.Column(db.String(200), nullable=False)
    filleul_uid = db.Column(db.String(200), nullable=False)
    montant = db.Column(db.Float, nullable=False)
    niveau = db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

class Retrait(db.Model):
    __tablename__ = "retrait"

    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(30), nullable=False)
    montant = db.Column(db.Float, nullable=False)
    statut = db.Column(db.String(20), default="en_attente")
    date = db.Column(db.DateTime, default=datetime.utcnow)
    payment_method = db.Column(db.String(50))

    pays = db.Column(db.String(50), nullable=True)
    frais = db.Column(db.Float, default=0.0)

class Staking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(30), nullable=False)
    vip_level = db.Column(db.String(20), nullable=False)
    montant = db.Column(db.Float, nullable=False)
    duree = db.Column(db.Integer, default=15)
    taux_min = db.Column(db.Float, default=1.80)
    taux_max = db.Column(db.Float, default=2.20)
    revenu_total = db.Column(db.Float, nullable=False)
    date_debut = db.Column(db.DateTime, default=datetime.utcnow)
    actif = db.Column(db.Boolean, default=True)


class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(255), nullable=False)
    correct_answer = db.Column(db.String(255), nullable=False)

class QuestionReponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    date = db.Column(db.Date, default=date.today)
    points = db.Column(db.Integer, default=0)

class ClickTache(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    date = db.Column(db.Date, default=datetime.utcnow().date)
    clicks = db.Column(db.Integer, default=0)  # Nombre de clicks effectués
    points = db.Column(db.Integer, default=0)  # Points gagnés


class ClickJeudiReponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    points = db.Column(db.Integer, default=0)
    date = db.Column(db.Date, default=date.today)

class RetraitPoints(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    points_utilises = db.Column(db.Integer, nullable=False)
    montant_xof = db.Column(db.Float, nullable=False)
    statut = db.Column(db.String(20), default='en_attente')  # en_attente / valide / refusé
    date_creation = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('retraits_points', lazy='dynamic'))

def donner_commission(parrain_username, montant_depot):
    """Crée la commission et remplit solde_revenu, solde_parrainage et commission_total selon les niveaux."""
    
    if not parrain_username:
        return

    parrain = User.query.filter_by(username=parrain_username).first()
    if not parrain:
        return

    # --- NIVEAU 1 ---
    commission_niveau1 = 1700

    parrain.solde_revenu = (parrain.solde_revenu or 0) + commission_niveau1
    parrain.solde_parrainage = (parrain.solde_parrainage or 0) + commission_niveau1
    parrain.commission_total = (parrain.commission_total or 0) + commission_niveau1

    db.session.commit()

    # --- NIVEAU 2 ---
    if parrain.parrain:
        parrain2 = User.query.filter_by(username=parrain.parrain).first()
        if parrain2:
            commission_niveau2 = 700

            parrain2.solde_revenu = (parrain2.solde_revenu or 0) + commission_niveau2
            parrain2.solde_parrainage = (parrain2.solde_parrainage or 0) + commission_niveau2
            parrain2.commission_total = (parrain2.commission_total or 0) + commission_niveau2

            db.session.commit()

            # --- NIVEAU 3 ---
            if parrain2.parrain:
                parrain3 = User.query.filter_by(username=parrain2.parrain).first()
                if parrain3:
                    commission_niveau3 = 300

                    parrain3.solde_revenu = (parrain3.solde_revenu or 0) + commission_niveau3
                    parrain3.solde_parrainage = (parrain3.solde_parrainage or 0) + commission_niveau3
                    parrain3.commission_total = (parrain3.commission_total or 0) + commission_niveau3

                    db.session.commit()
# -----------------------
# Traductions
# -----------------------
# Traductions


# -----------------------
# Décorateur login
# -----------------------
# -----------------------
# Traductions
# -----------------------
def t(key):
    lang = session.get("lang", "fr")
    return TRANSLATIONS.get(lang, TRANSLATIONS["fr"]).get(key, key)

# enregistrer la fonction dans Jinja2
app.jinja_env.globals.update(t=t)


# -----------------------
# Utilisateur connecté
# -----------------------
def get_logged_in_user():
    """Retourne l'utilisateur connecté via user_id en session."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    # db.session.get est compatible SQLAlchemy 2.0
    return db.session.get(User, user_id)


# -----------------------
# Décorateur login
# -----------------------
def login_required(f):
    """Protège une route, redirige vers la page de connexion si non connecté."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not get_logged_in_user():
            return redirect(url_for("connexion_page"))
        return f(*args, **kwargs)
    return wrapper


def calculer_montant_points(user):
    total_points = (
        (user.points or 0) +
        (user.points_video or 0) +
        (user.points_youtube or 0) +
        (user.points_tiktok or 0) +
        (user.points_instagram or 0) +
        (user.points_ads or 0) +
        (user.points_spin or 0) +
        (user.points_games or 0)
    )
    tranches = total_points // 100
    montant_xof = tranches * 500
    points_utilisables = tranches * 100  # points qui peuvent être retirés
    return montant_xof, points_utilisables
# -----------------------
# Vérification des investissements
# -----------------------



@app.cli.command("init-db")
def init_db():
    db.create_all()
    print("✅ Base de données initialisée avec succès !")



@app.route("/inscription", methods=["GET", "POST"])
def inscription_page():
    ref_code = request.args.get("ref", "").strip().lower()
    session.pop('username_exists', None)

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        email = request.form.get("email", "").strip()
        country = request.form.get("country", "").strip()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "").strip()
        confirm = request.form.get("confirm_password", "").strip()
        parrain_code = (request.form.get("parrain", "") or ref_code).strip().lower()

        # 🔒 Vérifications
        if not all([username, email, country, phone, password, confirm]):
            flash("Tous les champs sont obligatoires.", "danger")
            return render_template("inscription.html", code_ref=ref_code)

        if not re.fullmatch(r"[a-z0-9]+", username):
            flash("Nom d'utilisateur invalide : lettres & chiffres uniquement.", "danger")
            return render_template("inscription.html", code_ref=ref_code)

        if password != confirm:
            flash("Les mots de passe ne correspondent pas.", "danger")
            return render_template("inscription.html", code_ref=ref_code)

        if User.query.filter_by(username=username).first():
            flash(f"Nom d'utilisateur '{username}' existe déjà, veuillez ajouter 3 chiffres.", "danger")
            session['username_exists'] = True
            return render_template("inscription.html", code_ref=ref_code)

        if User.query.filter_by(email=email).first():
            flash("Cet email est déjà utilisé.", "danger")
            return render_template("inscription.html", code_ref=ref_code)

        if User.query.filter_by(phone=phone).first():
            flash("Ce numéro est déjà enregistré.", "danger")
            return render_template("inscription.html", code_ref=ref_code)

        # 🔗 Parrainage
        parrain_user = None
        if parrain_code:
            parrain_user = User.query.filter_by(username=parrain_code).first()
            if not parrain_user:
                flash("Code parrain invalide.", "danger")
                return render_template("inscription.html", code_ref=ref_code)

        try:
            new_user = User(
                uid=str(uuid.uuid4()),
                username=username,
                email=email,
                phone=phone,
                country=country,
                password=generate_password_hash(password),
                parrain=parrain_user.username if parrain_user else None,
                solde_total=0,
                solde_depot=0,
                solde_revenu=0,
                solde_parrainage=0,
                date_creation=datetime.now(timezone.utc)
            )

            db.session.add(new_user)
            db.session.commit()

            # ✅ CONNEXION VIA SESSION (ancienne logique)
            session["user_id"] = new_user.id

            flash("Inscription réussie !", "success")
            return redirect(url_for("dashboard_bloque"))

        except Exception as e:
            db.session.rollback()
            flash("Erreur lors de l’inscription : " + str(e), "danger")
            return render_template("inscription.html", code_ref=ref_code)

    return render_template("inscription.html", code_ref=ref_code)

from flask import render_template



@app.route("/connexion", methods=["GET", "POST"])
def connexion_page():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "").strip()

        # Vérification des champs requis
        if not username or not password:
            flash("Veuillez remplir tous les champs.", "danger")
            return redirect(url_for("connexion_page"))

        # Récupérer l'utilisateur (username unique obligatoire)
        user = User.query.filter_by(username=username).first()

        # Vérification utilisateur + mot de passe
        if not user or not check_password_hash(user.password, password):
            flash("Identifiants incorrects.", "danger")
            return redirect(url_for("connexion_page"))

        # Vérification compte suspendu
        if getattr(user, "is_banned", False):
            flash("Votre compte a été suspendu. Contactez le support.", "danger")
            return redirect(url_for("connexion_page"))

        # Sécurisation de la session
        session.clear()
        session["user_id"] = user.id
        session["username"] = user.username
        session.permanent = True  # Pour éviter la déconnexion rapide

        flash(f"Connexion réussie ! Bienvenue {user.username}.", "success")
        return redirect(url_for("dashboard_page"))

    # Méthode GET : afficher la page de connexion
    return render_template("connexion.html")

SOLEAS_API_KEY = "SP_y7QKkaamPsVTlw8GDDGyzlJ7bmPUvdLorOQqWUXfRLI_AP"

SERVICES = {

    # 🇨🇲 CAMEROUN
    "CM": [
        {"id": 1, "name": "MOMO CM", "description": "MTN MOBILE MONEY CAMEROUN"},
        {"id": 2, "name": "OM CM", "description": "ORANGE MONEY CAMEROUN"},
    ],

    # 🇨🇮 CÔTE D’IVOIRE
    "CI": [
        {"id": 29, "name": "OM CI", "description": "ORANGE MONEY COTE D'IVOIRE"},
        {"id": 30, "name": "MOMO CI", "description": "MTN MONEY COTE D'IVOIRE"},
        {"id": 31, "name": "MOOV CI", "description": "MOOV COTE D'IVOIRE"},
        {"id": 32, "name": "WAVE CI", "description": "WAVE COTE D'IVOIRE"},
    ],

    # 🇧🇫 BURKINA FASO
    "BF": [
        {"id": 33, "name": "MOOV BF", "description": "MOOV BURKINA FASO"},
        {"id": 34, "name": "OM BF", "description": "ORANGE MONEY BURKINA FASO"},
    ],

    # 🇧🇯 BENIN
    "BJ": [
        {"id": 35, "name": "MOMO BJ", "description": "MTN MONEY BENIN"},
        {"id": 36, "name": "MOOV BJ", "description": "MOOV BENIN"},
    ],

    # 🇹🇬 TOGO
    "TG": [
        {"id": 37, "name": "T-MONEY TG", "description": "T-MONEY TOGO"},
        {"id": 38, "name": "MOOV TG", "description": "MOOV TOGO"},
    ],

    # 🇨🇩 CONGO DRC
    "COD": [
        {"id": 52, "name": "VODACOM COD", "description": "VODACOM CONGO DRC"},
        {"id": 53, "name": "AIRTEL COD", "description": "AIRTEL CONGO DRC"},
        {"id": 54, "name": "ORANGE COD", "description": "ORANGE CONGO DRC"},
    ],

    # 🇨🇬 CONGO BRAZZAVILLE
    "COG": [
        {"id": 55, "name": "AIRTEL COG", "description": "AIRTEL CONGO"},
        {"id": 56, "name": "MOMO COG", "description": "MTN MOMO CONGO"},
    ],

    # 🇬🇦 GABON
    "GAB": [
        {"id": 57, "name": "AIRTEL GAB", "description": "AIRTEL GABON"},
    ],

    # 🇺🇬 UGANDA
    "UGA": [
        {"id": 58, "name": "AIRTEL UGA", "description": "AIRTEL UGANDA"},
        {"id": 59, "name": "MOMO UGA", "description": "MTN MOMO UGANDA"},
    ],
}

COUNTRY_CODE = {
    # Cameroun
    "Cameroun": "CM",
    "Cameroon": "CM",

    # Côte d'Ivoire
    "Côte d'Ivoire": "CI",
    "Cote d Ivoire": "CI",
    "Ivory Coast": "CI",

    # Burkina Faso
    "Burkina Faso": "BF",

    # Bénin
    "Bénin": "BJ",
    "Benin": "BJ",

    # Togo
    "Togo": "TG",

    # Congo DRC
    "Congo DRC": "COD",
    "RDC": "COD",
    "République Démocratique du Congo": "COD",

    # Congo Brazzaville
    "Congo": "COG",
    "Congo Brazzaville": "COG",

    # Gabon
    "Gabon": "GAB",

    # Uganda
    "Uganda": "UGA",
}


def get_soleaspay_services():
    return SOLEASPAY_SERVICES_JSON

@app.route("/dashboard_bloque", methods=["GET", "POST"])
def dashboard_bloque():
    user = get_logged_in_user()

    if user_is_activated(user):
        return redirect(url_for("dashboard_page"))

    # Simule un dépôt pending
    pending_depot = None
    user_has_pending_depot = bool(pending_depot)

    # Récupération du code pays
    country_code = COUNTRY_CODE.get(user.country.strip())
    if not country_code:
        flash("Pays non supporté.", "danger")
        return redirect(url_for("dashboard_page"))

    # =========================
    # POST : paiement
    # =========================
    if request.method == "POST":
        operator_name = request.form.get("operator")
        amount = request.form.get("montant", type=int)
        fullname = request.form.get("fullname")
        phone = request.form.get("phone")  # ✅ numéro modifiable

        # 🔒 Vérifications
        if not operator_name or not amount or not fullname or not phone:
            flash("Tous les champs sont requis.", "danger")
            return redirect(url_for("dashboard_bloque"))

        if amount != 3800:
            flash("Le montant d'activation est exactement 3800 FCFA.", "danger")
            return redirect(url_for("dashboard_bloque"))

        # 🔒 Nettoyage numéro
        phone = phone.replace(" ", "").replace("-", "")

        if not phone.isdigit() or len(phone) < 8:
            flash("Numéro de paiement invalide.", "danger")
            return redirect(url_for("dashboard_bloque"))

        # 🔹 Recherche du service SoleasPay
        service = next(
            (s for s in SERVICES[country_code] if s["name"] == operator_name),
            None
        )

        if not service:
            flash("Opérateur non supporté pour votre pays.", "danger")
            return redirect(url_for("dashboard_bloque"))

        # 🔹 Création du dépôt AVANT paiement avec toutes les infos obligatoires
        new_depot = Depot(
            user_name=user.username,
            phone=phone,
            operator=operator_name,  # ✅ maintenant obligatoire
            country=country_code,    # ✅ maintenant obligatoire
            montant=amount,
            statut="en_attente",
            email=user.email
        )
        db.session.add(new_depot)
        db.session.commit()

        # 🔹 Payload SoleasPay avec DEPOT_ID
        payload = {
            "wallet": phone,  # ✅ NUMÉRO SAISI PAR L’UTILISATEUR
            "amount": amount,
            "currency": "XOF",
            "order_id": f"ORD-{new_depot.id}",
            "description": f"Activation {user.username} DEPOT_ID={new_depot.id}",
            "payer": fullname,
            "payerEmail": user.email,
            "successUrl": "https://lumina-stars.com/paiement/soleaspay/retour?status=success",
            "failureUrl": "https://lumina-stars.com/dashboard_bloque"
        }

        headers = {
            "x-api-key": SOLEAS_API_KEY,
            "operation": "2",
            "service": str(service["id"]),
            "Content-Type": "application/json"
        }

        try:
            response = requests.post(
                "https://soleaspay.com/api/agent/bills/v3",
                headers=headers,
                json=payload,
                timeout=30
            )
            result = response.json()
        except Exception as e:
            flash(f"Erreur de connexion au serveur de paiement : {e}", "danger")
            return redirect(url_for("dashboard_bloque"))

        if not result.get("success"):
            flash(result.get("message", "Erreur paiement"), "danger")
            return redirect(url_for("dashboard_bloque"))

        flash("Veuillez confirmer le paiement sur votre téléphone.", "info")
        return redirect(url_for("dashboard_bloque"))

    # =========================
    # GET : affichage page
    # =========================
    return render_template(
        "dashboard_bloque.html",
        user=user,
        user_has_pending_depot=user_has_pending_depot,
        services_by_country=SERVICES,
        country_code=country_code
    )

@app.route("/verify", methods=["GET"])
def verify_payment():
    order_id = request.args.get("orderId")
    pay_id = request.args.get("payId")
    headers = {
        "x-api-key": API_KEY
    }
    url = f"https://soleaspay.com/api/agent/verif-pay?orderId={order_id}&payId={pay_id}"
    response = requests.get(url, headers=headers)
    return jsonify(response.json())



@app.route("/logout")
def logout_page():
    session.clear()
    flash("Déconnexion effectuée.", "info")
    return redirect(url_for("connexion_page"))


def get_global_stats():
    total_users = db.session.query(func.count(User.id)).scalar() or 0
    total_deposits = db.session.query(func.sum(Depot.montant)).filter(Depot.statut=="valide").scalar() or 0
    total_withdrawn = db.session.query(func.sum(User.total_retrait)).scalar() or 0  # ← On utilise maintenant total_retrait
    return total_users, total_deposits, total_withdrawn


# --------------------------------------
# 1️⃣ Page dashboard_bloque (initiation paiement)
# --------------------------------------
from urllib.parse import urlencode

@app.route("/api/webhook/soleaspay", methods=["POST"])
def webhook_soleaspay():
    data = request.get_json()

    status = data.get("status")
    success = data.get("success")
    reference = data.get("reference")
    amount = float(data.get("amount", 0))
    description = data.get("description", "")

    # 🔍 Extraire DEPOT_ID
    depot_id = None
    if "DEPOT_ID=" in description:
        try:
            depot_id = int(description.split("DEPOT_ID=")[1])
        except ValueError:
            return jsonify({"error": "DEPOT_ID invalide"}), 400

    if not depot_id:
        return jsonify({"error": "DEPOT_ID manquant"}), 400

    depot = Depot.query.get(depot_id)
    if not depot:
        return jsonify({"error": "Depot introuvable"}), 404

    # 🔐 Anti double validation
    if depot.statut == "valide":
        return jsonify({"received": True, "message": "Déjà validé"}), 200

    if success is True and status == "SUCCESS":

        if depot.montant != amount:
            return jsonify({"error": "Montant incorrect"}), 400

        user = User.query.filter_by(username=depot.user_name).first()
        if not user:
            return jsonify({"error": "Utilisateur introuvable"}), 404

        # ✅ Validation du dépôt
        depot.statut = "valide"
        depot.reference = reference

        # 🔹 Mise à jour des soldes
        user.solde_depot += depot.montant
        user.solde_total += depot.montant

        # 🔑 Activation du compte si pas déjà actif
        if not user.is_active:
            user.is_active = True
            user.premier_depot = True

            # 🎁 Commission UNIQUE au parrain
            if user.parrain:
                donner_commission(user.parrain, depot.montant)

        db.session.commit()

        return jsonify({
            "received": True,
            "message": "Compte activé et dépôt validé"
        }), 200

    # Cas paiement échoué ou autre status
    return jsonify({"received": True, "message": "Paiement non validé"}), 200

@app.route("/paiement/soleaspay/retour")
def bkapay_retour():
    status = request.args.get("status")

    # 🔐 Récupération de l'utilisateur connecté
    user = get_logged_in_user()  # Assure-toi que cette fonction retourne l'utilisateur connecté

    if status == "success":
        flash("Paiement reçu ! Votre compte sera activé automatiquement.", "success")

        # ✅ Donner la commission si l'utilisateur a un parrain
        if user.parrain:
            donner_commission(user.parrain, 0)  # Le montant n'a plus d'importance

        db.session.commit()
        return redirect(url_for("dashboard_pay_ok"))

    # Paiement échoué ou annulé
    flash("Paiement échoué ou annulé.", "danger")
    return redirect(url_for("dashboard_bloque"))

@app.route("/dashboard/pay/ok", methods=["GET"])
def dashboard_pay_ok():
    user_id = session.get("user_id")
    if not user_id:
        flash("Vous devez vous connecter pour accéder au dashboard.", "danger")
        return redirect(url_for("connexion_page"))

    user = db.session.get(User, user_id)
    if not user:
        session.clear()
        flash("Session invalide, veuillez vous reconnecter.", "danger")
        return redirect(url_for("connexion_page"))

    # ✅ MARQUER DÉFINITIVEMENT L'ACCÈS PAY OK
    if not user.has_seen_pay_ok:
        user.has_seen_pay_ok = True
        db.session.commit()

    # 🔗 Lien de parrainage
    referral_code = user.username
    referral_link = url_for("inscription_page", _external=True) + f"?ref={referral_code}"

    # 📊 Stats globales
    total_users, total_deposits, total_withdrawn = get_global_stats()
    revenu_cumule = (user.solde_parrainage or 0) + (user.solde_revenu or 0)

    return render_template(
        "dashboard.html",
        user=user,
        points=user.points or 0,
        revenu_cumule=revenu_cumule,
        solde_parrainage=user.solde_parrainage or 0,
        solde_revenu=user.solde_revenu or 0,
        total_users=total_users,
        total_deposits=total_deposits,
        total_withdrawn=total_withdrawn,
        total_withdrawn_user=getattr(user, "total_retrait", 0),
        referral_code=referral_code,
        referral_link=referral_link
    )



@app.route("/api/check-activation")
def api_check_activation():
    user = get_logged_in_user()
    return {
        "activated": user_is_activated(user)
    }

@app.route("/chaine")
def whatsapp_channel():
    return render_template("chaine.html")


@app.route("/dashboard")
def dashboard_page():
    user_id = session.get("user_id")
    if not user_id:
        flash("Vous devez vous connecter pour accéder au dashboard.", "danger")
        return redirect(url_for("connexion_page"))

    user = db.session.get(User, user_id)
    if not user:
        session.clear()
        flash("Session invalide, veuillez vous reconnecter.", "danger")
        return redirect(url_for("connexion_page"))

    # 🔗 Lien de parrainage
    referral_code = user.username
    referral_link = url_for("inscription_page", _external=True) + f"?ref={referral_code}"

    # 🔒 Bloqué SEULEMENT si :
    # - pas activé
    # - ET n'a jamais visité dashboard_pay_ok
    if not user_is_activated(user) and not user.has_seen_pay_ok:
        return redirect(url_for("dashboard_bloque"))

    # 📊 Stats globales
    total_users, total_deposits, total_withdrawn = get_global_stats()
    revenu_cumule = (user.solde_parrainage or 0) + (user.solde_revenu or 0)

    return render_template(
        "dashboard.html",
        user=user,
        points=user.points or 0,
        revenu_cumule=revenu_cumule,
        solde_parrainage=user.solde_parrainage or 0,
        solde_revenu=user.solde_revenu or 0,
        total_users=total_users,
        total_withdrawn_user=user.total_retrait or 0,
        total_deposits=total_deposits,
        referral_code=referral_code,
        referral_link=referral_link,
        total_withdrawn=total_withdrawn
    )

def user_is_activated(user):
    if user.premier_depot:
        return True

    return Depot.query.filter_by(
        user_name=user.username,
        statut="valide"
    ).first() is not None

# ===== Décorateur admin =====
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not getattr(current_user, "is_admin", False):
            abort(403)
        return f(*args, **kwargs)
    return decorated

@app.route("/admin/users")
def admin_users():
    user = get_logged_in_admin()

    if not user:
        flash("Accès refusé.", "danger")
        return redirect(url_for("admin_finance"))

    users = User.query.order_by(User.date_creation.desc()).all()

    user_data = []
    for u in users:
        niveau1 = u.downlines.count()
        niveau2 = sum([child.downlines.count() for child in u.downlines])
        niveau3 = sum([sum([c.downlines.count() for c in child.downlines]) for child in u.downlines])

        user_data.append({
            "username": u.username,
            "email": u.email,
            "phone": u.phone,
            "parrain": u.parrain if u.parrain else "—",
            "niveau1": niveau1,
            "niveau2": niveau2,
            "niveau3": niveau3,
            "date_creation": u.date_creation,
            "premier_depot": u.premier_depot
        })

    return render_template("admin_users.html", user=user, users=user_data)

@app.route("/admin/users/inactifs")
def admin_users_inactifs():
    user = get_logged_in_admin()

    if not user:
        flash("Accès refusé.", "danger")
        return redirect(url_for("admin_finance"))

    inactifs = User.query.filter_by(premier_depot=False).order_by(User.date_creation.desc()).all()

    return render_template(
        "admin_users_inactifs.html",
        user=user,
        inactifs=inactifs,
        total_inactifs=len(inactifs)
    )

@app.route("/admin/users/actifs")
def admin_users_actifs():
    user = get_logged_in_admin()

    if not user:
        flash("Accès refusé.", "danger")
        return redirect(url_for("admin_finance"))

    actifs = User.query.filter_by(premier_depot=True).order_by(User.date_creation.desc()).all()

    return render_template(
        "admin_users_actifs.html",
        user=user,
        actifs=actifs,
        total_actifs=len(actifs)
    )

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        # Vérifie l'utilisateur admin
        user = User.query.filter_by(username=username, is_admin=True).first()
        if user and check_password_hash(user.password, password):
            session["admin_id"] = user.id
            return redirect(url_for("admin_parrainage"))
        else:
            flash("Nom d'utilisateur ou mot de passe incorrect.", "danger")
            return redirect(url_for("admin_login"))
    return render_template("admin_login.html")

@app.route("/admin/parrainage", methods=["GET", "POST"])
def admin_parrainage():
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))

    users = User.query.all()

    if request.method == "POST":
        user_id = request.form.get("user_id")
        nouveau_parrain = (request.form.get("parrain") or "").strip().lower()
        nouveau_phone = (request.form.get("phone") or "").strip()

        user = User.query.get(user_id)

        if not user:
            flash("Utilisateur introuvable.", "danger")
            return redirect(url_for("admin_parrainage"))

        # ✅ Modifier le phone (avec vérification unicité)
        if nouveau_phone and nouveau_phone != user.phone:
            phone_existe = User.query.filter(User.phone == nouveau_phone, User.id != user.id).first()
            if phone_existe:
                flash(f"Le numéro '{nouveau_phone}' est déjà utilisé par un autre utilisateur.", "danger")
                return redirect(url_for("admin_parrainage"))
            user.phone = nouveau_phone

        # ✅ Modifier le parrain (optionnel)
        # Si champ vide => on enlève le parrain
        if nouveau_parrain == "":
            user.parrain = None
        else:
            # Vérifier que le parrain existe
            parrain_user = User.query.filter_by(username=nouveau_parrain).first()
            if not parrain_user:
                flash("Parrain invalide : ce username n'existe pas.", "danger")
                return redirect(url_for("admin_parrainage"))

            # éviter parrainage sur soi-même
            if nouveau_parrain == user.username:
                flash("Un utilisateur ne peut pas être son propre parrain.", "danger")
                return redirect(url_for("admin_parrainage"))

            user.parrain = nouveau_parrain

        db.session.commit()
        flash(f"✅ Mise à jour effectuée pour {user.username}.", "success")
        return redirect(url_for("admin_parrainage"))

    return render_template("admin_parrainage.html", users=users)

# ===== Helpers =====
def get_logged_in_user_phone():
    return session.get("phone")

from flask import send_from_directory

@app.route('/download/contact')
def download_contact():
    return send_from_directory('static/files', 'con.vcf', as_attachment=True)

from flask import Flask, render_template


# Route pour la page About
@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/mes-retraits")
def mes_retraits():
    user = get_logged_in_user()
    retraits = Retrait.query.filter_by(phone=user.phone).order_by(Retrait.date.desc()).all()

    return render_template("mes_retraits.html", retraits=retraits, user=user)


from datetime import datetime

from datetime import date

@app.route("/taches/click-jeudi", methods=["GET", "POST"])
def click_jeudi():
    user = get_logged_in_user()

    # Vérifier si c'est jeudi
    if date.today().weekday() != 3:  # 0 = lundi, 3 = jeudi
        return render_template("pas_jeudi.html", user=user)

    # Vérifier si l'utilisateur a déjà fait le click cette semaine
    debut_semaine = date.today() - timedelta(days=date.today().weekday())  # lundi de cette semaine
    deja_fait = ClickJeudiReponse.query.filter(
        ClickJeudiReponse.user_id == user.id,
        ClickJeudiReponse.date >= debut_semaine
    ).first()

    if deja_fait:
        return render_template("deja_click.html", user=user)

    if request.method == "POST":
        points = 20
        user.points = user.points or 0  # corrige le None
        user.points += points
        db.session.commit()

        # Enregistrer la tentative
        click_reponse = ClickJeudiReponse(user_id=user.id, points=points, date=date.today())
        db.session.add(click_reponse)
        db.session.commit()

        return render_template("resultat_click.html", points=points, user=user)

    return render_template("click_jeudi.html", user=user)


@app.route("/whatsapp-number", methods=["POST"])
def whatsapp_number():
    user = User.query.get(session["user_id"])

    number = request.form.get("number").strip()

    if not number.startswith("+") or not number[1:].isdigit() or len(number) < 10:
        flash("Numéro invalide !", "error")
        return redirect("/dashboard")

    user.whatsapp_number = number
    db.session.commit()

    vcf_path = os.path.join("static", "files", "con.vcf")

    try:
        with open(vcf_path, "a", encoding="utf-8") as file:
            file.write(
                f"BEGIN:VCARD\n"
                f"VERSION:3.0\n"
                f"N:{user.username}\n"
                f"TEL:{number}\n"
                f"END:VCARD\n\n"
            )
    except Exception as e:
        print("Erreur VCF :", e)

    return redirect("/dashboard")

@app.route("/apk")
def apk_page():
    """
    Retourne la liste des APK disponibles via liens Google Drive.
    """
    apk_files = [
        {
            "name": "Netflix",
            "filename": "Netflix.apk",
            "link": "https://drive.google.com/file/d/1afSa24_oVoTWRCgpO07Lbu4qjKMUhwLC/view?usp=drivesdk"
        },
        {
            "name": "Chat",
            "filename": "chat.apk",
            "link": "https://drive.google.com/file/d/1-4idwrgNxjNilpLzR8zHkdMroVo41g9b/view?usp=drivesdk"
        },
        {
            "name": "CapCut",
            "filename": "capcut.apk",
            "link": "https://drive.google.com/file/d/1hwEzqwQWV2FKnTg1u0QAWrPjjOEyZCyj/view?usp=drivesdk"
        }
    ]

    return render_template("apk.html", apk_files=apk_files)

@app.route("/ecom")
def ecom():
    return render_template("ecom.html")



@app.route("/nous")
def nous_page():
    return render_template("nous.html")

@app.route("/trade")
def trade():
    return render_template("trade.html")

from flask import send_from_directory

@app.route("/sitemap.xml")
def sitemap():
    return send_from_directory(".", "sitemap.xml")

from flask import request, redirect, url_for, flash
import os
from werkzeug.utils import secure_filename
from datetime import datetime

@app.route("/profile", methods=["GET", "POST"])
def profile_page():
    user = get_logged_in_user()

    # Gestion du upload de photo
    if request.method == "POST":
        if 'profile_photo' in request.files:
            file = request.files['profile_photo']
            if file.filename == '':
                flash("Aucun fichier sélectionné.", "warning")
            elif allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Ajouter l'UID pour éviter conflits
                filename = f"{user.uid}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER_PROFILE'], filename)
                file.save(filepath)
                user.profile_image = filename
                db.session.commit()
                flash("Photo de profil mise à jour avec succès !", "success")
            else:
                flash("Format de fichier non autorisé.", "danger")
        return redirect(url_for("profile_page"))

    # Photo par défaut si l'utilisateur n'a pas uploadé
    profile_pic = user.profile_image if getattr(user, 'profile_image', None) else 'default.png'

    # ✅ Calcul du total de la team
    team_total = get_team_total(user)

    return render_template(
        "profile.html",
        user=user,
        profile_pic=profile_pic,
        team_total=team_total
    )

@app.route("/retrait", methods=["GET", "POST"])
def retrait_page():
    user = get_logged_in_user()

    MIN_RETRAIT = 4000
    FRAIS = 500

    # Stats pour le template : afficher le solde parrainage
    stats = {
        "commissions_total": float(user.solde_parrainage or 0)
    }

    if request.method == "POST":
        montant = float(request.form.get("montant", 0))
        payment_method = request.form.get("payment_method")

        # Vérification du montant
        if montant <= 0:
            flash("Veuillez saisir un montant valide.", "danger")
            return redirect(url_for("retrait_page"))

        if montant < MIN_RETRAIT:
            flash(f"Le montant minimum de retrait est de {MIN_RETRAIT} XOF.", "danger")
            return redirect(url_for("retrait_page"))

        # Montant total incluant les frais
        montant_total = montant + FRAIS

        # Vérifier que le solde parrainage est suffisant
        if montant_total > stats["commissions_total"]:
            flash("Solde parrainage insuffisant pour ce retrait + les frais.", "danger")
            return redirect(url_for("retrait_page"))

        # Enregistrer la demande
        nouveau_retrait = Retrait(
            montant=montant,
            frais=FRAIS,
            payment_method=payment_method,
            statut="en_attente",
            phone=user.phone,
            pays=user.country
        )
        db.session.add(nouveau_retrait)

        # Déduire du solde parrainage (commission)
        user.solde_parrainage -= montant_total

        db.session.commit()

        flash(f"Votre demande de {montant} XOF a été soumise avec succès. Frais appliqués : {FRAIS} XOF.", "success")
        return redirect(url_for("dashboard_page"))

    # Passer stats au template
    return render_template("retrait.html", user=user, stats=stats)

def get_team_total(user):
    # Niveau 1 : filleuls directs
    niveau1 = User.query.filter_by(parrain=user.username).all()
    total = len(niveau1)
    niveau2, niveau3 = [], []

    # Niveau 2 : filleuls des filleuls
    for u1 in niveau1:
        f2 = User.query.filter_by(parrain=u1.username).all()  # 👈 username au lieu de uid
        total += len(f2)
        niveau2.extend(f2)

    # Niveau 3 : filleuls du niveau 2
    for u2 in niveau2:
        f3 = User.query.filter_by(parrain=u2.username).all()  # 👈 username au lieu de uid
        total += len(f3)
        niveau3.extend(f3)

    return total

@app.route("/revenus")
def revenus_page():
    user = get_logged_in_user()

    total_points = sum([
        user.points_youtube or 0,
        user.points_tiktok or 0,
        user.points_instagram or 0,
        user.points_ads or 0,
        user.points_spin or 0,
        user.points_games or 0,
    ])

    team_total = get_team_total(user)
    total_commission = user.solde_revenu or 0

    return render_template(
        "revenus.html",
        user=user,
        points_youtube=user.points_youtube,
        points_tiktok=user.points_tiktok,
        points_instagram=user.points_instagram,
        points_ads=user.points_ads,
        points_spin=user.points_spin,
        points_games=user.points_games,
        team_total=team_total,
        total_commission=total_commission
    )

@app.route("/points/retrait", methods=["GET", "POST"])
def retrait_points_page():
    user = get_logged_in_user()

    # Calculer le montant des points disponibles
    total_points = (
        (user.points or 0) +
        (user.points_video or 0) +
        (user.points_youtube or 0) +
        (user.points_tiktok or 0) +
        (user.points_instagram or 0) +
        (user.points_ads or 0) +
        (user.points_spin or 0) +
        (user.points_games or 0)
    )
    tranches = total_points // 100
    montant_xof = tranches * 500
    points_utilisables = tranches * 100
    retrait_min = 3500

    if request.method == "POST":
        if montant_xof < retrait_min:
            flash(f"Le montant minimum pour un retrait est de {retrait_min} XOF.", "danger")
            return redirect(url_for("retrait_points_page"))

        payment_method = request.form.get("payment_method")
        if not payment_method:
            flash("Veuillez sélectionner un mode de paiement.", "danger")
            return redirect(url_for("retrait_points_page"))

        # Créer la demande de retrait (à traiter par admin si nécessaire)
        retrait = RetraitPoints(
            user_id=user.id,
            points_utilises=points_utilisables,
            montant_xof=montant_xof,
            statut='en_attente'
        )
        db.session.add(retrait)

        # Déduire les points utilisés
        user.points = total_points - points_utilisables
        db.session.commit()

        flash(f"Votre demande de retrait de {montant_xof} XOF a été enregistrée.", "success")
        return redirect(url_for("retrait_points_page"))

    return render_template(
        "retrait_points.html",
        user=user,
        montant_xof=montant_xof,
        points_utilisables=points_utilisables,
        retrait_min=retrait_min
    )

@app.route("/wheel")
def wheel():
    user = get_logged_in_user()

    # Vérifier si l’utilisateur a déjà tourné la roue
    if user.has_spun_wheel:
        already_spun = True
    else:
        already_spun = False

    return render_template("wheel.html", user=user, already_spun=already_spun)

import random

@app.route("/wheel/spin", methods=["POST"])
def spin_wheel():
    user = get_logged_in_user()

    # Si déjà tourné → refus
    if user.has_spun_wheel:
        return jsonify({"status": "error", "message": "Vous avez déjà utilisé votre chance !"})

    import random

    values = [0, 50, 80, 130, 150, 180, 200, 220, 250, 300, 340, 460]

    # Génération pondérée (rare, commun)
    weighted = []
    for v in values:
        if v in [250, 300, 340, 460]:
            weighted += [v] * 1
        elif v >= 200:
            weighted += [v] * 3
        else:
            weighted += [v] * 10

    reward = random.choice(weighted)

    # Enregistrer que le joueur a déjà joué
    user.has_spun_wheel = True
    user.solde_revenu += reward
    db.session.commit()

    return jsonify({"status": "success", "reward": reward})

@app.route("/team")
def team_page():
    user = get_logged_in_user()

    # 🔗 lien de parrainage basé sur username
    referral_code = user.username
    referral_link = url_for("inscription_page", _external=True) + f"?ref={referral_code}"

    # 🔍 Niveaux basés sur username
    level1 = User.query.filter_by(parrain=user.username).all()
    level1_usernames = [u.username for u in level1]

    level2 = User.query.filter(User.parrain.in_(level1_usernames)).all() if level1_usernames else []
    level2_usernames = [u.username for u in level2]

    level3 = User.query.filter(User.parrain.in_(level2_usernames)).all() if level2_usernames else []

    stats = {
        "level1": len(level1),
        "level2": len(level2),
        "level3": len(level3),
        "commissions_total": float(user.solde_revenu or 0)
    }

    return render_template(
        "team.html",
        referral_code=referral_code,
        referral_link=referral_link,
        stats=stats,
        level1_users=level1,
        level2_users=level2,
        level3_users=level3
    )

# ===== Page de connexion admin =====
@app.route("/admin/finance", methods=["GET", "POST"])
def admin_finance():
    submitted = False  # Sert à afficher le loader
    if request.method == "POST":
        submitted = True
        username = request.form.get("username")
        password = request.form.get("password")

        # Vérifie l'utilisateur admin
        user = User.query.filter_by(username=username, is_admin=True).first()
        if user and check_password_hash(user.password, password):
            session["admin_id"] = user.id  # Stocke l'id de l'admin
            # Redirection vers admin_deposits après connexion
            return redirect(url_for("admin_deposits"))
        else:
            flash("Nom d'utilisateur ou mot de passe incorrect.", "danger")
            # Reste sur la page avec le message flash
            return render_template("admin_finance.html", submitted=False)

    # GET → formulaire normal
    return render_template("admin_finance.html", submitted=submitted)

# ===== Détection de l'admin connecté =====
def get_logged_in_admin():
    admin_id = session.get("admin_id")
    if admin_id:
        return User.query.filter_by(id=admin_id, is_admin=True).first()
    return None

from flask import request, render_template, flash, redirect, url_for

PER_PAGE = 50


from sqlalchemy import func

@app.route("/admin/deposits")
def admin_deposits():
    user = get_logged_in_admin()
    if not user:
        flash("Accès refusé.", "danger")
        return redirect(url_for("admin_finance"))

    page = request.args.get("page", 1, type=int)

    # ==========================
    # ===== UTILISATEURS (LIGHT)
    # ==========================
    users_query = User.query.order_by(User.date_creation.desc())
    users_paginated = users_query.paginate(page=page, per_page=PER_PAGE, error_out=False)

    users_data = []
    for u in users_paginated.items:
        users_data.append({
            "username": u.username,
            "email": u.email,
            "phone": u.phone,
            "parrain": u.parrain if u.parrain else "—",
            "niveau1": "-",
            "niveau2": "-",
            "niveau3": "-",
            "date_creation": u.date_creation,
            "premier_depot": bool(u.premier_depot)
        })

    actifs = [u for u in users_data if u["premier_depot"]]
    inactifs = [u for u in users_data if not u["premier_depot"]]

    total_actifs = User.query.filter(User.premier_depot == True).count()
    total_inactifs = User.query.filter(User.premier_depot == False).count()

    # ==========================
    # ===== DEPOTS (INCHANGÉ)
    # ==========================
    subquery = (
        db.session.query(func.max(Depot.id).label("last_id"))
        .join(User, Depot.user_name == User.username)
        .filter(Depot.statut == "en_attente", User.premier_depot == False)
        .group_by(Depot.phone)
        .subquery()
    )

    depots = (
        Depot.query
        .filter(Depot.id.in_(db.session.query(subquery.c.last_id)))
        .join(User, Depot.user_name == User.username)
        .order_by(User.username.asc(), Depot.date.desc())
        .all()
    )

    # (optionnel mais safe)
    for d in depots:
        d.username_display = d.user_name or d.phone

    # ==========================
    # ===== RETRAITS (FIX FINAL)
    # ==========================
    retraits_query = (
        db.session.query(Retrait, User.username)
        .join(User, Retrait.phone == User.phone)
        .filter(Retrait.statut == "en_attente")
        .order_by(Retrait.date.desc())
    )

    retraits_paginated = retraits_query.paginate(
        page=page,
        per_page=PER_PAGE,
        error_out=False
    )

    # ✅ On renvoie UNIQUEMENT des objets Retrait au template
    retraits = []
    for retrait, username in retraits_paginated.items:
        retrait.username_display = username  # 👈 affichable dans Jinja
        retraits.append(retrait)

    return render_template(
        "admin_deposits.html",
        user=user,
        users=users_data,
        depots=depots,
        retraits=retraits,
        actifs=actifs,
        inactifs=inactifs,
        total_actifs=total_actifs,
        total_inactifs=total_inactifs,
        users_paginated=users_paginated,
        retraits_paginated=retraits_paginated
    )

@app.route("/admin/deposits/valider/<int:depot_id>")
def valider_depot(depot_id):

    depot = Depot.query.get_or_404(depot_id)

    # User concerné par le dépôt via username
    user = User.query.filter_by(username=depot.user_name).first()

    if not user:
        flash("Utilisateur introuvable.", "danger")
        return redirect(url_for("admin_deposits"))

    # Si déjà validé
    if depot.statut == "valide":
        flash("Ce dépôt est déjà validé.", "warning")
        return redirect(url_for("admin_deposits"))

    # Vérifier si l'utilisateur n'a jamais eu de dépôt validé avant
    premier_depot_valide = not Depot.query.filter_by(
        user_name=user.username,
        statut="valide"
    ).first()

    # Valider le dépôt
    depot.statut = "valide"

    # Créditer le compte
    user.solde_depot += depot.montant
    user.solde_total += depot.montant

    # Premier dépôt
    if premier_depot_valide:
        user.premier_depot = True

        # Commission parrain
        if user.parrain:
            donner_commission(user.parrain, depot.montant)

    db.session.commit()

    flash("Dépôt validé et crédité avec succès !", "success")
    return redirect(url_for("admin_deposits"))

@app.route("/admin/deposits/rejeter/<int:depot_id>")
def rejeter_depot(depot_id):
    user_admin = get_logged_in_user()

    depot = Depot.query.get_or_404(depot_id)

    if depot.statut in ["valide", "rejete"]:
        flash("Ce dépôt a déjà été traité.", "warning")
        return redirect(url_for("admin_deposits"))

    depot.statut = "rejete"
    db.session.commit()

    flash("Dépôt rejeté avec succès.", "danger")
    return redirect(url_for("admin_deposits"))

@app.route("/admin/retraits")
def admin_retraits():

    # Récupération avec join
    retraits_query = (
        db.session.query(Retrait, User.username)
        .join(User, User.phone == Retrait.phone)
        .filter(Retrait.statut == "en_attente")
        .order_by(Retrait.date.desc())
    )

    # Liste finale de retraits avec username_display
    retraits = []
    for retrait, username in retraits_query.all():
        retrait.username_display = username  # pour le template
        retraits.append(retrait)

    return render_template(
        "admin_retraits.html",
        retraits=retraits
    )

@app.route("/admin/retraits/valider/<int:retrait_id>")
def valider_retrait(retrait_id):
    user_admin = get_logged_in_user()

    retrait = Retrait.query.get_or_404(retrait_id)
    user = User.query.filter_by(phone=retrait.phone).first()

    if not user:
        flash("Utilisateur introuvable.", "danger")
        return redirect(url_for("admin_retraits"))

    if retrait.statut == "validé":
        flash("Ce retrait a déjà été validé.", "info")
        return redirect(url_for("admin_retraits"))

    retrait.statut = "validé"

    # Total retrait
    user.total_retrait += retrait.montant + (retrait.frais or 0)

    db.session.commit()

    flash("Retrait validé avec succès !", "success")
    return redirect(url_for("admin_retraits"))

@app.route("/admin/retraits/refuser/<int:retrait_id>")
def refuser_retrait(retrait_id):
    user_admin = get_logged_in_user()

    retrait = Retrait.query.get_or_404(retrait_id)
    user = User.query.filter_by(phone=retrait.phone).first()

    if not user:
        flash("Utilisateur introuvable.", "danger")
        return redirect(url_for("admin_retraits"))

    if retrait.statut == "refusé":
        flash("Ce retrait a déjà été refusé.", "info")
        return redirect(url_for("admin_retraits"))

    # Recréditer
    user.solde_parrainage += (retrait.montant + (retrait.frais or 0))
    retrait.statut = "refusé"

    db.session.commit()

    flash("Retrait refusé et montant recrédité à l’utilisateur.", "warning")
    return redirect(url_for("admin_retraits"))


@app.route("/taches/questions-lundi", methods=["GET", "POST"])
def questions_lundi():
    user = get_logged_in_user()  # récupère l'utilisateur connecté

    # Vérifier si aujourd'hui est lundi (0 = lundi)
    if date.today().weekday() != 0:
        return render_template("pas_lundi.html", user=user)

    # Vérifier si l'utilisateur a déjà participé aujourd'hui
    deja_fait = QuestionReponse.query.filter_by(
        user_id=user.id,
        date=date.today()
    ).first()

    if deja_fait:
        return render_template("deja_fait.html", user=user)

    # Sélectionner 5 questions aléatoires
    questions = Question.query.order_by(db.func.random()).limit(5).all()

    if request.method == "POST":
        score = 0
        for q in questions:
            user_answer = request.form.get(f"question_{q.id}", "").strip().lower()
            if user_answer == q.correct_answer.lower():
                score += 5  # Chaque question correcte = 5 points

        # Ajouter les points à l'utilisateur
        user.points += score
        db.session.commit()

        # Enregistrer la tentative dans QuestionReponse
        reponse = QuestionReponse(user_id=user.id, points=score, date=date.today())
        db.session.add(reponse)
        db.session.commit()

        # Préparer le message
        if score == 25:
            message = "Bravo ! Vous avez répondu correctement à toutes les questions et gagné 25 points !"
        else:
            message = f"Vous avez obtenu {score} points sur 25."

        return render_template("resultat_lundi.html", score=score, message=message, user=user)

    return render_template("questions_lundi.html", questions=questions, user=user)


@app.route("/admin/users/activer/<username>")
def admin_activer_user(username):
    admin = get_logged_in_admin()
    if not admin:
        flash("Accès refusé.", "danger")
        return redirect(url_for("admin_finance"))

    user = User.query.filter_by(username=username).first()
    if not user:
        flash("Utilisateur introuvable.", "danger")
        return redirect(url_for("admin_deposits"))

    if user.premier_depot:
        flash("Cet utilisateur est déjà actif.", "warning")
        return redirect(url_for("admin_deposits"))

    # 🔥 Montant d’activation (tu peux changer)
    montant_activation = 0

    # Activer user
    user.premier_depot = True

    # Si tu veux créditer aussi automatiquement
    if montant_activation > 0:
        user.solde_depot += montant_activation
        user.solde_total += montant_activation

        # Créer un dépôt validé (recommandé pour historique)
        depot = Depot(
            user_name=user.username,
            phone=user.phone,
            email=user.email,
            montant=montant_activation,
            statut="valide"
        )
        db.session.add(depot)

        # Commission parrain
        if user.parrain:
            donner_commission(user.parrain, montant_activation)

    db.session.commit()
    flash("Utilisateur activé avec succès !", "success")
    return redirect(url_for("admin_deposits"))


# 🟣 ROUTE TIKTOK

@app.route("/tiktok/complete")
def tiktok_complete():
    user = get_logged_in_user()

    today = datetime.today().weekday()  # mardi = 1
    current_date = datetime.today().strftime("%Y-%m-%d")

    if today != 1:
        return {"status": "error", "message": "La vidéo n’est disponible que le mardi."}

    if user.last_tiktok_date != current_date:
        user.points_tiktok += 20
        user.points_video += 20
        user.points += 20
        user.last_tiktok_date = current_date
        db.session.commit()
        return {"status": "ok", "message": "Points ajoutés"}

    return {"status": "done", "message": "Vous avez déjà obtenu vos points aujourd’hui."}


@app.route("/tiktok")
def tiktok_page():
    user = get_logged_in_user()
    today = datetime.today().weekday()  # mardi = 1
    current_date = datetime.today().strftime("%Y-%m-%d")

    return render_template(
        "tiktok.html",
        user=user,
        today=today,
        current_date=current_date
    )


@app.route("/youtube")
def youtube_page():
    user = get_logged_in_user()
    today = datetime.today().weekday()  # mercredi = 2
    current_date = datetime.today().strftime("%Y-%m-%d")

    return render_template(
        "youtube.html",
        user=user,
        today=today,
        current_date=current_date
    )

@app.route("/youtube/complete")
def youtube_complete():
    user = get_logged_in_user()
    today = datetime.today().weekday()  # mercredi = 2
    current_date = datetime.today().strftime("%Y-%m-%d")

    if today != 2:
        return jsonify({"status": "error", "message": "La vidéo n’est disponible que le mercredi."})

    if user.last_youtube_date != current_date:
        user.points_youtube += 20
        user.points += 20
        user.last_youtube_date = current_date
        db.session.commit()
        return jsonify({"status": "ok", "message": "Points ajoutés"})

    return jsonify({"status": "done", "message": "Vous avez déjà obtenu vos points aujourd’hui."})

# 🟢 ROUTE INSTAGRAM

@app.route("/instagram")
def instagram_page():
    user = get_logged_in_user()
    today = datetime.today().weekday()  # jeudi = 3
    current_date = datetime.today().strftime("%Y-%m-%d")

    return render_template(
        "instagram.html",
        user=user,
        today=today,
        current_date=current_date
    )

@app.route("/instagram/complete")
def instagram_complete():
    user = get_logged_in_user()
    today = datetime.today().weekday()  # jeudi = 3
    current_date = datetime.today().strftime("%Y-%m-%d")

    if today != 4:
        return jsonify({"status": "error", "message": "La vidéo n’est disponible que le jeudi."})

    if user.last_instagram_date != current_date:
        user.points_instagram += 20
        user.points += 20
        user.last_instagram_date = current_date
        db.session.commit()
        return jsonify({"status": "ok", "message": "Points ajoutés"})

    return jsonify({"status": "done", "message": "Vous avez déjà obtenu vos points aujourd’hui."})

@app.route("/health")
def health():
    return "OK", 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))  # Render fournit le PORT
    app.run(host="0.0.0.0", port=port, debug=False)
