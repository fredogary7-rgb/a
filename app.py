
import os
import re
import uuid
from datetime import datetime, timedelta, timezone, date
from functools import wraps
from urllib.parse import urlencode
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import create_engine
# ─── FLASK APP ───────────────────────────────────────────
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = "ma_cle_ultra_secrete"

# ─── ENV VARIABLES ───────────────────────────────────────
load_dotenv()
MONEYFUSION_API_KEY = os.getenv("MONEYFUSION_API_KEY")
MONEYFUSION_API_URL = os.getenv("MONEYFUSION_API_URL")

# ─── UPLOAD CONFIG ───────────────────────────────────────
# Dossiers pour les uploads
UPLOAD_FOLDER_PROFILE = 'static/uploads/profiles'
UPLOAD_FOLDER_VLOGS = 'static/vlogs'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Initialisation
os.makedirs(UPLOAD_FOLDER_PROFILE, exist_ok=True)
os.makedirs(UPLOAD_FOLDER_VLOGS, exist_ok=True)

# Configuration dans Flask
app.config['UPLOAD_FOLDER_PROFILE'] = UPLOAD_FOLDER_PROFILE
UPLOAD_FOLDER_APPS = "static/uploads/apps"
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
    pool_size=10,          # connexions actives
    max_overflow=20,       # connexions supplémentaires si surcharge
    pool_timeout=30,       # temps avant erreur
    pool_recycle=1800,     # recycle pour éviter les timeouts Neon
)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True,   # Vérifie si la connexion est encore vivante
    "pool_recycle": 280,     # Recycle la connexion avant expiration
    "pool_timeout": 20       # Timeout raisonnable
}

# ─── INITIALISATION DE LA BASE DE DONNÉES ───────────────
db = SQLAlchemy(app)

from sqlalchemy import text
from flask_migrate import Migrate

migrate = Migrate(app, db)

@app.cli.command("add-ref-col")
def add_reference_column():
    """
    Ajoute la colonne `reference` à la table depot si elle n'existe pas.
    Usage: flask --app app.py add-ref-col
    """
    with db.engine.connect() as conn:
        conn.execute(text("""
            ALTER TABLE depot
            ADD COLUMN IF NOT EXISTS reference VARCHAR(200);
        """))
        conn.commit()
    print("✅ Colonne 'reference' ajoutée si elle n'existait pas.")


class User(db.Model):
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
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(30))
    montant = db.Column(db.Float)
    statut = db.Column(db.String(20), default="en_attente")
    date = db.Column(db.DateTime, default=datetime.utcnow)
    payment_method = db.Column(db.String(50))

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
    """Crée la commission pour le parrain et remplit son solde_revenu selon le niveau."""
    if not parrain_username:
        return  # pas de parrain, rien à faire

    parrain = User.query.filter_by(username=parrain_username).first()
    if not parrain:
        return

    # Niveau 1
    commission_niveau1 = 1700
    parrain.solde_revenu = (parrain.solde_revenu or 0) + commission_niveau1

    db.session.commit()

    # 🔹 Vérifier le parrain du parrain (niveau 2)
    if parrain.parrain:
        parrain2 = User.query.filter_by(username=parrain.parrain).first()
        if parrain2:
            commission_niveau2 = 700
            parrain2.solde_revenu = (parrain2.solde_revenu or 0) + commission_niveau2
            db.session.commit()

            # 🔹 Vérifier le parrain du parrain du parrain (niveau 3)
            if parrain2.parrain:
                parrain3 = User.query.filter_by(username=parrain2.parrain).first()
                if parrain3:
                    commission_niveau3 = 300
                    parrain3.solde_revenu = (parrain3.solde_revenu or 0) + commission_niveau3
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

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        email = request.form.get("email", "").strip()
        country = request.form.get("country", "").strip()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "").strip()
        confirm = request.form.get("confirm_password", "").strip()

        # code parrain du formulaire OU URL
        parrain_code = (request.form.get("parrain", "") or ref_code).strip().lower()

        # 1️⃣ champs obligatoires
        if not all([username, email, country, phone, password, confirm]):
            flash("Tous les champs sont obligatoires.", "danger")
            return redirect(url_for("inscription_page", ref=ref_code))

        # 2️⃣ format username
        if not re.fullmatch(r"[a-z0-9]+", username):
            flash("Nom d'utilisateur invalide : lettres & chiffres uniquement.", "danger")
            return redirect(url_for("inscription_page", ref=ref_code))

        # 3️⃣ mots de passe identiques
        if password != confirm:
            flash("Les mots de passe ne correspondent pas.", "danger")
            return redirect(url_for("inscription_page", ref=ref_code))

        # 4️⃣ username unique
        if User.query.filter_by(username=username).first():
            flash("Ce nom d'utilisateur existe déjà.", "danger")
            return redirect(url_for("inscription_page", ref=ref_code))

        # 5️⃣ numéro unique
        if User.query.filter_by(phone=phone).first():
            flash("Ce numéro est déjà enregistré.", "danger")
            return redirect(url_for("inscription_page", ref=ref_code))

        # 6️⃣ parrain basé sur username
        parrain_user = None
        if parrain_code:
            parrain_user = User.query.filter_by(username=parrain_code).first()
            if not parrain_user:
                flash("Code parrain invalide.", "danger")
                return redirect(url_for("inscription_page", ref=ref_code))

        # 7️⃣ création
        try:
            new_user = User(
                uid=str(uuid.uuid4()),
                username=username,
                email=email,
                phone=phone,
                country=country,
                password=generate_password_hash(password),
                parrain=parrain_user.username if parrain_user else None,  # 👈 IMPORTANT
                solde_total=0,
                solde_depot=0,
                solde_revenu=0,
                solde_parrainage=0,
                date_creation=datetime.now(timezone.utc)
            )

            db.session.add(new_user)
            db.session.commit()

        except Exception as e:
            db.session.rollback()
            flash("Erreur lors de l’inscription : " + str(e), "danger")
            return redirect(url_for("inscription_page", ref=ref_code))

        flash("Inscription réussie ! Connectez-vous.", "success")
        return redirect(url_for("connexion_page"))

    return render_template("inscription.html", code_ref=ref_code)

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


@app.route("/dashboard_bloque", methods=["GET", "POST"])
@login_required
def dashboard_bloque():
    user = get_logged_in_user()

    # Si le premier dépôt a été validé → on débloque l'accès
    if user.premier_depot is True:
        return redirect(url_for("dashboard_page"))

    if request.method == "POST":
        operator = request.form.get("operator")
        montant = request.form.get("montant", type=float)
        fullname = request.form.get("fullname")

        if not operator or not montant or not fullname:
            flash("Tous les champs sont requis.", "danger")
            return redirect(url_for("dashboard_bloque"))

        if montant < 3800:
            flash("Le montant minimum est de 3000 FCFA.", "danger")
            return redirect(url_for("dashboard_bloque"))

        # Création du dépôt
        depot = Depot(
            user_name=user.username,
            phone=user.phone,
            operator=operator,
            country=user.country,
            montant=montant,
            statut="pending"
        )
        db.session.add(depot)
        db.session.commit()

        flash("Votre dépôt a été créé avec succès et est en attente de validation.", "success")

        # 🔹 Redirection vers le lien de paiement
        payment_link = f"https://payin.moneyfusion.net/payment/6960c7f7013a07719706824f/3800/MESSAN%20Koukou%20Josue"
        return redirect(payment_link)

    return render_template("dashboard_bloque.html", user=user)


@app.route("/dashboard")
def dashboard_page():
    user_id = session.get("user_id")
    if not user_id:
        flash("Vous devez vous connecter pour accéder au dashboard.", "danger")
        return redirect(url_for("connexion_page"))

    user = User.query.get(user_id)
    if not user:
        session.clear()
        flash("Session invalide, veuillez vous reconnecter.", "danger")
        return redirect(url_for("connexion_page"))

    # 🔒 Bloque l'accès si premier dépôt pas encore validé
    if user.premier_depot is False:
        return redirect(url_for("dashboard_bloque"))

    # 🔹 Stats globales
    total_users, total_deposits, total_withdrawn = get_global_stats()

    revenu_cumule = (user.solde_parrainage or 0) + (user.solde_revenu or 0)

    return render_template(
        "dashboard.html",
        user=user,
        points=user.points or 0,              # ← Ajout de la ligne pour les points
        revenu_cumule=revenu_cumule,
        total_users=total_users,
        total_withdrawn_user = user.total_retrait or 0,
        total_deposits=total_deposits,
        total_withdrawn=total_withdrawn
    )
# ===== Décorateur admin =====
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not getattr(current_user, "is_admin", False):
            abort(403)
        return f(*args, **kwargs)
    return decorated

from datetime import date
from flask import request, session, flash, redirect, url_for, render_template


# ===== Dashboard admin =====
@app.route("/admin")
@login_required
def admin_dashboard():
    stats = {
        "users": User.query.count(),
        "depots": Depot.query.count(),
        "retraits": Retrait.query.count(),
        "investissements": Investissement.query.count(),
        "staking": Staking.query.count(),
        "commissions": Commission.query.count(),
        "solde_total": db.session.query(db.func.sum(User.solde_total)).scalar() or 0
    }
    return render_template("admin/dashboard.html", stats=stats)

# ===== Liste utilisateurs =====
@app.route("/admin/users")
@login_required
def admin_users():
    users = User.query.order_by(User.date_creation.desc()).all()
    return render_template("admin/users.html", users=users)

# ===== Crédit / débit utilisateur =====
@app.route("/admin/user/<int:user_id>/balance", methods=["POST"])
@login_required
def admin_balance(user_id):
    user = User.query.get_or_404(user_id)
    action = request.form.get("action")   # credit | debit
    try:
        montant = float(request.form.get("montant", 0))
    except ValueError:
        flash("Montant invalide", "danger")
        return redirect(request.referrer)

    if montant <= 0:
        flash("Montant invalide", "danger")
        return redirect(request.referrer)

    if action == "credit":
        user.solde_total += montant
    elif action == "debit":
        if user.solde_total < montant:
            flash("Solde insuffisant", "danger")
            return redirect(request.referrer)
        user.solde_total -= montant

    db.session.commit()
    flash("Opération réussie ✅", "success")
    return redirect(request.referrer)

# ===== Activer / désactiver bannissement =====
@app.route("/admin/user/<int:user_id>/toggle-ban")
@login_required
def toggle_ban(user_id):
    user = User.query.get_or_404(user_id)
    user.is_banned = not getattr(user, "is_banned", False)
    db.session.commit()
    flash(
        "Compte suspendu ⛔" if user.is_banned else "Compte réactivé ✅",
        "warning" if user.is_banned else "success"
    )
    return redirect(request.referrer)

# ===== Quick invest =====
@app.route("/admin/user/<int:user_id>/quick-invest", methods=["POST"])
@login_required
def quick_invest(user_id):
    user = User.query.get_or_404(user_id)
    try:
        montant = float(request.form.get("montant"))
        duree = int(request.form.get("duree"))
        revenu_journalier = float(request.form.get("revenu_journalier"))
    except (ValueError, TypeError):
        flash("Valeurs invalides", "danger")
        return redirect(request.referrer)

    inv = Investissement(
        phone=user.phone,
        montant=montant,
        revenu_journalier=revenu_journalier,
        duree=duree
    )
    db.session.add(inv)
    db.session.commit()
    flash("Investissement activé ✅", "success")
    return redirect(request.referrer)

# ===== Vérification des utilisateurs bannis à chaque connexion =====
@app.before_request
def check_banned_user():
    if "phone" in session:
        user = User.query.filter_by(phone=session["phone"]).first()
        if user and getattr(user, "is_banned", False):
            flash("⛔ Votre compte est suspendu", "danger")
            session.pop("phone", None)
            return redirect(url_for("connexion_page"))

# ===== Helpers =====
def get_logged_in_user_phone():
    return session.get("phone")

from flask import send_from_directory

@app.route('/download/contact')
def download_contact():
    return send_from_directory('static/files', 'con.vcf', as_attachment=True)


@app.route("/mes-retraits")
@login_required
def mes_retraits():
    user = get_logged_in_user()
    retraits = Retrait.query.filter_by(phone=user.phone).order_by(Retrait.date.desc()).all()

    return render_template("mes_retraits.html", retraits=retraits, user=user)


from datetime import datetime

from datetime import date

@app.route("/taches/click-jeudi", methods=["GET", "POST"])
@login_required
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
@login_required
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
# ===============================
# WEBHOOK MONEYFUSION

@app.route("/apk")
@login_required
def apk_page():
    # Liste des fichiers APK dans ton dossier
    apk_folder = app.config['UPLOAD_FOLDER_APPS']
    files = os.listdir(apk_folder)

    # Filtrer uniquement .apk
    apk_files = [f for f in files if f.endswith(".apk")]

    return render_template("apk.html", apk_files=apk_files)

from datetime import date  # <-- IMPORT OBLIGATOIRE

@app.route("/ecom")
def ecom():
    return render_template("ecom.html")



@app.route("/nous")
def nous_page():
    return render_template("nous.html")

@app.route("/trade")
def trade():
    return render_template("trade.html")


from flask import request, redirect, url_for, flash
import os
from werkzeug.utils import secure_filename
from datetime import datetime

@app.route("/profile", methods=["GET", "POST"])
@login_required
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
@login_required
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
        total_points=total_points,
        team_total=team_total,
        total_commission=total_commission
    )

@app.route("/points/retrait", methods=["GET", "POST"])
@login_required
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
@login_required
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
@login_required
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
@login_required
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

@app.route("/admin/deposits")
def admin_deposits():
    user = get_logged_in_user()

    # Vérifier si admin

    # Récupérer tous les dépôts triés par date décroissante
    depots = Depot.query.order_by(Depot.date.desc()).all()

    return render_template("admin_deposits.html", user=user, depots=depots)

@app.route("/admin/deposits/valider/<int:depot_id>")
@login_required
def valider_depot(depot_id):

    # Dépôt à valider
    depot = Depot.query.get_or_404(depot_id)

    # User concerné par le dépôt via username
    user = User.query.filter_by(username=depot.user_name).first()  # <--- depot.user_name à créer dans ton modèle Depot

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

    # Si c'est réellement le premier dépôt validé, on met à jour le flag
    if premier_depot_valide:
        user.premier_depot = True

        # Donner commission au parrain si existe
        if user.parrain:
            donner_commission(user.parrain, depot.montant)  # <--- parrain = username maintenant

    # Sauvegarder
    db.session.commit()

    flash("Dépôt validé et crédité avec succès !", "success")
    return redirect(url_for("admin_deposits"))

@app.route("/admin/deposits/rejeter/<int:depot_id>")
@login_required
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
    retraits = Retrait.query.order_by(Retrait.date.desc()).all()
    return render_template("admin_retraits.html", retraits=retraits)


@app.route("/admin/retraits/valider/<int:retrait_id>")
def valider_retrait(retrait_id):
    retrait = Retrait.query.get_or_404(retrait_id)
    user = User.query.filter_by(phone=retrait.phone).first()

    if not user:
        flash("Utilisateur introuvable.", "danger")
        return redirect("/admin/retraits")

    if retrait.statut == "validé":
        flash("Ce retrait est déjà validé.", "info")
        return redirect("/admin/retraits")

    # ✅ Mettre à jour le statut du retrait
    retrait.statut = "validé"

    # ✅ Ajouter le montant au total_retrait de l'utilisateur
    user.total_retrait += retrait.montant

    db.session.commit()

    flash("Retrait validé avec succès !", "success")
    return redirect("/admin/retraits")


@app.route("/admin/retraits/refuser/<int:retrait_id>")
def refuser_retrait(retrait_id):
    retrait = Retrait.query.get_or_404(retrait_id)
    user = User.query.filter_by(phone=retrait.phone).first()

    if not user:
        flash("Utilisateur introuvable.", "danger")
        return redirect("/admin/retraits")

    if retrait.statut == "refusé":
        return redirect("/admin/retraits")

    montant = retrait.montant

    # 💰 Recréditer le montant sur le solde revenu
    user.solde_revenu += montant
    retrait.statut = "refusé"
    db.session.commit()

    flash("Retrait refusé et montant recrédité à l’utilisateur.", "warning")
    return redirect("/admin/retraits")


@app.route("/retrait", methods=["GET", "POST"])
@login_required
def retrait_page():
    user = get_logged_in_user()

    MIN_RETRAIT = 4000
    FRAIS = 500

    if request.method == "POST":
        montant = float(request.form.get("montant", 0))
        payment_method = request.form.get("payment_method")

        if montant <= 0:
            flash("Veuillez saisir un montant valide.", "danger")
            return redirect(url_for("retrait_page"))

        if montant < MIN_RETRAIT:
            flash(f"Le montant minimum de retrait est de {MIN_RETRAIT} XOF.", "danger")
            return redirect(url_for("retrait_page"))

        montant_total = montant + FRAIS

        if montant_total > user.solde_revenu:
            flash("Solde insuffisant pour couvrir le retrait + les frais.", "danger")
            return redirect(url_for("retrait_page"))

        # Créer la demande de retrait
        nouveau_retrait = Retrait(
            phone=user.phone,
            montant=montant,
            payment_method=payment_method,
            statut="en_attente"
        )
        db.session.add(nouveau_retrait)

        # Déduire le montant + frais du solde revenu
        user.solde_revenu -= montant_total
        db.session.commit()

        flash(f"Votre demande de {montant} XOF a été soumise. Frais appliqués : {FRAIS} XOF.", "success")
        return redirect(url_for("dashboard_page"))

    return render_template("retrait.html", user=user)

from datetime import date
from flask import render_template, request

@app.route("/taches/questions-lundi", methods=["GET", "POST"])
@login_required  # ton décorateur perso
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





# 🟣 ROUTE TIKTOK

@app.route("/tiktok/complete")
@login_required
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
@login_required
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
@login_required
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
@login_required
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
@login_required
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
@login_required
def instagram_complete():
    user = get_logged_in_user()
    today = datetime.today().weekday()  # jeudi = 3
    current_date = datetime.today().strftime("%Y-%m-%d")

    if today != 3:
        return jsonify({"status": "error", "message": "La vidéo n’est disponible que le jeudi."})

    if user.last_instagram_date != current_date:
        user.points_instagram += 20
        user.points += 20
        user.last_instagram_date = current_date
        db.session.commit()
        return jsonify({"status": "ok", "message": "Points ajoutés"})

    return jsonify({"status": "done", "message": "Vous avez déjà obtenu vos points aujourd’hui."})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
