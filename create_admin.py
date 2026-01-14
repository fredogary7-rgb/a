from app import app, db, User  # on importe l'app Flask, la db et le modèle
from werkzeug.security import generate_password_hash

with app.app_context():  # ⚡ important : ouvre le contexte de l'application

    # Créer le hash du mot de passe
    hash_password = generate_password_hash("LuMinA123")

    # Vérifier si l'admin existe déjà
    existing_admin = User.query.filter_by(username="adAmine").first()
    if existing_admin:
        print("Admin existe déjà !")
    else:
        # Créer l'utilisateur admin
        admin_user = User(
            username="adAmine",
            email="admin@example.com",
            phone="0000000000",
            password=hash_password,
            is_admin=True
        )

        # Ajouter et valider dans la base
        db.session.add(admin_user)
        db.session.commit()

        print("Admin créé avec succès !")
