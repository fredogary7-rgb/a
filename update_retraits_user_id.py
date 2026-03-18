from app import app, db, Retrait, User  # importe ton app Flask et les modèles

# ⚡ Crée un contexte d'application
with app.app_context():
    # Récupère tous les retraits
    retraits = Retrait.query.all()

    for r in retraits:
        # Cherche l'utilisateur correspondant au numéro de téléphone
        user = User.query.filter_by(phone=r.phone).first()
        if user:
            r.user_id = user.id
        else:
            print(f"⚠️ Aucun utilisateur trouvé pour le phone {r.phone} (retrait id={r.id})")

    # Valide les changements dans la base
    db.session.commit()
    print("✅ Tous les user_id des retraits ont été mis à jour !")
