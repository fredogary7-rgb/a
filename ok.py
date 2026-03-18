from app import db, Retrait, User  # importe depuis app.py

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
