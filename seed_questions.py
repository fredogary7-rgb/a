from app import app, db, Question  # Tout est dans app.py
from datetime import date

with app.app_context():
    # Créer les questions
    q1 = Question(question="Quelle est la capitale du Togo ?", correct_answer="Lomé")
    q2 = Question(question="Combien font 5 × 6 ?", correct_answer="30")
    q3 = Question(question="Quelle est la planète la plus proche du soleil ?", correct_answer="Mercure")
    q4 = Question(question="Combien de continents y a-t-il ?", correct_answer="7")
    q5 = Question(question="Qui a découvert l'Amérique ?", correct_answer="Christophe Colomb")

    # Ajouter à la base
    db.session.add_all([q1, q2, q3, q4, q5])
    db.session.commit()

    print("✅ Questions ajoutées avec succès !")
