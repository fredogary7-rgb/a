# script_ajout_questions.py

from app import app, db, Question  # Tout est défini dans app.py

with app.app_context():  # Obligatoire pour accéder à la DB en dehors de Flask
    # Liste des questions
    questions = [
        Question(question="Quelle est la capitale de la France ?", correct_answer="Paris"),
        Question(question="Combien y a-t-il de continents ?", correct_answer="7"),
        Question(question="Quelle est la couleur du ciel par temps clair ?", correct_answer="Bleu"),
        Question(question="Combien de jours y a-t-il en février lors d'une année non bissextile ?", correct_answer="28"),
        Question(question="Qui a écrit 'Les Misérables' ?", correct_answer="Victor Hugo")
    ]

    # Ajouter les questions à la base
    db.session.add_all(questions)
    db.session.commit()

    print("✅ 5 questions ajoutées avec succès !")
