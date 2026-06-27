from app import app, db
from sqlalchemy import text

with app.app_context():
    try:
        db.session.execute(text("""
            CREATE TABLE IF NOT EXISTS soleaspay_routing (
                id SERIAL PRIMARY KEY,
                reference_soleaspay VARCHAR(100) UNIQUE NOT NULL,
                projet VARCHAR(20) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """))

        db.session.commit()
        print("✅ Table soleaspay_routing créée avec succès.")

    except Exception as e:
        db.session.rollback()
        print(f"❌ Erreur : {e}")
