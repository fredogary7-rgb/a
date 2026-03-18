"""drop user_name column from depot

Revision ID: a7c9e6328a5c
Revises: 8e58d9cc9b5d
Create Date: 2026-03-18 14:09:08.319296
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a7c9e6328a5c'
down_revision = '8e58d9cc9b5d'
branch_labels = None
depends_on = None


def upgrade():
    # supprimer la colonne user_name qui causait l'erreur
    with op.batch_alter_table('depot') as batch_op:
        batch_op.drop_column('user_name')


def downgrade():
    # recréer la colonne si tu veux revenir en arrière
    with op.batch_alter_table('depot') as batch_op:
        batch_op.add_column(sa.Column(
            'user_name',
            sa.String(50),
            nullable=False
        ))
        batch_op.create_foreign_key(
            "depot_user_name_fkey",
            "user",
            ["user_name"],
            ["username"],
            ondelete="CASCADE"
        )
