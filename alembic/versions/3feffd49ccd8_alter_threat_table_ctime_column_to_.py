"""alter threat table ctime column to integer

Revision ID: 3feffd49ccd8
Revises: 6bb4de329171
Create Date: 2022-07-17 12:22:59.232667

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3feffd49ccd8'
down_revision = 'db641254a248'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_column("threat", "ctime")
    op.add_column("threat", sa.Column("ctime", sa.BigInteger(), nullable=False))


def downgrade() -> None:
    op.drop_column("threat", "ctime")
    sa.add_column("threat", "ctime", sa.Column('ctime', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True))
