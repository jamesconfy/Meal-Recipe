"""empty message

Revision ID: ba015127a6cc
Revises: 
Create Date: 2022-06-14 17:26:52.510948

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ba015127a6cc'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('mealplan', sa.Column('introduction', sa.Text(), nullable=False))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('mealplan', 'introduction')
    # ### end Alembic commands ###
