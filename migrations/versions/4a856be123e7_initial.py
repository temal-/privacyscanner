"""initial

Revision ID: 4a856be123e7
Revises:
Create Date: 2018-05-20 11:32:34.717176

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


# revision identifiers, used by Alembic.
revision = '4a856be123e7'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
            'scanner_scaninfo',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('scan_id', sa.Integer, ),
            sa.Column('scan_host', sa.String()),
            sa.Column('scan_module', sa.String()),
            sa.Column('time_started', sa.TIMESTAMP),
            sa.Column('time_finished', sa.TIMESTAMP),
            sa.Column('num_tries', sa.Integer)
            )
    op.create_unique_constraint('unique_scan_id', 'scanner_scaninfo', ['scan_id'])
    op.create_table(
            'scanner_scanjob',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('scan_id', sa.Integer, sa.ForeignKey('scanner_scaninfo.scan_id')),
            sa.Column('scan_module', sa.String()),
            sa.Column('priority', sa.Integer),
            sa.Column('dependency_order', sa.Integer)
            )
    op.create_table(
            'scanner_scan',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('scan_id', sa.Integer, sa.ForeignKey('scanner_scaninfo.scan_id')),
            sa.Column('result', JSONB)
            )
    op.create_table(
            'scanner_logentry',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('scan_id', sa.Integer, sa.ForeignKey('scanner_scaninfo.scan_id')),
            sa.Column('scan_module', sa.String()),
            sa.Column('scan_host', sa.String()),
            sa.Column('time_created', sa.TIMESTAMP, server_default=sa.func.now()),
            sa.Column('level', sa.Integer),
            sa.Column('message', sa.String()),
            )


def downgrade():
    op.drop_table('scanner_logentry')
    op.drop_table('scanner_scan')
    op.drop_table('scanner_scanjob')
    op.drop_constraint('unique_scan_id', 'scanner_scaninfo')
    op.drop_table('scanner_scaninfo')
