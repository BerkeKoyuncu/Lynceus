import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from app import create_app
from models import db
import sqlalchemy as sa

app = create_app()
with app.app_context():
    insp = sa.inspect(db.engine)
    if insp.has_table("alembic_version"):
        with db.engine.connect() as conn:
            conn.execute(sa.text("DELETE FROM alembic_version"))
            conn.commit()
        print("alembic_version cleared")
    else:
        print("alembic_version table not found - fresh DB")
