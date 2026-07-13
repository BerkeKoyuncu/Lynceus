import logging
from logging.config import fileConfig

from flask import current_app

from alembic import context
from alembic.script import ScriptDirectory
from alembic.script.revision import RangeNotAncestorError
from alembic.util import CommandError
import sqlalchemy as sa

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
fileConfig(config.config_file_name)
logger = logging.getLogger('alembic.env')


def get_engine():
    try:
        # this works with Flask-SQLAlchemy<3 and Alchemical
        return current_app.extensions['migrate'].db.get_engine()
    except (TypeError, AttributeError):
        # this works with Flask-SQLAlchemy>=3
        return current_app.extensions['migrate'].db.engine


def get_engine_url():
    try:
        return get_engine().url.render_as_string(hide_password=False).replace(
            '%', '%%')
    except AttributeError:
        return str(get_engine().url).replace('%', '%%')


# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata
config.set_main_option('sqlalchemy.url', get_engine_url())
target_db = current_app.extensions['migrate'].db
SAFE_DOWNGRADE_FLOOR = 'b5a93e3d9370'

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def get_metadata():
    if hasattr(target_db, 'metadatas'):
        return target_db.metadatas[None]
    return target_db.metadata


def _is_ancestor(script, ancestor, descendant):
    if ancestor == descendant:
        return True
    if ancestor is None:
        return True
    try:
        list(script.iterate_revisions(descendant, ancestor))
        return True
    except RangeNotAncestorError:
        return False


def _enforce_safe_downgrade_floor():
    current_revision = context.get_context().get_current_revision()
    try:
        target_revision = context.get_revision_argument()
    except (KeyError, CommandError):
        # Read-only commands such as `db current` have no destination revision.
        return
    if isinstance(target_revision, (tuple, list)):
        if len(target_revision) != 1:
            return
        target_revision = target_revision[0]
    if current_revision is None:
        return

    script = ScriptDirectory.from_config(config)
    is_downgrade = _is_ancestor(script, target_revision, current_revision)
    target_is_below_floor = (
        target_revision != SAFE_DOWNGRADE_FLOOR
        and _is_ancestor(script, target_revision, SAFE_DOWNGRADE_FLOOR)
    )
    if is_downgrade and target_is_below_floor:
        raise CommandError(
            'Downgrades below b5a93e3d9370 are blocked because historical '
            'honeypot downgrade steps can destroy timestamp data. Restore a '
            'backup/export instead of crossing this migration floor.'
        )


def _enforce_safe_offline_downgrade_floor():
    try:
        starting_revision = context.get_starting_revision_argument()
        target_revision = context.get_revision_argument()
    except (KeyError, CommandError):
        return
    if starting_revision is None:
        # Offline upgrades do not have an explicit starting revision.
        return

    script = ScriptDirectory.from_config(config)
    is_downgrade = _is_ancestor(script, target_revision, starting_revision)
    target_is_below_floor = (
        target_revision != SAFE_DOWNGRADE_FLOOR
        and _is_ancestor(script, target_revision, SAFE_DOWNGRADE_FLOOR)
    )
    if is_downgrade and target_is_below_floor:
        raise CommandError(
            'Offline downgrades below b5a93e3d9370 are blocked because they '
            'would generate destructive honeypot migration SQL.'
        )


def _repair_pre_c7_blocked_ip_drift(connection):
    """Compatibility bridge for b5 databases that cannot enter c7 safely."""
    if context.get_context().get_current_revision() != SAFE_DOWNGRADE_FLOOR:
        return
    try:
        target_revision = context.get_revision_argument()
    except (KeyError, CommandError):
        return
    if isinstance(target_revision, (tuple, list)):
        if len(target_revision) != 1:
            return
        target_revision = target_revision[0]
    if target_revision == SAFE_DOWNGRADE_FLOOR:
        return
    script = ScriptDirectory.from_config(config)
    if not _is_ancestor(script, SAFE_DOWNGRADE_FLOOR, target_revision):
        return

    inspector = sa.inspect(connection)
    if "honeypot_blocked_ip" not in inspector.get_table_names():
        return
    unique_constraints = inspector.get_unique_constraints("honeypot_blocked_ip")
    indexes = inspector.get_indexes("honeypot_blocked_ip")
    has_ip_unique = any(
        constraint.get("column_names") == ["ip_address"]
        for constraint in unique_constraints
    ) or any(
        index.get("unique") is True
        and index.get("column_names") == ["ip_address"]
        for index in indexes
    )
    if has_ip_unique:
        return

    connection.execute(sa.text(
        "DELETE FROM honeypot_blocked_ip "
        "WHERE ip_address IS NULL OR TRIM(ip_address) = ''"
    ))
    connection.execute(sa.text(
        "DELETE FROM honeypot_blocked_ip WHERE id NOT IN ("
        "SELECT keep_id FROM ("
        "SELECT MIN(id) AS keep_id FROM honeypot_blocked_ip GROUP BY ip_address"
        ") AS deduplicated)"
    ))


def run_migrations_offline():
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url, target_metadata=get_metadata(), literal_binds=True
    )

    _enforce_safe_offline_downgrade_floor()

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """

    # this callback is used to prevent an auto-migration from being generated
    # when there are no changes to the schema
    # reference: http://alembic.zzzcomputing.com/en/latest/cookbook.html
    def process_revision_directives(context, revision, directives):
        if getattr(config.cmd_opts, 'autogenerate', False):
            script = directives[0]
            if script.upgrade_ops.is_empty():
                directives[:] = []
                logger.info('No changes in schema detected.')

    conf_args = current_app.extensions['migrate'].configure_args
    if conf_args.get("process_revision_directives") is None:
        conf_args["process_revision_directives"] = process_revision_directives

    connectable = get_engine()

    with connectable.connect() as connection:
        is_sqlite = connection.dialect.name == "sqlite"
        if is_sqlite:
            # SQLite batch migrations recreate tables. Foreign-key enforcement
            # must be disabled for that copy/drop cycle and is restored below.
            cursor = connection.connection.cursor()
            cursor.execute("PRAGMA foreign_keys=OFF")
            cursor.close()

        try:
            context.configure(
                connection=connection,
                target_metadata=get_metadata(),
                **conf_args
            )

            _enforce_safe_downgrade_floor()

            with context.begin_transaction():
                _repair_pre_c7_blocked_ip_drift(connection)
                context.run_migrations()
        finally:
            if is_sqlite:
                cursor = connection.connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
