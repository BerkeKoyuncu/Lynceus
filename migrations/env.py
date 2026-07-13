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


# Retrieve engine.
def get_engine():
    # Run this block with structured exception handling.
    try:
        # this works with Flask-SQLAlchemy<3 and Alchemical
        return current_app.extensions['migrate'].db.get_engine()
    # Handle an exception raised by the preceding protected block.
    except (TypeError, AttributeError):
        # this works with Flask-SQLAlchemy>=3
        return current_app.extensions['migrate'].db.engine


# Retrieve engine url.
def get_engine_url():
    # Run this block with structured exception handling.
    try:
        return get_engine().url.render_as_string(hide_password=False).replace(
            '%', '%%')
    # Handle an exception raised by the preceding protected block.
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
    # Handle the branch where hasattr(target_db, 'metadatas') evaluates to true.
    if hasattr(target_db, 'metadatas'):
        return target_db.metadatas[None]
    return target_db.metadata


# Determine whether ancestor.
def _is_ancestor(script, ancestor, descendant):
    # Handle the branch where ancestor == descendant evaluates to true.
    if ancestor == descendant:
        return True
    # Handle the branch where ancestor is None evaluates to true.
    if ancestor is None:
        return True
    # Run this block with structured exception handling.
    try:
        list(script.iterate_revisions(descendant, ancestor))
        return True
    # Handle an exception raised by the preceding protected block.
    except RangeNotAncestorError:
        return False


# Handle the enforce safe downgrade floor operation.
def _enforce_safe_downgrade_floor():
    current_revision = context.get_context().get_current_revision()
    # Run this block with structured exception handling.
    try:
        target_revision = context.get_revision_argument()
    # Handle an exception raised by the preceding protected block.
    except (KeyError, CommandError):
        # Read-only commands such as `db current` have no destination revision.
        return
    # Handle the branch where isinstance(target_revision, (tuple, list)) evaluates to true.
    if isinstance(target_revision, (tuple, list)):
        # Handle the branch where len(target_revision) != 1 evaluates to true.
        if len(target_revision) != 1:
            return
        target_revision = target_revision[0]
    # Handle the branch where current_revision is None evaluates to true.
    if current_revision is None:
        return

    script = ScriptDirectory.from_config(config)
    is_downgrade = _is_ancestor(script, target_revision, current_revision)
    target_is_below_floor = (
        target_revision != SAFE_DOWNGRADE_FLOOR
        and _is_ancestor(script, target_revision, SAFE_DOWNGRADE_FLOOR)
    )
    # Handle the branch where is_downgrade and target_is_below_floor evaluates to true.
    if is_downgrade and target_is_below_floor:
        raise CommandError(
            'Downgrades below b5a93e3d9370 are blocked because historical '
            'honeypot downgrade steps can destroy timestamp data. Restore a '
            'backup/export instead of crossing this migration floor.'
        )


# Handle the enforce safe offline downgrade floor operation.
def _enforce_safe_offline_downgrade_floor():
    # Run this block with structured exception handling.
    try:
        starting_revision = context.get_starting_revision_argument()
        target_revision = context.get_revision_argument()
    # Handle an exception raised by the preceding protected block.
    except (KeyError, CommandError):
        return
    # Handle the branch where starting_revision is None evaluates to true.
    if starting_revision is None:
        # Offline upgrades do not have an explicit starting revision.
        return

    script = ScriptDirectory.from_config(config)
    is_downgrade = _is_ancestor(script, target_revision, starting_revision)
    target_is_below_floor = (
        target_revision != SAFE_DOWNGRADE_FLOOR
        and _is_ancestor(script, target_revision, SAFE_DOWNGRADE_FLOOR)
    )
    # Handle the branch where is_downgrade and target_is_below_floor evaluates to true.
    if is_downgrade and target_is_below_floor:
        raise CommandError(
            'Offline downgrades below b5a93e3d9370 are blocked because they '
            'would generate destructive honeypot migration SQL.'
        )


# Handle the repair pre c7 blocked ip drift operation.
def _repair_pre_c7_blocked_ip_drift(connection):
    """Compatibility bridge for b5 databases that cannot enter c7 safely."""
    # Handle the branch where context.get_context().get_current_revision() != SAFE_DOWNGRADE_FLOOR evaluates to true.
    if context.get_context().get_current_revision() != SAFE_DOWNGRADE_FLOOR:
        return
    # Run this block with structured exception handling.
    try:
        target_revision = context.get_revision_argument()
    # Handle an exception raised by the preceding protected block.
    except (KeyError, CommandError):
        return
    # Handle the branch where isinstance(target_revision, (tuple, list)) evaluates to true.
    if isinstance(target_revision, (tuple, list)):
        # Handle the branch where len(target_revision) != 1 evaluates to true.
        if len(target_revision) != 1:
            return
        target_revision = target_revision[0]
    # Handle the branch where target_revision == SAFE_DOWNGRADE_FLOOR evaluates to true.
    if target_revision == SAFE_DOWNGRADE_FLOOR:
        return
    script = ScriptDirectory.from_config(config)
    # Handle the branch where not _is_ancestor(script, SAFE_DOWNGRADE_FLOOR, target_revision) evaluates to true.
    if not _is_ancestor(script, SAFE_DOWNGRADE_FLOOR, target_revision):
        return

    inspector = sa.inspect(connection)
    # Handle the branch where 'honeypot_blocked_ip' not in inspector.get_table_names() evaluates to true.
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
    # Handle the branch where has_ip_unique evaluates to true.
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


# Handle the preflight required sqlite foreign keys operation.
def _preflight_required_sqlite_foreign_keys(connection):
    """Stop before batch rebuilds when required ownership links are orphaned."""
    # Handle the branch where connection.dialect.name != 'sqlite' evaluates to true.
    if connection.dialect.name != "sqlite":
        return
    # Run this block with structured exception handling.
    try:
        target_revision = context.get_revision_argument()
    # Handle an exception raised by the preceding protected block.
    except (KeyError, CommandError):
        return
    # Handle the branch where isinstance(target_revision, (tuple, list)) evaluates to true.
    if isinstance(target_revision, (tuple, list)):
        # Handle the branch where len(target_revision) != 1 evaluates to true.
        if len(target_revision) != 1:
            return
        target_revision = target_revision[0]

    current_revision = context.get_context().get_current_revision()
    script = ScriptDirectory.from_config(config)
    # Handle the branch where not _is_ancestor(script, current_revision, target_revision) evaluates to true.
    if not _is_ancestor(script, current_revision, target_revision):
        return

    inspector = sa.inspect(connection)
    tables = set(inspector.get_table_names())
    required_links = (
        ("scan_result", "user_id", "user"),
        ("scan_schedule", "user_id", "user"),
        ("system_setting", "user_id", "user"),
        ("scan_credential", "user_id", "user"),
        ("security_rule", "user_id", "user"),
    )
    violations = []
    # Iterate over required_links and bind each item to (child_table, foreign_key, parent_table).
    for child_table, foreign_key, parent_table in required_links:
        # Handle the branch where child_table not in tables or parent_table not in tables evaluates to true.
        if child_table not in tables or parent_table not in tables:
            continue
        child_columns = {
            column["name"] for column in inspector.get_columns(child_table)
        }
        # Handle the branch where 'id' not in child_columns or foreign_key not in child_columns evaluates to true.
        if "id" not in child_columns or foreign_key not in child_columns:
            continue
        rows = connection.execute(sa.text(
            f'SELECT child.id, child."{foreign_key}" '
            f'FROM "{child_table}" AS child '
            f'LEFT JOIN "{parent_table}" AS parent '
            f'ON parent.id = child."{foreign_key}" '
            f'WHERE child."{foreign_key}" IS NOT NULL AND parent.id IS NULL '
            'LIMIT 10'
        )).fetchall()
        violations.extend(
            (child_table, row[0], foreign_key, row[1], parent_table)
            for row in rows
        )

    # Handle the branch where violations evaluates to true.
    if violations:
        details = ", ".join(
            f"{table}[id={row_id}].{foreign_key}={value} -> {parent}.id"
            for table, row_id, foreign_key, value, parent in violations
        )
        raise CommandError(
            "Required SQLite foreign-key orphans must be resolved before "
            f"schema migration; no schema changes were started: {details}"
        )


# Run migrations offline.
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

    # Manage context.begin_transaction() within this scoped block.
    with context.begin_transaction():
        context.run_migrations()


# Run migrations online.
def run_migrations_online():
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """

    # this callback is used to prevent an auto-migration from being generated
    # when there are no changes to the schema
    # reference: http://alembic.zzzcomputing.com/en/latest/cookbook.html
    def process_revision_directives(context, revision, directives):
        # Handle the branch where getattr(config.cmd_opts, 'autogenerate', False) evaluates to true.
        if getattr(config.cmd_opts, 'autogenerate', False):
            script = directives[0]
            # Handle the branch where script.upgrade_ops.is_empty() evaluates to true.
            if script.upgrade_ops.is_empty():
                directives[:] = []
                logger.info('No changes in schema detected.')

    conf_args = current_app.extensions['migrate'].configure_args
    # Handle the branch where conf_args.get('process_revision_directives') is None evaluates to true.
    if conf_args.get("process_revision_directives") is None:
        conf_args["process_revision_directives"] = process_revision_directives

    connectable = get_engine()

    # Manage connectable.connect() within this scoped block.
    with connectable.connect() as connection:
        is_sqlite = connection.dialect.name == "sqlite"
        # Handle the branch where is_sqlite evaluates to true.
        if is_sqlite:
            # SQLite batch migrations recreate tables. Foreign-key enforcement
            # must be disabled for that copy/drop cycle and is restored below.
            cursor = connection.connection.cursor()
            cursor.execute("PRAGMA foreign_keys=OFF")
            cursor.close()

        # Run this block with structured exception handling.
        try:
            context.configure(
                connection=connection,
                target_metadata=get_metadata(),
                **conf_args
            )

            _enforce_safe_downgrade_floor()

            # Manage context.begin_transaction() within this scoped block.
            with context.begin_transaction():
                _preflight_required_sqlite_foreign_keys(connection)
                _repair_pre_c7_blocked_ip_drift(connection)
                context.run_migrations()
        # Run cleanup that must occur after the protected block.
        finally:
            # Handle the branch where is_sqlite evaluates to true.
            if is_sqlite:
                cursor = connection.connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()


# Handle the branch where context.is_offline_mode() evaluates to true.
if context.is_offline_mode():
    run_migrations_offline()
# Handle the fallback branch when the preceding condition does not match.
else:
    run_migrations_online()
