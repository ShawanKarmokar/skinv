# db.py
#
# Database utilities for the ATN Inventory application.
#
# This module centralises database access and schema management.  It uses
# a dynamic `data` directory relative to the running location so that when
# packaged as a standalone executable (e.g. via PyInstaller) the SQLite
# database is created alongside the binary.  When run from source, the
# database lives in a `data` folder next to this file.  See `_base_dir`
# for details.

import os
import sys
import sqlite3
import time
import hashlib
from typing import Optional, Iterable, Tuple, Dict


def _base_dir() -> str:
    """
    Determine the base directory for storing persistent application data.

    If the application is packaged as an executable via PyInstaller, it
    writes data into a `data` subfolder next to the executable.  When
    running from source, it writes into a `data` subfolder next to this
    source file.  The directory is created if it does not already exist.

    Returns
    -------
    str
        Absolute path to the `data` directory used by the application.
    """
    if getattr(sys, 'frozen', False):  # running as packaged exe
        root = os.path.dirname(sys.executable)
    else:
        root = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(root, "data")
    # Ensure the data directory exists; this covers the case where the
    # application runs for the first time and needs to create its storage.
    os.makedirs(data_dir, exist_ok=True)
    return data_dir


# Construct the full path to the SQLite database file.  Storing the
# database inside the data directory keeps it alongside the application
# without hard‑coding absolute paths.  The CONFIG dict exposes this
# path so that it can be modified at runtime (e.g. by the GUI).
DB_PATH: str = os.path.join(_base_dir(), "inventory.db")

# Expose a CONFIG mapping for backwards compatibility with existing
# application code.  ``DB_PATH`` holds the primary location of the
# SQLite file.  ``ALT_DB_PATHS`` is a list of additional database
# locations used for redundancy.  The GUI (admin/superadmin only) may
# modify these values at runtime to switch or mirror database files.
CONFIG: Dict[str, object] = {
    "DB_PATH": DB_PATH,
    # Alternative database paths.  On write operations the primary
    # database file will be copied to each of these locations.  On
    # connection failures the system will attempt to connect to these
    # paths in order until a working database is found.
    "ALT_DB_PATHS": [],
    # Indicates whether the last successful connection came from a mirror
    # (i.e. one of the ALT_DB_PATHS).  The UI may check this flag and
    # display a warning when falling back to a local mirror.
    "FROM_MIRROR": False,
    # Store the current database password used for encryption/decryption.
    # This is set when decrypt_db() or encrypt_db() is called successfully.
    "DB_PASSWORD": None,
    # Application secret used when deriving encryption keys.  This
    # ensures that only this application (with the same secret) can
    # open encrypted database files.  Do not modify this value unless
    # you also update the matching logic in the executable when
    # bundling via PyInstaller.  Changing it will invalidate existing
    # encrypted databases.
    "APP_SECRET": "ATN_APP_SECRET_V1",
}

# --------------------------------------------------------------------
#                        Encryption Helpers
#
# To prevent casual inspection of the SQLite database when the
# application is not running, this module provides simple file‑level
# encryption using an XOR stream cipher derived from a password and a
# static application secret.  The encryption is intentionally simple
# (not AES) so that it has no external dependencies, yet it renders
# the database unreadable by text editors.  When the user chooses
# to lock the database, the plain *.db file remains on disk to
# preserve concurrent access while the application is running.  An
# encrypted copy (*.db.enc) is written alongside it.  On exit the
# plain file is removed so that only the encrypted copy remains.  When
# the application starts, if an encrypted copy exists but the plain
# file does not, the user must supply the correct password to
# decrypt it.

def _derive_key(password: str) -> bytes:
    """
    Derive a 32‑byte key from the given password using SHA‑256 and the
    application secret.  The secret binds the encryption to this
    application so that the same password used in a different program
    will not generate the same key.

    Parameters
    ----------
    password: str
        The user‑supplied password.

    Returns
    -------
    bytes
        A 32‑byte key derived from the password and APP_SECRET.
    """
    # Combine the password with the app secret to prevent reuse in
    # other contexts.  Use encode to convert to bytes and hash via
    # SHA‑256 to obtain a fixed‑length key.
    secret = str(CONFIG.get("APP_SECRET", "")).encode("utf-8")
    return hashlib.sha256(password.encode("utf-8") + secret).digest()


def is_db_encrypted(path: Optional[str] = None) -> bool:
    """
    Determine whether the database at the given path has an encrypted
    copy.  A database is considered encrypted if a file with the
    extension ``.enc`` exists alongside the plain file and the plain
    file does not exist.

    Parameters
    ----------
    path: str, optional
        Base path of the database (without the .enc suffix).  If not
        provided, ``CONFIG['DB_PATH']`` is used.

    Returns
    -------
    bool
        True if the encrypted file exists and the plain file is
        missing, False otherwise.
    """
    p = path or CONFIG.get("DB_PATH", DB_PATH)
    return os.path.exists(p + ".enc") and not os.path.exists(p)


def encrypt_db(password: str, path: Optional[str] = None) -> None:
    """
    Encrypt the database file using the provided password.

    The encrypted file contains a simple header to allow integrity
    checking on decryption.  The format is:

    - 4 bytes: magic string ``b'ATN1'`` indicating the version of the
      encryption scheme.
    - 32 bytes: SHA‑256 digest of the plain file concatenated with
      ``APP_SECRET``.  This digest is used to verify that the correct
      password was supplied during decryption.
    - Remaining bytes: XOR encrypted database bytes.

    The plain database remains on disk after encryption so that the
    application can continue operating.  On exit, the calling code
    should remove the plain file to leave only the encrypted copy.

    Parameters
    ----------
    password: str
        The password used to derive the encryption key.
    path: str, optional
        Path to the plain database file.  Defaults to
        ``CONFIG['DB_PATH']``.
    """
    p = path or CONFIG.get("DB_PATH", DB_PATH)
    enc_p = p + ".enc"
    # Skip if the plain DB does not exist
    if not os.path.exists(p):
        return
    # Derive key from password
    key = _derive_key(password)
    # Read plain database bytes
    with open(p, "rb") as f:
        data = f.read()
    # Compute digest of the plain bytes combined with app secret to
    # bind the checksum to this application.  This prevents reuse of
    # digests across different applications.
    secret = str(CONFIG.get("APP_SECRET", "")).encode("utf-8")
    digest = hashlib.sha256(data + secret).digest()
    # XOR encrypt the data
    encrypted = bytearray(len(data))
    for i, b in enumerate(data):
        encrypted[i] = b ^ key[i % len(key)]
    # Write header, digest, and encrypted payload
    with open(enc_p, "wb") as f:
        f.write(b"ATN1")
        f.write(digest)
        f.write(encrypted)
    # Store password for re‑encryption on exit
    try:
        CONFIG["DB_PASSWORD"] = password
    except Exception:
        pass


def decrypt_db(password: str, path: Optional[str] = None) -> None:
    """
    Decrypt an encrypted database file.

    This function restores a plain SQLite database from ``<path>.enc``
    using the supplied password.  It supports both the legacy format
    (plain XOR) and the new format introduced in ``encrypt_db``.  For
    legacy files (no header) the decrypted bytes are validated to look
    like a SQLite database; if validation fails a ``ValueError`` is
    raised and the plain file is not written.  For the new format the
    digest stored in the header is compared to the digest computed
    during decryption.  A mismatch indicates an incorrect password or
    corruption and raises a ``ValueError``.

    Parameters
    ----------
    password: str
        The password used to derive the decryption key.
    path: str, optional
        Path of the plain database file (without .enc).  Defaults to
        ``CONFIG['DB_PATH']``.
    """
    p = path or CONFIG.get("DB_PATH", DB_PATH)
    enc_p = p + ".enc"
    # If encrypted file does not exist, nothing to decrypt
    if not os.path.exists(enc_p):
        return
    # Read header to determine format
    with open(enc_p, "rb") as f:
        header = f.read(4)
        # Legacy format: no header or header different from ATN1
        if header != b"ATN1":
            # Rewind and read full encrypted bytes
            f.seek(0)
            enc_data = f.read()
            key = _derive_key(password)
            plain = bytearray(len(enc_data))
            for i, b in enumerate(enc_data):
                plain[i] = b ^ key[i % len(key)]
            # Validate header of decrypted bytes; SQLite files begin
            # with b"SQLite format 3\x00"
            if not plain.startswith(b"SQLite format 3\x00"):
                raise ValueError("Incorrect password or corrupted encrypted file")
            # Write plain file
            with open(p, "wb") as out:
                out.write(plain)
            try:
                CONFIG["DB_PASSWORD"] = password
            except Exception:
                pass
            return
        # New format: read digest and encrypted payload
        digest_stored = f.read(32)
        enc_data = f.read()
    # Decrypt payload
    key = _derive_key(password)
    plain = bytearray(len(enc_data))
    for i, b in enumerate(enc_data):
        plain[i] = b ^ key[i % len(key)]
    # Validate digest
    secret = str(CONFIG.get("APP_SECRET", "")).encode("utf-8")
    calc = hashlib.sha256(bytes(plain) + secret).digest()
    if calc != digest_stored:
        raise ValueError("Incorrect password or corrupted encrypted file")
    # Write plain file
    with open(p, "wb") as out:
        out.write(plain)
    try:
        CONFIG["DB_PASSWORD"] = password
    except Exception:
        pass


def get_conn() -> sqlite3.Connection:
    """
    Open a new connection to the SQLite database with sane defaults for
    concurrency.

    The function first tries the primary database path stored in
    ``CONFIG['DB_PATH']``.  If that fails (e.g. the network share
    containing the primary DB is down), it falls back to any paths
    listed in ``CONFIG['ALT_DB_PATHS']``.  The first successful
    connection is returned.  On every connection we enable Write‑Ahead
    Logging (WAL) and set a generous busy timeout to improve
    concurrent access when the database is on a shared location.

    Returns
    -------
    sqlite3.Connection
        A connection to the inventory database.
    """
    primary = CONFIG.get("DB_PATH", DB_PATH)
    alt_paths = CONFIG.get("ALT_DB_PATHS", []) or []
    candidates = [primary] + list(alt_paths)
    last_err: Optional[Exception] = None
    for idx, path in enumerate(candidates):
        try:
            # Use check_same_thread=False to allow connections from multiple
            # threads (e.g. GUI and worker) and set a timeout to 30s to
            # prevent immediate lock errors.  Configure WAL and busy timeout
            # after connecting to support concurrent reads and a single writer.
            conn = sqlite3.connect(path, timeout=30.0, check_same_thread=False)
            try:
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("PRAGMA busy_timeout=30000;")
            except Exception:
                pass
            # Update mirror flag: index 0 means primary; others are mirrors
            try:
                CONFIG["FROM_MIRROR"] = (idx != 0)
            except Exception:
                pass
            return conn
        except Exception as e:
            last_err = e
            continue
    # If all attempts failed, propagate the last encountered error
    if last_err:
        raise last_err
    # Fallback should not be reached, but return primary path
    conn = sqlite3.connect(primary, timeout=30.0, check_same_thread=False)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=30000;")
    except Exception:
        pass
    return conn


def _replicate_db_file() -> None:
    """
    Replicate the primary database file to all configured alternate paths.

    Whenever a mutating operation (insert, update, delete) completes,
    this helper will be invoked to copy the SQLite file located at
    ``CONFIG['DB_PATH']`` to each path in ``CONFIG['ALT_DB_PATHS']``.
    Failures during copying are silently ignored; replication will
    automatically retry on the next write.
    """
    import shutil

    primary = CONFIG.get("DB_PATH", DB_PATH)
    alt_paths = CONFIG.get("ALT_DB_PATHS", []) or []
    if not os.path.exists(primary):
        return
    for dest in alt_paths:
        try:
            # Ensure the destination directory exists
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copy2(primary, dest)
        except Exception:
            # Ignore errors; next call may succeed
            pass


def now_str() -> str:
    """
    Return the current timestamp formatted for SQLite (YYYY‑MM‑DD HH:MM:SS).

    Returns
    -------
    str
        The current date/time as a string.
    """
    return time.strftime("%Y-%m-%d %H:%M:%S")


def init_db() -> None:
    """
    Initialise the database schema.

    Creates the tables if they do not already exist.  This function can
    safely be called multiple times; it will not drop existing tables.  It
    also seeds default user accounts when the user table is empty, so
    freshly created databases will have the default credentials required
    for initial logins.
    """
    conn = get_conn()
    cur = conn.cursor()

    # Create the users table.  Roles enforce a whitelist of roles.
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT CHECK(role IN ('superadmin','admin','user')) DEFAULT 'user',
            created_at TEXT
        );
        """
    )

    # After creating the items table ensure certain columns exist for
    # backwards compatibility.  Older databases may lack the 'approved'
    # column or the newer 'serial_number' column.  The following block
    # inspects the existing table schema and adds missing columns as
    # required.
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='items'")
    if cur.fetchone():
        cur.execute("PRAGMA table_info(items)")
        cols = [row[1] for row in cur.fetchall()]
        # Add the approved flag if missing and default to approved for
        # existing rows.  Without this column the GUI cannot track
        # pending items.
        if "approved" not in cols:
            cur.execute("ALTER TABLE items ADD COLUMN approved INTEGER DEFAULT 1")
            cur.execute("UPDATE items SET approved=1 WHERE approved IS NULL")
        # Add the serial_number column if missing.  Default NULL values
        # are acceptable; they simply mean no serial number is recorded.
        if "serial_number" not in cols:
            cur.execute("ALTER TABLE items ADD COLUMN serial_number TEXT")


    # ------------------------------------------------------------------
    # Migration: ensure the `users` table has a `password` column.  Some
    # earlier versions of this application stored passwords under
    # different column names (e.g. `p_hash` or `password_hash`).  If the
    # existing table does not have a `password` column we add it and, if
    # possible, populate it from the old column.  This prevents
    # "no such column: password" errors when inserting or updating users.
    cur.execute("PRAGMA table_info(users)")
    user_cols = [row[1] for row in cur.fetchall()]
    if 'password' not in user_cols:
        # Add the password column so new queries work.  Use TEXT type to
        # align with our schema.  Existing rows will have NULL/empty
        # values unless we populate from an old hash column below.
        cur.execute("ALTER TABLE users ADD COLUMN password TEXT")
        # If an old hash column exists, copy its value into the new column.
        if 'p_hash' in user_cols:
            cur.execute("UPDATE users SET password = p_hash")
        elif 'password_hash' in user_cols:
            cur.execute("UPDATE users SET password = password_hash")
        elif 'pass' in user_cols:
            cur.execute("UPDATE users SET password = pass")
        # Otherwise leave password as NULL; the GUI will require a
        # password reset for such accounts.

    # Create the audit_log table for recording actions.  This table is used
    # by the application to log operations (e.g. add/edit/delete).  It is
    # created here to avoid failures when log_action is called before
    # audit_log has been created.
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT,
            action TEXT,
            item_id INTEGER,
            details TEXT,
            created_at TEXT
        );
        """
    )

    # Create the items table.  An additional column, ``serial_number``, stores
    # a product's unique serial number separate from the product name.
    # Existing databases may not have this column; a migration below will
    # add it if required.
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_code TEXT NOT NULL,
            name TEXT NOT NULL,
            product_id TEXT,
            serial_number TEXT,
            status TEXT NOT NULL,
            deployed_to TEXT,
            ip_address TEXT,
            item_type TEXT CHECK(item_type IN ('Part','Laptop','Desktop','Peripherals')) DEFAULT 'Part',
            unit INTEGER,
            unit_price REAL,
            total_price REAL,
            purchase_date TEXT,
            invoice_no TEXT,
            vendor_name TEXT,
            warranty_left TEXT,
            created_at TEXT,
            updated_at TEXT,
            approved INTEGER DEFAULT 1
        );
        """
    )

    # Create the components table; components are associated with a parent item.
    #
    # Columns:
    #  * seq_no   – legacy integer sequence number (may be unused in modern
    #    versions but retained for backwards compatibility).
    #  * seq_name – human friendly sequence identifier composed from the
    #    parent item's deployed_to value and the component name (e.g.
    #    "Dept 10_Corsair RAM").  This column supersedes seq_no for
    #    display and ordering.
    #  * unit, unit_price, total_price – numeric quantities allowing the
    #    cost of each component to be recorded.  Total price can be
    #    automatically derived from unit and unit_price if omitted.
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS components (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            parent_item_id INTEGER NOT NULL,
            kind TEXT,
            seq_no INTEGER,
            seq_name TEXT,
            sub_code TEXT,
            name TEXT,
            product_id TEXT,
            status TEXT,
            unit INTEGER,
            unit_price REAL,
            total_price REAL,
            created_at TEXT,
            updated_at TEXT,
            FOREIGN KEY(parent_item_id) REFERENCES items(id) ON DELETE CASCADE
        );
        """
    )

    # Migrate existing components tables: add new columns if missing.  Some
    # databases may predate the addition of seq_name/unit/unit_price/total_price.
    cur.execute("PRAGMA table_info(components)")
    comp_cols = [row[1] for row in cur.fetchall()]
    # Add seq_name if not present
    if "seq_name" not in comp_cols:
        cur.execute("ALTER TABLE components ADD COLUMN seq_name TEXT")
    # Add unit if missing
    if "unit" not in comp_cols:
        cur.execute("ALTER TABLE components ADD COLUMN unit INTEGER")
    # Add unit_price if missing
    if "unit_price" not in comp_cols:
        cur.execute("ALTER TABLE components ADD COLUMN unit_price REAL")
    # Add total_price if missing
    if "total_price" not in comp_cols:
        cur.execute("ALTER TABLE components ADD COLUMN total_price REAL")

    # Seed default users if none exist.  When initialising a new database
    # we create a set of twelve accounts: one superadmin, one admin and
    # ten regular user accounts (user1 through user10).  All default
    # passwords are '1234' hashed via SHA‑256.  Admins and superadmins
    # can later rename these accounts.  This ensures the system has
    # sufficient pre‑created accounts for early use without hitting
    # the user creation limit.
    cur.execute("SELECT COUNT(*) FROM users")
    count = cur.fetchone()[0]
    if count == 0:
        defaults = [
            ("superadmin", sha256("1234"), "superadmin"),
            ("admin", sha256("1234"), "admin"),
        ]
        # Generate ten user accounts user1..user10
        for i in range(1, 11):
            uname = f"user{i}"
            defaults.append((uname, sha256("1234"), "user"))
        cur.executemany(
            "INSERT INTO users(username, password, role, created_at) VALUES(?,?,?,?)",
            [(u, p, r, now_str()) for (u, p, r) in defaults],
        )

    conn.commit()
    conn.close()
    # Ensure that our required custom superadmin accounts exist.  This helper
    # inserts "Shawan" (password "01632") and "ATN" (password "1230") if
    # they are missing.  It runs after closing the initial connection so
    # that migrations and default seeding have completed.  Calling this
    # function multiple times is safe; it will not create duplicate rows.
    try:
        _ensure_custom_users()
    except Exception:
        # If anything goes wrong during user insertion, silently ignore
        # to avoid interrupting app startup.  Missing users can be
        # added manually via the GUI.
        pass


def seed_defaults() -> None:
    """
    Seed default data into the database.

    Currently this simply calls `init_db()` to ensure the schema and
    default users are present.  Additional default items or components
    could be added here if desired.
    """
    init_db()


def sha256(text: str) -> str:
    """
    Compute the SHA‑256 hash of the given text.

    This helper is used for password hashing.  It does not salt the hash
    because the example inventory application stores simple hashed
    passwords; in a real system you should use a salted hash (e.g.
    bcrypt).  The function returns a hex string.

    Parameters
    ----------
    text: str
        The plain text to hash.

    Returns
    -------
    str
        The SHA‑256 hash of the input as a hexadecimal string.
    """
    import hashlib
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


# --------------------------------------------------------------------
#                        Additional User Helpers
# --------------------------------------------------------------------

def get_all_users() -> list:
    """
    Retrieve all users from the database.

    Returns
    -------
    list of dict
        Each element contains the user's id, username and role.
    """
    conn = get_conn()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT id, username, role FROM users")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delete_user(user_id: int) -> None:
    """
    Delete a user by ID.  Does nothing if the user does not exist.

    Parameters
    ----------
    user_id: int
        The unique ID of the user to delete.
    """
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()


def update_item_total_from_components(parent_item_id: int) -> None:
    """
    Recalculate and update the total_price of a Desktop or Laptop item
    based on the sum of its component total prices.

    This helper queries the item to determine its category and current
    total price.  For Desktop and Laptop items, if the existing
    total_price is NULL or zero (meaning the user did not supply a
    price), the function computes the sum of the total_price of
    associated components and writes this value back to the items table.
    For other categories or where the item already has a non-zero
    total_price, the function leaves the value unchanged.

    Parameters
    ----------
    parent_item_id: int
        The ID of the item whose total_price should be recalculated.
    """
    try:
        conn = get_conn()
        cur = conn.cursor()
        # Fetch the item type and current total_price
        cur.execute("SELECT item_type, total_price FROM items WHERE id=?", (parent_item_id,))
        row = cur.fetchone()
        if not row:
            conn.close()
            return
        item_type, current_total = row
        # Only recalc for Desktop and Laptop
        if item_type not in ("Desktop", "Laptop"):
            conn.close()
            return
        # Interpret None as 0 for comparison
        if current_total is None:
            current_total_val = 0.0
        else:
            try:
                current_total_val = float(current_total)
            except Exception:
                current_total_val = 0.0
        # Sum the component total_price values; ignore NULL entries
        cur.execute("SELECT SUM(total_price) FROM components WHERE parent_item_id=?", (parent_item_id,))
        comp_sum = cur.fetchone()[0]
        if comp_sum is None:
            comp_sum = 0.0
        # Update if the current total is None or zero
        if current_total is None or current_total_val == 0.0:
            cur.execute(
                "UPDATE items SET total_price=?, updated_at=? WHERE id=?",
                (comp_sum, now_str(), parent_item_id),
            )
            conn.commit()
        conn.close()
    except Exception:
        # Ignore failures; the UI will compute totals on the fly if needed
        pass


# --------------------------------------------------------------------
#                            User Operations
# --------------------------------------------------------------------

def get_user(username: str, password: Optional[str] = None) -> Optional[Tuple[int, str, str, str]]:
    """
    Retrieve a user record and optionally validate the password.

    Parameters
    ----------
    username : str
        The username of the user to fetch.
    password : str, optional
        If provided, this plain‑text password will be hashed and compared
        to the stored password hash.  If it does not match, the function
        returns ``None`` even if the user exists.  This allows older
        callers who passed both username and password to ``get_user``
        to continue working without errors.

    Returns
    -------
    Optional[Tuple[int, str, str, str]]
        A tuple of ``(id, username, password_hash, role)`` if the user
        exists (and, if a password was provided, it matches).  Returns
        ``None`` if the user does not exist or the password does not
        match.
    """
    conn = get_conn()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(
        "SELECT id, username, password, role FROM users WHERE username=?",
        (username,),
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    # Always return a 4‑tuple if the user exists
    result = (row["id"], row["username"], row["password"], row["role"])
    # If a plain password was provided, validate it against the stored hash
    if password is not None:
        # Hash the provided plain‑text password and compare to stored hash.
        # ``sha256`` is defined in this module below.
        if sha256(password) != row["password"]:
            return None
    return result


def insert_user(username: str, password: str, role: str = "user") -> None:
    """
    Insert a new user.

    Parameters
    ----------
    username: str
        The new user's username.
    password: str
        Plain text password; will be hashed with SHA‑256.
    role: str
        Role for the user; must be one of superadmin, admin, or user.
    """
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users(username, password, role, created_at) VALUES(?,?,?,?)",
        (username, sha256(password), role, now_str()),
    )
    conn.commit()
    conn.close()

# Provide `add_user` as an alias for backwards compatibility.
add_user = insert_user


# --------------------------------------------------------------------
#                        Custom Seeding Helpers
#
# Some deployments of this application rely on the presence of specific
# administrative accounts (e.g. ``Shawan`` and ``ATN``) for ongoing
# operations.  These helpers ensure that these accounts exist on every
# run, regardless of whether the database was freshly initialised,
# encrypted/decrypted or migrated from an older version.  Without
# explicitly inserting these users when missing, a newly created or
# decrypted database would only contain the built‑in default accounts,
# causing logins for these custom superadmin users to fail.

def _ensure_custom_users() -> None:
    """
    Ensure required custom superadmin accounts exist.

    This helper inserts the accounts ``Shawan`` (password ``01632``)
    and ``ATN`` (password ``1230``) into the ``users`` table if they
    are absent.  The passwords are hashed via SHA‑256 before
    insertion.  If an account already exists, it is left unchanged.
    The current timestamp is recorded for the ``created_at`` field.

    This function should be called after the tables have been
    created (e.g. from within ``init_db()``) and can be safely
    invoked multiple times without creating duplicate rows.
    """
    try:
        conn = get_conn()
        cur = conn.cursor()
        required = [
            ("Shawan", "01632", "superadmin"),
            ("ATN", "1230", "superadmin"),
        ]
        for uname, pwd, role in required:
            cur.execute("SELECT id FROM users WHERE username=?", (uname,))
            row = cur.fetchone()
            if not row:
                # Insert the user with hashed password
                cur.execute(
                    "INSERT INTO users(username, password, role, created_at) VALUES(?,?,?,?)",
                    (uname, sha256(pwd), role, now_str()),
                )
        conn.commit()
        conn.close()
    except Exception:
        # If anything fails, ignore silently; missing users will
        # simply not be available until the next successful call.
        try:
            conn.close()
        except Exception:
            pass


# --------------------------------------------------------------------
#                            Item Operations
# --------------------------------------------------------------------

def insert_item(
    actor: str,
    item_code: str,
    name: str,
    product_id: Optional[str],
    serial_number: Optional[str] = None,
    status: str = "Available",
    deployed_to: Optional[str] = None,
    ip_address: Optional[str] = None,
    item_type: str = "Part",
    unit: Optional[int] = None,
    unit_price: Optional[float] = None,
    total_price: Optional[float] = None,
    purchase_date: Optional[str] = None,
    invoice_no: Optional[str] = None,
    vendor_name: Optional[str] = None,
    warranty_left: Optional[str] = None,
    approved: Optional[int] = None,
) -> int:
    """
    Insert a new item into the inventory.

    Parameters
    ----------
    actor: str
        Username performing the operation (not used here but accepted for logging if needed).
    item_code: str
        Inventory code for the item.
    name: str
        Human‑readable name for the item.
    product_id: str, optional
        Manufacturer's product ID or serial.
    status: str
        Stock status (In Stock, Deployed, Under Repair, Retired).
    deployed_to: str, optional
        Person or location to which the item is deployed.
    ip_address: str, optional
        Network IP address associated with the item.
    item_type: str
        Category: Part, Laptop, or Desktop.
    unit: int, optional
        Quantity purchased.
    unit_price: float, optional
        Price per unit.
    total_price: float, optional
        Total price.  If None and unit and unit_price are provided, this
        value is computed automatically.
    purchase_date: str, optional
        Date of purchase.
    invoice_no: str, optional
        Invoice or receipt number.
    vendor_name: str, optional
        Supplier name.
    warranty_left: str, optional
        Warranty description (e.g. "12 months" or "365 days left").

    Returns
    -------
    int
        The new item's database ID.
    """
    conn = get_conn()
    cur = conn.cursor()
    if total_price is None and unit is not None and unit_price is not None:
        total_price = float(unit) * float(unit_price)
    # Determine approval state: new items are unapproved (0) unless
    # explicitly overridden.  Approval happens via `approve_item` later.
    approved_flag = 0 if approved is None else int(bool(approved))
    cur.execute(
        """
        INSERT INTO items(
            item_code, name, product_id, serial_number, status, deployed_to,
            ip_address, item_type, unit, unit_price, total_price, purchase_date,
            invoice_no, vendor_name, warranty_left, created_at, updated_at, approved
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            item_code,
            name,
            product_id,
            serial_number,
            status,
            deployed_to,
            ip_address,
            item_type,
            unit,
            unit_price,
            total_price,
            purchase_date,
            invoice_no,
            vendor_name,
            warranty_left,
            now_str(),
            now_str(),
            approved_flag,
        ),
    )
    item_id = cur.lastrowid
    conn.commit()
    conn.close()
    # Replicate the updated database to any alternate locations
    _replicate_db_file()
    return item_id


def update_item(
    actor: str,
    item_id: int,
    item_code: str,
    name: str,
    product_id: Optional[str],
    serial_number: Optional[str] = None,
    status: str = "Available",
    deployed_to: Optional[str] = None,
    ip_address: Optional[str] = None,
    item_type: str = "Part",
    unit: Optional[int] = None,
    unit_price: Optional[float] = None,
    total_price: Optional[float] = None,
    purchase_date: Optional[str] = None,
    invoice_no: Optional[str] = None,
    vendor_name: Optional[str] = None,
    warranty_left: Optional[str] = None,
    approved: Optional[int] = None,
) -> None:
    """
    Update an existing item.

    Parameters are the same as for `insert_item`, except for `item_id` which
    identifies the record to update.  If `total_price` is None and both
    `unit` and `unit_price` are provided, the total price is recalculated.
    """
    conn = get_conn()
    cur = conn.cursor()
    if total_price is None and unit is not None and unit_price is not None:
        total_price = float(unit) * float(unit_price)
    # Build the base update statement.  Always update the timestamp.
    sql = (
        "UPDATE items SET "
        "item_code=?, name=?, product_id=?, serial_number=?, status=?, deployed_to=?, ip_address=?, item_type=?, "
        "unit=?, unit_price=?, total_price=?, purchase_date=?, invoice_no=?, vendor_name=?, warranty_left=?, "
        "updated_at=?"
    )
    params = [
        item_code,
        name,
        product_id,
        serial_number,
        status,
        deployed_to,
        ip_address,
        item_type,
        unit,
        unit_price,
        total_price,
        purchase_date,
        invoice_no,
        vendor_name,
        warranty_left,
        now_str(),
    ]
    # If an approval flag is provided, update it; otherwise leave the
    # current approval value untouched.
    if approved is not None:
        sql += ", approved=?"
        params.append(int(bool(approved)))
    sql += " WHERE id=?"
    params.append(item_id)
    cur.execute(sql, tuple(params))
    conn.commit()
    conn.close()
    _replicate_db_file()


def delete_item(actor: str, item_id: int) -> None:
    """
    Delete an item by its ID.

    Parameters
    ----------
    actor: str
        Username performing the operation (unused but accepted for logging).
    item_id: int
        Identifier of the item to delete.
    """
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM items WHERE id=?", (item_id,))
    conn.commit()
    conn.close()
    _replicate_db_file()


def fetch_items(
    search: Optional[str] = None,
    status_filter: Optional[str] = None,
    type_filter: Optional[str] = None,
    include_pending: bool = False,
) -> Iterable[Dict[str, object]]:
    """
    Retrieve items from the database with optional filtering.

    Parameters
    ----------
    search: str, optional
        A free text search applied to the `item_code` and `name` fields.
    status_filter: str, optional
        If provided, only items with this status are returned.  Pass 'All'
        or None to disable the filter.
    type_filter: str, optional
        If provided, only items of this type (Part/Laptop/Desktop) are
        returned.  Pass 'All' or None to disable the filter.

    Returns
    -------
    Iterable[Dict[str, object]]
        A list of dicts representing items.
    """
    # Purge any unapproved items older than two days before fetching
    cleanup_unapproved_items()
    conn = get_conn()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    query = "SELECT * FROM items"
    clauses = []
    params = []
    if search:
        # Apply a case‑insensitive search to multiple fields.  To
        # broaden the search beyond just item_code and name, include
        # several textual columns.  Numeric fields are cast to TEXT so
        # they can be matched by LIKE as well.  Each field is
        # compared using LIKE with surrounding wildcards.  Future
        # maintainers can add or remove fields here to adjust the
        # search scope.
        search_cols = [
            "item_code",
            "name",
            "product_id",
            "serial_number",
            "status",
            "deployed_to",
            "item_type",
            "unit",
            "unit_price",
            "total_price",
            "purchase_date",
            "invoice_no",
            "vendor_name",
            "warranty_left",
            "updated_at",
            "ip_address",
        ]
        like_exprs = []
        for col in search_cols:
            # Cast numeric columns to text for LIKE comparison
            if col in ("unit", "unit_price", "total_price"):
                like_exprs.append(f"CAST({col} AS TEXT) LIKE ?")
            else:
                like_exprs.append(f"{col} LIKE ?")
        clauses.append("(" + " OR ".join(like_exprs) + ")")
        params.extend([f"%{search}%"] * len(search_cols))
    if status_filter and status_filter != "All":
        clauses.append("status = ?")
        params.append(status_filter)
    if type_filter and type_filter != "All":
        clauses.append("item_type = ?")
        params.append(type_filter)
    # Exclude unapproved items for non-admin users by default
    if not include_pending:
        clauses.append("approved = 1")
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY id DESC"
    cur.execute(query, params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


# --------------------------------------------------------------------
#                         Component Operations
# --------------------------------------------------------------------

def insert_component(
    actor: str,
    parent_item_id: int,
    kind: str,
    seq_name: Optional[str],
    sub_code: Optional[str],
    name: str,
    product_id: Optional[str],
    status: Optional[str],
    unit: Optional[int] = None,
    unit_price: Optional[float] = None,
    total_price: Optional[float] = None,
) -> int:
    """
    Insert a new component for a specific item.

    Parameters
    ----------
    actor: str
        Username performing the operation (unused but accepted for future logging).
    parent_item_id: int
        Identifier of the parent item to which the component belongs.
    kind: str
        Component type category (desktop_part or laptop_peripheral).
    seq_name: str, optional
        Human friendly sequence identifier, usually composed of the
        deployed_to value of the parent item and the component's name
        (e.g. "Dept 10_Corsair RAM").  Can be None.
    sub_code: str, optional
        Sub code or secondary identifier.  Optional.
    name: str
        Name of the component.
    product_id: str, optional
        Manufacturer's product ID or code.  Optional.
    status: str, optional
        Status (e.g. Available, Damaged).  Optional.
    unit: int, optional
        Quantity of this component.  Optional.
    unit_price: float, optional
        Price per unit.  Optional.
    total_price: float, optional
        Total price for this component.  If None and both unit and
        unit_price are provided, total_price is computed automatically.

    Returns
    -------
    int
        The new component's database ID.
    """
    conn = get_conn()
    cur = conn.cursor()
    # Compute total_price if necessary
    if total_price is None and unit is not None and unit_price is not None:
        try:
            total_price = float(unit) * float(unit_price)
        except Exception:
            total_price = None
    cur.execute(
        """
        INSERT INTO components(
            parent_item_id, kind, seq_name, sub_code, name, product_id, status,
            unit, unit_price, total_price, created_at, updated_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            parent_item_id,
            kind,
            seq_name,
            sub_code,
            name,
            product_id,
            status,
            unit,
            unit_price,
            total_price,
            now_str(),
            now_str(),
        ),
    )
    cid = cur.lastrowid
    conn.commit()
    conn.close()
    _replicate_db_file()
    # Note: automatic total update for the parent item has been removed.
    # The GUI now exposes an explicit "Update Price" action which calls
    # update_item_total_from_components when appropriate.
    return cid


def update_component(
    actor: str,
    component_id: int,
    seq_name: Optional[str],
    sub_code: Optional[str],
    name: str,
    product_id: Optional[str],
    status: Optional[str],
    unit: Optional[int] = None,
    unit_price: Optional[float] = None,
    total_price: Optional[float] = None,
) -> None:
    """
    Update an existing component.

    Parameters mirror those of `insert_component` except that
    ``component_id`` identifies which component to update.
    ``total_price`` will be calculated from unit × unit_price if
    omitted and both values are provided.
    """
    conn = get_conn()
    cur = conn.cursor()
    # Recompute total_price if necessary
    if total_price is None and unit is not None and unit_price is not None:
        try:
            total_price = float(unit) * float(unit_price)
        except Exception:
            total_price = None
    cur.execute(
        """
        UPDATE components
        SET seq_name=?, sub_code=?, name=?, product_id=?, status=?,
            unit=?, unit_price=?, total_price=?, updated_at=?
        WHERE id=?
        """,
        (
            seq_name,
            sub_code,
            name,
            product_id,
            status,
            unit,
            unit_price,
            total_price,
            now_str(),
            component_id,
        ),
    )
    conn.commit()
    conn.close()
    _replicate_db_file()
    # Note: automatic total update for the parent item has been removed.  The
    # GUI triggers this when the user presses the "Update Price" button.


def fetch_components(parent_item_id: int, kind: str) -> Iterable[Dict[str, object]]:
    """
    Get all components for a parent item and kind (desktop_part or laptop_peripheral).
    Returns a list of dictionaries ordered by ID.
    """
    conn = get_conn()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM components WHERE parent_item_id=? AND kind=? ORDER BY id",
        (parent_item_id, kind),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def delete_component(actor: str, component_id: int) -> None:
    """
    Delete a component by its ID.

    Parameters
    ----------
    actor: str
        Username performing the operation (unused but accepted for logging).
    component_id: int
        Identifier of the component to delete.
    """
    # Before deletion, find the parent item id to later recalculate totals
    parent_id = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT parent_item_id FROM components WHERE id=?", (component_id,))
        row = cur.fetchone()
        if row:
            parent_id = row[0]
        cur.execute("DELETE FROM components WHERE id=?", (component_id,))
        conn.commit()
        conn.close()
    except Exception:
        # On failure, ensure connection is closed if open
        try:
            conn.close()
        except Exception:
            pass
        raise
    # Replicate DB file
    _replicate_db_file()
    # Note: automatic total update for the parent item has been removed.  The
    # GUI triggers this when the user presses the "Update Price" button.


def count_components(parent_item_id: int, kind: str) -> int:
    """
    Count the number of components for a given item and kind.

    Returns
    -------
    int
        Number of matching components.
    """
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT COUNT(*) FROM components WHERE parent_item_id=? AND kind=?",
        (parent_item_id, kind),
    )
    count = cur.fetchone()[0]
    conn.close()
    return count


def list_users() -> Iterable[Dict[str, object]]:
    """
    List all users with their ID, username and role.

    Returns
    -------
    Iterable[Dict[str, object]]
        A list of user dictionaries.
    """
    conn = get_conn()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT id, username, role FROM users ORDER BY id")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def set_password(username: str, new_password: str) -> None:
    """
    Reset a user's password.
    The password is hashed with SHA‑256 before storage.
    """
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET password=?, created_at=? WHERE username=?",
        (sha256(new_password), now_str(), username),
    )
    conn.commit()
    conn.close()


def log_action(actor: str, action: str, item_id: Optional[int] = None, details: Optional[str] = None) -> None:
    """
    Record an operation in the audit log.

    Parameters
    ----------
    actor: str
        Username performing the action.
    action: str
        A short description of the action (e.g. 'ADD', 'EDIT', 'DELETE').
    item_id: int, optional
        The ID of the affected item, if applicable.
    details: str, optional
        Additional textual details about the operation.
    """
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO audit_log(actor, action, item_id, details, created_at) VALUES(?,?,?,?,?)",
        (actor, action, item_id, details, now_str()),
    )
    conn.commit()
    conn.close()


# --------------------------------------------------------------------
#                          Approval Operations
# --------------------------------------------------------------------
def cleanup_unapproved_items() -> None:
    """
    Delete unapproved items older than two days.

    This function should be invoked periodically (e.g. when listing
    items) to enforce the requirement that pending items must be
    authorised by an admin or superadmin within two days.  Items
    inserted with ``approved=0`` and a ``created_at`` older than two
    days will be removed.  Removal is silent but could be logged via
    ``audit_log`` if desired.
    """
    conn = get_conn()
    cur = conn.cursor()
    # Delete any items that are unapproved and older than 2 days
    cur.execute(
        "DELETE FROM items WHERE approved=0 AND (julianday('now') - julianday(created_at)) > 2"
    )
    conn.commit()
    conn.close()
    # replication will occur via delete_item when using high-level helpers,
    # but direct cleanup should also replicate to keep mirrors consistent
    _replicate_db_file()


def approve_item(actor: str, item_id: int) -> None:
    """
    Mark an item as approved.

    Only admin or superadmin roles should call this helper.  The
    ``approved`` flag is set to 1 and ``updated_at`` is refreshed.
    """
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE items SET approved=1, updated_at=? WHERE id=?",
        (now_str(), item_id),
    )
    conn.commit()
    conn.close()
    _replicate_db_file()
