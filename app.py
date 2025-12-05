# app.py (Part 1)
import tkinter as tk
import datetime as dt
import os, sys
from tkinter import ttk, messagebox, simpledialog
from tkinter import filedialog
from db import *

APP_TITLE = "ATN Inventory Manager"
WELCOME_TEXT = (
    "ATN Inventory System by Shawan\n"
    "Welcome back, Administrator. System privileges enabled.\n"
    "You now have full operational control.\n"

)


def asset_path(relative_path: str) -> str:
    """
    Resolves file paths for both source run and PyInstaller .exe.
    Example: asset_path("assets/atn_logo.png")
    """
    # When packaged by PyInstaller, sys._MEIPASS stores the temp dir of extracted files
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))

    return os.path.join(base_path, relative_path)


class LoginWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE); self.geometry("520x520")
        self.resizable(False, False)
        # Apply a subtle checkerboard pattern to the login window.
        # This draws alternating light grey squares on a canvas that fills
        # the window.  The canvas is lowered below the other widgets
        # so it does not interfere with layout.  The pattern is purely
        # decorative and uses small squares to avoid distraction.
        self.configure(bg="white")
        try:
            bg_canvas = tk.Canvas(self, highlightthickness=0)
            bg_canvas.place(x=0, y=0, relwidth=1, relheight=1)
            square = 20
            # Draw a 20px checkerboard pattern across the window.  Use
            # winfo_width/height if available; fallback to geometry values.
            width = 520
            height = 520
            try:
                width = max(int(self.winfo_width()), 520)
                height = max(int(self.winfo_height()), 520)
            except Exception:
                pass
            for i in range(0, width, square):
                for j in range(0, height, square):
                    # Use soft yellow tones for a warm background
                    color = "#fff9e6" if (i // square + j // square) % 2 == 0 else "#fff2cc"
                    bg_canvas.create_rectangle(i, j, i + square, j + square, fill=color, outline=color)
            bg_canvas.lower()  # send behind other widgets
        except Exception:
            # If canvas creation fails, fall back silently to a solid background
            pass

        # If the database is locked (only an .enc file exists), prompt
        # the user for the encryption password before proceeding.  The
        # plain database will be restored by decrypt_db() if the
        # correct password is provided.  If the user fails to
        # authenticate after three attempts, the application exits.
        try:
            from db import is_db_encrypted, decrypt_db, CONFIG
            if is_db_encrypted():
                attempts = 3
                while attempts > 0:
                    pwd = simpledialog.askstring(
                        "Unlock Database",
                        "The database is locked. Enter encryption password:",
                        show="*",
                    )
                    if not pwd:
                        # User cancelled
                        attempts = 0
                        break
                    try:
                        decrypt_db(pwd)
                        # Save the password for re‑encryption on exit
                        CONFIG["DB_PASSWORD"] = pwd
                        # After successful decryption ensure the schema and
                        # required users exist.  This will create tables and
                        # insert any missing default/custom accounts without
                        # overwriting existing data.
                        try:
                            from db import init_db
                            init_db()
                        except Exception:
                            pass
                        break
                    except Exception:
                        attempts -= 1
                        messagebox.showerror("Incorrect Password", f"Incorrect password. {attempts} attempt(s) remaining.")
                if attempts == 0:
                    messagebox.showerror("Locked", "Failed to unlock the database. Exiting.")
                    self.destroy()
                    # Terminate the app entirely
                    sys.exit()
        except Exception:
            # If encryption helpers fail, silently continue; the app will operate on plain DB
            pass
        # If the database is not encrypted, ensure it is initialised now.
        try:
            from db import init_db, is_db_encrypted
            if not is_db_encrypted():
                init_db()
        except Exception:
            pass
        ttk.Label(
            self,
            text=(
                "ATN NEWS INVENTORY MANAGEMENT SYSTEM\n"
                "Developed By\n"
                "Shawan Karmokar\n"
                "Executive, System Administrator\n"
                "ATN NEWS\n"
                "বাংলার ২৪ ঘণ্টা\n"
            ),
            font=("Times New Roman", 10, "bold"),
            justify="center",
            anchor="center"
        ).pack(pady=(25, 5))

        try:
            # Safe logo loader (works in editor and frozen exe)
            self.logo = None
            try:
                from PIL import Image, ImageTk
                # primary attempt (PyInstaller-aware)
                logo_file = asset_path("assets/atn_logo.png")

                # fallback attempts if the case/extension differs or path missing
                if not os.path.exists(logo_file):
                    # try common variations
                    candidates = [
                        "assets/atn_logo.png", "assets/ATN_logo.png",
                        "assets/logo.png", "assets/atn_logo.jpg"
                    ]
                    for c in candidates:
                        p = asset_path(c)
                        if os.path.exists(p):
                            logo_file = p
                            break

                if os.path.exists(logo_file):
                    img = Image.open(logo_file)
                    img = img.resize((120, 120))
                    self.logo = ImageTk.PhotoImage(img)
                    tk.Label(self, image=self.logo, bg="white").pack(pady=10)
                else:
                    ttk.Label(self, text="[Logo missing: assets/atn_logo.png]").pack(pady=10)
            except Exception as e:
                # Pillow not installed or other error
                ttk.Label(self, text=f"[Logo not loaded: {e}]").pack(pady=10)

        except Exception:
            ttk.Label(self,text="[Logo missing]").pack(pady=10)
        self.username = ttk.Entry(self, width=25)
        self.username.pack(pady=(20,5)); self.username.insert(0,"admin")
        self.password = ttk.Entry(self, width=25, show="*"); self.password.pack()
        ttk.Button(self, text="Login", command=self.try_login).pack(pady=15)
        self.bind("<Return>", lambda e: self.try_login())

    def try_login(self):
        """
        Attempt to authenticate the provided username/password.

        The underlying ``get_user`` function returns a tuple of
        ``(id, username, password_hash, role)`` when a user exists, or
        ``None`` if the user does not exist or the password does not
        match.  To make the returned value easy to work with in the
        rest of the GUI, we convert this tuple into a dictionary with
        ``id``, ``username`` and ``role`` keys.  Older code that
        expected ``get_user`` to return a dictionary can therefore
        continue to use ``user['role']`` without modification.
        """
        u = self.username.get().strip()
        p = self.password.get().strip()
        user_info = get_user(u, p)
        if not user_info:
            messagebox.showerror("Login Failed", "Invalid credentials.")
            return
        # Convert the (id, username, password_hash, role) tuple to a dict
        if isinstance(user_info, tuple) and len(user_info) == 4:
            user = {
                "id": user_info[0],
                "username": user_info[1],
                "role": user_info[3],
            }
        else:
            # In case get_user returns a dict (future compatibility), use it directly
            user = user_info
        messagebox.showinfo(
            "Welcome",
            f"{WELCOME_TEXT}\n\nLogged in as {user['role'].upper()}"
        )
        self.destroy()
        MainApp(user).mainloop()

    def asset_path(rel):
        """
        Works both from source and from a PyInstaller EXE.
        """
        if getattr(sys, 'frozen', False):
            base = sys._MEIPASS  # extracted temp dir used by PyInstaller
        else:
            base = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(base, rel)
# app.py (Part 2)
class MainApp(tk.Tk):
    def __init__(self, user):
        super().__init__()
        self.user=user; self.title(f"{APP_TITLE} - {user['role'].upper()}"); self.geometry("1350x750")

        # Draw a subtle checkerboard pattern as the background of the main
        # application window.  This uses a canvas that covers the entire
        # window and draws alternating squares in light colours.  The canvas
        # is lowered to sit behind all other widgets.  If any error
        # occurs (e.g. Tk on certain platforms), the pattern falls back
        # silently.
        try:
            bg_canvas = tk.Canvas(self, highlightthickness=0)
            bg_canvas.place(x=0, y=0, relwidth=1, relheight=1)
            size = 30  # size of each square in pixels
            width = 1350
            height = 750
            try:
                width = max(int(self.winfo_width()), width)
                height = max(int(self.winfo_height()), height)
            except Exception:
                pass
            for i in range(0, width, size):
                for j in range(0, height, size):
                    # Yellow themed chequer pattern for main window
                    colour = "#fff9e6" if ((i // size + j // size) % 2 == 0) else "#fff2cc"
                    bg_canvas.create_rectangle(i, j, i + size, j + size, fill=colour, outline=colour)
            bg_canvas.lower()
        except Exception:
            pass

        tb=ttk.Frame(self,padding=8); tb.pack(fill="x")
        ttk.Button(tb,text="Add Item",command=self.add_item).pack(side="left")
        ttk.Button(tb,text="Edit Item",command=self.edit_item).pack(side="left",padx=6)
        ttk.Button(tb,text="Delete",command=self.delete_item).pack(side="left")
        ttk.Button(tb, text="Refresh", command=self.refresh).pack(side="left", padx=6)
        # Export items.  This button allows the user to export the
        # visible items to either a Word or Excel file.  PDF export
        # was removed due to missing matplotlib on some systems.
        ttk.Button(tb, text="Export", command=self.export_items).pack(side="left", padx=6)

        # DB Settings button to manage database location and redundancy.  Only
        # available to admin/superadmin.  This opens a dialog to set the
        # primary DB or add mirrors.
        if self.user["role"] in ("admin", "superadmin"):
            ttk.Button(tb, text="DB Settings", command=self.open_db_settings).pack(side="left", padx=6)

        # Provide a way for admins and superadmins to load an existing or
        # locked database file.  This function merges the old "Open DB"
        # and "Unlock DB" behaviours into a single entry.  The user will
        # be prompted for confirmation and a password when necessary.
        if self.user["role"] in ("admin", "superadmin"):
            ttk.Button(tb, text="Open DB", command=self.open_or_unlock_db).pack(side="left", padx=6)

        # Manage Users button (superadmin only).  Allows the superadmin to add or remove users
        # and change passwords.  Limit to creating up to 12 users.
        if self.user["role"] in ("admin", "superadmin"):
            ttk.Button(tb, text="Manage Users", command=self.manage_users).pack(side="left", padx=6)

        # Lock/Unlock Database button.  Only the superadmin may encrypt
        # or decrypt the database on demand.  Admins and regular users
        # can still unlock the database at application start when an
        # encrypted file is present, but they cannot trigger lock/unlock
        # actions during runtime via the UI.
        if self.user["role"] == "superadmin":
            ttk.Button(tb, text="Lock DB", command=self.lock_or_unlock_db).pack(side="left", padx=6)

        # Define tree columns including the approval flag.  The 'approved'
        # column will be hidden for non‑admin users by setting its width to
        # zero.  Admins and superadmins can view this column to see
        # which items are pending approval.
        # Define the table columns.  The first column "no" displays a
        # sequential number rather than the database ID.  The ID column is
        # included but will be hidden by default.  A new column
        # "serial_number" holds the product's unique serial number.
        cols = (
            "no",
            "id",
            "item_code",
            "name",
            "product_id",
            "serial_number",
            "ip_address",
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
            "approved",
        )
        # Wrap the main treeview in a frame with a vertical scrollbar.  This
        # ensures that long lists of items remain navigable.  The Treeview
        # itself is configured to use the scrollbar via the yscrollcommand.
        tree_frame = ttk.Frame(self)
        tree_frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings")
        # Vertical scrollbar
        self.tree_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.tree_scroll.set)
        # Configure row tags for approval state.  Pending (unapproved)
        # items will appear in grey, whereas approved items use the
        # default black foreground.  The 'pending' tag is applied later
        # during refresh() and search_items().
        try:
            self.tree.tag_configure("pending", foreground="#999999")
            self.tree.tag_configure("approved", foreground="black")
        except Exception:
            pass
        # Assign column widths.  The approved column width will be set
        # according to the user's role below.
        widths = [
            40,   # no
            0,    # id hidden
            120,  # item_code
            160,  # name
            200,  # product_id (Product Full Name)
            150,  # serial_number
            0,    # ip_address hidden
            100,  # status
            120,  # deployed_to
            90,   # item_type
            60,   # unit
            100,  # unit_price
            100,  # total_price
            100,  # purchase_date
            120,  # invoice_no
            120,  # vendor_name
            120,  # warranty_left
            130,  # updated_at
            80,   # approved
        ]
        for c, w in zip(cols, widths):
            # Customise header names for certain columns
            if c == "no":
                header = "No."
            elif c == "id":
                header = "ID"
            elif c == "product_id":
                header = "Product Full Name"
            elif c == "serial_number":
                header = "Serial Number"
            elif c == "approved":
                header = "Approved"
            elif c == "ip_address":
                header = ""  # Hide IP column header
            else:
                header = c.replace("_", " ").title()
            self.tree.heading(c, text=header)
            self.tree.column(c, width=w)

        # Hide the internal ID and IP address columns so that they do not display
        try:
            self.tree.column("id", width=0, minwidth=0)
            self.tree.heading("id", text="")
        except Exception:
            pass
        try:
            self.tree.column("ip_address", width=0, minwidth=0)
            self.tree.heading("ip_address", text="")
        except Exception:
            pass
        # Layout: tree on the left, scrollbar on the right
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree_scroll.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>",lambda e:self.refresh_components())

        # Bind F2 key on the items table to open the edit dialog.  Pressing F2 when
        # a row in the main table is selected will call edit_item().  This
        # matches typical spreadsheet behaviour where F2 edits the current cell.
        self.tree.bind("<F2>", lambda e: self.edit_item())

        # Components live panel
        cf=ttk.LabelFrame(self,text="Components (Live Edit for Admins)"); cf.pack(fill="x",pady=5)
        # Draw a decorative background pattern inside the components frame.  A
        # canvas is created to fill the label frame and draws alternating
        # pale yellow squares.  The canvas is lowered behind other
        # widgets so it does not interfere with layout.  If creation
        # fails (e.g. unsupported on some platforms), the frame remains
        # plain.
        try:
            bgc = tk.Canvas(cf, highlightthickness=0)
            bgc.place(x=0, y=0, relwidth=1, relheight=1)
            size_c = 20
            # Determine pixel dimensions; fallback if unavailable
            width_c = max(int(cf.winfo_width()), 600)
            height_c = max(int(cf.winfo_height()), 150)
            for i in range(0, width_c, size_c):
                for j in range(0, height_c, size_c):
                    colour = "#fffbe6" if ((i // size_c + j // size_c) % 2 == 0) else "#fff8d1"
                    bgc.create_rectangle(i, j, i + size_c, j + size_c, fill=colour, outline=colour)
            bgc.lower()
        except Exception:
            pass
        # Define component columns including custom sequence name, pricing and total
        comp_cols = (
            "display_id",
            "seq_name",
            "sub_code",
            "name",
            "product_id",
            "status",
            "unit",
            "unit_price",
            "total_price",
        )
        # Frame for components tree and its scrollbar
        comp_frame = ttk.Frame(cf)
        comp_frame.pack(fill="x", padx=5, pady=3)
        self.tree_c = ttk.Treeview(comp_frame, columns=comp_cols, show="headings", height=6)
        # Define headings and widths.  The first column (display_id) shows
        # hierarchical IDs like 17.1; label it "id" for compatibility.
        for c, w in zip(
            comp_cols,
            (60, 140, 80, 180, 140, 80, 60, 90, 90),
        ):
            if c == "display_id":
                header = "id"
            elif c == "seq_name":
                header = "Seq Name"
            elif c == "unit_price":
                header = "Unit Price"
            elif c == "total_price":
                header = "Total"
            else:
                header = c.replace("_", " ")
            self.tree_c.heading(c, text=header)
            self.tree_c.column(c, width=w)
        # Vertical scrollbar for components
        self.comp_scroll = ttk.Scrollbar(comp_frame, orient="vertical", command=self.tree_c.yview)
        self.tree_c.configure(yscrollcommand=self.comp_scroll.set)
        self.tree_c.pack(side="left", fill="x", expand=True)
        self.comp_scroll.pack(side="right", fill="y")
        # Bind editing via double click and F2
        self.tree_c.bind("<Double-1>", self.live_edit_component)
        self.tree_c.bind("<F2>", self.live_edit_component)

        bb=ttk.Frame(cf); bb.pack(fill="x")
        ttk.Button(bb,text="Add",command=self.add_component).pack(side="left")
        ttk.Button(bb,text="Delete",command=self.delete_component).pack(side="left",padx=5)

        # Button to update parent item price from its components.  When pressed,
        # this sums the Total column of all components belonging to the
        # selected item (for Desktop or Laptop) and writes the result back
        # into the main item table.  This manual action replaces the
        # previous automatic behaviour.
        ttk.Button(bb, text="Update Price", command=self.update_parent_price).pack(side="left", padx=5)

        # Search bar for components.  Allows filtering the components list
        # by sub‑code, name or product ID.  The search is case‑insensitive
        # and updates the component tree without affecting stored data.
        comp_search_frame = ttk.Frame(cf)
        comp_search_frame.pack(fill="x", padx=5, pady=(0, 3))
        ttk.Label(comp_search_frame, text="Search Components:").pack(side="left")
        self.comp_search_var = tk.StringVar()
        comp_search_entry = ttk.Entry(comp_search_frame, textvariable=self.comp_search_var, width=20)
        comp_search_entry.pack(side="left")
        ttk.Button(comp_search_frame, text="Search", command=self.search_components).pack(side="left", padx=(2, 0))
        comp_search_entry.bind("<Return>", lambda e: self.search_components())

        # Display IP address below the components for desktop/laptop items.  This
        # label is updated by refresh_components().  Initially empty.
        self.ip_display = ttk.Label(cf, text="")
        self.ip_display.pack(fill="x", padx=5, pady=(2, 0))

        # Display parent IP address when a Desktop is selected
        self.ip_display_var = tk.StringVar(value="")
        self.ip_display_label = ttk.Label(bb, textvariable=self.ip_display_var, foreground="blue")
        self.ip_display_label.pack(side="right", padx=5)

        # Only admin/superadmin should see the approve button (labelled Authorise)
        if self.user["role"] in ("admin", "superadmin"):
            ttk.Button(tb, text="Authorize", command=self.approve_item).pack(side="left", padx=6)

        # Hide the approved column for non‑admins by setting width to 0
        if self.user["role"] not in ("admin", "superadmin"):
            self.tree.column("approved", width=0, minwidth=0)
            self.tree.heading("approved", text="")

        # --- Search bar for the main items table ---
        # Place a search entry and button on the toolbar after other buttons.  The user can
        # type a fragment of the item code or name and click Search to filter the table.
        search_frame = ttk.Frame(tb)
        search_frame.pack(side="left", padx=6)
        ttk.Label(search_frame, text="Search:").pack(side="left")
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=15)
        search_entry.pack(side="left")
        ttk.Button(search_frame, text="Search", command=self.search_items).pack(side="left")
        # Bind Enter key in the search entry to perform search
        search_entry.bind("<Return>", lambda e: self.search_items())

        # --- Switch user button ---
        # Allow any user to quickly log out and return to the login screen without
        # closing the application entirely.  This is especially useful when the
        # application is packaged as an executable.  A confirmation prompt
        # prevents accidental logouts.
        ttk.Button(tb, text="Switch User", command=self.switch_user).pack(side="right", padx=6)

        # Bind a hidden key sequence to show developer information.  Pressing
        # Ctrl+Shift+D will display an about message with the names of the
        # developers.  This provides a concealed Easter egg without cluttering
        # the UI.  Only the main window listens for this key.
        self.bind_all("<Control-Shift-D>", lambda e: self.show_about())

        # Display a loading overlay while initial data is loaded.  On large
        # databases this prevents the application appearing unresponsive.
        loader = self._show_loader("Loading data...")
        try:
            self.refresh()
        finally:
            if loader:
                try:
                    loader.destroy()
                except Exception:
                    pass

        # Bind Shift+= (which corresponds to '+') to calculate the sum of
        # total_price values across all visible items.  When triggered,
        # it iterates the rows currently displayed in the main table,
        # accumulates the Total Price column (ignoring non-numeric
        # entries) and shows the result in an information dialog.
        self.bind_all("<Shift-KeyPress-=>", self.show_total_sum)

        # Intercept window close to ensure we encrypt the database on exit.
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # -------- Items --------
    def refresh(self):
        # Clear existing rows
        for i in self.tree.get_children():
            self.tree.delete(i)
        # Determine whether to include pending (unapproved) items based on role
        include_pending = self.user["role"] in ("admin", "superadmin")
        # Preserve any active search filter
        search_term = getattr(self, "_current_search", None)
        # Enumerate items so the first column shows a simple sequential number
        rows = list(fetch_items(search=search_term, include_pending=include_pending))
        for idx, r in enumerate(rows, start=1):
            # Compose row values; the first column 'no' gets idx
            row_vals = []
            for k in self.tree["columns"]:
                if k == "no":
                    row_vals.append(str(idx))
                else:
                    row_vals.append(r.get(k, ""))
            # Choose tag based on approval state (0 => pending).
            try:
                approved_flag = int(r.get("approved", 1))
            except Exception:
                approved_flag = 1
            tag = ("pending",) if (include_pending and not approved_flag) else ("approved",)
            self.tree.insert(
                "",
                "end",
                values=row_vals,
                tags=tag,
            )
        self.refresh_components()
        # If the database connection fell back to a mirror, notify the user once
        try:
            from db import CONFIG as _dbcfg
            if _dbcfg.get("FROM_MIRROR"):
                messagebox.showwarning(
                    "Database Fallback",
                    "Primary database unavailable. Loaded data from local mirror."
                )
                # reset flag to avoid repeated warnings
                _dbcfg["FROM_MIRROR"] = False
        except Exception:
            pass

    def search_items(self):
        """
        Filter the items in the main table based on the search term in
        ``self.search_var``.  The search is applied to the item code and
        name fields.  After filtering the tree, the components area is
        refreshed to correspond to the first matching item (if any).
        """
        term = self.search_var.get().strip()
        # Store the current search term so that subsequent refreshes retain the filter
        self._current_search = term if term else None
        # Rebuild the table with the filtered results
        for i in self.tree.get_children():
            self.tree.delete(i)
        include_pending = self.user["role"] in ("admin", "superadmin")
        rows = list(fetch_items(search=term, include_pending=include_pending))
        for idx, r in enumerate(rows, start=1):
            row_vals = []
            for k in self.tree["columns"]:
                if k == "no":
                    row_vals.append(str(idx))
                else:
                    row_vals.append(r.get(k, ""))
            try:
                approved_flag = int(r.get("approved", 1))
            except Exception:
                approved_flag = 1
            tag = ("pending",) if (include_pending and not approved_flag) else ("approved",)
            self.tree.insert(
                "",
                "end",
                values=row_vals,
                tags=tag,
            )
        # After filtering, refresh the components for the first row if any
        self.refresh_components()

    def switch_user(self):
        """
        Log out the current user and return to the login screen.  A confirmation
        dialog is shown to prevent accidental logouts.  Once confirmed the
        current window is destroyed and a new login window is launched.
        """
        if messagebox.askyesno("Switch User", "Are you sure you want to switch user?\nUnsaved changes will be lost."):
            # Destroy current main window and open login
            self.destroy()
            # Re-launch login window
            try:
                LoginWindow().mainloop()
            except Exception as e:
                print(e)

    def open_shared_db(self):
        """
        Allow the superadmin to choose an existing SQLite database file to
        open as the primary database.  This does not offer mirroring or
        replication options; it simply switches ``CONFIG['DB_PATH']`` to
        the selected file, initialises the schema if necessary and refreshes
        the UI.  Useful for opening shared or remote database locations.
        """
        if self.user["role"] != "superadmin":
            return
        # Ask for password confirmation before opening a database.  Verify the
        # current user's credentials via get_user().  Abort on failure.
        try:
            pwd = simpledialog.askstring("Confirm", "Enter your password to proceed:", show="*")
        except Exception:
            pwd = None
        if not pwd:
            return
        try:
            from db import get_user
            # Validate credentials; get_user returns None if invalid
            if not get_user(self.user["username"], pwd):
                messagebox.showerror("Authorization", "Incorrect password. Operation cancelled.")
                return
        except Exception:
            # proceed without check if get_user not available
            pass
        path = filedialog.askopenfilename(
            title="Open Existing Database",
            filetypes=[("SQLite database", "*.db"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            from db import CONFIG, init_db
            CONFIG["DB_PATH"] = path
            # Ensure the DB exists and has the required schema
            init_db()
            messagebox.showinfo("Database Loaded", f"Database set to:\n{path}")
            self.refresh()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ------------------------------------------------------------------
    #                       Database Loader / Unlocker
    # ------------------------------------------------------------------
    def _show_loader(self, message: str = "Loading..."):
        """
        Display a simple modal loading overlay with the given message.

        The overlay prevents interaction with the main window while a
        long‑running operation is in progress.  Call the returned
        object's ``destroy()`` method to hide the loader.
        """
        try:
            loader = tk.Toplevel(self)
            loader.transient(self)
            loader.grab_set()
            loader.overrideredirect(True)
            # Centre the loader over the parent window
            w, h = 250, 100
            try:
                x = self.winfo_rootx() + (self.winfo_width() // 2) - (w // 2)
                y = self.winfo_rooty() + (self.winfo_height() // 2) - (h // 2)
            except Exception:
                x, y = 100, 100
            loader.geometry(f"{w}x{h}+{x}+{y}")
            ttk.Label(loader, text=message, anchor="center").pack(expand=True, fill="both", padx=10, pady=10)
            loader.update()
            return loader
        except Exception:
            return None

    def open_or_unlock_db(self):
        """
        Allow an admin or superadmin to load an existing plain or encrypted
        database file.  When choosing an encrypted ``*.db.enc`` file the
        user will be prompted for the encryption password.  If the
        password is incorrect the operation is aborted without
        modifying the current database.  Changing the database path
        requires confirmation to avoid accidental data loss.
        """
        # Only admin and superadmin may open a database
        if self.user["role"] not in ("admin", "superadmin"):
            return
        # Confirm intention
        proceed = messagebox.askyesno(
            "Change Database",
            "Loading a different database will replace the current data.\n"
            "Are you sure you want to continue?",
        )
        if not proceed:
            return
        # Authenticate the current user via their login password
        try:
            pwd_confirm = simpledialog.askstring(
                "Confirm", "Enter your login password to proceed:", show="*"
            )
        except Exception:
            pwd_confirm = None
        if not pwd_confirm:
            return
        try:
            # Validate credentials; get_user returns None if invalid
            if not get_user(self.user["username"], pwd_confirm):
                messagebox.showerror("Authorization", "Incorrect password. Operation cancelled.")
                return
        except Exception:
            pass
        # Let the user choose a file; support .db and .db.enc
        path = filedialog.askopenfilename(
            title="Open or Unlock Database",
            filetypes=[("Database files", "*.db;*.db.enc"), ("All files", "*.*")],
        )
        if not path:
            return
        # Determine base path and whether file is encrypted
        is_enc = path.endswith(".enc")
        base_path = path[:-4] if is_enc else path
        # Ask for encryption password if needed
        enc_pwd = None
        if is_enc:
            try:
                enc_pwd = simpledialog.askstring(
                    "Unlock Database", "Enter the encryption password:", show="*"
                )
            except Exception:
                enc_pwd = None
            if not enc_pwd:
                return
        # Show loading overlay
        loader = self._show_loader("Loading database...")
        try:
            # If encrypted, attempt to decrypt.  Errors will raise and abort
            if is_enc:
                try:
                    decrypt_db(enc_pwd, path=base_path)
                except Exception as exc:
                    messagebox.showerror("Error", f"Failed to unlock database: {exc}")
                    return
            # Switch DB path to selected file
            CONFIG["DB_PATH"] = base_path
            # Initialise schema if needed
            try:
                init_db()
            except Exception as exc:
                messagebox.showerror("Error", str(exc))
                return
            # Refresh UI to load new data
            self.refresh()
            # Inform user
            messagebox.showinfo("Database Loaded", f"Database set to:\n{base_path}")
        finally:
            # Hide loading overlay
            try:
                if loader:
                    loader.destroy()
            except Exception:
                pass

    def search_components(self):
        """
        Filter the list of displayed components based on the value of
        ``self.comp_search_var``.  Only components whose sub-code,
        name or product ID contains the search term (case insensitive) will
        be shown.  If the search box is empty, the full list of
        components for the selected item is displayed.  This method
        operates on the in-memory list stored in ``self._current_components``
        by ``refresh_components``.
        """
        term = (self.comp_search_var.get() or "").strip().lower()
        # Clear the existing displayed rows
        for i in self.tree_c.get_children():
            self.tree_c.delete(i)
        comps = getattr(self, "_current_components", [])
        # If there is no search term, display all components
        if not term:
            for r in comps:
                self.tree_c.insert("", "end", values=[r.get(k, "") for k in self.tree_c["columns"]])
            return
        # Otherwise display only matching components
        for i, r in enumerate(comps, start=1):
            # Build search fields from sub_code, name and product_id
            fields = [
                str(r.get("sub_code", "")).lower(),
                str(r.get("name", "")).lower(),
                str(r.get("product_id", "")).lower(),
            ]
            if any(term in f for f in fields):
                # Compose display id and seq_name similarly to refresh_components
                itm = self.get_selected_item() or {}
                prefix = str(itm.get("no", "")).strip()
                display_id = f"{prefix}.{i}" if prefix else str(i)
                seq_name_val = r.get("seq_name")
                if not seq_name_val:
                    seq_name_val = f"{itm.get('deployed_to','')}_{r.get('name','')}".strip('_')
                vals = [
                    display_id,
                    seq_name_val,
                    r.get("sub_code", ""),
                    r.get("name", ""),
                    r.get("product_id", ""),
                    r.get("status", ""),
                    r.get("unit", ""),
                    r.get("unit_price", ""),
                    r.get("total_price", ""),
                ]
                cid = r.get("id")
                self.tree_c.insert("", "end", iid=str(cid), values=vals)

    def show_about(self):
        """
        Display a hidden about dialog showing the developers' names.  This
        function is bound to Ctrl+Shift+D and is not visible in the UI.
        """
        messagebox.showinfo("About", "ATN Inventory Manager\n\nDesigned and Developed by\nShawan and Shovon")

    def show_total_sum(self, event=None):
        """
        Calculate and display the sum of the Total Price column across all
        currently visible items.  This method is invoked when the user
        presses Shift+= (i.e. the '+' key).  It ignores rows where the
        total_price value cannot be converted to a float.  The result
        is shown in a message box.

        Parameters
        ----------
        event: optional
            Tkinter event (unused but accepted for binding compatibility).
        """
        try:
            # Find the index of the total_price column
            cols = list(self.tree["columns"])
            if "total_price" not in cols:
                return
            idx = cols.index("total_price")
            total = 0.0
            for row_id in self.tree.get_children():
                vals = self.tree.item(row_id, "values")
                if idx < len(vals):
                    v = vals[idx]
                    try:
                        total += float(v)
                    except Exception:
                        pass
            messagebox.showinfo("Total Amount", f"Sum of Total Price: {round(total, 2):,.2f}")
        except Exception as e:
            try:
                messagebox.showerror("Error", str(e))
            except Exception:
                pass

    def update_parent_price(self):
        """
        Update the total price of the selected Desktop or Laptop item
        using the sum of its component total prices.  This function is
        invoked by the "Update Price" button in the components panel.
        Only Desktop and Laptop items are eligible; Parts and
        Peripherals are unaffected.
        """
        itm = self.get_selected_item()
        if not itm:
            return
        # Only compute for Desktop or Laptop items
        if itm.get("item_type") not in ("Desktop", "Laptop"):
            messagebox.showinfo("Not Applicable", "Price update is only available for Desktop or Laptop items.")
            return
        try:
            # Update via DB helper; this sums component totals and updates parent
            update_item_total_from_components(int(itm["id"]))
            # Refresh UI to reflect new total
            self.refresh()
            messagebox.showinfo("Price Updated", "Total price updated from components.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def get_selected_item(self):
        sel=self.tree.selection()
        if not sel: return None
        vals=self.tree.item(sel[0],"values")
        keys=self.tree["columns"]
        return dict(zip(keys,vals))

    def add_item(self):
        ItemDialog(self,self.user,mode="add")

    def edit_item(self):
        itm=self.get_selected_item()
        if not itm: return
        ItemDialog(self,self.user,mode="edit",data=itm)

    # ------------------------------------------------------------------
    #                       Database Encryption Control
    # ------------------------------------------------------------------
    def lock_or_unlock_db(self):
        """
        Encrypt (lock) or decrypt (unlock) the database on demand.

        If the database is not currently encrypted (a plain .db file
        exists), this function prompts the admin/superadmin for their
        own password to authorise the action.  After successful
        authorisation it asks for an encryption password and writes
        an encrypted copy of the database alongside the plain file.
        The plain file remains in place so that the application can
        continue operating; it will be removed when the application
        exits, ensuring that only the encrypted copy remains.

        If the database is already encrypted (a .db.enc file exists
        without a plain .db), the function prompts for the encryption
        password and decrypts the file.  The decrypted plain file
        allows the application to run normally; the encrypted file
        remains for backup.
        """
        from db import is_db_encrypted, encrypt_db, decrypt_db, get_user, CONFIG
        # Verify actor has privileges.  Only the superadmin may invoke
        # lock/unlock operations during runtime.  Admins can still unlock
        # encrypted databases at startup via the LoginWindow prompt.
        if self.user["role"] != "superadmin":
            return
        # Ask for current account password to authorise this sensitive action
        try:
            pwd = simpledialog.askstring("Confirm", "Enter your login password to proceed:", show="*")
        except Exception:
            pwd = None
        if not pwd:
            return
        try:
            if not get_user(self.user["username"], pwd):
                messagebox.showerror("Authorization", "Incorrect password. Operation cancelled.")
                return
        except Exception:
            # If get_user fails, deny access
            messagebox.showerror("Error", "User lookup failed.")
            return
        # Determine current state and prompt accordingly
        if not is_db_encrypted():
            # Encrypt the database
            try:
                enc_pwd = simpledialog.askstring(
                    "Encrypt Database",
                    "Enter a new password for encryption:",
                    show="*",
                )
            except Exception:
                enc_pwd = None
            if not enc_pwd:
                return
            try:
                encrypt_db(enc_pwd)
                messagebox.showinfo(
                    "Database Locked",
                    "Database encrypted successfully. The plain database will remain usable until you exit the application.",
                )
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {e}")
        else:
            # Decrypt
            try:
                dec_pwd = simpledialog.askstring(
                    "Unlock Database",
                    "Enter the encryption password:",
                    show="*",
                )
            except Exception:
                dec_pwd = None
            if not dec_pwd:
                return
            try:
                decrypt_db(dec_pwd)
                messagebox.showinfo("Database Unlocked", "Database decrypted successfully. You may continue using the application.")
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {e}")

    # ------------------------------------------------------------------
    #                       Window Close Handler
    # ------------------------------------------------------------------
    def on_close(self):
        """
        Handle application shutdown.  Before exiting the GUI, encrypt
        the database if it is not already encrypted and remove the
        plain file.  This ensures that outside of the running
        application, the database remains protected.  The encryption
        password used will be taken from CONFIG['DB_PASSWORD'] if set.
        """
        from db import is_db_encrypted, encrypt_db, CONFIG
        import os
        try:
            # If the DB is not yet encrypted, ensure it is encrypted before
            # exit.  If a password has been stored from a prior unlock
            # operation, use it.  Otherwise prompt the user to supply a
            # password now.  If the user cancels, the database will
            # remain unencrypted.
            if not is_db_encrypted():
                pwd = CONFIG.get("DB_PASSWORD")
                if not pwd:
                    try:
                        pwd = simpledialog.askstring(
                            "Encrypt Database",
                            "Enter a password to encrypt the database:",
                            show="*",
                        )
                    except Exception:
                        pwd = None
                if pwd:
                    try:
                        encrypt_db(pwd)
                    except Exception:
                        pass
            # Remove the plain database file so only the encrypted copy
            # remains.  This prevents accidental inspection when the
            # application is closed.  When the app starts, decrypt_db
            # will restore the plain file.
            plain_path = CONFIG.get("DB_PATH")
            if plain_path and os.path.exists(plain_path):
                try:
                    os.remove(plain_path)
                except Exception:
                    pass
        except Exception:
            # Ignore any errors during clean up
            pass
        # Proceed with destroying the window
        try:
            self.destroy()
        except Exception:
            pass

    def delete_item(self):
        itm=self.get_selected_item()
        if not itm: return
        if messagebox.askyesno("Delete","Delete selected item?"):
            # Use the db helper which logs actor; pass the logged-in username
            delete_item(self.user["username"], itm["id"])
            self.refresh()

    def print_items(self):
        """
        Export the current items table to a Word (.docx) file.

        This function no longer offers PDF export because matplotlib may
        not be available on all target systems.  The user is prompted to
        choose a save location for the .docx file.  The exported
        document will omit internal columns (No., ID, IP Address) and
        will exclude the Approved column for non-admin users.
        """
        # Choose save path; only Word export is supported now
        path = filedialog.asksaveasfilename(
            title="Export Items to Word",
            defaultextension=".docx",
            filetypes=[("Word Document", "*.docx")],
        )
        if not path:
            return
        # Gather items based on current search and approval settings
        include_pending = self.user["role"] in ("admin", "superadmin")
        search_term = getattr(self, "_current_search", None)
        try:
            all_rows = list(fetch_items(search=search_term, include_pending=include_pending))
        except Exception as exc:
            messagebox.showerror("Error", str(exc))
            return
        # Determine columns to export (drop internal columns).  Remove
        # Approved for non-admin exports.
        columns = list(self.tree["columns"])
        for drop in ("no", "id", "ip_address"):
            if drop in columns:
                columns.remove(drop)
        exclude_approved = self.user["role"] not in ("admin", "superadmin")
        if exclude_approved and "approved" in columns:
            columns.remove("approved")
        # Prepare headers for the export
        headers = []
        for c in columns:
            if c == "product_id":
                headers.append("Product Full Name")
            elif c == "serial_number":
                headers.append("Serial Number")
            elif c == "unit_price":
                headers.append("Unit Price")
            elif c == "total_price":
                headers.append("Total Price")
            elif c == "purchase_date":
                headers.append("Purchase Date")
            elif c == "invoice_no":
                headers.append("Invoice No")
            elif c == "vendor_name":
                headers.append("Vendor Name")
            elif c == "warranty_left":
                headers.append("Warranty Left")
            elif c == "updated_at":
                headers.append("Updated At")
            elif c == "item_code":
                headers.append("Item Code")
            elif c == "name":
                headers.append("Name")
            else:
                headers.append(c.replace("_", " ").title())
        # Compose table data
        table_rows = []
        for r in all_rows:
            row_data = []
            for col in columns:
                val = r.get(col, "")
                row_data.append(str(val) if val is not None else "")
            table_rows.append(row_data)
        # Export to docx
        try:
            self._export_to_docx(path, headers, table_rows)
            messagebox.showinfo("Success", f"Word document saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to write DOCX: {e}")

    # ------------------------------------------------------------------
    #                            Export Items
    # ------------------------------------------------------------------
    def export_items(self):
        """
        Export the current items table to either a Word (.docx) or Excel
        (.xlsx) file.  The user is prompted to choose the destination
        filename and format.  Internal columns (No., ID, IP Address)
        are omitted, and the Approved column is excluded for
        non‑administrative users.  This function supersedes
        `print_items` which only exported to Word.
        """
        # Ask for destination path and format
        path = filedialog.asksaveasfilename(
            title="Export Items",
            defaultextension=".docx",
            filetypes=[("Word Document", "*.docx"), ("Excel Workbook", "*.xlsx")],
        )
        if not path:
            return
        ext = os.path.splitext(path)[1].lower()
        # Collect items subject to current search and approval filter
        include_pending = self.user["role"] in ("admin", "superadmin")
        search_term = getattr(self, "_current_search", None)
        try:
            rows = list(fetch_items(search=search_term, include_pending=include_pending))
        except Exception as exc:
            messagebox.showerror("Error", str(exc))
            return
        # Determine which columns to include
        columns = list(self.tree["columns"])
        for drop in ("no", "id", "ip_address"):
            if drop in columns:
                columns.remove(drop)
        if self.user["role"] not in ("admin", "superadmin") and "approved" in columns:
            columns.remove("approved")
        # Construct headers
        headers = []
        for c in columns:
            if c == "product_id":
                headers.append("Product Full Name")
            elif c == "serial_number":
                headers.append("Serial Number")
            elif c == "unit_price":
                headers.append("Unit Price")
            elif c == "total_price":
                headers.append("Total Price")
            elif c == "purchase_date":
                headers.append("Purchase Date")
            elif c == "invoice_no":
                headers.append("Invoice No")
            elif c == "vendor_name":
                headers.append("Vendor Name")
            elif c == "warranty_left":
                headers.append("Warranty Left")
            elif c == "updated_at":
                headers.append("Updated At")
            elif c == "item_code":
                headers.append("Item Code")
            elif c == "name":
                headers.append("Name")
            else:
                headers.append(c.replace("_", " ").title())
        # Build data rows
        table_rows = []
        for r in rows:
            row = []
            for col in columns:
                val = r.get(col, "")
                row.append(str(val) if val is not None else "")
            table_rows.append(row)
        # Dispatch based on extension
        if ext == ".xlsx":
            try:
                self._export_to_xlsx(path, headers, table_rows)
                messagebox.showinfo("Success", f"Excel file saved to:\n{path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to write Excel file: {e}")
        else:
            try:
                self._export_to_docx(path, headers, table_rows)
                messagebox.showinfo("Success", f"Word document saved to:\n{path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to write DOCX: {e}")

    def _export_to_xlsx(self, path: str, headers: list, rows: list) -> None:
        """
        Write the provided data to an Excel workbook (.xlsx).  The
        xlsxwriter module is used to build a worksheet from scratch.

        Parameters
        ----------
        path: str
            Destination filename; if it does not end with .xlsx, the
            extension will be appended.
        headers: list of str
            Column headers for the worksheet.
        rows: list of list of str
            Row data.
        """
        import xlsxwriter
        # Ensure correct extension
        if not path.lower().endswith(".xlsx"):
            path = path + ".xlsx"
        workbook = xlsxwriter.Workbook(path)
        worksheet = workbook.add_worksheet("Items")
        bold = workbook.add_format({"bold": True})
        # Write headers
        for col_idx, header in enumerate(headers):
            worksheet.write(0, col_idx, header, bold)
        # Write rows
        for row_idx, row in enumerate(rows, start=1):
            for col_idx, cell in enumerate(row):
                worksheet.write(row_idx, col_idx, cell)
        # Auto size columns
        for col_idx, header in enumerate(headers):
            max_len = len(str(header))
            for row in rows:
                try:
                    length = len(str(row[col_idx]))
                except Exception:
                    length = 0
                if length > max_len:
                    max_len = length
            worksheet.set_column(col_idx, col_idx, max_len + 2)
        workbook.close()

    def _export_to_docx(self, path: str, headers: list, rows: list) -> None:
        """
        Create a simple Word document (.docx) containing a table with the
        provided headers and rows.  This helper builds the minimal set
        of XML parts required for a docx and writes them using the
        zipfile module.  It does not depend on external libraries.

        Parameters
        ----------
        path: str
            Destination filename (should end with .docx)
        headers: list of str
            Column headers for the table
        rows: list of list of str
            Row data; each row is a list of cell values corresponding to headers
        """
        import zipfile
        from xml.sax.saxutils import escape

        # Ensure extension
        if not path.lower().endswith('.docx'):
            path = path + '.docx'
        # Build document.xml with a table
        # Construct table grid: equal widths for each column.  Word uses units of
        # twentieths of a point (dxa).  We'll set each column to 2000 dxa (~1 inch).
        num_cols = len(headers)
        col_width = 2000
        # Build table grid
        grid_cols_xml = ''.join([f'<w:gridCol w:w="{col_width}"/>' for _ in headers])
        # Build the header row
        header_cells_xml = ''
        for h in headers:
            txt = escape(str(h))
            header_cells_xml += (
                '<w:tc>'
                f'<w:tcPr><w:tcW w:w="{col_width}" w:type="dxa"/></w:tcPr>'
                '<w:p><w:r><w:rPr><w:b/></w:rPr><w:t>' + txt + '</w:t></w:r></w:p>'
                '</w:tc>'
            )
        header_row_xml = f'<w:tr>{header_cells_xml}</w:tr>'
        # Build data rows
        data_rows_xml = ''
        for row in rows:
            cells_xml = ''
            for val in row:
                text = escape(str(val) if val is not None else '')
                cells_xml += (
                    '<w:tc>'
                    f'<w:tcPr><w:tcW w:w="{col_width}" w:type="dxa"/></w:tcPr>'
                    '<w:p><w:r><w:t>' + text + '</w:t></w:r></w:p>'
                    '</w:tc>'
                )
            data_rows_xml += f'<w:tr>{cells_xml}</w:tr>'
        # Compose the document.xml body
        document_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            '<w:body>'
            '<w:tbl>'
            '<w:tblPr><w:tblW w:w="0" w:type="auto"/></w:tblPr>'
            f'<w:tblGrid>{grid_cols_xml}</w:tblGrid>'
            f'{header_row_xml}'
            f'{data_rows_xml}'
            '</w:tbl>'
            '<w:p></w:p>'
            '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr>'
            '</w:body>'
            '</w:document>'
        )
        # [Content_Types].xml
        content_types_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '</Types>'
        )
        # _rels/.rels
        rels_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            '</Relationships>'
        )
        # Ensure directories exist inside zip
        with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as docx:
            # Write required files
            docx.writestr('[Content_Types].xml', content_types_xml)
            docx.writestr('_rels/.rels', rels_xml)
            docx.writestr('word/document.xml', document_xml)

    def open_db_settings(self):
        """
        Allow an admin/superadmin to change the primary database location
        or add an additional redundant mirror.  Selecting a new file via
        the file dialog prompts whether to set it as the primary or to
        add it as a mirror.  After changing the primary database, the
        schema will be initialised and the tree refreshed.
        """
        if self.user["role"] not in ("admin", "superadmin"):
            return
        # Ask the user to confirm password before any database configuration.
        try:
            pwd = simpledialog.askstring("Confirm", "Enter your password to change database settings:", show="*")
        except Exception:
            pwd = None
        if not pwd:
            return
        try:
            from db import get_user
            if not get_user(self.user["username"], pwd):
                messagebox.showerror("Authorization", "Incorrect password. Operation cancelled.")
                return
        except Exception:
            pass
        # Ask the user to pick a SQLite file.  Use asksaveasfilename so a
        # new file path can be chosen.  The default extension helps
        # identify SQLite files.
        path = filedialog.asksaveasfilename(
            title="Select or create a SQLite database",
            defaultextension=".db",
            filetypes=[("SQLite database", "*.db"), ("All files", "*.*")],
        )
        if not path:
            return
        # Ask whether to set as primary
        if messagebox.askyesno("Primary Database", "Use this file as the primary database?\nClick 'No' to add as a mirror."):
            # Set as primary DB
            from db import CONFIG, init_db, _replicate_db_file
            # Update the primary path
            CONFIG["DB_PATH"] = path
            # Ensure the DB exists and has tables
            init_db()
            # Replicate the new primary to mirrors (if any)
            _replicate_db_file()
            messagebox.showinfo("Database", f"Primary database set to:\n{path}")
            # Refresh the UI to reflect any new data
            self.refresh()
        else:
            # Add as a mirror location
            from db import CONFIG, _replicate_db_file
            alt_paths = CONFIG.get("ALT_DB_PATHS", []) or []
            if path not in alt_paths:
                alt_paths.append(path)
                CONFIG["ALT_DB_PATHS"] = alt_paths
                # Immediately replicate the current primary to the new mirror
                try:
                    _replicate_db_file()
                    messagebox.showinfo("Mirror Added", f"Mirror database added:\n{path}")
                except Exception as e:
                    messagebox.showerror("Replication Error", str(e))
            else:
                messagebox.showinfo("Mirror Exists", "This path is already configured as a mirror.")

    def approve_item(self):
        """Approve the selected item (admin only)."""
        itm = self.get_selected_item()
        if not itm:
            return
        if messagebox.askyesno("Approve", "Approve selected item?"):
            try:
                # Approve via db helper; actor is logged‑in username
                approve_item(self.user["username"], int(itm["id"]))
                messagebox.showinfo("Approved", "Item approved successfully.")
            except Exception as e:
                messagebox.showerror("Error", str(e))
            self.refresh()

    # -------- Components --------
    def refresh_components(self):
        # Clear existing component rows
        for i in self.tree_c.get_children():
            self.tree_c.delete(i)
        itm = self.get_selected_item()
        if not itm:
            return
        # Determine component kind based on item_type
        kind = None
        item_type = itm.get("item_type")
        if item_type == "Desktop":
            kind = "desktop_part"
        elif item_type == "Laptop":
            kind = "laptop_peripheral"
        # Update IP display for Desktop and Laptop selections
        try:
            if item_type in ("Desktop", "Laptop"):
                ip_val = itm.get("ip_address") or ""
                self.ip_display_var.set(f"IP Address: {ip_val}")
                self.ip_display_label.pack(anchor="w", padx=5, pady=(0, 5))
            else:
                self.ip_display_var.set("")
                self.ip_display_label.pack_forget()
        except Exception:
            pass
        # Retrieve and display components for supported kinds
        if kind:
            comps = list(fetch_components(itm["id"], kind))
            # Save for search filtering
            self._current_components = comps
            # Reset search string when switching items
            if hasattr(self, "comp_search_var"):
                self.comp_search_var.set("")
            # Compute display ID prefix from item's sequential number
            try:
                prefix = str(itm.get("no", "")).strip()
            except Exception:
                prefix = ""
            # Populate component rows
            for idx, r in enumerate(comps, start=1):
                display_id = f"{prefix}.{idx}" if prefix else str(idx)
                # Fallback for seq_name: use stored value or compose on the fly
                seq_name_val = r.get("seq_name")
                if not seq_name_val:
                    seq_name_val = f"{itm.get('deployed_to','')}_{r.get('name','')}".strip('_')
                # Build value list in the same order as tree_c columns
                vals = [
                    display_id,
                    seq_name_val,
                    r.get("sub_code", ""),
                    r.get("name", ""),
                    r.get("product_id", ""),
                    r.get("status", ""),
                    r.get("unit", ""),
                    r.get("unit_price", ""),
                    r.get("total_price", ""),
                ]
                # Use DB component id as the Treeview item ID for easy lookup
                cid = r.get("id")
                self.tree_c.insert("", "end", iid=str(cid), values=vals)
        else:
            # Items without components (e.g. Parts) have no rows
            self._current_components = []

    def add_component(self):
        itm = self.get_selected_item()
        if not itm:
            return
        if self.user["role"] not in ("admin", "superadmin"):
            messagebox.showinfo("Access", "Only admin/superadmin can add components.")
            return
        # Determine component kind only for Desktop and Laptop
        if itm["item_type"] == "Desktop":
            kind = "desktop_part"
        elif itm["item_type"] == "Laptop":
            kind = "laptop_peripheral"
        else:
            messagebox.showinfo("No Components", "Components can only be added to Desktop or Laptop items.")
            return
        # Create a small modal dialog to collect component fields.  Using a
        # Toplevel keeps the window within the application and prevents
        # prompts from appearing behind the main window.
        dlg = tk.Toplevel(self)
        dlg.title("Add Component")
        dlg.transient(self)
        dlg.grab_set()
        # Fields for a component: Name, Sub Code, Product ID, Unit, Unit Price,
        # Total Price and Status.  Seq name is computed automatically from
        # the parent item's deployed_to and the component's name.
        labels = [
            "Name",
            "Sub Code",
            "Product ID",
            "Unit",
            "Unit Price",
            "Total Price",
            "Status",
        ]
        entries = []
        for i, lbl in enumerate(labels):
            ttk.Label(dlg, text=lbl + ":").grid(row=i, column=0, sticky="e", padx=5, pady=3)
            ent = ttk.Entry(dlg, width=25)
            ent.grid(row=i, column=1, padx=5, pady=3)
            entries.append(ent)
        # auto-calc total price when unit or unit price changes
        def recalc_comp_total(_evt=None):
            try:
                unit_val = float(entries[3].get()) if entries[3].get() else None
                price_val = float(entries[4].get()) if entries[4].get() else None
                if unit_val is not None and price_val is not None:
                    entries[5].delete(0, 'end')
                    entries[5].insert(0, str(round(unit_val * price_val, 2)))
            except Exception:
                pass
        entries[3].bind("<KeyRelease>", recalc_comp_total)
        entries[4].bind("<KeyRelease>", recalc_comp_total)

        def on_cancel():
            dlg.destroy()

        def on_save():
            name_val = entries[0].get().strip() or None
            sub_code = entries[1].get().strip() or None
            prod_id = entries[2].get().strip() or None
            unit_val = entries[3].get().strip() or None
            try:
                unit_int = int(unit_val) if unit_val else None
            except Exception:
                unit_int = None
            unit_price_val = entries[4].get().strip() or None
            try:
                unit_price_f = float(unit_price_val) if unit_price_val else None
            except Exception:
                unit_price_f = None
            total_val = entries[5].get().strip() or None
            try:
                total_f = float(total_val) if total_val else None
            except Exception:
                total_f = None
            status_val = entries[6].get().strip() or None
            # Compose seq_name from deployed_to and name
            seq_name_val = None
            try:
                if name_val:
                    dep = itm.get("deployed_to") or ""
                    seq_name_val = f"{dep}_{name_val}".strip('_')
            except Exception:
                seq_name_val = name_val
            # Insert via db helper
            insert_component(
                self.user["username"],
                itm["id"],
                kind,
                seq_name_val,
                sub_code,
                name_val,
                prod_id,
                status_val,
                unit_int,
                unit_price_f,
                total_f,
            )
            # Refresh and close
            self.refresh_components()
            dlg.destroy()

        btn_frame = ttk.Frame(dlg)
        btn_frame.grid(row=len(labels), column=0, columnspan=2, pady=5)
        ttk.Button(btn_frame, text="Cancel", command=on_cancel).pack(side="right", padx=4)
        ttk.Button(btn_frame, text="Save", command=on_save).pack(side="right")

    def manage_users(self):
        """
        Open a user management dialog.  Only available to superadmins.
        Allows creating up to five user accounts.  If a user exists
        already, changing the password will update the stored hash via
        ``set_password``.  Roles may be assigned as 'admin' or 'user'.
        """
        if self.user["role"] != "superadmin":
            return
        import functools
        from db import list_users, insert_user, set_password

        dlg = tk.Toplevel(self)
        dlg.title("Manage Users")
        dlg.geometry("400x300")

        # Treeview for existing users
        cols = ("id", "username", "role")
        tree = ttk.Treeview(dlg, columns=cols, show="headings")
        for c in cols:
            tree.heading(c, text=c.title())
            tree.column(c, width=120 if c != "id" else 40)
        tree.pack(fill="both", expand=True, padx=5, pady=5)

        def refresh_users():
            # clear tree
            for i in tree.get_children():
                tree.delete(i)
            for u in list_users():
                tree.insert("", "end", values=(u["id"], u["username"], u["role"]))

        refresh_users()

        # Add user function (max 5)
        def add_user_dialog():
            # enforce maximum of 12 users; default accounts number 12
            users = list(list_users())
            if len(users) >= 12:
                messagebox.showwarning("Limit Reached", "Maximum of 12 users reached. Delete an existing user before adding more.")
                return
            top = tk.Toplevel(dlg)
            top.title("Add User")
            ttk.Label(top, text="Username:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
            e_user = ttk.Entry(top)
            e_user.grid(row=0, column=1, padx=5, pady=5)
            ttk.Label(top, text="Password:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
            e_pass = ttk.Entry(top, show="*")
            e_pass.grid(row=1, column=1, padx=5, pady=5)
            ttk.Label(top, text="Role:").grid(row=2, column=0, sticky="e", padx=5, pady=5)
            role_cb = ttk.Combobox(top, values=["admin", "user"], state="readonly")
            role_cb.current(1)
            role_cb.grid(row=2, column=1, padx=5, pady=5)
            from db import now_str, get_conn
            def save_new_user():
                uname = e_user.get().strip()
                pwd = e_pass.get().strip()
                role = role_cb.get().strip() or "user"
                if not uname or not pwd:
                    messagebox.showerror("Error", "Username and password required")
                    return
                try:
                    insert_user(uname, pwd, role)
                except Exception:
                    # user exists; update password and role
                    try:
                        set_password(uname, pwd)
                        # change role if necessary
                        from db import get_conn
                        conn = get_conn()
                        cur = conn.cursor()
                        cur.execute("UPDATE users SET role=?, created_at=? WHERE username=?", (role, now_str(), uname))
                        conn.commit()
                        conn.close()
                    except Exception as ex:
                        messagebox.showerror("Error", str(ex))
                        return
                refresh_users()
                top.destroy()
            ttk.Button(top, text="Save", command=save_new_user).grid(row=3, column=0, columnspan=2, pady=10)

        # Delete user function
        def delete_user():
            sel = tree.selection()
            if not sel:
                return
            vals = tree.item(sel[0], "values")
            uid, uname, role = int(vals[0]), vals[1], vals[2]
            # cannot delete own account
            if uname == self.user["username"]:
                messagebox.showwarning("Forbidden", "You cannot delete your own account.")
                return
            if messagebox.askyesno("Delete User", f"Delete user '{uname}'?"):
                conn = get_conn()
                cur = conn.cursor()
                cur.execute("DELETE FROM users WHERE id=?", (uid,))
                conn.commit()
                conn.close()
                refresh_users()

        # Buttons
        btn_frame = ttk.Frame(dlg)
        btn_frame.pack(fill="x", padx=5, pady=5)
        ttk.Button(btn_frame, text="Add User", command=add_user_dialog).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Delete User", command=delete_user).pack(side="left", padx=3)

    def live_edit_component(self,ev=None):
        if self.user["role"] not in ("admin", "superadmin"):
            return
        sel = self.tree_c.selection()
        if not sel:
            return
        # The Treeview row ID is the component's DB ID
        cid = int(sel[0])
        vals = self.tree_c.item(sel[0], "values")
        # values: display_id, seq_name, sub_code, name, product_id, status, unit, unit_price, total_price
        # Prompt for editable fields
        sub = simpledialog.askstring("Sub Code", initialvalue=vals[2])
        nm = simpledialog.askstring("Name", initialvalue=vals[3])
        pid = simpledialog.askstring("Product ID", initialvalue=vals[4])
        unit_str = simpledialog.askstring("Unit", initialvalue=vals[6])
        price_str = simpledialog.askstring("Unit Price", initialvalue=vals[7])
        total_str = simpledialog.askstring("Total Price", initialvalue=vals[8])
        st = simpledialog.askstring("Status", initialvalue=vals[5])
        # Convert numeric fields
        try:
            unit_int = int(unit_str) if unit_str else None
        except Exception:
            unit_int = None
        try:
            unit_price_f = float(price_str) if price_str else None
        except Exception:
            unit_price_f = None
        try:
            total_f = float(total_str) if total_str else None
        except Exception:
            total_f = None
        # Compose new seq_name based on current selected item
        itm = self.get_selected_item() or {}
        seq_name_val = None
        try:
            if nm:
                dep = itm.get("deployed_to") or ""
                seq_name_val = f"{dep}_{nm}".strip('_')
        except Exception:
            seq_name_val = nm
        update_component(
            self.user["username"],
            cid,
            seq_name_val,
            sub,
            nm,
            pid,
            st,
            unit_int,
            unit_price_f,
            total_f,
        )
        self.refresh_components()

    def delete_component(self):
        if self.user["role"] not in ("admin","superadmin"): return
        sel = self.tree_c.selection()
        if not sel:
            return
        cid = int(self.tree_c.item(sel[0], "values")[0])
        if messagebox.askyesno("Delete", "Delete this component?"):
            # delete_component expects actor first
            delete_component(self.user["username"], cid)
            self.refresh_components()

    # --- User Management (superadmin only) ---
    def manage_users(self):
        """
        Open a simple user management window.  Superadmins can add or
        remove up to 5 users.  Roles allowed for new users are 'admin'
        and 'user'.  The superadmin account cannot be deleted.
        """
        # Only admin or superadmin may manage users
        if self.user["role"] not in ("admin", "superadmin"):
            return
        # Ask for the current user's password to authorise management
        try:
            pwd_confirm = simpledialog.askstring("Confirm", "Enter your login password:", show="*")
        except Exception:
            pwd_confirm = None
        if not pwd_confirm:
            return
        try:
            from db import get_user
            if not get_user(self.user["username"], pwd_confirm):
                messagebox.showerror("Authorization", "Incorrect password. Operation cancelled.")
                return
        except Exception:
            messagebox.showerror("Error", "Failed to verify user.")
            return

        win = tk.Toplevel(self)
        win.title("Manage Users")
        win.geometry("400x400")

        # Treeview to list users
        cols = ("id", "username", "role")
        tv = ttk.Treeview(win, columns=cols, show="headings")
        for c, w in zip(cols, (50, 150, 100)):
            tv.heading(c, text=c.title())
            tv.column(c, width=w)
        tv.pack(fill="both", expand=True, padx=5, pady=5)

        def load_users():
            tv.delete(*tv.get_children())
            try:
                from db import get_all_users
                users = get_all_users()
            except Exception:
                users = []
            for u in users:
                tv.insert("", "end", values=(u.get("id"), u.get("username"), u.get("role")))

        load_users()

        # Form to add a new user
        form = ttk.Frame(win)
        form.pack(fill="x", padx=5, pady=5)
        ttk.Label(form, text="Username").grid(row=0, column=0, sticky="w")
        ent_user = ttk.Entry(form)
        ent_user.grid(row=0, column=1, sticky="w")
        ttk.Label(form, text="Password").grid(row=1, column=0, sticky="w")
        ent_pass = ttk.Entry(form, show="*")
        ent_pass.grid(row=1, column=1, sticky="w")
        ttk.Label(form, text="Role").grid(row=2, column=0, sticky="w")
        cb_role = ttk.Combobox(form, values=["admin", "user"], state="readonly")
        cb_role.grid(row=2, column=1, sticky="w")
        cb_role.set("user")

        def add_user_action():
            uname = ent_user.get().strip()
            pwd = ent_pass.get().strip()
            role = cb_role.get().strip()
            if not uname or not pwd or not role:
                messagebox.showerror("Input Error", "Please fill all fields.")
                return
            # Enforce max 12 users.  Twelve accounts are allowed by default
            try:
                from db import get_all_users, insert_user
                users = get_all_users()
            except Exception:
                users = []
            if len(users) >= 12:
                messagebox.showwarning("Limit", "Maximum number of users reached (12).")
                return
            # Insert user
            try:
                insert_user(uname, pwd, role)
                messagebox.showinfo("User Added", f"User '{uname}' added successfully.")
                load_users()
                ent_user.delete(0, 'end')
                ent_pass.delete(0, 'end')
            except Exception as e:
                messagebox.showerror("Error", str(e))

        ttk.Button(form, text="Add User", command=add_user_action).grid(row=3, column=0, columnspan=2, pady=5)

        # Delete selected user
        def delete_user_action():
            sel = tv.selection()
            if not sel:
                return
            item_vals = tv.item(sel[0], "values")
            uid = int(item_vals[0])
            username = item_vals[1]
            # Prevent deletion of superadmin account
            if username == self.user.get("username"):
                messagebox.showwarning("Protected", "Cannot delete the currently logged in superadmin account.")
                return
            if username == "superadmin":
                messagebox.showwarning("Protected", "Cannot delete the default superadmin account.")
                return
            if messagebox.askyesno("Delete", f"Delete user '{username}'?"):
                try:
                    from db import delete_user
                    delete_user(uid)
                    load_users()
                except Exception as e:
                    messagebox.showerror("Error", str(e))

        ttk.Button(win, text="Delete User", command=delete_user_action).pack(pady=5)

        # Change password for selected user
        def change_password_action():
            sel = tv.selection()
            if not sel:
                messagebox.showinfo("Select User", "Please select a user to change the password.")
                return
            item_vals = tv.item(sel[0], "values")
            uid = int(item_vals[0])
            username = item_vals[1]
            # Prevent changing password for the logged-in superadmin if not desired?  Allow but caution
            new_pass = simpledialog.askstring("Change Password", f"Enter new password for '{username}':", show="*")
            if not new_pass:
                return
            try:
                from db import set_password
                set_password(username, new_pass)
                messagebox.showinfo("Password Updated", f"Password for '{username}' has been updated.")
            except Exception as e:
                messagebox.showerror("Error", str(e))

        ttk.Button(win, text="Change Password", command=change_password_action).pack(pady=5)


# app.py (Part 3)
class ItemDialog(tk.Toplevel):
    def __init__(self, master, user, mode="add", data=None):
        super().__init__(master);
        self.user = user;
        self.mode = mode;
        self.data = data
        self.title(f"{mode.title()} Item");
        self.geometry("500x560")
        # 1️⃣ Frame creation (same as before)
        f = ttk.Frame(self, padding=10)
        f.pack(fill="both", expand=True)

        # 2️⃣ Define field list before creating entries
        # Define the fields shown in the dialog.  The category will
        # become a drop‑down (combobox) and the purchase date row will
        # include a calendar button.  The warranty field represents
        # warranty months and will be parsed into a remaining days
        # string.
        # Define the form fields.  The "Product ID" is the unique code for the item.
        # The product full name refers to the brand and model.  A separate
        # field is provided for the product's serial number.  The status
        # uses a drop‑down.  Warranty is split into months (editable) and
        # left (read‑only).
        fields = [
            ("Product ID", "item_code"),
            ("Product Name", "name"),
            ("Product Full Name", "product_id"),
            ("Product Serial Number", "serial_number"),
            ("Status", "status"),
            ("Deployed To", "deployed_to"),
            ("Category", "item_type"),
            ("UNIT", "unit"),
            ("UNIT PRICE", "unit_price"),
            ("Total price", "total_price"),
            ("Purchase Date", "purchase_date"),
            ("Invoice No", "invoice_no"),
            ("Vendor", "vendor_name"),
            ("Warranty Months", "warranty_months"),
            ("Warranty Left", "warranty_left"),
        ]

        self.entries = {}  # dictionary to hold entry widgets

        # References for special fields we need to control dynamically
        self.ip_label = None
        self.ip_entry = None
        self.type_entry = None
        self.date_button = None

        # 3️⃣ Create labels + entry boxes or specialised widgets.  Category and
        # status use comboboxes; purchase date uses an entry with a calendar
        # button; warranty_left is read‑only; warranty_months is editable; the
        # IP address row is added separately after this loop.
        row_index = 0
        for lbl, key in fields:
            lab = ttk.Label(f, text=lbl)
            lab.grid(row=row_index, column=0, sticky="w")
            # Category uses a combobox
            if key == "item_type":
                cb = ttk.Combobox(f, values=["Part", "Laptop", "Desktop", "Peripherals"], state="readonly", width=22)
                cb.grid(row=row_index, column=1, sticky="w")
                # Set default value
                cb.set("Part")
                self.entries[key] = cb
                self.type_entry = cb
            # Status uses a combobox with fixed values
            elif key == "status":
                cb = ttk.Combobox(f, values=["Available", "Retired", "Spare", "Damaged"], state="readonly", width=22)
                cb.grid(row=row_index, column=1, sticky="w")
                # Default to Available
                cb.set("Available")
                self.entries[key] = cb
            # Purchase date uses an entry and a calendar button
            elif key == "purchase_date":
                ent = ttk.Entry(f, width=18)
                ent.grid(row=row_index, column=1, sticky="w")
                btn = ttk.Button(f, text="📅", width=2)
                btn.grid(row=row_index, column=2, padx=(2, 0))
                self.date_button = btn
                self.entries[key] = ent
            # Warranty left is read‑only; warranty months is editable
            elif key == "warranty_left":
                ent = ttk.Entry(f, width=25, state="readonly")
                ent.grid(row=row_index, column=1)
                self.entries[key] = ent
            elif key == "warranty_months":
                ent = ttk.Entry(f, width=25)
                ent.grid(row=row_index, column=1)
                self.entries[key] = ent
            # Default entry for other fields
            else:
                ent = ttk.Entry(f, width=25)
                ent.grid(row=row_index, column=1)
                self.entries[key] = ent
            row_index += 1

        # After building the main fields, insert the IP Address row as the last
        # form field.  This will be shown only when the category is Desktop or
        # Laptop.  The grid row is the current value of row_index.
        ip_lab = ttk.Label(f, text="IP Address")
        ip_lab.grid(row=row_index, column=0, sticky="w")
        ip_ent = ttk.Entry(f, width=25)
        ip_ent.grid(row=row_index, column=1)
        # Store references for later show/hide
        self.ip_label = ip_lab
        self.ip_entry = ip_ent
        # Add to entries dictionary
        self.entries["ip_address"] = ip_ent
        row_index += 1

        # 4️⃣ Add auto-calculation code *after* the widget creation.
        # We define helper functions below; these parse dates, months and
        # calculate totals and warranty in days.  These functions are
        # rebound later in the file to avoid duplication when editing.
        # (See the later definitions of _parse_date_flexible and
        # recalc_warranty below.)

        def _parse_date_flexible(s: str):
            """Try multiple date formats commonly used."""
            s = (s or "").strip()
            if not s:
                return None
            for fmt in ("%Y-%m-%d", "%d.%m.%Y", "%d-%m-%Y", "%m/%d/%Y", "%d/%m/%Y"):
                try:
                    return dt.datetime.strptime(s, fmt)
                except ValueError:
                    continue  # Continue to try the next format
            return None  # Return None if no format matched

        def _months_from_text(wtxt: str):
            """Return number of months from strings like '1 year', '12 months', '6 Month'."""
            if not wtxt:
                return None
            w = wtxt.strip().lower()
            # if it's already 'xxx days left', don't try to parse again
            if "day" in w and "left" in w:
                return None
            # numeric only? (interpret as months)
            parts = w.split()
            try:
                num = float(parts[0])
            except Exception:
                return None

            if "year" in w:
                return num * 12.0
            if "month" in w:
                return num
            # default to months if user typed just a number
            return num

        def recalc_warranty(_=None):
            # Recalculate days left based on purchase date and warranty months.
            pdate_text = self.entries["purchase_date"].get().strip()
            mtxt = None
            # warranty_months entry may not exist if editing older data
            if "warranty_months" in self.entries:
                mtxt = self.entries["warranty_months"].get().strip()
            base = _parse_date_flexible(pdate_text)
            months = None
            try:
                if mtxt:
                    months = float(mtxt)
            except Exception:
                months = None
            if not base or months is None:
                return
            # approximate months as 30 days (no external deps)
            expire = base + dt.timedelta(days=int(round(months * 30)))
            days_left = (expire - dt.datetime.today()).days
            days_left = max(days_left, 0)
            # Update read‑only warranty_left field
            try:
                wl = self.entries.get("warranty_left")
                wl.config(state="normal")
                wl.delete(0, "end")
                wl.insert(0, f"{days_left} days left")
                wl.config(state="readonly")
            except Exception:
                pass

        # 5️⃣ Calendar picker for purchase date
        def open_calendar():
            """Open a calendar dialog that allows users to pick a date via a month view."""
            import calendar as _cal
            top = tk.Toplevel(self)
            top.title("Select Date")
            # Determine the starting date (current entry or today)
            dt_obj = None
            try:
                curr = self.entries["purchase_date"].get().strip()
                for fmt in ("%d-%m-%Y", "%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%d.%m.%Y"):
                    try:
                        dt_obj = dt.datetime.strptime(curr, fmt)
                        break
                    except Exception:
                        pass
            except Exception:
                dt_obj = None
            if not dt_obj:
                dt_obj = dt.datetime.today()
            current_year = dt_obj.year
            current_month = dt_obj.month
            selected_day = dt_obj.day
            # Header with navigation
            header_frame = ttk.Frame(top)
            header_frame.pack(padx=5, pady=5)
            month_label = ttk.Label(header_frame, text="", font=("Arial", 12, "bold"))
            month_label.pack(side="left", expand=True)
            def update_label():
                month_label.config(text=f"{_cal.month_name[current_month]} {current_year}")
            # Navigation functions
            def change_month(delta):
                nonlocal current_month, current_year
                current_month += delta
                if current_month < 1:
                    current_month = 12
                    current_year -= 1
                elif current_month > 12:
                    current_month = 1
                    current_year += 1
                build_calendar()
            ttk.Button(header_frame, text="<", command=lambda: change_month(-1)).pack(side="left")
            ttk.Button(header_frame, text=">", command=lambda: change_month(1)).pack(side="left")
            # Frame for day names and days
            cal_frame = ttk.Frame(top)
            cal_frame.pack(padx=5, pady=5)
            def pick_day(d):
                nonlocal selected_day
                selected_day = d
                # Format as DD-MM-YYYY
                new_date = f"{d:02d}-{current_month:02d}-{current_year}"
                try:
                    self.entries["purchase_date"].delete(0, "end")
                    self.entries["purchase_date"].insert(0, new_date)
                    recalc_warranty()
                except Exception:
                    pass
                top.destroy()
            def build_calendar():
                # Clear existing widgets in cal_frame
                for w in cal_frame.winfo_children():
                    w.destroy()
                update_label()
                # Day names row
                days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
                for idx, day_name in enumerate(days):
                    ttk.Label(cal_frame, text=day_name, font=("Arial", 9, "bold")).grid(row=0, column=idx, padx=3, pady=2)
                # Weeks of month
                month_weeks = _cal.monthcalendar(current_year, current_month)
                for row_idx, week in enumerate(month_weeks, start=1):
                    for col_idx, day in enumerate(week):
                        if day == 0:
                            # blank cell
                            ttk.Label(cal_frame, text="").grid(row=row_idx, column=col_idx, padx=3, pady=3)
                        else:
                            btn_style = {}
                            if day == selected_day and current_month == dt_obj.month and current_year == dt_obj.year:
                                btn_style = {"style": "Selected.TButton"}
                            b = ttk.Button(cal_frame, text=str(day), width=3, command=lambda d=day: pick_day(d))
                            b.grid(row=row_idx, column=col_idx, padx=2, pady=2)
                # Force update to adjust sizes
                cal_frame.update_idletasks()
            # Initial build
            build_calendar()

        # --- Live total: UNIT × UNIT PRICE -> TOTAL PRICE ---
        def recalc_total(_evt=None):
            """Compute total price whenever unit or unit price changes."""
            try:
                u = float(self.entries["unit"].get())
                p = float(self.entries["unit_price"].get())
                self.entries["total_price"].delete(0, "end")
                self.entries["total_price"].insert(0, str(round(u * p, 2)))
            except Exception:
                # leave field unchanged on parse error
                pass

        # Show/hide IP address field based on category
        def update_ip_visibility(_=None):
            val = (self.entries.get("item_type").get() or "").strip().lower()
            if val in ("desktop", "laptop"):
                if self.ip_label:
                    self.ip_label.grid()
                if self.ip_entry:
                    self.ip_entry.grid()
            else:
                if self.ip_label:
                    self.ip_label.grid_remove()
                if self.ip_entry:
                    self.ip_entry.grid_remove()
                    self.ip_entry.delete(0, "end")

        # Bind the dynamic behaviours after all widgets exist
        # Total price recalculation
        try:
            self.entries["unit"].bind("<KeyRelease>", recalc_total)
            self.entries["unit_price"].bind("<KeyRelease>", recalc_total)
        except Exception:
            pass
        # Warranty recalculation: trigger when purchase_date or warranty_months change
        try:
            self.entries["purchase_date"].bind("<KeyRelease>", recalc_warranty)
            if "warranty_months" in self.entries:
                self.entries["warranty_months"].bind("<KeyRelease>", recalc_warranty)
            self.entries["purchase_date"].bind("<FocusOut>", recalc_warranty)
            if "warranty_months" in self.entries:
                self.entries["warranty_months"].bind("<FocusOut>", recalc_warranty)
        except Exception:
            pass
        # IP visibility toggling
        if self.type_entry:
            try:
                self.type_entry.bind("<<ComboboxSelected>>", update_ip_visibility)
                self.type_entry.bind("<FocusOut>", update_ip_visibility)
            except Exception:
                pass

        # Attach calendar button command after definition
        if self.date_button:
            self.date_button.config(command=open_calendar)

        # 6️⃣ Add Scan button for scanner‑based data loading.  Scanned data
        # should be a comma‑separated list of fields in the same order as
        # defined in ``fields`` (item_code,name,product_id,status,deployed_to,
        # ip_address,item_type,unit,unit_price,total_price,purchase_date,
        # invoice_no,vendor_name,warranty_left).  If fewer values are
        # provided they will populate the leading fields.
        def scan_data():
            pop = tk.Toplevel(self)
            pop.title("Scan Data")
            ttk.Label(pop, text="Scan or paste comma separated data:").pack(padx=10, pady=5)
            data_var = tk.StringVar()
            entry = ttk.Entry(pop, textvariable=data_var, width=50)
            entry.pack(padx=10, pady=5)
            entry.focus()
            def on_ok():
                raw = data_var.get().strip()
                parts = [p.strip() for p in raw.split(',')]
                # List of keys in the expected order for scanning.  The
                # sequence corresponds to item fields and optionally IP address.
                # Warranty months is expected; warranty_left will be computed.
                # Define the order of fields expected when scanning comma‑separated data.
                # The sequence corresponds to item fields and optionally IP address.
                keys_order = [
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
                    "warranty_months",
                    "ip_address",
                ]
                for k, val in zip(keys_order, parts):
                    if k not in self.entries:
                        continue
                    widget = self.entries[k]
                    # For combobox set directly; for others clear and insert
                    try:
                        from tkinter.ttk import Combobox
                        if isinstance(widget, Combobox):
                            widget.set(val)
                        else:
                            widget.delete(0, 'end')
                            widget.insert(0, val)
                    except Exception:
                        try:
                            widget.delete(0, 'end')
                            widget.insert(0, val)
                        except Exception:
                            pass
                # After setting the type and months, update derived fields
                try:
                    update_ip_visibility()
                    recalc_total()
                    recalc_warranty()
                except Exception:
                    pass
                pop.destroy()
            ttk.Button(pop, text="OK", command=on_ok).pack(pady=5)
        # Place the Scan Data button below the last form row (IP row).  There are
        # len(fields) rows for the fields and one additional row for IP.
        ttk.Button(f, text="Scan Data", command=scan_data).grid(row=len(fields)+1, column=0, columnspan=2, pady=4)
        # Place the Save button below the Scan button
        ttk.Button(f, text="Save", command=self.save).grid(row=len(fields)+2, column=0, columnspan=2, pady=8)

        if data:
            for key, widget in self.entries.items():
                value = data.get(key, "")
                if not value:
                    continue
                # Set value appropriately depending on widget type
                try:
                    if isinstance(widget, ttk.Combobox):
                        widget.set(value)
                    else:
                        widget.insert(0, value)
                except Exception:
                    # ignore if cannot insert
                    pass
        # Recalculate derived fields and apply IP field visibility based on
        # prefilled category.  We call the helper once here because
        # binding is only triggered on user input.
        try:
            recalc_total()
            recalc_warranty()
        except Exception:
            pass
        # Ensure IP field visibility corresponds to the current category
        try:
            update_ip_visibility()
        except Exception:
            pass

    def save(self):
        vals = {k: v.get().strip() or None for k, v in self.entries.items()}

        # Fallback: compute total if unit & price exist but total is blank
        try:
            if (not vals.get("total_price")) and vals.get("unit") and vals.get("unit_price"):
                vals["total_price"] = str(round(float(vals["unit"]) * float(vals["unit_price"]), 2))
        except Exception:
            pass

        # Compute warranty_left based on warranty_months and purchase_date
        try:
            pdate = vals.get("purchase_date") or ""
            mtxt = vals.get("warranty_months")
            base = _parse_date_flexible(pdate)
            months = None
            try:
                if mtxt:
                    months = float(mtxt)
            except Exception:
                months = None
            if base and months is not None:
                expire = base + dt.timedelta(days=int(round(months * 30)))
                days_left = max((expire - dt.datetime.today()).days, 0)
                vals["warranty_left"] = f"{days_left} days left"
            # Remove warranty_months from the dictionary; DB has no column for this
            if "warranty_months" in vals:
                del vals["warranty_months"]
        except Exception:
            # Ensure warranty_months is removed even on failure
            if "warranty_months" in vals:
                del vals["warranty_months"]
            pass

        try:
            # Automatically approve items added by admins or superadmins
            if self.mode == "add":
                if self.user.get("role") in ("admin", "superadmin"):
                    vals["approved"] = 1
                insert_item(self.user["username"], **vals)
            else:
                if self.user.get("role") in ("admin", "superadmin"):
                    vals["approved"] = 1
                update_item(self.user["username"], self.data["id"], **vals)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return

        self.destroy()
        self.master.refresh()


if __name__ == "__main__":
    # Start the application.  Database initialisation and decryption
    # are handled within the LoginWindow constructor.  We avoid
    # initialising the DB here because doing so before checking for
    # an encrypted file would create a fresh plain DB and bypass the
    # existing encrypted data.  See LoginWindow.__init__ for details.
    LoginWindow().mainloop() # your normal startup


