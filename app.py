import os
from datetime import datetime
import sqlite3
from types import SimpleNamespace
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "app.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-secret-key"
app.config["DATABASE"] = DB_PATH
login_manager = LoginManager(app)
login_manager.login_view = "login"

def get_db():
    conn = sqlite3.connect(app.config["DATABASE"], check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

class User(UserMixin):
    def __init__(self, id, username, password_hash, created_at):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.created_at = created_at

    @staticmethod
    def from_row(row):
        return User(row["id"], row["username"], row["password_hash"], row["created_at"])

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class TaskStatus:
    EM_ATENDIMENTO = "em_atendimento"
    VERIFICANDO = "verificando"
    EM_ANALISE = "em_analise"
    RETORNAR = "retornar"

    @staticmethod
    def choices():
        return [
            TaskStatus.EM_ATENDIMENTO,
            TaskStatus.VERIFICANDO,
            TaskStatus.EM_ANALISE,
            TaskStatus.RETORNAR,
        ]

CARD_COLORS = [
    "#e3f2fd", "#e7f5e9", "#fff3e6", "#f3e8ff",
    "#fde68a", "#d1fae5", "#e0f2fe", "#fee2e2",
    "#fef3c7", "#cffafe", "#f5d0fe", "#dcfce7"
]

@app.context_processor
def inject_globals():
    return dict(CARD_COLORS=CARD_COLORS)

def find_user_by_id(user_id: int):
    conn = get_db()
    cur = conn.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return User.from_row(row) if row else None

def find_user_by_username(username: str):
    conn = get_db()
    cur = conn.execute("SELECT * FROM user WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return User.from_row(row) if row else None

def add_task_db(client_name: str, notes: str, status: str, user_id: int, color: str):
    conn = get_db()
    conn.execute(
        "INSERT INTO task (title, client_name, notes, status, color, created_at, deleted_at, user_id) VALUES (?, ?, ?, ?, ?, ?, NULL, ?)",
        (client_name, client_name, notes, status, color, datetime.utcnow().isoformat(), user_id),
    )
    conn.commit()
    conn.close()

def soft_delete_task(task_id: int, user_id: int):
    conn = get_db()
    conn.execute(
        "UPDATE task SET deleted_at = ? WHERE id = ? AND user_id = ?",
        (datetime.utcnow().isoformat(), task_id, user_id),
    )
    conn.commit()
    conn.close()

def undo_soft_delete_task(task_id: int, user_id: int):
    conn = get_db()
    conn.execute(
        "UPDATE task SET deleted_at = NULL WHERE id = ? AND user_id = ?",
        (task_id, user_id),
    )
    conn.commit()
    conn.close()

def update_password_db(user_id: int, new_hash: str):
    conn = get_db()
    conn.execute(
        "UPDATE user SET password_hash = ? WHERE id = ?",
        (new_hash, user_id),
    )
    conn.commit()
    conn.close()

def update_task_db(task_id: int, client_name: str, notes: str, status: str, user_id: int, color: str):
    conn = get_db()
    conn.execute(
        "UPDATE task SET client_name = ?, notes = ?, status = ?, color = ? WHERE id = ? AND user_id = ?",
        (client_name, notes, status, color, task_id, user_id),
    )
    conn.commit()
    conn.close()

def update_task_status(task_id: int, user_id: int, new_status: str):
    conn = get_db()
    conn.execute(
        "UPDATE task SET status = ? WHERE id = ? AND user_id = ?",
        (new_status, task_id, user_id),
    )
    conn.commit()
    conn.close()

def list_tasks(user_id: int, show_all: bool, q: str, only_deleted: bool = False):
    conn = get_db()
    base_sql = "SELECT * FROM task WHERE user_id = ?"
    params = [user_id]
    if only_deleted:
        base_sql += " AND deleted_at IS NOT NULL"
    elif not show_all:
        base_sql += " AND deleted_at IS NULL"
    if q:
        base_sql += " AND client_name LIKE ?"
        params.append(f"%{q}%")
    base_sql += " ORDER BY created_at DESC"
    rows = conn.execute(base_sql, tuple(params)).fetchall()
    conn.close()
    return [SimpleNamespace(**dict(row)) for row in rows]


@login_manager.user_loader
def load_user(user_id):
    return find_user_by_id(int(user_id))


def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS user ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "username TEXT UNIQUE NOT NULL,"
        "password_hash TEXT NOT NULL,"
        "created_at TEXT NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS task ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "title TEXT NULL,"
        "client_name TEXT NULL,"
        "notes TEXT NULL,"
        "status TEXT NOT NULL,"
        "color TEXT NULL,"
        "created_at TEXT NOT NULL,"
        "deleted_at TEXT NULL,"
        "user_id INTEGER NOT NULL,"
        "FOREIGN KEY(user_id) REFERENCES user(id))"
    )
    cols = [r["name"] for r in conn.execute("PRAGMA table_info('task')").fetchall()]
    if "client_name" not in cols:
        conn.execute("ALTER TABLE task ADD COLUMN client_name TEXT NULL")
        conn.execute("UPDATE task SET client_name = title WHERE client_name IS NULL")
    if "notes" not in cols:
        conn.execute("ALTER TABLE task ADD COLUMN notes TEXT NULL")
    if "color" not in cols:
        conn.execute("ALTER TABLE task ADD COLUMN color TEXT NULL")
    cur = conn.execute("SELECT id FROM user WHERE username = 'admin'")
    row = cur.fetchone()
    if not row:
        conn.execute(
            "INSERT INTO user (username, password_hash, created_at) VALUES (?, ?, ?)",
            ("admin", generate_password_hash("123"), datetime.utcnow().isoformat()),
        )
    conn.commit()
    conn.close()


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = find_user_by_username(username)
        if user and user.check_password(password):
            login_user(user)
            flash("Login realizado com sucesso", "success")
            return redirect(url_for("board"))
        flash("Usuário ou senha inválidos", "error")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logout realizado", "info")
    return redirect(url_for("login"))


@app.route("/board", methods=["GET"])
@login_required
def board():
    q = request.args.get("q", "").strip()
    show_all = request.args.get("all") == "1"
    tasks = list_tasks(current_user.id, show_all, q)
    status_groups = {s: [] for s in TaskStatus.choices()}
    for t in tasks:
        status_groups.setdefault(t.status, []).append(t)
    return render_template(
        "index.html",
        tasks=tasks,
        status_groups=status_groups,
        q=q,
        show_all=show_all,
        TaskStatus=TaskStatus,
    )


@app.route("/trash", methods=["GET"])
@login_required
def trash():
    q = request.args.get("q", "").strip()
    tasks = list_tasks(current_user.id, False, q, only_deleted=True)
    return render_template("index.html", tasks=tasks, q=q, trash_mode=True)


@app.route("/trash/restore/<int:task_id>", methods=["POST"])
@login_required
def restore_task(task_id):
    undo_soft_delete_task(task_id, current_user.id)
    flash("Tarefa restaurada com sucesso", "success")
    return redirect(url_for("trash"))


@app.route("/trash/delete/<int:task_id>", methods=["POST"])
@login_required
def delete_permanently(task_id):
    conn = get_db()
    conn.execute("DELETE FROM task WHERE id = ? AND user_id = ?", (task_id, current_user.id))
    conn.commit()
    conn.close()
    flash("Tarefa excluída permanentemente", "success")
    return redirect(url_for("trash"))


@app.route("/trash/batch_delete", methods=["POST"])
@login_required
def batch_delete():
    task_ids = request.form.getlist("task_ids")
    for tid in task_ids:
        conn = get_db()
        conn.execute("DELETE FROM task WHERE id = ? AND user_id = ?", (int(tid), current_user.id))
        conn.commit()
        conn.close()
    flash(f"{len(task_ids)} tarefas excluídas permanentemente", "success")
    return redirect(url_for("trash"))


@app.route("/board/batch_soft_delete", methods=["POST"])
@login_required
def batch_soft_delete():
    task_ids = request.form.getlist("task_ids")
    for tid in task_ids:
        soft_delete_task(int(tid), current_user.id)
    flash(f"{len(task_ids)} tarefas enviadas para a lixeira", "info")
    return redirect(url_for("board"))



@app.route("/settings/password", methods=["POST"])
@login_required
def change_password():
    username = request.form.get("username", "").strip()
    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")

    if username != current_user.username:
        flash("Nome de usuário incorreto", "error")
        return redirect(url_for("board"))
    
    if not current_user.check_password(old_password):
        flash("Senha atual incorreta", "error")
        return redirect(url_for("board"))
    
    new_hash = generate_password_hash(new_password)
    update_password_db(current_user.id, new_hash)
    flash("Senha alterada com sucesso", "success")
    return redirect(url_for("board"))

@app.route("/", methods=["GET"])
def home():
    return redirect(url_for("login"))


@app.route("/tasks", methods=["POST"])
@login_required
def create_task():
    client_name = request.form.get("client_name", "").strip()
    notes = request.form.get("notes", "").strip()
    status = request.form.get("status", TaskStatus.EM_ATENDIMENTO)
    color = request.form.get("color", CARD_COLORS[0])
    if not client_name:
        flash("Informe o nome do cliente", "error")
        return redirect(url_for("board"))
    if status not in TaskStatus.choices():
        status = TaskStatus.EM_ATENDIMENTO
    if color not in CARD_COLORS:
        color = CARD_COLORS[0]
    add_task_db(client_name, notes, status, current_user.id, color)
    flash("Tarefa criada com sucesso", "success")
    return redirect(url_for("board"))


@app.route("/tasks/edit/<int:task_id>", methods=["POST"])
@login_required
def edit_task(task_id):
    client_name = request.form.get("client_name", "").strip()
    notes = request.form.get("notes", "").strip()
    status = request.form.get("status", TaskStatus.EM_ATENDIMENTO)
    color = request.form.get("color", CARD_COLORS[0])
    
    if not client_name:
        flash("Informe o nome do cliente", "error")
        return redirect(url_for("board"))
        
    update_task_db(task_id, client_name, notes, status, current_user.id, color)
    flash("Tarefa atualizada com sucesso", "success")
    return redirect(url_for("board"))


@app.route("/tasks/<int:task_id>/delete", methods=["POST"])
@login_required
def delete_task(task_id: int):
    soft_delete_task(task_id, current_user.id)
    flash(
        f"Tarefa excluída com sucesso. "
        f"<a href='{url_for('undo_delete_task', task_id=task_id)}' class='undo-link'>Desfazer exclusão</a>",
        "warning",
    )
    return redirect(url_for("board"))


@app.route("/tasks/<int:task_id>/undo", methods=["GET"])
@login_required
def undo_delete_task(task_id: int):
    undo_soft_delete_task(task_id, current_user.id)
    flash("Exclusão desfeita", "info")
    return redirect(url_for("board"))


@app.route("/tasks/<int:task_id>/status", methods=["POST"])
@login_required
def update_status(task_id: int):
    new_status = request.form.get("status")
    if new_status not in TaskStatus.choices():
        flash("Status inválido", "error")
        return redirect(url_for("board"))
    update_task_status(task_id, current_user.id, new_status)
    flash("Status atualizado", "success")
    return redirect(url_for("board"))


if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
