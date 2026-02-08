import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
USE_SA = True
try:
    from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
    from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session
except Exception:
    USE_SA = False
    import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "app.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret-key")
raw_db = os.environ.get("DATABASE_URL") or os.environ.get("DATABASE")
if USE_SA:
    if raw_db:
        DB_URL = raw_db
    else:
        DB_URL = "sqlite:///" + DB_PATH.replace("\\", "/")
    engine = create_engine(DB_URL, pool_pre_ping=True)
    SessionLocal = scoped_session(sessionmaker(bind=engine, autocommit=False, autoflush=False))
    Base = declarative_base()
login_manager = LoginManager(app)
login_manager.login_view = "login"

if USE_SA:
    class User(Base, UserMixin):
        __tablename__ = "user"
        id = Column(Integer, primary_key=True)
        username = Column(String, unique=True, nullable=False)
        password_hash = Column(String, nullable=False)
        created_at = Column(String, nullable=False)
        def check_password(self, password: str) -> bool:
            return check_password_hash(self.password_hash, password)
    class Task(Base):
        __tablename__ = "task"
        id = Column(Integer, primary_key=True)
        title = Column(String)
        client_name = Column(String)
        notes = Column(String)
        status = Column(String, nullable=False)
        color = Column(String)
        created_at = Column(String, nullable=False)
        deleted_at = Column(String)
        user_id = Column(Integer, ForeignKey("user.id"), nullable=False)
else:
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
    if USE_SA:
        session = SessionLocal()
        try:
            return session.get(User, user_id)
        finally:
            session.close()
    else:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        cur = conn.execute("SELECT * FROM user WHERE id = ?", (user_id,))
        row = cur.fetchone()
        conn.close()
        return User.from_row(row) if row else None

def find_user_by_username(username: str):
    if USE_SA:
        session = SessionLocal()
        try:
            return session.query(User).filter(User.username == username).first()
        finally:
            session.close()
    else:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        cur = conn.execute("SELECT * FROM user WHERE username = ?", (username,))
        row = cur.fetchone()
        conn.close()
        return User.from_row(row) if row else None

def add_task_db(client_name: str, notes: str, status: str, user_id: int, color: str):
    if USE_SA:
        session = SessionLocal()
        try:
            t = Task(title=client_name, client_name=client_name, notes=notes, status=status, color=color, created_at=datetime.utcnow().isoformat(), deleted_at=None, user_id=user_id)
            session.add(t)
            session.commit()
        finally:
            session.close()
    else:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.execute(
            "INSERT INTO task (title, client_name, notes, status, color, created_at, deleted_at, user_id) VALUES (?, ?, ?, ?, ?, ?, NULL, ?)",
            (client_name, client_name, notes, status, color, datetime.utcnow().isoformat(), user_id),
        )
        conn.commit()
        conn.close()

def soft_delete_task(task_id: int, user_id: int):
    if USE_SA:
        session = SessionLocal()
        try:
            t = session.query(Task).filter(Task.id == task_id, Task.user_id == user_id).first()
            if t:
                t.deleted_at = datetime.utcnow().isoformat()
                session.commit()
        finally:
            session.close()
    else:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.execute("UPDATE task SET deleted_at = ? WHERE id = ? AND user_id = ?", (datetime.utcnow().isoformat(), task_id, user_id))
        conn.commit()
        conn.close()

def undo_soft_delete_task(task_id: int, user_id: int):
    if USE_SA:
        session = SessionLocal()
        try:
            t = session.query(Task).filter(Task.id == task_id, Task.user_id == user_id).first()
            if t:
                t.deleted_at = None
                session.commit()
        finally:
            session.close()
    else:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.execute("UPDATE task SET deleted_at = NULL WHERE id = ? AND user_id = ?", (task_id, user_id))
        conn.commit()
        conn.close()

def update_password_db(user_id: int, new_hash: str):
    if USE_SA:
        session = SessionLocal()
        try:
            u = session.get(User, user_id)
            if u:
                u.password_hash = new_hash
                session.commit()
        finally:
            session.close()
    else:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.execute("UPDATE user SET password_hash = ? WHERE id = ?", (new_hash, user_id))
        conn.commit()
        conn.close()

def update_task_db(task_id: int, client_name: str, notes: str, status: str, user_id: int, color: str):
    if USE_SA:
        session = SessionLocal()
        try:
            t = session.query(Task).filter(Task.id == task_id, Task.user_id == user_id).first()
            if t:
                t.client_name = client_name
                t.notes = notes
                t.status = status
                t.color = color
                session.commit()
        finally:
            session.close()
    else:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.execute("UPDATE task SET client_name = ?, notes = ?, status = ?, color = ? WHERE id = ? AND user_id = ?", (client_name, notes, status, color, task_id, user_id))
        conn.commit()
        conn.close()

def update_task_status(task_id: int, user_id: int, new_status: str):
    if USE_SA:
        session = SessionLocal()
        try:
            t = session.query(Task).filter(Task.id == task_id, Task.user_id == user_id).first()
            if t:
                t.status = new_status
                session.commit()
        finally:
            session.close()
    else:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.execute("UPDATE task SET status = ? WHERE id = ? AND user_id = ?", (new_status, task_id, user_id))
        conn.commit()
        conn.close()

def list_tasks(user_id: int, show_all: bool, q: str, only_deleted: bool = False):
    if USE_SA:
        session = SessionLocal()
        try:
            query = session.query(Task).filter(Task.user_id == user_id)
            if only_deleted:
                query = query.filter(Task.deleted_at.isnot(None))
            elif not show_all:
                query = query.filter(Task.deleted_at.is_(None))
            if q:
                query = query.filter(Task.client_name.like(f"%{q}%"))
            return query.order_by(Task.created_at.desc()).all()
        finally:
            session.close()
    else:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
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
        return [type("T", (), dict(row)) for row in rows]


@login_manager.user_loader
def load_user(user_id):
    return find_user_by_id(int(user_id))


def init_db():
    if USE_SA:
        Base.metadata.create_all(engine)
        session = SessionLocal()
        try:
            exists = session.query(User).filter(User.username == "admin").first()
            if not exists:
                u = User(username="admin", password_hash=generate_password_hash("123"), created_at=datetime.utcnow().isoformat())
                session.add(u)
                session.commit()
        finally:
            session.close()
    else:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
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
        cur = conn.execute("SELECT id FROM user WHERE username = 'admin'")
        row = cur.fetchone()
        if not row:
            conn.execute(
                "INSERT INTO user (username, password_hash, created_at) VALUES (?, ?, ?)",
                ("admin", generate_password_hash("123"), datetime.utcnow().isoformat()),
            )
        conn.commit()
        conn.close()

_did_init = False
@app.before_request
def setup_app():
    global _did_init
    if not _did_init:
        init_db()
        _did_init = True

@app.teardown_appcontext
def remove_session(exception=None):
    if USE_SA:
        SessionLocal.remove()

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
    if USE_SA:
        session = SessionLocal()
        try:
            t = session.query(Task).filter(Task.id == task_id, Task.user_id == current_user.id).first()
            if t:
                session.delete(t)
                session.commit()
        finally:
            session.close()
    else:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.execute("DELETE FROM task WHERE id = ? AND user_id = ?", (task_id, current_user.id))
        conn.commit()
        conn.close()
    flash("Tarefa excluída permanentemente", "success")
    return redirect(url_for("trash"))


@app.route("/trash/batch_delete", methods=["POST"])
@login_required
def batch_delete():
    task_ids = request.form.getlist("task_ids")
    if USE_SA:
        session = SessionLocal()
        try:
            for tid in task_ids:
                t = session.query(Task).filter(Task.id == int(tid), Task.user_id == current_user.id).first()
                if t:
                    session.delete(t)
            session.commit()
        finally:
            session.close()
    else:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        for tid in task_ids:
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
