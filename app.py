from __future__ import annotations
import os, sqlite3, secrets, hashlib, hmac
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Tuple

from flask import Flask, render_template, request, redirect, make_response, g, url_for

#########################################################################
#                    Banco de Dados                                     #
#########################################################################

class Banco_Dados:
    def __init__(self, banco: str = "skinperfect.db"):
        self.banco = banco
        self.criar_tabela()
    
    def criar_tabela(self):
        with sqlite3.connect(self.banco) as conn:
            cur = conn.cursor()

            cur.execute("""
            CREATE TABLE IF NOT EXISTS users(
              id INTEGER PRIMARY KEY AUTOINCREMENT, 
              nome TEXT NOT NULL,
              email TEXT NOT NULL UNIQUE,
              pwd_hash BLOB NOT NULL,
              pwd_salt BLOB NOT NULL,
              last_login_at TEXT,
              termo_consentimento INTEGER NOT NULL DEFAULT 0,
              consentimento_at TEXT
            )""")


            cur.execute("""
            CREATE TABLE IF NOT EXISTS sessions(
              id TEXT PRIMARY KEY,
              usuario_id INTEGER NOT NULL,
              criado_at TEXT NOT NULL,
              expirado_at TEXT NOT NULL,
              FOREIGN KEY(usuario_id) REFERENCES users(id)
            )""")
            cur.execute("""
            CREATE TABLE IF NOT EXISTS recovery_tokens(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              usuario_id INTEGER NOT NULL,
              token_hash BLOB NOT NULL,
              criado_at TEXT NOT NULL,
              expirado_at TEXT NOT NULL,
              used_at TEXT,
              FOREIGN KEY(usuario_id) REFERENCES users(id)
            )""")
            conn.commit()

    def connect(self):
        return sqlite3.connect(self.banco)

# ================== Segurança de senha ==================
class PasswordHasher:
    def __init__(self, iterations: int = 310_000, dklen: int = 32):
        self.iterations = iterations
        self.dklen = dklen

    def make_hash(self, password: str) -> Tuple[bytes, bytes]:
        salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                  self.iterations, dklen=self.dklen)
        return key, salt

    def verificar(self, password: str, expected_hash: bytes, salt: bytes) -> bool:
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                  self.iterations, dklen=self.dklen)
        return hmac.compare_digest(key, expected_hash)
    

# ================== Entidades ==================

@dataclass
class User:
    id: int
    nome: str
    email: str
    last_login_at: Optional[str]
    termo_consentimento: bool
    consentimento_at: Optional[str]


@dataclass
class Session:
    id: str
    usuario_id: int
    criado_at: str
    expirado_at: str

# ================== Repositórios ==================

class Usuario:
    def __init__(self, db: Banco_Dados, hasher: PasswordHasher):
        self.db = db
        self.hasher = hasher
    
    def criar_usuario(self, nome: str, email: str, password: str,
                    termo_consentimento: bool) -> User:
        email_norm = email.lower().strip()
        pwd_hash, pwd_salt = self.hasher.make_hash(password)
        consentimento_at = datetime.utcnow().isoformat() if termo_consentimento else None
        with self.db.connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users(nome, email, pwd_hash, pwd_salt, termo_consentimento, consentimento_at) "
                "VALUES(?,?,?,?,?,?)",
                (nome, email_norm, pwd_hash, pwd_salt,
                 1 if termo_consentimento else 0, consentimento_at),
            )
            usuario_id = cur.lastrowid
            conn.commit()
            return self.get_by_id(usuario_id)

    
    def get_by_email_with_secret(self, email: str):
        email_norm = email.lower().strip()
        with self.db.connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT id,nome,email,pwd_hash,pwd_salt,last_login_at,termo_consentimento,consentimento_at "
                "FROM users WHERE email=?",
                (email_norm,),
            )
            return cur.fetchone()

    def get_by_id(self, usuario_id: int) -> Optional[User]:
        with self.db.connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT id,nome,email,last_login_at,termo_consentimento,consentimento_at "
                "FROM users WHERE id=?",
                (usuario_id,),
            )
            r = cur.fetchone()
            if not r:
                return None
            return User(
                id=r[0],
                nome=r[1],
                email=r[2],
                last_login_at=r[3],
                termo_consentimento=bool(r[4]),
                consentimento_at=r[5],
            )

    def set_last_login(self, usuario_id: int):
        with self.db.connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE users SET last_login_at=? WHERE id=?",
                (datetime.utcnow().isoformat(), usuario_id),
            )
            conn.commit()

    def change_password(self, usuario_id: int, new_password: str):
        pwd_hash, pwd_salt = self.hasher.make_hash(new_password)
        with self.db.connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE users SET pwd_hash=?, pwd_salt=? WHERE id=?",
                (pwd_hash, pwd_salt, usuario_id),
            )
            conn.commit()


class SessionManager:
    def __init__(self, db: Banco_Dados, ttl_minutes: int = 60):
        self.db = db
        self.ttl = ttl_minutes

    def create(self, usuario_id: int) -> Session:
        sid = secrets.token_urlsafe(32)
        now = datetime.utcnow()
        exp = now + timedelta(minutes=self.ttl)
        with self.db.connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO sessions(id, usuario_id, criado_at, expirado_at) "
                "VALUES(?,?,?,?)",
                (sid, usuario_id, now.isoformat(), exp.isoformat()),
            )
            conn.commit()
        return Session(id=sid, usuario_id=usuario_id,
                       criado_at=now.isoformat(),
                       expirado_at=exp.isoformat())

    def validate(self, sid: str) -> Optional[Session]:
        with self.db.connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT id,usuario_id,criado_at,expirado_at FROM sessions "
                "WHERE id=?",
                (sid,),
            )
            r = cur.fetchone()
            if not r:
                return None
            if datetime.fromisoformat(r[3]) < datetime.utcnow():
                cur.execute("DELETE FROM sessions WHERE id=?", (sid,))
                conn.commit()
                return None
            return Session(id=r[0], usuario_id=r[1],
                           criado_at=r[2], expirado_at=r[3])
        
# ================== E-mail (simulado) ==================
class EmailService:
    def send_password_recovery(self, to_email: str, link: str):
        msg = (
            f"[SkinPerfect] Recuperação de senha\n"
            f"Para: {to_email}\n"
            f"Link seguro: {link}\n"
            f"Enviado em: {datetime.utcnow().isoformat()}"
        )
        print("\n=== EMAIL SIMULADO ===\n" + msg + "\n======================\n")

# ================== Recuperação de senha ==================
class RecoveryService:
    def __init__(self, db: Banco_Dados, token_ttl_minutes: int = 15):
        self.db = db
        self.token_ttl = token_ttl_minutes

    def _hash_token(self, token: str) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256", token.encode("utf-8"), b"__recovery__", 200_000, dklen=32
        )

    def generate_and_store(self, usuario_id: int) -> str:
        token = secrets.token_urlsafe(24)
        token_hash = self._hash_token(token)
        now = datetime.utcnow()
        expires = now + timedelta(minutes=self.token_ttl)
        with self.db.connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO recovery_tokens(usuario_id, token_hash, criado_at, expirado_at) "
                "VALUES(?,?,?,?)",
                (usuario_id, token_hash, now.isoformat(), expires.isoformat()),
            )
            conn.commit()
        return token

    def validate_token(self, email: str, token: str) -> Optional[int]:
        token_hash = self._hash_token(token)
        with self.db.connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT rt.id, rt.token_hash, rt.expirado_at, rt.used_at
                FROM recovery_tokens rt
                JOIN users u ON u.id = rt.usuario_id
                WHERE u.email=?
                """,
                (email.lower().strip(),),
            )
            rows = cur.fetchall()
            if not rows:
                return None
            now = datetime.utcnow()
            for rid, stored_hash, expirado_at, used_at in rows:
                if used_at:
                    continue
                if datetime.fromisoformat(expirado_at) < now:
                    continue
                if hmac.compare_digest(token_hash, stored_hash):
                    return rid
            return None

    def mark_used(self, token_id: int):
        with self.db.connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE recovery_tokens SET used_at=? WHERE id=?",
                (datetime.utcnow().isoformat(), token_id),
            )
            conn.commit()

    def get_usuario_id_from_token(self, token_id: int) -> Optional[int]:
        with self.db.connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT usuario_id FROM recovery_tokens WHERE id=?",
                        (token_id,))
            r = cur.fetchone()
            return r[0] if r else None


# ================== Serviço de Autenticação ==================
class AuthService:
    def __init__(self, db: Banco_Dados):
        self.db = db
        self.hasher = PasswordHasher()
        self.users = Usuario(db, self.hasher)
        self.sessions = SessionManager(db)
        self.recovery = RecoveryService(db)
        self.email = EmailService()

    # 4) criação de usuário
    def register(self, name: str, email: str, password: str,
                 accepted_terms: bool) -> User:
        if not accepted_terms:
            raise ValueError("É necessário aceitar os termos de uso.")
        user = self.users.criar_usuario(name, email, password,
                                      termo_consentimento=True)
        return user

    # 1) credenciais + 2) sessão + 3) último acesso
    def login(self, email: str, password: str) -> Tuple[User, Session]:
        row = self.users.get_by_email_with_secret(email)
        if not row:
            raise ValueError("Credenciais inválidas.")
        usuario_id, nome, email_db, pwd_hash, pwd_salt, last_login_at, \
            termo_consentimento, consentimento_at = row
        if not self.hasher.verificar(password, pwd_hash, pwd_salt):
            raise ValueError("Credenciais inválidas.")
        session = self.sessions.create(usuario_id)
        self.users.set_last_login(usuario_id)
        user = User(
            id=usuario_id,
            nome=nome,
            email=email_db,
            last_login_at=last_login_at,
            termo_consentimento=bool(termo_consentimento),
            consentimento_at=consentimento_at,
        )
        return user, session

    def validate_session(self, session_id: str) -> Optional[User]:
        s = self.sessions.validate(session_id)
        if not s:
            return None
        return self.users.get_by_id(s.usuario_id)

    # 6, 7 e 8) fluxo de recuperação
    def request_password_reset(self, email: str) -> Optional[str]:
        row = self.users.get_by_email_with_secret(email)
        if not row:
            return None
        usuario_id = row[0]
        email_db = row[2]
        token = self.recovery.generate_and_store(usuario_id)
        link = url_for("reset_password", email=email_db, token=token,
                       _external=True)
        self.email.send_password_recovery(email_db, link)
        return token

    def reset_password_with_token(self, email: str, token: str,
                                  new_password: str) -> bool:
        token_id = self.recovery.validate_token(email, token)
        if not token_id:
            return False
        usuario_id = self.recovery.get_usuario_id_from_token(token_id)
        if not usuario_id:
            return False
        self.users.change_password(usuario_id, new_password)
        self.recovery.mark_used(token_id)
        return True

# ================== Flask app ==================
db = Banco_Dados()
auth = AuthService(db)


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY",
                                          "dev-secret-change-me")


@app.before_request
def load_current_user():
    g.current_user = None
    sid = request.cookies.get("session_id")
    if not sid:
        return
    user = auth.validate_session(sid)
    if user:
        g.current_user = user


@app.get("/")
def index():
    if g.current_user:
        return redirect(url_for("home"))
    message = request.args.get("message")
    error = request.args.get("error")
    return render_template("index.html", message=message, error=error)

@app.post("/register")
def register():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    accepted_terms = request.form.get("terms") == "on"

    try:
        auth.register(name, email, password, accepted_terms)
    except Exception as e:
        return render_template("index.html", error=str(e), message=None)

    # login automático após cadastro
    user, session = auth.login(email, password)
    resp = make_response(redirect(url_for("home")))
    resp.set_cookie("session_id", session.id,
                    httponly=True, samesite="Lax")
    return resp

@app.post("/login")
def login_user():
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")

    try:
        user, session = auth.login(email, password)
    except Exception as e:
        return render_template("index.html", error=str(e), message=None)

    resp = make_response(redirect(url_for("home")))
    resp.set_cookie("session_id", session.id,
                    httponly=True, samesite="Lax")
    return resp

@app.get("/home")
def home():
    return render_template("home.html", user=g.current_user)

@app.get("/logout")
def logout():
    resp = make_response(
        redirect(url_for("index", message="Sessão encerrada."))
    )
    resp.delete_cookie("session_id")
    return resp

@app.get("/forgot-password")
def forgot_password():
    return render_template("esqueceu.html",
                           message=None, error=None)


@app.post("/forgot-password")
def forgot_password_form():
    email = request.form.get("email", "").strip()
    token = auth.request_password_reset(email)
    if not token:
        return render_template("esqueceu.html",
                               error="E-mail não encontrado.",
                               message=None)
    msg = ("Se o e-mail existir, um link de recuperação foi enviado "
           "(simulado no console).")
    return render_template("esqueceu.html",
                           message=msg, error=None)

@app.get("/reset-password")
def reset_password_form():
    email = request.args.get("email", "")
    token = request.args.get("token", "")
    if not email or not token:
        return redirect(url_for("index",
                                error="Link de recuperação inválido."))
    return render_template("reset_password.html",
                           email=email, token=token, error=None)


@app.get("/cadastro")
def cadastro():
    return render_template("cadastro.html")

@app.get("/dicas")
def dicas():
    if not g.current_user:
        return redirect(url_for("index",
                                error="Você precisa estar logado."))
    return render_template("dicas.html")



@app.get("/quiz")
def quiz():
    return render_template("quiz1.html")

@app.get("/produto")
def produto():
    if not g.current_user:
        return redirect(url_for("index",
                                error="Você precisa estar logado."))
    return render_template("produto.html")

@app.get("/perfil")
def perfil():
    if not g.current_user:
        return redirect(url_for("index",
                                error="Você precisa estar logado."))
    return render_template("perfil.html")

@app.get("/suapele")
def suapele():
    if not g.current_user:
        return redirect(url_for("index",
                                error="Você precisa estar logado."))
    return render_template("sua_pele.html")

@app.get("/sobre")
def sobre():
    if not g.current_user:
        return redirect(url_for("index",
                                error="Você precisa estar logado."))
    return render_template("sobre.html")

@app.get("/curso")
def curso():
    if not g.current_user:
        return redirect(url_for("index",
                                error="Você precisa estar logado."))
    return render_template("curso.html")


if __name__ == "__main__":
    app.run(debug=True)

