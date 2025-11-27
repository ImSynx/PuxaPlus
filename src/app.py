from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
import os
import re

app = Flask(__name__)
load_dotenv()

app.config["SQLALCHEMY_DATABASE_URI"] = 'mysql+pymysql://{}:{}@localhost/{}'.format(
    os.environ.get('DB_USER'), 
    os.environ.get('DB_PASSWORD'),
    os.environ.get('DB_NAME')
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

db = SQLAlchemy()
db.init_app(app)


# Modelos de Base de Dados
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    bio = db.Column(db.Text, nullable=True)
    points = db.Column(db.Integer, default=0)
    level = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relacionamentos
    activities = db.relationship('Activity', backref='user', lazy=True, cascade='all, delete-orphan')
    progress_points = db.relationship('ProgressPoint', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Activity(db.Model):
    __tablename__ = 'activities'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    date = db.Column(db.String(10), nullable=False)  # formato: "DD/MM"
    value = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ProgressPoint(db.Model):
    __tablename__ = 'progress_points'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    x = db.Column(db.Integer, nullable=False)
    y = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# Dataclasses para compatibilidade com código existente
@dataclass(frozen=True)
class ActivityPoint:
    date: str
    value: int


@dataclass(frozen=True)
class ProgressPointData:
    x: int
    y: int


# Dados padrão (fallback se não houver dados na base de dados)
DEFAULT_ACTIVITY_DATA: List[ActivityPoint] = [
    ActivityPoint("01/10", 5),
    ActivityPoint("02/10", 3),
    ActivityPoint("03/10", 2),
    ActivityPoint("04/10", 5),
    ActivityPoint("05/10", 1),
    ActivityPoint("06/10", 4),
    ActivityPoint("07/10", 3),
]

DEFAULT_PROGRESS_POINTS: List[ProgressPointData] = [
    ProgressPointData(10, 60),
    ProgressPointData(30, 40),
    ProgressPointData(50, 80),
    ProgressPointData(70, 30),
    ProgressPointData(90, 90),
]


# Funções auxiliares de autenticação
def get_current_user():
    """Retorna o utilizador atual da sessão"""
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None


def login_required(f):
    """Decorator para proteger rotas que requerem autenticação"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Por favor, faça login para aceder a esta página.", "error")
            return redirect(url_for('welcome'))
        return f(*args, **kwargs)
    return decorated_function


def validate_email(email: str) -> bool:
    """Valida formato de email"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_username(username: str) -> Tuple[bool, str]:
    """Valida username"""
    if len(username) < 3:
        return False, "O username deve ter pelo menos 3 caracteres."
    if len(username) > 80:
        return False, "O username não pode ter mais de 80 caracteres."
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "O username só pode conter letras, números e underscores."
    return True, ""


def validate_password(password: str) -> Tuple[bool, str]:
    """Valida password"""
    if len(password) < 6:
        return False, "A password deve ter pelo menos 6 caracteres."
    if len(password) > 128:
        return False, "A password não pode ter mais de 128 caracteres."
    return True, ""


@app.context_processor
def inject_navigation_helpers():
    path = request.path

    def is_nav_active(prefix: str) -> bool:
        if path == "/":
            return prefix == "/dashboard"
        return path.startswith(prefix)

    def nav_section_name() -> str:
        if path.startswith("/dieta"):
            return "Dieta"
        if path.startswith("/treino"):
            return "Treino"
        if path.startswith("/feed"):
            return "Feed"
        if path.startswith("/perfil"):
            return "Perfil"
        return "Puxa+"

    return {
        "is_nav_active": is_nav_active,
        "nav_section_name": nav_section_name(),
        "current_user": get_current_user(),
    }


@app.route("/")
def welcome():
    # Se já estiver autenticado, redirecionar para o dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template("welcome.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    # Se já estiver autenticado, redirecionar para o dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember_me = request.form.get("remember_me") == "on"
        
        # Validações básicas
        if not username:
            flash("Por favor, introduza o username.", "error")
            return render_template("welcome.html")
        
        if not password:
            flash("Por favor, introduza a password.", "error")
            return render_template("welcome.html")
        
        # Procurar utilizador por username ou email
        user = User.query.filter(
            (User.username == username) | (User.email == username)
        ).first()
        
        if not user:
            flash("Username/Email ou password incorretos.", "error")
            return render_template("welcome.html")
        
        # Verificar password
        if not user.check_password(password):
            flash("Username/Email ou password incorretos.", "error")
            return render_template("welcome.html")
        
        # Login bem-sucedido
        session['user_id'] = user.id
        session['username'] = user.username
        if remember_me:
            session.permanent = True
        
        flash(f"Bem-vindo, {user.username}!", "success")
        return redirect(url_for('dashboard'))
    
    return redirect(url_for('welcome'))


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    flash("Sessão terminada com sucesso.", "success")
    return redirect(url_for('welcome'))


@app.route("/register", methods=["GET", "POST"])
def register():
    # Se já estiver autenticado, redirecionar para o dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        
        # Validação: campos obrigatórios
        if not username or not email or not password:
            flash("Por favor, preencha todos os campos.", "error")
            return render_template("register.html")
        
        # Validação: username
        username_valid, username_error = validate_username(username)
        if not username_valid:
            flash(username_error, "error")
            return render_template("register.html")
        
        # Validação: email
        if not validate_email(email):
            flash("Por favor, introduza um email válido.", "error")
            return render_template("register.html")
        
        # Validação: password
        password_valid, password_error = validate_password(password)
        if not password_valid:
            flash(password_error, "error")
            return render_template("register.html")
        
        # Verificar se o username já existe
        if User.query.filter_by(username=username).first():
            flash("Este username já está em uso.", "error")
            return render_template("register.html")
        
        # Verificar se o email já existe
        if User.query.filter_by(email=email).first():
            flash("Este email já está em uso.", "error")
            return render_template("register.html")
        
        # Criar novo utilizador
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash("Conta criada com sucesso! Pode fazer login agora.", "success")
            return redirect(url_for("welcome"))
        except Exception as e:
            db.session.rollback()
            flash(f"Erro ao criar conta: {str(e)}", "error")
            return render_template("register.html")
    
    return render_template("register.html")


@app.route("/account-created")
def account_created():
    return render_template("account_created.html")


@app.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()
    return render_template("dashboard.html", user=user)


@app.route("/feed")
@login_required
def feed():
    return render_template("feed.html")


@app.route("/perfil")
@login_required
def perfil():
    user = get_current_user()
    
    if user and user.activities:
        activity_data = [ActivityPoint(a.date, a.value) for a in user.activities]
        max_value = max(point.value for point in activity_data) if activity_data else 1
    else:
        activity_data = DEFAULT_ACTIVITY_DATA
        max_value = max(point.value for point in activity_data) if activity_data else 1
    
    return render_template(
        "perfil.html",
        activity_data=activity_data,
        max_value=max_value or 1,
        user=user,
    )


@app.route("/resumo")
@login_required
def resumo():
    return render_template("resumo.html")


@app.route("/dieta")
@login_required
def dieta():
    return render_template("dieta.html")


@app.route("/dieta/desafios")
@login_required
def dieta_desafios():
    return render_template("dieta_desafios.html")


@app.route("/treino")
@login_required
def treino():
    return render_template("treino.html")


@app.route("/treino/desafios")
@login_required
def treino_desafios():
    return render_template("treino_desafios.html")


@app.route("/treino/plano")
@login_required
def treino_plano():
    return render_template("treino_plano.html")


@app.route("/treino/progresso")
@login_required
def treino_progresso():
    width = 400
    height = 300
    padding = 40

    user = get_current_user()
    
    if user and user.progress_points:
        progress_points = [ProgressPointData(p.x, p.y) for p in user.progress_points]
    else:
        progress_points = DEFAULT_PROGRESS_POINTS

    def scale_x(x_value: int) -> float:
        return ((x_value - 0) / 100) * (width - padding * 2) + padding

    def scale_y(y_value: int) -> float:
        max_y = 100
        min_y = 0
        return height - padding - ((y_value - min_y) / (max_y - min_y)) * (
            height - padding * 2
        )

    scaled_points = [
        {"x": round(scale_x(point.x), 2), "y": round(scale_y(point.y), 2)}
        for point in progress_points
    ]
    path_data = " ".join(
        f"{'M' if index == 0 else 'L'} {coords['x']} {coords['y']}"
        for index, coords in enumerate(scaled_points)
    )

    return render_template(
        "treino_progresso.html",
        width=width,
        height=height,
        padding=padding,
        path_data=path_data,
        scaled_points=scaled_points,
    )


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

