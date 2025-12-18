from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from dotenv import load_dotenv
import os
import re
from uuid import uuid4

app = Flask(__name__)
load_dotenv()

app.config["SQLALCHEMY_DATABASE_URI"] = 'mysql+pymysql://{}:{}@localhost/{}'.format(
    os.environ.get('DB_USER'), 
    os.environ.get('DB_PASSWORD'),
    os.environ.get('DB_NAME')
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'uploads', 'profile_pictures')
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5MB max file size
app.config["ALLOWED_EXTENSIONS"] = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# Criar diretório de uploads se não existir
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

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
    profile_picture = db.Column(db.String(255), nullable=True)
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


class Post(db.Model):
    __tablename__ = 'posts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relacionamentos
    user = db.relationship('User', backref='posts', lazy=True)
    comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan', order_by='Comment.created_at')
    likes = db.relationship('PostLike', backref='post', lazy=True, cascade='all, delete-orphan')


class Comment(db.Model):
    __tablename__ = 'comments'
    
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relacionamentos
    user = db.relationship('User', backref='comments', lazy=True)
    replies = db.relationship('Reply', backref='comment', lazy=True, cascade='all, delete-orphan', order_by='Reply.created_at')


class Reply(db.Model):
    __tablename__ = 'replies'
    
    id = db.Column(db.Integer, primary_key=True)
    comment_id = db.Column(db.Integer, db.ForeignKey('comments.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relacionamentos
    user = db.relationship('User', backref='replies', lazy=True)


class PostLike(db.Model):
    __tablename__ = 'post_likes'
    
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relacionamentos
    user = db.relationship('User', backref='post_likes', lazy=True)
    
    # Garantir que um utilizador só pode dar like uma vez por post
    __table_args__ = (db.UniqueConstraint('post_id', 'user_id', name='unique_post_like'),)


class Notification(db.Model):
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # 'like', 'comment', 'reply'
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=True)
    comment_id = db.Column(db.Integer, db.ForeignKey('comments.id'), nullable=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relacionamentos
    user = db.relationship('User', foreign_keys=[user_id], backref='notifications', lazy=True)
    from_user = db.relationship('User', foreign_keys=[from_user_id], lazy=True)
    post = db.relationship('Post', backref='notifications', lazy=True)
    comment = db.relationship('Comment', backref='notifications', lazy=True)


class Challenge(db.Model):
    __tablename__ = 'challenges'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)  # 'dieta' ou 'treino'
    frequency = db.Column(db.String(20), nullable=False)  # 'daily' ou 'weekly'
    points_reward = db.Column(db.Integer, default=1)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relacionamentos
    user_challenges = db.relationship('UserChallenge', backref='challenge', lazy=True, cascade='all, delete-orphan')


class UserChallenge(db.Model):
    __tablename__ = 'user_challenges'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    challenge_id = db.Column(db.Integer, db.ForeignKey('challenges.id'), nullable=False)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    date_key = db.Column(db.String(20), nullable=False)  # Para desafios diários: 'YYYY-MM-DD', semanais: 'YYYY-WW'
    
    # Relacionamentos
    user = db.relationship('User', backref='user_challenges', lazy=True)
    
    # Garantir que um utilizador só pode completar o mesmo desafio uma vez por dia/semana
    __table_args__ = (db.UniqueConstraint('user_id', 'challenge_id', 'date_key', name='unique_user_challenge_date'),)


class MealPlan(db.Model):
    __tablename__ = 'meal_plans'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    day_of_week = db.Column(db.String(20), nullable=False)  # 'monday', 'tuesday', etc.
    meal_type = db.Column(db.String(50), nullable=False)  # 'breakfast', 'lunch', 'dinner', 'snack'
    meal_name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    calories = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relacionamentos
    user = db.relationship('User', backref='meal_plans', lazy=True)


class WorkoutPlan(db.Model):
    __tablename__ = 'workout_plans'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    day_of_week = db.Column(db.String(20), nullable=False)  # 'monday', 'tuesday', etc.
    workout_type = db.Column(db.String(50), nullable=False)  # 'cardio', 'strength', 'flexibility', 'hiit', etc.
    workout_name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    duration = db.Column(db.Integer, nullable=True)  # Duração em minutos
    exercises = db.Column(db.Text, nullable=True)  # Lista de exercícios
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relacionamentos
    user = db.relationship('User', backref='workout_plans', lazy=True)


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


def allowed_file(filename: str) -> bool:
    """Verifica se o ficheiro tem uma extensão permitida"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def get_profile_picture_url(user) -> str:
    """Retorna a URL da foto de perfil do utilizador"""
    if user and user.profile_picture:
        return url_for('uploaded_file', filename=user.profile_picture)
    return None


def create_notification(user_id: int, type: str, from_user_id: int, post_id: int = None, comment_id: int = None, message: str = None):
    """Cria uma notificação para um utilizador"""
    if not message:
        if type == 'like':
            message = f"deu like no seu post"
        elif type == 'comment':
            message = f"comentou no seu post"
        elif type == 'reply':
            message = f"respondeu ao seu comentário"
    
    notification = Notification(
        user_id=user_id,
        type=type,
        from_user_id=from_user_id,
        post_id=post_id,
        comment_id=comment_id,
        message=message
    )
    db.session.add(notification)


def get_daily_date_key() -> str:
    """Retorna a chave de data para desafios diários (YYYY-MM-DD)"""
    return datetime.utcnow().strftime('%Y-%m-%d')


def get_weekly_date_key() -> str:
    """Retorna a chave de data para desafios semanais (YYYY-WW)"""
    now = datetime.utcnow()
    year, week, _ = now.isocalendar()
    return f"{year}-{week:02d}"


def has_completed_challenge(user_id: int, challenge_id: int, date_key: str) -> bool:
    """Verifica se o utilizador já completou o desafio na data especificada"""
    return UserChallenge.query.filter_by(
        user_id=user_id,
        challenge_id=challenge_id,
        date_key=date_key
    ).first() is not None


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
        if path.startswith("/notificacoes"):
            return "Notificações"
        if path.startswith("/desafios"):
            return "Desafios"
        return "Puxa+"

    def user_liked_post(post, user):
        """Verifica se o utilizador deu like no post"""
        if not user or not post.likes:
            return False
        return any(like.user_id == user.id for like in post.likes)

    def get_unread_notifications_count():
        """Retorna o número de notificações não lidas do utilizador atual"""
        user = get_current_user()
        if user:
            return Notification.query.filter_by(user_id=user.id, read=False).count()
        return 0

    return {
        "is_nav_active": is_nav_active,
        "nav_section_name": nav_section_name(),
        "current_user": get_current_user(),
        "user_liked_post": user_liked_post,
        "unread_notifications_count": get_unread_notifications_count(),
        "get_profile_picture_url": get_profile_picture_url,
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
    
    # Calcular progresso dos desafios
    daily_key = get_daily_date_key()
    weekly_key = get_weekly_date_key()
    
    # Obter todos os desafios ativos
    all_daily_challenges = Challenge.query.filter_by(frequency='daily', active=True).all()
    all_weekly_challenges = Challenge.query.filter_by(frequency='weekly', active=True).all()
    
    total_challenges = len(all_daily_challenges) + len(all_weekly_challenges)
    
    # Contar desafios completados
    all_daily_ids = [c.id for c in all_daily_challenges]
    all_weekly_ids = [c.id for c in all_weekly_challenges]
    
    completed_count = 0
    
    if all_daily_ids:
        completed_daily = UserChallenge.query.filter(
            UserChallenge.user_id == user.id,
            UserChallenge.date_key == daily_key,
            UserChallenge.challenge_id.in_(all_daily_ids)
        ).count()
        completed_count += completed_daily
    
    if all_weekly_ids:
        completed_weekly = UserChallenge.query.filter(
            UserChallenge.user_id == user.id,
            UserChallenge.date_key == weekly_key,
            UserChallenge.challenge_id.in_(all_weekly_ids)
        ).count()
        completed_count += completed_weekly
    
    # Calcular percentagem
    progress_percentage = int((completed_count / total_challenges * 100)) if total_challenges > 0 else 0
    
    # Obter treinos de hoje
    today_weekday = datetime.utcnow().weekday()  # 0 = Monday, 6 = Sunday
    days_of_week = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
    today_key = days_of_week[today_weekday]
    
    today_workouts = WorkoutPlan.query.filter_by(
        user_id=user.id,
        day_of_week=today_key
    ).all()
    
    return render_template(
        "dashboard.html",
        user=user,
        total_challenges=total_challenges,
        completed_challenges=completed_count,
        progress_percentage=progress_percentage,
        today_workouts=today_workouts
    )


@app.route("/feed", methods=["GET", "POST"])
@login_required
def feed():
    user = get_current_user()
    
    if request.method == "POST":
        # Criar novo post
        content = request.form.get("content", "").strip()
        if content:
            new_post = Post(user_id=user.id, content=content)
            try:
                db.session.add(new_post)
                db.session.commit()
                flash("Publicação criada com sucesso!", "success")
            except Exception as e:
                db.session.rollback()
                flash(f"Erro ao criar publicação: {str(e)}", "error")
        else:
            flash("O conteúdo da publicação não pode estar vazio.", "error")
        return redirect(url_for('feed'))
    
    # Carregar todos os posts ordenados por data (mais recentes primeiro)
    posts = Post.query.order_by(Post.created_at.desc()).all()
    
    return render_template("feed.html", posts=posts, user=user)


@app.route("/feed/post/<int:post_id>/comment", methods=["POST"])
@login_required
def add_comment(post_id):
    user = get_current_user()
    post = Post.query.get_or_404(post_id)
    
    content = request.form.get("content", "").strip()
    if content:
        new_comment = Comment(post_id=post_id, user_id=user.id, content=content)
        try:
            db.session.add(new_comment)
            # Criar notificação para o autor do post (se não for o próprio utilizador)
            if post.user_id != user.id:
                create_notification(post.user_id, 'comment', user.id, post_id=post_id)
            db.session.commit()
            flash("Comentário adicionado!", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Erro ao adicionar comentário: {str(e)}", "error")
    else:
        flash("O comentário não pode estar vazio.", "error")
    
    return redirect(url_for('feed'))


@app.route("/feed/comment/<int:comment_id>/reply", methods=["POST"])
@login_required
def add_reply(comment_id):
    user = get_current_user()
    comment = Comment.query.get_or_404(comment_id)
    
    content = request.form.get("content", "").strip()
    if content:
        new_reply = Reply(comment_id=comment_id, user_id=user.id, content=content)
        try:
            db.session.add(new_reply)
            # Criar notificação para o autor do comentário (se não for o próprio utilizador)
            if comment.user_id != user.id:
                create_notification(comment.user_id, 'reply', user.id, post_id=comment.post_id, comment_id=comment_id)
            db.session.commit()
            flash("Resposta adicionada!", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Erro ao adicionar resposta: {str(e)}", "error")
    else:
        flash("A resposta não pode estar vazia.", "error")
    
    return redirect(url_for('feed'))


@app.route("/feed/post/<int:post_id>/like", methods=["POST"])
@login_required
def toggle_like(post_id):
    user = get_current_user()
    post = Post.query.get_or_404(post_id)
    
    existing_like = PostLike.query.filter_by(post_id=post_id, user_id=user.id).first()
    
    if existing_like:
        # Remover like
        db.session.delete(existing_like)
        db.session.commit()
    else:
        # Adicionar like
        new_like = PostLike(post_id=post_id, user_id=user.id)
        db.session.add(new_like)
        # Criar notificação para o autor do post (se não for o próprio utilizador)
        if post.user_id != user.id:
            create_notification(post.user_id, 'like', user.id, post_id=post_id)
        db.session.commit()
    
    return redirect(url_for('feed'))


@app.route("/notificacoes")
@login_required
def notificacoes():
    user = get_current_user()
    
    # Carregar notificações do utilizador ordenadas por data (mais recentes primeiro)
    notifications = Notification.query.filter_by(user_id=user.id).order_by(Notification.created_at.desc()).all()
    
    # Contar notificações não lidas
    unread_count = Notification.query.filter_by(user_id=user.id, read=False).count()
    
    return render_template("notificacoes.html", notifications=notifications, unread_count=unread_count)


@app.route("/notificacoes/<int:notification_id>/read", methods=["POST"])
@login_required
def mark_notification_read(notification_id):
    user = get_current_user()
    notification = Notification.query.get_or_404(notification_id)
    
    # Verificar se a notificação pertence ao utilizador
    if notification.user_id == user.id:
        notification.read = True
        db.session.commit()
        flash("Notificação marcada como lida.", "success")
    
    return redirect(url_for('notificacoes'))


@app.route("/notificacoes/mark-all-read", methods=["POST"])
@login_required
def mark_all_notifications_read():
    user = get_current_user()
    
    Notification.query.filter_by(user_id=user.id, read=False).update({'read': True})
    db.session.commit()
    flash("Todas as notificações foram marcadas como lidas.", "success")
    
    return redirect(url_for('notificacoes'))


@app.route("/perfil", methods=["GET", "POST"])
@login_required
def perfil():
    user = get_current_user()
    
    if request.method == "POST":
        # Processar atualização de perfil
        if 'update_bio' in request.form:
            # Atualizar bio
            bio = request.form.get("bio", "").strip()
            user.bio = bio if bio else None
            try:
                db.session.commit()
                flash("Bio atualizada com sucesso!", "success")
            except Exception as e:
                db.session.rollback()
                flash(f"Erro ao atualizar bio: {str(e)}", "error")
        
        elif 'profile_picture' in request.files:
            # Processar upload de foto de perfil
            file = request.files['profile_picture']
            if file and file.filename != '' and allowed_file(file.filename):
                # Gerar nome único para o ficheiro
                filename = f"{user.id}_{uuid4().hex}.{file.filename.rsplit('.', 1)[1].lower()}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                
                # Remover foto antiga se existir
                if user.profile_picture:
                    old_filepath = os.path.join(app.config['UPLOAD_FOLDER'], user.profile_picture)
                    if os.path.exists(old_filepath):
                        try:
                            os.remove(old_filepath)
                        except Exception:
                            pass  # Ignorar erros ao remover ficheiro antigo
                
                # Guardar novo ficheiro
                try:
                    file.save(filepath)
                    user.profile_picture = filename
                    db.session.commit()
                    flash("Foto de perfil atualizada com sucesso!", "success")
                except Exception as e:
                    db.session.rollback()
                    flash(f"Erro ao guardar foto: {str(e)}", "error")
            elif file and file.filename != '':
                flash("Formato de ficheiro não permitido. Use PNG, JPG, JPEG, GIF ou WEBP.", "error")
        
        return redirect(url_for('perfil'))
    
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


@app.route("/uploads/profile_pictures/<filename>")
def uploaded_file(filename):
    """Serve os ficheiros de upload"""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route("/resumo")
@login_required
def resumo():
    return render_template("resumo.html")


@app.route("/dieta", methods=["GET", "POST"])
@login_required
def dieta():
    user = get_current_user()
    
    if request.method == "POST":
        # Adicionar nova refeição
        day_of_week = request.form.get("day_of_week", "").strip()
        meal_type = request.form.get("meal_type", "").strip()
        meal_name = request.form.get("meal_name", "").strip()
        description = request.form.get("description", "").strip()
        calories = request.form.get("calories", "").strip()
        
        if day_of_week and meal_type and meal_name:
            calories_int = int(calories) if calories and calories.isdigit() else None
            new_meal = MealPlan(
                user_id=user.id,
                day_of_week=day_of_week,
                meal_type=meal_type,
                meal_name=meal_name,
                description=description if description else None,
                calories=calories_int
            )
            try:
                db.session.add(new_meal)
                db.session.commit()
                flash("Refeição adicionada com sucesso!", "success")
            except Exception as e:
                db.session.rollback()
                flash(f"Erro ao adicionar refeição: {str(e)}", "error")
        else:
            flash("Por favor, preencha todos os campos obrigatórios.", "error")
        
        return redirect(url_for('dieta'))
    
    # Carregar refeições do utilizador organizadas por dia
    days_of_week = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
    day_names_pt = {
        'monday': 'Segunda-feira',
        'tuesday': 'Terça-feira',
        'wednesday': 'Quarta-feira',
        'thursday': 'Quinta-feira',
        'friday': 'Sexta-feira',
        'saturday': 'Sábado',
        'sunday': 'Domingo'
    }
    
    meal_types_pt = {
        'breakfast': 'Pequeno-almoço',
        'lunch': 'Almoço',
        'dinner': 'Jantar',
        'snack': 'Snack'
    }
    
    meals_by_day = {}
    for day in days_of_week:
        meals_by_day[day] = MealPlan.query.filter_by(
            user_id=user.id,
            day_of_week=day
        ).order_by(MealPlan.meal_type).all()
    
    return render_template(
        "dieta.html",
        meals_by_day=meals_by_day,
        days_of_week=days_of_week,
        day_names_pt=day_names_pt,
        meal_types_pt=meal_types_pt
    )


@app.route("/dieta/meal/<int:meal_id>/delete", methods=["POST"])
@login_required
def delete_meal(meal_id):
    user = get_current_user()
    meal = MealPlan.query.get_or_404(meal_id)
    
    # Verificar se a refeição pertence ao utilizador
    if meal.user_id == user.id:
        try:
            db.session.delete(meal)
            db.session.commit()
            flash("Refeição eliminada com sucesso!", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Erro ao eliminar refeição: {str(e)}", "error")
    else:
        flash("Não tem permissão para eliminar esta refeição.", "error")
    
    return redirect(url_for('dieta'))


@app.route("/dieta/meal/<int:meal_id>/edit", methods=["POST"])
@login_required
def edit_meal(meal_id):
    user = get_current_user()
    meal = MealPlan.query.get_or_404(meal_id)
    
    # Verificar se a refeição pertence ao utilizador
    if meal.user_id != user.id:
        flash("Não tem permissão para editar esta refeição.", "error")
        return redirect(url_for('dieta'))
    
    meal_name = request.form.get("meal_name", "").strip()
    description = request.form.get("description", "").strip()
    calories = request.form.get("calories", "").strip()
    
    if meal_name:
        meal.meal_name = meal_name
        meal.description = description if description else None
        meal.calories = int(calories) if calories and calories.isdigit() else None
        meal.updated_at = datetime.utcnow()
        
        try:
            db.session.commit()
            flash("Refeição atualizada com sucesso!", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Erro ao atualizar refeição: {str(e)}", "error")
    else:
        flash("O nome da refeição é obrigatório.", "error")
    
    return redirect(url_for('dieta'))


@app.route("/desafios")
@login_required
def desafios():
    user = get_current_user()
    
    # Carregar todos os desafios
    dieta_daily = Challenge.query.filter_by(category='dieta', frequency='daily', active=True).all()
    dieta_weekly = Challenge.query.filter_by(category='dieta', frequency='weekly', active=True).all()
    treino_daily = Challenge.query.filter_by(category='treino', frequency='daily', active=True).all()
    treino_weekly = Challenge.query.filter_by(category='treino', frequency='weekly', active=True).all()
    
    # Obter chaves de data
    daily_key = get_daily_date_key()
    weekly_key = get_weekly_date_key()
    
    # Obter todos os IDs de desafios
    all_daily_ids = [c.id for c in dieta_daily] + [c.id for c in treino_daily]
    all_weekly_ids = [c.id for c in dieta_weekly] + [c.id for c in treino_weekly]
    
    # Verificar quais desafios foram completados
    completed_daily_ids = set()
    if all_daily_ids:
        completed_daily = UserChallenge.query.filter(
            UserChallenge.user_id == user.id,
            UserChallenge.date_key == daily_key,
            UserChallenge.challenge_id.in_(all_daily_ids)
        ).all()
        completed_daily_ids = {uc.challenge_id for uc in completed_daily}
    
    completed_weekly_ids = set()
    if all_weekly_ids:
        completed_weekly = UserChallenge.query.filter(
            UserChallenge.user_id == user.id,
            UserChallenge.date_key == weekly_key,
            UserChallenge.challenge_id.in_(all_weekly_ids)
        ).all()
        completed_weekly_ids = {uc.challenge_id for uc in completed_weekly}
    
    return render_template(
        "desafios.html",
        dieta_daily=dieta_daily,
        dieta_weekly=dieta_weekly,
        treino_daily=treino_daily,
        treino_weekly=treino_weekly,
        completed_daily_ids=completed_daily_ids,
        completed_weekly_ids=completed_weekly_ids,
        daily_key=daily_key,
        weekly_key=weekly_key
    )


@app.route("/dieta/desafios")
@login_required
def dieta_desafios():
    # Redirecionar para a página de desafios
    return redirect(url_for('desafios'))


@app.route("/challenge/<int:challenge_id>/complete", methods=["POST"])
@login_required
def complete_challenge(challenge_id):
    user = get_current_user()
    challenge = Challenge.query.get_or_404(challenge_id)
    
    # Determinar a chave de data baseada na frequência
    if challenge.frequency == 'daily':
        date_key = get_daily_date_key()
    else:
        date_key = get_weekly_date_key()
    
    # Verificar se já completou
    if has_completed_challenge(user.id, challenge_id, date_key):
        flash("Já completou este desafio hoje/esta semana!", "error")
        return redirect(request.referrer or url_for('dashboard'))
    
    # Criar registo de conclusão
    user_challenge = UserChallenge(
        user_id=user.id,
        challenge_id=challenge_id,
        date_key=date_key
    )
    db.session.add(user_challenge)
    
    # Adicionar pontos ao utilizador
    user.points += challenge.points_reward
    db.session.commit()
    
    flash(f"Desafio completado! Ganhou {challenge.points_reward} ponto(s)!", "success")
    return redirect(request.referrer or url_for('dashboard'))


@app.route("/treino", methods=["GET", "POST"])
@login_required
def treino():
    user = get_current_user()
    
    if request.method == "POST":
        # Adicionar novo treino
        day_of_week = request.form.get("day_of_week", "").strip()
        workout_type = request.form.get("workout_type", "").strip()
        workout_name = request.form.get("workout_name", "").strip()
        description = request.form.get("description", "").strip()
        duration = request.form.get("duration", "").strip()
        exercises = request.form.get("exercises", "").strip()
        
        if day_of_week and workout_type and workout_name:
            duration_int = int(duration) if duration and duration.isdigit() else None
            new_workout = WorkoutPlan(
                user_id=user.id,
                day_of_week=day_of_week,
                workout_type=workout_type,
                workout_name=workout_name,
                description=description if description else None,
                duration=duration_int,
                exercises=exercises if exercises else None
            )
            try:
                db.session.add(new_workout)
                db.session.commit()
                flash("Treino adicionado com sucesso!", "success")
            except Exception as e:
                db.session.rollback()
                flash(f"Erro ao adicionar treino: {str(e)}", "error")
        else:
            flash("Por favor, preencha todos os campos obrigatórios.", "error")
        
        return redirect(url_for('treino'))
    
    # Carregar treinos do utilizador organizados por dia
    days_of_week = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
    day_names_pt = {
        'monday': 'Segunda-feira',
        'tuesday': 'Terça-feira',
        'wednesday': 'Quarta-feira',
        'thursday': 'Quinta-feira',
        'friday': 'Sexta-feira',
        'saturday': 'Sábado',
        'sunday': 'Domingo'
    }
    
    workout_types_pt = {
        'cardio': 'Cardio',
        'strength': 'Força',
        'flexibility': 'Flexibilidade',
        'hiit': 'HIIT',
        'yoga': 'Yoga',
        'pilates': 'Pilates',
        'crossfit': 'CrossFit',
        'other': 'Outro'
    }
    
    workouts_by_day = {}
    for day in days_of_week:
        workouts_by_day[day] = WorkoutPlan.query.filter_by(
            user_id=user.id,
            day_of_week=day
        ).order_by(WorkoutPlan.workout_type).all()
    
    return render_template(
        "treino.html",
        workouts_by_day=workouts_by_day,
        days_of_week=days_of_week,
        day_names_pt=day_names_pt,
        workout_types_pt=workout_types_pt
    )


@app.route("/treino/workout/<int:workout_id>/delete", methods=["POST"])
@login_required
def delete_workout(workout_id):
    user = get_current_user()
    workout = WorkoutPlan.query.get_or_404(workout_id)
    
    # Verificar se o treino pertence ao utilizador
    if workout.user_id == user.id:
        try:
            db.session.delete(workout)
            db.session.commit()
            flash("Treino eliminado com sucesso!", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Erro ao eliminar treino: {str(e)}", "error")
    else:
        flash("Não tem permissão para eliminar este treino.", "error")
    
    return redirect(url_for('treino'))


@app.route("/treino/workout/<int:workout_id>/edit", methods=["POST"])
@login_required
def edit_workout(workout_id):
    user = get_current_user()
    workout = WorkoutPlan.query.get_or_404(workout_id)
    
    # Verificar se o treino pertence ao utilizador
    if workout.user_id != user.id:
        flash("Não tem permissão para editar este treino.", "error")
        return redirect(url_for('treino'))
    
    workout_name = request.form.get("workout_name", "").strip()
    description = request.form.get("description", "").strip()
    duration = request.form.get("duration", "").strip()
    exercises = request.form.get("exercises", "").strip()
    
    if workout_name:
        workout.workout_name = workout_name
        workout.description = description if description else None
        workout.duration = int(duration) if duration and duration.isdigit() else None
        workout.exercises = exercises if exercises else None
        workout.updated_at = datetime.utcnow()
        
        try:
            db.session.commit()
            flash("Treino atualizado com sucesso!", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Erro ao atualizar treino: {str(e)}", "error")
    else:
        flash("O nome do treino é obrigatório.", "error")
    
    return redirect(url_for('treino'))


@app.route("/treino/desafios")
@login_required
def treino_desafios():
    # Redirecionar para a página de desafios
    return redirect(url_for('desafios'))


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


def init_default_challenges():
    """Inicializa desafios padrão se não existirem"""
    # Verificar se já existem desafios
    if Challenge.query.first():
        return
    
    default_challenges = [
        # Desafios diários de dieta
        Challenge(
            title="Beber 2 litros de água",
            description="Beba pelo menos 2 litros de água durante o dia para manter-se hidratado.",
            category='dieta',
            frequency='daily',
            points_reward=1
        ),
        Challenge(
            title="Comer 5 porções de frutas/vegetais",
            description="Inclua pelo menos 5 porções de frutas e vegetais nas suas refeições do dia.",
            category='dieta',
            frequency='daily',
            points_reward=1
        ),
        Challenge(
            title="Evitar alimentos processados",
            description="Evite comer alimentos processados ou fast food durante o dia.",
            category='dieta',
            frequency='daily',
            points_reward=1
        ),
        # Desafios semanais de dieta
        Challenge(
            title="Planejar refeições da semana",
            description="Planeje todas as refeições da semana com antecedência.",
            category='dieta',
            frequency='weekly',
            points_reward=1
        ),
        Challenge(
            title="Experimentar 3 receitas novas",
            description="Experimente pelo menos 3 receitas novas e saudáveis durante a semana.",
            category='dieta',
            frequency='weekly',
            points_reward=1
        ),
        # Desafios diários de treino
        Challenge(
            title="Fazer 30 minutos de exercício",
            description="Complete pelo menos 30 minutos de exercício físico hoje.",
            category='treino',
            frequency='daily',
            points_reward=1
        ),
        Challenge(
            title="Fazer 10.000 passos",
            description="Dê pelo menos 10.000 passos durante o dia.",
            category='treino',
            frequency='daily',
            points_reward=1
        ),
        Challenge(
            title="Fazer alongamentos",
            description="Dedique 10 minutos a fazer alongamentos para melhorar a flexibilidade.",
            category='treino',
            frequency='daily',
            points_reward=1
        ),
        # Desafios semanais de treino
        Challenge(
            title="Treinar 5 dias da semana",
            description="Complete pelo menos 5 sessões de treino durante a semana.",
            category='treino',
            frequency='weekly',
            points_reward=1
        ),
        Challenge(
            title="Aumentar carga ou repetições",
            description="Aumente a carga ou o número de repetições em pelo menos um exercício.",
            category='treino',
            frequency='weekly',
            points_reward=1
        ),
    ]
    
    for challenge in default_challenges:
        db.session.add(challenge)
    
    db.session.commit()
    print("Desafios padrão criados com sucesso!")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        init_default_challenges()
    app.run(debug=True)

