from __future__ import annotations

from dataclasses import dataclass
from typing import List

from flask import Flask, render_template, request

app = Flask(__name__)


@dataclass(frozen=True)
class ActivityPoint:
    date: str
    value: int


@dataclass(frozen=True)
class ProgressPoint:
    x: int
    y: int


ACTIVITY_DATA: List[ActivityPoint] = [
    ActivityPoint("01/10", 5),
    ActivityPoint("02/10", 3),
    ActivityPoint("03/10", 2),
    ActivityPoint("04/10", 5),
    ActivityPoint("05/10", 1),
    ActivityPoint("06/10", 4),
    ActivityPoint("07/10", 3),
]

PROGRESS_POINTS: List[ProgressPoint] = [
    ProgressPoint(10, 60),
    ProgressPoint(30, 40),
    ProgressPoint(50, 80),
    ProgressPoint(70, 30),
    ProgressPoint(90, 90),
]


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
    }


@app.route("/")
def welcome():
    return render_template("welcome.html")


@app.route("/register")
def register():
    return render_template("register.html")


@app.route("/account-created")
def account_created():
    return render_template("account_created.html")


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/feed")
def feed():
    return render_template("feed.html")


@app.route("/perfil")
def perfil():
    max_value = max(point.value for point in ACTIVITY_DATA)
    return render_template(
        "perfil.html",
        activity_data=ACTIVITY_DATA,
        max_value=max_value or 1,
    )


@app.route("/resumo")
def resumo():
    return render_template("resumo.html")


@app.route("/dieta")
def dieta():
    return render_template("dieta.html")


@app.route("/dieta/desafios")
def dieta_desafios():
    return render_template("dieta_desafios.html")


@app.route("/treino")
def treino():
    return render_template("treino.html")


@app.route("/treino/desafios")
def treino_desafios():
    return render_template("treino_desafios.html")


@app.route("/treino/plano")
def treino_plano():
    return render_template("treino_plano.html")


@app.route("/treino/progresso")
def treino_progresso():
    width = 400
    height = 300
    padding = 40

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
        for point in PROGRESS_POINTS
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
    app.run(debug=True)

