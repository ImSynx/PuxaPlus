#!/usr/bin/env python3
"""
Script para inicializar a base de dados.
Cria todas as tabelas definidas nos modelos.
"""

from app import app, db

if __name__ == "__main__":
    with app.app_context():
        print("Criando tabelas da base de dados...")
        db.create_all()
        print("Tabelas criadas com sucesso!")
        print("\nTabelas criadas:")
        print("- users")
        print("- activities")
        print("- progress_points")
