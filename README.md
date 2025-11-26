# Puxa+ - Flask

Aplicação em Flask para a plataforma Puxa+, mantendo as páginas estáticas que existiam na versão em Next.js (login, registo, dashboard, dieta, treino, feed, etc.).

## Tecnologias

- Python 3.11+
- Flask 3
- Tailwind via CDN

## Como executar

1. Crie o ambiente virtual (opcional, mas recomendado):

   ```bash
   python -m venv .venv
   .venv\Scripts\activate  # Windows
   source .venv/bin/activate  # Linux/Mac
   ```

2. Instale as dependências:

   ```bash
   pip install -r requirements.txt
   ```

3. Inicie o servidor em modo de desenvolvimento:

   ```bash
   flask --app app run --debug
   ```

4. A aplicação ficará disponível em [http://localhost:5000](http://localhost:5000).

## Estrutura

- `app.py`: define as rotas Flask e a lógica mínima (ex.: dados do gráfico).
- `templates/`: contém os templates Jinja, incluindo o layout com sidebar e header.
- `static/css/styles.css`: definições globais simples.
- `requirements.txt`: dependências Python.
