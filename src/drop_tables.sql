-- Script SQL para eliminar as tabelas da aplicação Puxa+
-- ATENÇÃO: Este script elimina todas as tabelas e os dados!
-- Execute apenas se tiver a certeza que quer eliminar tudo

-- Eliminar tabelas (na ordem correta devido às foreign keys)
DROP TABLE IF EXISTS progress_points;
DROP TABLE IF EXISTS activities;
DROP TABLE IF EXISTS users;

-- Verificar se as tabelas foram eliminadas
SHOW TABLES;

