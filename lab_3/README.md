# Лабораторная работа №3: Гибридная криптосистема
**Вариант:** 9  
**Алгоритм:** IDEA (128 бит) + RSA (2048 бит)  
**Студент:** Родионов Антон 6214-100503D

## Описание
Реализация гибридной криптосистемы, сочетающей асимметричное шифрование (RSA) для безопасной передачи симметричного ключа и блочное симметричное шифрование (IDEA) для защиты данных.  
Приложение поддерживает три независимых режима работы, запускаемых через аргументы командной строки:
- `-gen` / `--generation` — генерация и сериализация ключей
- `-enc` / `--encryption` — шифрование файла
- `-dec` / `--decryption` — дешифрование файла

## Установка
```bash
pip install -r requirements.txt
```

Использование
1. Генерация ключей
```bash
python hybrid_crypto.py -gen --sym-key keys/sym.enc --pub-key keys/pub.pem --priv-key keys/priv.pem
```
2. Шифрование
```bash
python hybrid_crypto.py -enc --input data.txt --output data.enc --enc-sym-key keys/sym.enc --priv-key keys/priv.pem
```
3. Дешифрование
```bash
python hybrid_crypto.py -dec --input data.enc --output restored.txt --enc-sym-key keys/sym.enc --priv-key keys/priv.pem
```