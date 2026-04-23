# Phishing Detector

Herramienta en Python para detectar URLs de phishing sin necesidad de APIs externas ni aprendizaje automático.

## Por qué?

Lo hice para ayudar a analizar URLs de forma simple y efectiva, sin depender de servicios de terceros. Este detector analiza el dominio, busca errores comunes y patrones sospechosos usando solo lógica de programación.

## Qué detecta?

- **Typosquatting**: googel.com, paypa1.com, faceb00k.com
- **Keywords sospechosas**: login, verify, support combinadas con marcas conocidas
- **TLDs sospechosos**: .xyz, .top, .gq, .tk
- **Dominios aleatorios**: alta entropía como xkfjshd.com
- **Números en lugar de letras**: amazon2024, google1
- **Blacklist local**: dominios conocidos de phishing

## Uso

```bash
# Una URL
python3 main.py google.com

# Batch desde archivo
python3 main.py -f urls.txt

# Exportar a CSV
python3 main.py -f urls.txt -o results.csv --csv
```

## Scoring

- 0-2: SEGURO 🟢
- 3+: AMENAZA 🔴

## Tech stack

- Python 3
- colorama (para colores en terminal)
- Sin dependencias externas para las detecciones principales

## Instalación

```bash
git clone https://github.com/Kyuler/phishing-detector.git
cd phishing-detector
pip install colorama  # opcional
```