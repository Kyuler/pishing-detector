# Configuración del detector de phishing

# Dominios targets para detección
TARGET_DOMAINS = [
    # Redes sociales
    "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com",
    "tiktok.com", "snapchat.com", "pinterest.com", "reddit.com", "tumblr.com",
    "threads.net",
    # Correo y servicios web
    "google.com", "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "protonmail.com",
    "icloud.com", "mail.com",
    # Pagos y bancos
    "paypal.com", "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com",
    "usbank.com", "amex.com", "capitalone.com", "discover.com", "visa.com",
    "mastercard.com", "bbva.com", "santander.com", "caixa.gov.br", "banorte.com",
    "bbm.com", "bradesco.com", "itau.com", "mercadopago.com",
    "mercadolibre.com", "mercadolibre.com.ar",
    # Bancos Argentina
    "bancoprovincia.com.ar", "bancofrances.com", "bancogalicia.com.ar", 
    "banconacion.com.ar", "bancocity.com.ar", "hipotecario.com.ar",
    "macro.com", "santander.com.ar", "bbva.com.ar", "credicoop.com.ar",
    "patagonia.com", "supervielle.com.ar", "nacion.com.ar",
    # Bancos Mexico
    "bbva.com.mx", "santander.com.mx", "bancomer.com.mx",
    # Tech
    "microsoft.com", "apple.com", "amazon.com", "netflix.com", "dropbox.com",
    "adobe.com", "github.com", "gitlab.com", "bitbucket.org",
    "whatsapp.com", "telegram.org", "discord.com", "slack.com", "zoom.us",
    "teams.microsoft.com", "shopify.com", "wordpress.com",
    # Gaming
    "steampowered.com", "epicgames.com", "riotgames.com", "battle.net",
    "ea.com", "ubisoft.com", "blizzard.com", "sony.com", "playstation.com",
    "xbox.com", "nintendo.com", "twitch.tv", "hulu.com", "disneyplus.com",
    # Tiendas y marcas
    "nike.com", "adidas.com", "puma.com",
    "zara.com", "hm.com", "uniqlo.com", "shein.com", "aliexpress.com",
    "ebay.com", "walmart.com", "target.com", "bestbuy.com", "costco.com",
    # Tiendas Argentina
    "garbarino.com", "fravega.com", "musimundo.com.ar", "cetrogar.com.ar",
    "jeanpiere.com.ar", "hites.com.ar", "cotodigital.com.ar", "liverpool.com.mx",
    # Educacion
    "coursera.org", "udemy.com", "edx.org", "khanacademy.org", "duolingo.com",
    # Otros servicios
    "spotify.com", "soundcloud.com", "medium.com", "wikipedia.org", "wikiwand.com"
]

# TLDs comunes en phishing
SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".online", ".site", ".work", ".gq", ".ml", ".cf", ".tk",
    ".buzz", ".fun", ".rest", ".icu", ".shop", ".store", ".tech", ".pro",
    ".click", ".link", ".download", ".win", ".bid", ".stream", ".trade",
    ".date", ".racing", ".cricket", ".science", ".party", ".casa", ".pw"
]

# Keywords de phishing en español e inglés
PHISHING_KEYWORDS = {
    "es": [
        "login", "signin", "iniciar", "sesion", "cuenta", "verificar", "actualizar",
        "datos", "password", "contrasena", "clave", "banco", "soporte", "ayuda",
        "urgente", "alert", "seguridad", "confirmar", "identidad", "acceder",
        "mi-cuenta", "mis-datos", "configuracion", "seguro",
        "pago", "factura", "ticket", "suscripcion", "premium", "gratis",
        "premio", "ganador", "sorteo", "promocion", "descuento", "oferta",
        "verificacion", "autenticacion", "2fa", "codigo", "token",
        "phishing", "estafa", "fraude", "robo", "cuentas", "contrasenas",
        "iniciar-sesion", "acceso", "webmail", "correo", "comprar", "tienda",
        "venta", "oferta", "descuento", "promocion", "gratis", "gratuito",
        "premio", "ganar", "loteria", "sorteo", "winner", "winning",
        "urgente", "inmediato", "ahora", "limite", "expirar", "expired",
        "envio", "enviar", "entrega", "paquete", "tracking", "seguimiento",
        "carrito", "comprar", "checkout", "pagar", "direccion", "facturacion"
    ],
    "en": [
        "login", "signin", "account", "verify", "update", "secure", "password",
        "confirm", "bank", "support", "help", "urgent", "alert", "security",
        "access", "my-account", "settings", "payment", "invoice", "subscription",
        "premium", "free", "winner", "promo", "discount", "offer", "prize",
        "verification", "authentication", "2fa", "code", "token", "reset",
        "sign-in", "e-mail", "webmail", "shop", "store", "buy", "sale",
        "deal", "limited", "offer", "claim", "reward", "winning", "lottery",
        "immediate", "now", "expire", "expiring", "suspended", "locked",
        "checkout", "shipping", "delivery", "track", "tracking", "package",
        "cart", "order", "billing", "address", "video", "stream", "live",
        "prime", "membership", "subscription", "gift", "card", "debit", "credit"
    ]
}

# Dominios conocidos de phishing (blacklist local)
BLACKLIST = [
    "g00gle.com", "faceb00k.com", "paypa1.com", "amaz0n.com",
    "micros0ft.com", "app1e.com", "netf1ix.com", "facebok.com",
    "gooogle.com", "paypal.com.ru", "microsoft.com.cn"
]

# Whitelist de excepciones legítimas
WHITELIST = [
    "whatsapp-web.com", "whatsapp.com", "stackoverflow.com", 
    "verify.com", "login.com", "mercadopago.com", "mercadopago.com.ar"
]

# Sufijos seguros que no deben detectarse como phishing
SAFE_SUFFIXES = [
    "-web", "-app", "-online", "-official", "-shop", 
    "-mobile", "-desktop", "-api", "-webmail"
]

REQUEST_TIMEOUT = 3