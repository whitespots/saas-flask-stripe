import os

config = {
    'SECRET_KEY': os.environ.get('SECRET_KEY'),
    'GOOGLE_LOGIN_REDIRECT_SCHEME': os.environ.get('GOOGLE_LOGIN_REDIRECT_SCHEME'),
    'GOOGLE_DISCOVERY_URL': os.environ.get('GOOGLE_DISCOVERY_URL'),
    'GOOGLE_CLIENT_ID': os.environ.get('GOOGLE_CLIENT_ID'),
    'GOOGLE_CLIENT_SECRET': os.environ.get('GOOGLE_CLIENT_SECRET'),
    'STRIPE_PUBLISHABLE_KEY': os.environ.get('STRIPE_PUBLISHABLE_KEY'),
    'STRIPE_SECRET_KEY': os.environ.get('STRIPE_SECRET_KEY'),
    'STRIPE_PRICE_ID': os.environ.get('STRIPE_PRICE_ID'),
    'STRIPE_WEBHOOK_SECRET': os.environ.get('STRIPE_WEBHOOK_SECRET')
}