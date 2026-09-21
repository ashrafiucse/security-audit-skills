# Fixture: intentionally insecure Django settings. FAKE values.
SECRET_KEY = 'django-insecure-fixture-key-0f4t8w2qbkx3'   # SEC-01: hardcoded

DEBUG = True                                              # SEC-02
ALLOWED_HOSTS = ['*']                                     # SEC-03

CSRF_COOKIE_SECURE = False                                # SEC-04
SESSION_COOKIE_SECURE = False                             # SEC-04

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'app',
        'PASSWORD': 'django-prod-pass-2026',              # SEC-01b
    }
}
