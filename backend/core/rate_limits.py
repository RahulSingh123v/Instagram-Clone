RATE_LIMITS = {
    "login": {
        "limit": 5,
        "window": 900  # 15 min
    },
    "signup": {
        "limit": 3,
        "window": 3600
    },
    "otp": {
        "limit": 5,
        "window": 600
    },
    "refresh": {
        "limit": 10,
        "window": 600
    },
    "password_reset": {
        "limit": 3,
        "window": 3600
    }
}