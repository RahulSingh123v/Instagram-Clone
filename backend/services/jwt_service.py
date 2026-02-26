import jwt
import hashlib
import structlog

from django.conf import settings
from django.utils import timezone
from backend.apps.accounts.models import RefreshToken
from backend.core import uuid7_str


logger = structlog.get_logger(__name__)

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = "HS256"


def generate_access_token(user):
    try:
        exp = timezone.now() + settings.ACCESS_TOKEN_LIFETIME

        payload = {
            "jti": str(uuid7_str()),
            "user_id": str(user.id),
            "type": "access",
            "exp": int(exp.timestamp()),
        }

        token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

        logger.info(
            "access_token_generated",
            user_id=str(user.id),
            expires_at=int(exp.timestamp()),
        )

        return token

    except Exception as e:
        logger.error(
            "access_token_generation_failed",
            user_id=str(user.id),
            error=str(e),
            exc_info=True,
        )
        raise


def generate_refresh_token(user, device_id):
    try:
        exp = timezone.now() + settings.REFRESH_TOKEN_LIFETIME

        payload = {
            "jti": str(uuid7_str()),
            "user_id": str(user.id),
            "type": "refresh",
            "exp": int(exp.timestamp()),
        }

        raw_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

        RefreshToken.objects.create(
            user=user,
            token_hash=token_hash,
            device_id=device_id,
            expires_at=exp,
        )

        logger.info(
            "refresh_token_created",
            user_id=str(user.id),
            device_id=device_id,
            expires_at=int(exp.timestamp()),
        )

        return raw_token

    except Exception as e:
        logger.error(
            "refresh_token_generation_failed",
            user_id=str(user.id),
            device_id=device_id,
            error=str(e),
            exc_info=True,
        )
        raise


