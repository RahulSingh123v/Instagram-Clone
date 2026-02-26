import secrets
import hashlib
from django.utils import timezone
from datetime import timedelta
from django.conf import settings
from backend.apps.accounts.models import EmailOTP
import structlog

logger = structlog.get_logger(__name__)

def generate_otp(user):
    otp = str(secrets.randbelow(900000) + 100000)
    otp_hash = hashlib.sha256(otp.encode()).hexdigest()

    try:

        EmailOTP.objects.create(
            user=user,
            otp_hash = otp_hash,
            expires_at = timezone.now() + timedelta(minutes=5)
        )
        logger.info(
            "otp_generated",
            user_id=str(user.id),
            otp=otp)
    except Exception as e:
        logger.error(
            "otp_generation_failed",
            user_id=str(user.id),
            error=str(e),
            exc_info=True
        )
        raise 


    return otp
