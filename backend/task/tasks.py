from celery import shared_task
from backend.services.email_service import send_email
import structlog
from botocore.exceptions import ClientError, EndpointConnectionError
from backend.apps.accounts.models import EmailOTP, RefreshToken, PasswordResetToken
from django.utils import timezone

logger = structlog.get_logger(__name__)

@shared_task(bind=True, max_retries=3)
def send_email_task(self, to_email, subject, body, html_body=None):
    try:
        send_email(to_email, subject, body, html_body)
        logger.info("Email sent successfully", email=to_email)

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code in ["Throttling", "ServiceUnavailable"]:
            logger.warning("email_transient_error_retrying",
                           to=to_email,
                           error_code=error_code,
                           retries=self.request.retries
                           )
            raise self.retry(e=e, countdown=2 ** self.request.retries)
        
        logger.error("email_permanent_failure",
                     to=to_email,
                     error_code=error_code
                    )
        raise

    except EndpointConnectionError as e:
        raise self.retry(e=e,countdown = 2 ** self.request.retries)
    
@shared_task
def cleanup_expired():
    now = timezone.now()

    otp_deleted = EmailOTP.objects.filter(
        expires_at__lt=now
    ).delete()

    refresh_deleted = RefreshToken.objects.filter(
        expires_at__lt=now
    ).delete()

    logger.info(
        "cleanup_completed",
        otp_deleted=otp_deleted,
        refresh_deleted=refresh_deleted
    )