import jwt
import structlog

from django.conf import settings
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from apps.accounts.models import User

logger = structlog.get_logger(__name__)

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = "HS256"


class CookieJWTAuthentication(BaseAuthentication):
    """
    Authenticates requests using a JWT stored in the 'access_token' HttpOnly cookie.
    Matches the token format produced by jwt_service.generate_access_token().
    """

    def authenticate(self, request):
        token = request.COOKIES.get("access_token")

        # No cookie present — let other authenticators (or AllowAny) handle it
        if not token:
            return None

        try:
            payload = jwt.decode(
                token,
                SECRET_KEY,
                algorithms=[ALGORITHM],
            )
        except jwt.ExpiredSignatureError:
            logger.warning("access_token_expired")
            raise AuthenticationFailed("Access token has expired.")
        except jwt.InvalidTokenError as e:
            logger.warning("access_token_invalid", error=str(e))
            raise AuthenticationFailed("Invalid access token.")

        # Ensure it is an access token, not a refresh token
        if payload.get("type") != "access":
            raise AuthenticationFailed("Invalid token type.")

        user_id = payload.get("user_id")

        if not user_id:
            raise AuthenticationFailed("Token payload is missing user_id.")

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise AuthenticationFailed("User not found.")

        if not user.is_active:
            raise AuthenticationFailed("User account is inactive.")

        logger.info("user_authenticated_via_cookie", user_id=str(user.id))

        return (user, None)
