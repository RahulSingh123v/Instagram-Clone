import jwt
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.conf import settings
from apps.accounts.models import User

class CookieJWTAuthentication(BaseAuthentication):

    def authenticate(Self,request):
        token = request.COOKIES.get("access_token")

        if not token:
            return None
        
        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithm=["HS256"]
            )
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Token expired")
        except jwt.InvalidTokenError:
            raise AuthenticationFailed("Invalid token")
        
        user = User.objects.get(id=payload["user_id"])

        return (user,None)
    
    