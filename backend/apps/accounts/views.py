from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
from django.utils import timezone
from django.contrib.auth import authenticate
from django.conf import settings
from django.db import transaction
import secrets
import hashlib
from backend.core.decorators.rate_limit import rate_limit as endpoint_rate_limit
from apps.accounts.models import RefreshToken, User, EmailOTP, PasswordResetToken
from apps.accounts.serializers import *
from backend.services.otp_service import generate_otp
from backend.services.jwt_service import generate_access_token, generate_refresh_token
from backend.services.rate_limit import rate_limit # NAive rate limit 
from structlog  import get_logger
from django.views.decorators.csrf import ensure_csrf_cookie
from rest_framework.decorators import api_view
from django_redis import get_redis_connection
from rest_framework.permissions import IsAuthenticated
from django.db import transaction
logger = get_logger(__name__)   

redis_client = get_redis_connection("default")

class SignupView(APIView):  
    @endpoint_rate_limit("signup", identifier_type="ip")
    def post(self,request):

        serializer = SignupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            with transaction.atomic():
                user = serializer.save()
                otp = generate_otp(user)

            logger.info(
                "Signup_otp_sent",
                user_id=str(user.id),
                ip = request.META.get("REMOTE_ADDR")
            )

            return Response(
                {"message":"otp has been sent successfully"},
                status=status.HTTP_201_CREATED
            )

        except Exception as e:
            logger.error(
                "Signup_failed",
                user_id = str(user.id),
                error = str(e),
                exc_info = True
            )

            return Response(
                "unable to process request",
                status = status.HTTP_500_INTERNAL_SERVER_ERROR       
            )
    
class LoginView(APIView):
    @endpoint_rate_limit("login", identifier_type="ip")
    def post(self, request):
        serializer = LoginSerializer(
            data=request.data,
            context={"request": request}
        )

        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]

        # Optional: store last login IP
        user.last_login_ip = request.META.get("REMOTE_ADDR")
        user.save(update_fields=["last_login_ip"])

        otp = generate_otp(user)

        logger.info(
            "login_otp_generated",
            user_id=str(user.id),
            ip=request.META.get("REMOTE_ADDR")
        )

        return Response(
            {"message": "OTP sent"},
            status=status.HTTP_200_OK
        )

class LoginOTPVerifyView(APIView):
    @endpoint_rate_limit("otp", identifier_type="ip")
    def post(self,request):
        serializer = LoginOTPVerifySerializer(data=request.data,context={"request":request})

        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        otp = serializer.validated_data["otp"]

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({
                "error":"user not found"
            },
            status=404
            )
        
        otp_record = EmailOTP.objects.filter(
            user=user,
            is_used=False,
            expires_at__gt=timezone.now()
        ).last()

        if not otp_record:
            logger.warning("otp_not_found",user_id=str(user.id))
            return Response(
                {"error":"otp not found"},
                status=404
            )
        
        hashed_otp = hashlib.sha256(otp.encode()).hexdigest()

        if hashed_otp != otp_record.otp_hash:
            logger.warning("Invalid otp",user_id = str(user.id))
            return Response(
                {"error":"Invalid otp"},
                status=404
            )
        
        otp_record.is_used = True
        otp_record.save()

        access = generate_access_token(user)
        refresh = generate_refresh_token(user,device_id="web")

        response = Response(
            {"message":"Authentication successful"}
        )

        response.set_cookie(
            "access_token",
            access,
            httponly=True,
            samesite="Lax"
        )

        response.set_cookie(
            "refresh_token",
            refresh,
            httponly=True,
            samesite="Lax"
        )

        logger.info("user_authenticated",user_id=str(user.id))

        return response
    
class SignupOTPVerifyView(APIView):
    @endpoint_rate_limit("otp", identifier_type="ip")
    def post(self, request):
        serializer = SignupOTPVerifySerializer(
            data=request.data,
            context={"request": request}
        )
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        otp = serializer.validated_data["otp"]

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # Avoid enumeration
            return Response(
                {"error": "Invalid or expired OTP"},
                status=status.HTTP_400_BAD_REQUEST
            )

        otp_record = EmailOTP.objects.filter(
            user=user,
            is_used=False,
            expires_at__gt=timezone.now()
        ).order_by("-created_at").first()

        if not otp_record:
            logger.warning("signup_otp_not_found", user_id=str(user.id))
            return Response(
                {"error": "Invalid or expired OTP"},
                status=status.HTTP_400_BAD_REQUEST
            )

        hashed_otp = hashlib.sha256(otp.encode()).hexdigest()

        if hashed_otp != otp_record.otp_hash:
            logger.warning("signup_invalid_otp", user_id=str(user.id))
            return Response(
                {"error": "Invalid or expired OTP"},
                status=status.HTTP_400_BAD_REQUEST
            )
        try:
            with transaction.atomic():
                otp_record.is_used = True
                otp_record.save()

                user.is_active = True
                user.save(update_fields=["is_active"])

            logger.info("signup_verified", user_id=str(user.id))
        except Exception as e:
            logger.error("User cannot be marked as active", 
                         user_id=str(user.id), 
                         error=str(e), 
                         exc_info=True
                         )

        return Response(
            {"message": "Account verified successfully"},
            status=status.HTTP_200_OK
        )

class RefreshView(APIView):
    @endpoint_rate_limit("refresh", identifier_type="ip")
    def post(self, request):

        refresh = request.COOKIES.get("refresh_token")

        if not refresh:
            return Response(
                {"error": "Refresh token missing"},
                status=status.HTTP_401_UNAUTHORIZED
            )

        redis_client = get_redis_connection("default")

        token_hash = hashlib.sha256(refresh.encode()).hexdigest()

        #  Redis blacklist check
        if redis_client.exists(f"refresh_blacklist:{token_hash}"):
            logger.warning("refresh_blacklisted")
            return Response(
                {"error": "Blacklisted refresh token"},
                status=status.HTTP_401_UNAUTHORIZED
            )

        #  DB lookup
        record = RefreshToken.objects.filter(
            token_hash=token_hash
        ).first()

        if not record:
            return Response(
                {"error": "Invalid refresh token"},
                status=status.HTTP_401_UNAUTHORIZED
            )

        #  Reuse detection
        if record.is_revoked:
            RefreshToken.objects.filter(
                user=record.user,
                is_revoked=False
            ).update(is_revoked=True)

            redis_client.set(
                f"refresh_blacklist:{token_hash}",
                "1",
                ex=int(settings.REFRESH_TOKEN_LIFETIME.total_seconds())
            )

            return Response(
                {"error": "Session compromised"},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Normal rotation
        try:
            with transaction.atomic():

                locked_record = (
                    RefreshToken.objects
                    .select_for_update()
                    .get(
                        id=record.id,
                        is_revoked=False,
                        expires_at__gt=timezone.now()
                    )
                )

                locked_record.is_revoked = True
                locked_record.save(update_fields=["is_revoked"])

                # Add to Redis blacklist
                redis_client.set(
                    f"refresh_blacklist:{token_hash}",
                    "1",
                    ex=int(settings.REFRESH_TOKEN_LIFETIME.total_seconds())
                )

                access = generate_access_token(locked_record.user)
                new_refresh = generate_refresh_token(
                    locked_record.user,
                    locked_record.device_id
                )

        except RefreshToken.DoesNotExist:
            return Response(
                {"error": "Invalid or expired refresh token"},
                status=status.HTTP_401_UNAUTHORIZED
            )

        response = Response({"message": "Token refreshed successfully"})

        response.set_cookie("access_token", 
                            access, 
                            httponly=True, 
                            samesite="Lax"
                            )
        response.set_cookie("refresh_token", 
                            new_refresh, 
                            httponly=True, 
                            samesite="Lax"
                            )

        return response
    

class LogoutView(APIView):
    def post(self, request):

        refresh = request.COOKIES.get("refresh_token")

        if refresh:
            token_hash = hashlib.sha256(refresh.encode()).hexdigest()

            try:
                RefreshToken.objects.filter(
                    token_hash=token_hash,
                    is_revoked=False
                ).update(is_revoked=True)

                
                redis_client.set(
                    f"refresh_blacklist:{token_hash}",
                    "1",
                    ex=int(settings.REFRESH_TOKEN_LIFETIME.total_seconds())
                )

            except Exception as e:
                logger.error(
                    "logout_db_error",
                    error=str(e),
                    exc_info=True
                )

        response = Response(
            {"message": "Logged out successfully"},
            status=status.HTTP_200_OK
        )

        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")

        return response
    
class PasswordResetRequestView(APIView):
    @endpoint_rate_limit("password_reset", identifier_type="ip")
    def post(self,request):
        serializer = PasswordResetRequestSerializer(data=request.data,context={"request":request})

        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            logger.warning("user_not_found",email=email)
            return Response(
                {"message": "If the account exists, an email has been sent."},
                status=status.HTTP_200_OK
            )
        
        if not rate_limit(f"password_reset:{request.META.get('REMOTE_ADDR')}",5,900):
            logger.warning("password_reset_rate_limit_exceeded",email=email)
            return Response(
                {"error":"Too many attempts"},
                status=429
            )
            
        
        token = secrets.toke_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        with transaction.atomic():
            # Invalidate old tokens must be deleted
            PasswordResetToken.objects.filter(
                user=user,
                is_used=False
            ).delete()

            PasswordResetToken.objects.create(
                user=user,
                token_hash=token_hash,
                expires_at=timezone.now() + settings.PASSWORD_RESET_TOKEN_LIFETIME
            )

        logger.info("Password_reset_token_generated",user_id=str(user.id))

        return Response({"message":"If exists,email sent successfully"})
    
class SessionListView(APIView):
    def post(self,request):
        user = request.user

        sessions = RefreshToken.objects.select_related("user").filter(user=user,is_revoked=False)

        data = [
            {
                "device_id":s.device_id,
                "created_at":s.created_at,
                "last_used_at":s.last_used_at,
            }
            for s in sessions
        ]

        return Response(data)

class PasswordRestConfirmView(APIView):

    def post(self,request):
        serializer = PasswordResetConfirmSerializer(data=request.data,conetxt={"request":request})

        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        otp = serializer.validated_data["otp"]
        new_password = serializer.validated_data["new_password"]

        token_hash = hashlib.sha256(otp.encode()).hexdigest()

        try:
            otp_record = PasswordResetToken.objects.select_for_update.get(
                user__email=email,
                token_hash=token_hash,
                is_used=False,
                expires_at__gt=timezone.now()
            )
        
        except PasswordResetToken.DoesNotExist:
            logger.warning("Passwrd_reset_token_not_found",email=email)
            return Response(
                "error":"Invalid or expired token",
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user = otp_record.user
        with transaction.atomic():
            user.set_password(new_password)
            user.save(update_fields=["password"])

            otp_record.is_used = True
            otp_record.save(update_fields=["is_used"])

            RefreshToken.objects.filter(
                user=user,
                is_revoked=False
                ).update(is_revoked=True)

        logger.info("password_reset_completed", user_id=str(user.id))

        return Response(
            {"message": "Password reset successful"},
            status=status.HTTP_200_OK,
        )
    
@ensure_csrf_cookie
@api_view(["GET"])
def csrf_cookie(request):
    return Response({"message": "CSRF cookie set"})
        

class SessionDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self,request,session_id):
        redis_client = get_redis_connection("default")

        record = RefreshToken.objects.filter(
            id=session_id,
            user=request.user,
        ).first()

        if not record:
            return Response(
                {"error": "Session not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        if record.is_revoked:
            return Response(
                {"error": "Session already terminated"},
                status=status.HTTP_400_BAD_REQUEST
            )

        with transaction.atomic():
            record.is_revoked = True
            record.save(update_fields=["is_revoked"])

            # Add to Redis blacklist
            redis_client.set(
                f"refresh_blacklist:{record.token_hash}",
                "1",
                ex=int(settings.REFRESH_TOKEN_LIFETIME.total_seconds())
            )

        logger.info(
            "session_terminated",
            user_id=str(request.user.id),
            session_id=str(session_id)
        )

        return Response(
            {"message": "Session terminated"},
            status=status.HTTP_200_OK
        )


class LogoutAllView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        redis_client = get_redis_connection("default")

        sessions = RefreshToken.objects.filter(
            user=request.user
        )

        for session in sessions:
            redis_client.set(
                f"refresh_blacklist:{session.token_hash}",
                "1",
                ex=int(settings.REFRESH_TOKEN_LIFETIME.total_seconds())
            )

        sessions.update(is_revoked=True)

        response = Response(
            {"message": "All sessions terminated"},
            status=status.HTTP_200_OK
        )

        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")

        logger.info(
            "all_sessions_terminated",
            user_id=str(request.user.id)
        )

        return response




        




        






            





