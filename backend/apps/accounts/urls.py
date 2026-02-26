from django.urls import path
from .views import(
    SignupView,
    LoginView,
    LoginOTPVerifyView,
    SignupOTPVerifyView,
    RefreshView,
    LogoutView,
    PasswordResetRequestView,
    SessionListView,
    PasswordRestConfirmView,
    csrf_cookie,
    SessionDeleteView,
    LogoutAllView
)

urlpatterns = [
    path("signup/", SignupView.as_view()),
    path("login/", LoginView.as_view()),
    path("verify-login-otp/", LoginOTPVerifyView.as_view()),
    path("verify-login-otp/", LoginOTPVerifyView.as_view()),
    path("verify-signup-otp/", SignupOTPVerifyView.as_view()),
    path("refresh/", RefreshView.as_view()),
    path("logout/", LogoutView.as_view()),
    path("password-reset/", PasswordResetRequestView.as_view()),
    path("password-reset/confirm/", PasswordRestConfirmView.as_view()),
    path("sessions/", SessionListView.as_view()),
    path("csrf/", csrf_cookie, name="csrf-cookie"),
    path("sessions/<uuid:session_id>/", SessionDeleteView.as_view()),
    path("sessions/logout-all/", LogoutAllView.as_view()),
]