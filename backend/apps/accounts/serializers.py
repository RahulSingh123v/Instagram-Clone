import re
from rest_framework import serializers
from backend.apps.accounts.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.contrib.auth import authenticate




class SignupSerializer(serializers.Serialiazer):
    email = serializers.EmialField()
    username = serializers.CharField(max_length=30)
    password = serializers.CharField(write_only=True, min_length=8)
    
    def validate_email(self,value):
        value = value.strip().lower()
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("email is already taken")
        
        return value
    
    def validate_username(self,value):
        value = value.strip().lower()

        if not re.match(r"^[a-zA-Z0-9_.]+$",value):
            raise serializers.ValidationError("username can contain only letters, numbers, underscore and dot.")

        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("username is already taken")
        
        return value
    
    def validate_passowrd(self,value):
        try:
            validate_password(value)
        except DjangoValidationError as e:
            raise serializers.ValidationError(str(e))
        
        return value

    
    def create(self,validated_data):
        return User.objects.create_user(**validated_data)
    
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email = attrs.get("email").strip().lower()
        password = attrs.get("password")

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid email or password")

        # Check lock first
        if user.is_account_locked:
            raise serializers.ValidationError("Account is locked")

        # Verify password manually
        if not user.check_password(password):
            user.register_failed_login()
            raise serializers.ValidationError("Invalid email or password")

        # Success → reset attempts
        user.reset_login_attempts()

        if not user.is_active:
            raise serializers.ValidationError("User is not active")

        attrs["user"] = user
        return attrs

class LoginOTPVerifySerializer(serializers.Serialzer): 
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

    def validate_email(self,value):
        return value.strip().lower()

class SignupOTPVerifySerializer(serializers.Serialzer): 
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

    def validate_email(self,value):
        return value.strip().lower()
        

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self,value):
        return value.strip().lower()
    
class PasswordResetConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True,min_length=8)

    def validate_email(self,value):
        return value.strip().lower()
    
    def validate_new_password(self,value):
        try:
            validate_password(value)
        except DjangoValidationError as e:
            raise serializers.ValidationError(str(e))
        
        return value
    
    









