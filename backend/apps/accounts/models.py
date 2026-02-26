from django.db import models
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractUser, PermissionsMixin
from django.utils import timezone
from core.uuid import uuid7_str
from datetime import timedelta


class UserManager(BaseUserManager):
    def create_user(self,email,username,password):
        if not email:
            raise ValueError("Email is required")
        
        if not password:
            raise ValueError("Password is required")
        
        email = self.normalize_email(email)
        username = username.lower()
        user = self.model(email=email,
                          username=username,
                          )
        user.set_password(password)
        user.save(using=self.db)
        
        return user
    
class User(AbstractUser):
    id = models.UUIDField(primary_key=True,
                          default=uuid7_str,
                          editable=False
                          )
    
    username = models.CharField(max_length=255,
                                unique=True,
                                db_index=True
                                )
    
    email = models.EmailField(
                              unique=True,
                              db_index=True
                              )
    
    is_active = models.BooleanField(default=True)
    
    is_verified = models.BooleanField(default=False)

    is_locked = models.BooleanField(default=False)

    failed_login_attempts = models.IntegerField(default=0)

    last_login_ip = models.GenericIPAddressField(null=True,blank=True)

    created_at = models.DateTimeField(default=timezone.now)

    updated_at = models.DateTimeField(auto_now=True)

    lock_untill = models.DateTimeField(null=True,blank=True)

    LOCK_THRESHOLD = 5
    LOCK_DURATION_MINUTES = 15

    def register_failed_logins(self):
        self.failed_login_attempts += 1

        if self.failed_login_attempts >= self.LOCK_THRESHOLD:
            self.lock_untill = timezone.now() + timedelta(minutes=self.LOCK_DURATION_MINUTES)
        self.is_locked = True
        self.save(update_fields=["failed_login_attempts","lock_untill","is_locked"])
        self.refresh_from_db()

    def reset_login_attempts(self):
        self.failed_login_attempts = 0
        self.lock_untill = None
        self.is_locked = False
        self.save(update_fields=["failed_login_attempts","lock_untill","is_locked"])

    @property
    def is_account_locked(self):
        if self.lock_untill and timezone.now() < self.lock_untill:
            return True

        # Auto unlock
        if self.lock_untill and timezone.now() >= self.lock_untill:
            self.reset_login_attempts()
            return False

        return False
    



    USERNAME_FIELD = "email"

    REQUIRED_FIELDS = ["username"]

    objects = UserManager()

class EmailOTP(models.Model):
    id  = models.UUIDField(
        primary_key = True,
        default = uuid7_str,
        editable=False
    )

    user = models.ForeignKey(User,on_delete=models.CASCADE)

    otp_hash = models.CharField(max_lenght=64)

    expires_at = models.DateTimeField()

    is_used = models.BooleanField(deafult=False)

    attempt_count = models.PositiveIntegerFieldIntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["user","is_used"]),
            models.Index(fields=["expires_at"]),
        ]

class RefreshToken(models.Model):
    id = models.UUIDField(primary_key=True,
                          default = uuid7_str,
                          editable=False
                          )
    user = models.ForeignKey(User,on_delete=models.CASCADE)

    token_hash = models.CharField(max_length=64, unique=True)

    device_id = models.CharField(max_length=64)

    expires_at = models.DateTimeField()

    is_revoked = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

    last_used_at = models.DateTimeField(null=True,blank=True)

    class Meta:
        index = [
            models.index(fields=["user"]),
            models.index(field=["expires_at"]),
            models.index(fields=["is_revoked"]),
            models.Index(fields=["user"], name="active_refresh_idx", condition=models.Q(is_revoked=False))
        ]

class PasswordResetToken(models.Model):

    id = models.UUIDField(
        primary_key = True,
        default = uuid7_str,
        editable = False
    )

    user = models.ForeignKey(User,on_delete=models.CASCADE)

    token_hash = models.CharField(max_length=64,unique=True)

    expires_at = models.DateTimeField()

    is_used = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)




    
                                      




    
    

