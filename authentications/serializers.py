import random
from rest_framework import serializers
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

from authentications.models import ResetToken, User, OTP
import random

from django.utils import timezone
from datetime import timedelta
from django.core.mail import send_mail
import secrets
from django.contrib.auth.password_validation import validate_password
from django.db import transaction


class UserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, required=True)
    first_name = serializers.CharField(max_length=255, required=True)
    last_name = serializers.CharField(max_length=255, required=True)
    phone_number = serializers.CharField(max_length=255, required=False)
    image = serializers.ImageField(required=False)
    password = serializers.CharField( max_length=128, min_length=6, write_only=True)
    confirm_password = serializers.CharField( max_length=128, min_length=6, write_only=True) 

    class Meta:
        model = User
        fields = ['email','first_name','last_name','phone_number', 'image', 'password', 'confirm_password']
       

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({
                "password": "Passwords do not match"
            })
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('confirm_password')

        password = validated_data.pop('password')

        user = User.objects.create_user(
            password=password,
            **validated_data
        )

        return user

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User 
        fields = ["email",'first_name', "last_name","phone_number",'created_at', 'image']
    
class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255, required=True)
    password = serializers.CharField(max_length=128, min_length=6, required=True, write_only=True)
    

    def validate_email(self, value):
        if '@' not in value:
            raise serializers.ValidationError('Invalid email address')
        return value
    
    def validate_password(self, value):
        if len(value) < 6:
            raise serializers.ValidationError('Password must be at least 6 characters long')
        return value

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        user = authenticate(email=email, password=password)

        if not user:
            raise serializers.ValidationError("Invalid credentials")

        if not user.is_active:
            raise serializers.ValidationError("Account is disabled")

        attrs['user'] = user
        return attrs
    

class UserLogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField(max_length=255, required=True)

    def validate(self, attrs):
        refresh = attrs.get('refresh')
        if not refresh:
            raise serializers.ValidationError("Refresh token is required")
        
        try:
            token = RefreshToken(refresh)
        except TokenError:
            raise serializers.ValidationError("Invalid refresh token")

        attrs['token'] = token
        return attrs

class ChangePasswordSerializer(serializers.Serializer):
        old_password = serializers.CharField(max_length = 100,write_only=True, required=True)
        new_password = serializers.CharField(max_length = 100,write_only=True, required=True)
        confirm_password = serializers.CharField(max_length = 100,write_only=True, required=True)


        def validate(self, attrs):
            old_password = attrs.get('old_password')
            new_password = attrs.get('new_password')
            confirm_password = attrs.get('confirm_password')

            user = self.context['request'].user


            if not user.check_password(old_password):
                raise serializers.ValidationError({"old_password": "Old password is incorrect"})
        
            if new_password != confirm_password:
                raise serializers.ValidationError({"new_password": "New passwords do not match"}) 

            if len(new_password) < 6:
                raise serializers.ValidationError({"new_password": "Password must be at least 6 characters long"})

            return attrs

        # def update(self, instance, validated_data):
        #     user = self.context['request'].user
        #     user.set_password(validated_data['new_password'])
        #     user.save()
        #     return user
        def save(self, **kwargs):
            user = self.context['request'].user
            user.set_password(self.validated_data['new_password'])
            user.save()
            return user
        
class OTPRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255, required=True)


    def validate(self, attrs):
        email = attrs.get('email')

        user = User.objects.filter(email=email).first()

        if not user:
            raise serializers.ValidationError("User does not exist")
        
        attrs['user'] = user
        return attrs
    
    @transaction.atomic
    def save(self, **kwargs):
        user = self.validated_data['user']

      
        otp = getattr(user, 'otps', None)

        if otp: 
            otp.delete()
               
        otp_code = str(secrets.randbelow(9000) + 1000)
        # expires_at = timezone.now() + timedelta(minutes=5)
        # Create new OTP record
        otp = OTP.objects.create(
            user=user,
            otp_code=otp_code,
            is_verified=False,
            is_used=False,
            expires_at=timezone.now() + timedelta(minutes=5)
        )

        reset_token = ResetToken.objects.create(
            user=user,
            expires_at=timezone.now() + timedelta(minutes=5),
            is_used=False
        )

        message = f''' Your one time OTP code is {otp.otp_code}, and it expires in 5 minutes '''

        send_mail(
            subject= "One timeOTP code",
            message= message ,
            from_email = "alojosiah6@gmail.com",
            recipient_list = [user.email],
            fail_silently = False,
        )  
        
        payload = {
            'reset_token' : reset_token.token
        }
        return payload
       
class VerifyOTPSerializer(serializers.Serializer):
    otp_code = serializers.CharField(
        required=True, write_only=True, max_length=4, min_length=4
    )
    token = serializers.CharField(required=True, write_only=True, max_length=255)

    def validate(self, attrs):
        otp_input_code = attrs.get('otp_code')
        token = attrs.get('token')

        otp = OTP.objects.filter(
            otp_code=otp_input_code,
            is_verified=False
        ).first()

        tkn = ResetToken.objects.filter(token=token).first()

        if not otp :
            raise serializers.ValidationError("Invalid or expired OTP.")

        if timezone.now() > otp.expires_at:
            raise serializers.ValidationError("OTP has expired.")

        if not tkn: 
            raise serializers.ValidationError("Error validation.")

        if tkn and timezone.now() > tkn.expires_at:
            raise serializers.ValidationError("Session expired.")

        # ✅ inject otp and user into validated_data
        attrs['otp'] = otp
        attrs['user'] = otp.user
        attrs['tkn'] = tkn
        return attrs

    def save(self, **kwargs):
        otp = self.validated_data['otp']
        user = self.validated_data['user']
        tkn = self.validated_data['tkn']

        # tkn.is_used = True
        # tkn.save()
        otp.is_verified = True
        otp.save(update_fields=['is_verified'])
        token = tkn.token

        payload = {
            'token':token
        }
        return payload


class UserOtpNewPasswordSerializer(serializers.Serializer):
    token = serializers.CharField(required=True, write_only=True, max_length=255)
    new_password = serializers.CharField(max_length = 100,write_only=True, required=True, min_length=6)
    confirm_password = serializers.CharField(max_length = 100,write_only=True, required=True, min_length=6)

    def validate(self, attrs):
        token = attrs.get("token")
        password = attrs.get("new_password")
        confirm = attrs.get("confirm_password")

        if password != confirm:
                raise serializers.ValidationError({
                "confirm_password": "Passwords do not match"
            })

        token = ResetToken.objects.filter(token=token).first()

        if not token:
            raise serializers.ValidationError("Invalid reset token.")
        
        if token.is_used == True:
            raise serializers.ValidationError("Token already used")

        if timezone.now() >  token.expires_at :
                raise serializers.ValidationError("Session expired.")
        
        user = token.user
        try:
            validate_password(password, user=token.user)
        except Exception as e:
            raise serializers.ValidationError({"new_password": list(e.messages)})
        
        attrs['password'] = password
        attrs['token'] = token
        attrs['user'] = user
        return attrs

    @transaction.atomic
    def save(self, **kwargs):
        token = self.validated_data['token']
        user = self.validated_data['user']
        password = self.validated_data['password']

        user.set_password(password)
        user.save(update_fields=["password"])
        token.is_used = True
        token.save(update_fields=['is_used'])

        payload = {
            'message': "Password reset successfully"
        }
        return payload