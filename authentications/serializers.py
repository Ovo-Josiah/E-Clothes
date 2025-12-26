import random
from rest_framework import serializers
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

from authentications.models import User, OTP
import random

from django.utils import timezone
from datetime import timedelta
from django.core.mail import send_mail


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
            raise serializers.ValidationError("Invalid email")
        
        attrs['user'] = user
        return attrs
    

    def save(self, **kwargs):
        user = self.validated_data['user']

       
        # Genrate OTP pin
        pin = str(random.randrange(1000,10000))

        # otp , created = OTP.objects.update_or_create(is_verified = False, expires_at = timezone.now() + timedelta(minutes=5),user = user, otp_code = pin)
        otp , created = OTP.objects.update_or_create(defaults={'is_verified': False, 'expires_at': timezone.now() + timedelta(minutes=5), 'otp_code': pin}, user = user)

        message = f''' Your one time OTP code is {otp.otp_code}, and it expires in 5 minutes '''

        send_mail(
            subject= "One timeOTP code",
            message= message ,
            from_email = "alojosiah6@gmail.com",
            recipient_list = [user.email],
            fail_silently = False,
        )  

        return otp 

       