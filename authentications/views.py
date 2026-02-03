from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.generics import CreateAPIView
from rest_framework import generics
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from authentications.models import User
from authentications.serializers import ChangePasswordSerializer, OTPRequestSerializer, UserLoginSerializer, UserLogoutSerializer, UserOtpNewPasswordSerializer, UserSerializer, VerifyOTPSerializer
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema

from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken


# Create your views here.
class UserCreateView(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)

        return Response({
            'message': "Account created successfully",
            'user': response.data
        }, status=status.HTTP_201_CREATED)
    
class UserLoginView(generics.GenericAPIView):
    serializer_class = UserLoginSerializer
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']

            refresh = RefreshToken.for_user(user)

            return Response({
                "message": "Login successful",
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                },
                "tokens": {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                }
            }, status=status.HTTP_200_OK)
        return Response({'message':'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

    
class UserLogoutView(generics.GenericAPIView):
    serializer_class = UserLogoutSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            try:
                 token.blacklist()
                 return Response({
                        "message": "Logout successful"
                    }, status=status.HTTP_200_OK)
            except TokenError:
                return Response({"message": "Token already blacklisted"}, status=status.HTTP_400_BAD_REQUEST)

            
        return Response({'message':'Invalid refresh token'}, status=status.HTTP_400_BAD_REQUEST)
    

class ChangePasswordView(generics.GenericAPIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.get_serializer(data = request.data)
        serializer.is_valid(raise_exception = True)
        serializer.save()

       
        tokens = OutstandingToken.objects.filter(user=request.user)
        for token in tokens:
            try:
                BlacklistedToken.objects.get_or_create(token=token)
            except:
                pass

        return Response({
            'message': 'Password changed successfully'
        }, status=status.HTTP_200_OK)
    

class OTPRequestView(generics.GenericAPIView):
    serializer_class = OTPRequestSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data = request.data)
        serializer.is_valid(raise_exception = True)
        serializer.save()

        return Response({   
            'message': 'OTP sent successfully'
        }, status=status.HTTP_200_OK)
    
class OTPVerificatioView(generics.GenericAPIView):
    serializer_class = VerifyOTPSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data = request.data)
        serializer.is_valid(raise_exception = True)
        serializer.save()

        return Response({
            'message': 'OTP verified successfully'
        }, status=status.HTTP_200_OK)
    

class UserOtpNewPasswordView(generics.GenericAPIView):
    serializer_class = UserOtpNewPasswordSerializer

    def post(self, request):
        serializer = self.get_serializer(data = request.data)
        serializer.is_valid(raise_exception = True)

        user = serializer.validated_data['user']
        
        otp = OTP.objects.filter(user=user).first()

        if otp.is_verified != True:
            return Response({'message': 'OTP is not verified'}, status=status.HTTP_400_BAD_REQUEST)
        serializer.save()

        return Response({
            'message': 'Password changed successfully'
        }, status=status.HTTP_200_OK)