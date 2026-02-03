from django.urls import path,include

from authentications.views import ChangePasswordView, OTPRequestView, UserCreateView, UserLoginView, UserLogoutView,OTPVerificatioView, UserOtpNewPasswordView
urlpatterns = [
    path('auth/register/',UserCreateView.as_view(), name='register-user'),
    path('auth/login/',UserLoginView.as_view(), name='login-user'),
    path('auth/logout/',UserLogoutView.as_view(), name='logout-user'),
    path('auth/change-password/',ChangePasswordView.as_view(), name='change-password'),
    path('auth/otp-request/',OTPRequestView.as_view(), name='otp-request'),
    path('auth/otp-verification/',OTPVerificatioView.as_view(), name='otp-request'),
    path('auth/otp-new-password/',UserOtpNewPasswordView.as_view(), name='otp-new-password'),
]
