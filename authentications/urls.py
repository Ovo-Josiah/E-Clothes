from django.urls import path,include

from authentications.views import ChangePasswordView, UserCreateView, UserLoginView, UserLogoutView
urlpatterns = [
    path('auth/register/',UserCreateView.as_view(), name='register-user'),
    path('auth/login/',UserLoginView.as_view(), name='login-user'),
    path('auth/logout/',UserLogoutView.as_view(), name='logout-user'),
    path('auth/change-password/',ChangePasswordView.as_view(), name='change-password'),
]
