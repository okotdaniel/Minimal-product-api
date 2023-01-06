from collections import UserList
from django.urls import path, include 
from .views import *

from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('register/user', RegisterView.as_view()),
    path('login/', LoginAPIView.as_view()),
    path('logout/', LogoutAPIView.as_view()),
    path('otp/verify', Verify_otp.as_view(), name="otp-verify"),
    path('password/reset/', RequestPasswordResetEmail.as_view(),name="request-reset-email "),
    path('password/reset/<uidb64>/<token>/',PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
    path('password/reset/done/', SetNewPasswordAPIView.as_view(),name='password-reset-complete'),

    # users
    path('', UserList.as_view(),name='users'),
    path('<int:id>', UserDeatail.as_view(),name='crud'),
  
]
