from django.urls import path
from accounts.views import (
    RegisterView, LoginView, PasswordResetRequestView, PasswordResetConfirmView,
    EmailVerifyView, ResendVerificationEmailView, LogoutView,
    ChangePasswordView, UserProfileView
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),

    path('password-reset/', PasswordResetRequestView.as_view(), name='password-reset'),
    path('password-reset-confirm/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),

    path('verify-email/<uidb64>/<token>/', EmailVerifyView.as_view(), name='verify-email'),
    path('resend-verification/', ResendVerificationEmailView.as_view(), name='resend-verification'),

    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('profile/', UserProfileView.as_view(), name='user-profile'),
]
