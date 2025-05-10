from django.urls import path
from accounts.views import RegisterView, LoginView, PasswordResetRequestView, PasswordResetConfirmView, EmailVerifyView, LogoutView, ResendVerificationEmailView,ChangePasswordView,UserProfileView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('auth/password-reset/', PasswordResetRequestView.as_view(), name='password-reset'),
    path('auth/password-reset-confirm/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('auth/email-verify/<uidb64>/<token>/', EmailVerifyView.as_view(), name='email-verify'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('auth/email-resend/', ResendVerificationEmailView.as_view(), name='email-resend'),
    path('auth/change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('profile/', UserProfileView.as_view(), name='user-profile'),
]
