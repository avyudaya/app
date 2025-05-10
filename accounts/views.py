from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator, default_token_generator
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.urls import reverse
from django.db import transaction
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .serializers import (
    RegisterSerializer, LoginSerializer, PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer, ResendEmailVerificationSerializer,
    UserProfileSerializer, ChangePasswordSerializer, RoleSerializer, LogoutSerializer
)
from accounts.utils import generate_email_verification_link
from utils.email import send_verification_email, send_password_reset_email, send_welcome_email

User = get_user_model()
token_generator = PasswordResetTokenGenerator()

class RegisterView(APIView):
    @swagger_auto_schema(
        operation_summary="Register a new user",
        operation_description="Registers a new user under the institution resolved from the subdomain.",
        request_body=RegisterSerializer,
        responses={
            201: openapi.Response(description="User registered successfully"),
            400: "Validation Error"
        }
    )
    def post(self, request):
        institution = getattr(request, 'institution', None)
        if not institution:
            return Response({"error": "Institution not found."}, status=400)

        serializer = RegisterSerializer(data=request.data, context={'institution': institution})
        if serializer.is_valid():
            with transaction.atomic():
                user = serializer.save()
                try:
                    verification_url = generate_email_verification_link(request, user)
                    send_verification_email(user, verification_url)
                except Exception as e:
                    user.delete()
                    return Response({"error": f"Failed to send verification email: {str(e)}"}, status=500)
            return Response({"message": "User registered successfully. Check your email for verification."}, status=201)
        return Response(serializer.errors, status=400)

class LoginView(APIView):
    @swagger_auto_schema(
        operation_summary="Log in a user",
        operation_description="Logs in a user using email and password for the institution identified from subdomain.",
        request_body=LoginSerializer,
        responses={
            200: openapi.Response(
                description="JWT tokens",
                examples={"application/json": {"refresh": "string", "access": "string"}}
            ),
            400: "Validation error",
            401: "Invalid credentials"
        }
    )
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=400)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        institution = getattr(request, 'institution', None)

        if not institution:
            return Response({"error": "Institution not found."}, status=400)

        try:
            user = User.objects.get(email=email, institution=institution)
        except User.DoesNotExist:
            return Response({"error": "Invalid credentials."}, status=401)

        if not authenticate(username=user.username, password=password):
            return Response({"error": "Invalid credentials."}, status=401)

        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user': {
                'id': user.id,
                'email': user.email,
                'role': RoleSerializer(user.role).data,
                'institution': user.institution.name,
            }
        })

class PasswordResetRequestView(APIView):
    @swagger_auto_schema(
        operation_summary="Request password reset",
        operation_description="Sends a password reset link to the registered email.",
        request_body=PasswordResetRequestSerializer,
        responses={
            200: openapi.Response(description="Password reset link sent"),
            400: "Validation error",
            404: "User not found"
        }
    )
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=404)

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = token_generator.make_token(user)

        reset_url = request.build_absolute_uri(
            reverse('password-reset-confirm', kwargs={'uidb64': uid, 'token': token})
        )

        send_password_reset_email(user, reset_url)
        return Response({"detail": "Password reset link sent."}, status=200)


class PasswordResetConfirmView(APIView):
    @swagger_auto_schema(
        operation_summary="Confirm password reset",
        request_body=PasswordResetConfirmSerializer,
        manual_parameters=[
            openapi.Parameter('uidb64', openapi.IN_PATH, description="User ID (base64)", type=openapi.TYPE_STRING),
            openapi.Parameter('token', openapi.IN_PATH, description="Password reset token", type=openapi.TYPE_STRING)
        ],
        responses={
            200: "Password reset successful",
            400: "Invalid token or data"
        }
    )
    def post(self, request, uidb64, token):
        serializer = PasswordResetConfirmSerializer(data={
            **request.data,
            "uidb64": uidb64,
            "token": token
        })
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"detail": "Password has been reset."})


class EmailVerifyView(APIView):
    @swagger_auto_schema(
        operation_summary="Verify email",
        manual_parameters=[
            openapi.Parameter('uidb64', openapi.IN_PATH, type=openapi.TYPE_STRING),
            openapi.Parameter('token', openapi.IN_PATH, type=openapi.TYPE_STRING),
        ],
        responses={200: "Email verified", 400: "Invalid or expired token"}
    )
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
            if default_token_generator.check_token(user, token):
                if not user.is_email_verified:
                    user.is_email_verified = True
                    user.save()
                    send_welcome_email(user)
                return Response({"message": "Email verified successfully."})
            return Response({"error": "Invalid or expired token."}, status=400)
        except Exception:
            return Response({"error": "Something went wrong."}, status=400)


class ResendVerificationEmailView(APIView):
    @swagger_auto_schema(
        operation_summary="Resend verification email",
        request_body=ResendEmailVerificationSerializer,
        responses={
            200: "Verification email resent",
            400: "Email already verified",
            404: "User not found"
        }
    )
    def post(self, request):
        serializer = ResendEmailVerificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        institution = getattr(request, 'institution', None)

        try:
            user = User.objects.get(email=email, institution=institution)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=404)

        if user.is_email_verified:
            return Response({"detail": "Email already verified."}, status=400)

        verification_url = generate_email_verification_link(request, user)
        send_verification_email(user, verification_url)
        return Response({"detail": "Verification email resent."})


class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Log out user",
        request_body=LogoutSerializer,
        responses={205: "Logout successful"}
    )
    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"detail": "Logout successful."}, status=status.HTTP_205_RESET_CONTENT)


class ChangePasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Change password",
        request_body=ChangePasswordSerializer,
        responses={200: "Password changed successfully"}
    )
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        request.user.set_password(serializer.validated_data['new_password'])
        request.user.save(update_fields=['password'])
        return Response({"detail": "Password changed successfully."})


class UserProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Get user profile",
        responses={200: UserProfileSerializer()}
    )
    def get(self, request):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_summary="Update user profile",
        request_body=UserProfileSerializer
    )
    def put(self, request):
        serializer = UserProfileSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)