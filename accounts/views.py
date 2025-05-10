from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import authenticate
from .serializers import RegisterSerializer, LoginSerializer, PasswordResetRequestSerializer, PasswordResetConfirmSerializer, ResendEmailVerificationSerializer, UserProfileSerializer, ChangePasswordSerializer,RoleSerializer,LogoutSerializer
from accounts.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.urls import reverse
from rest_framework import status, permissions
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.db import transaction
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from accounts.utils import generate_email_verification_link
from utils.email import send_verification_email, send_password_reset_email, send_welcome_email

token_generator = PasswordResetTokenGenerator()

class RegisterView(APIView):
    @swagger_auto_schema(
        request_body=RegisterSerializer,
        responses={201: "User registered successfully", 400: "Validation Error"},
        operation_summary="Register a new user for a institution",
        operation_description="Requires email and password. institution is resolved from subdomain."
    )
    def post(self, request):
        institution = getattr(request, 'institution', None)
        if not institution:
            return Response({"error": "Institution not found."}, status=400)

        serializer = RegisterSerializer(data=request.data, context={'institution': institution})
        if serializer.is_valid():
            with transaction.atomic():
                user = serializer.save()  # Create the user
                try:
                    # Generate email verification link
                    verification_url = generate_email_verification_link(request, user)
                    # Send email
                    send_verification_email(user, verification_url)
                except Exception as e:
                    # If sending fails, rollback user creation
                    user.delete()  # Or use `user.set_password` to reset if necessary
                    return Response({"error": f"Failed to send verification email: {str(e)}"}, status=500)
            
            return Response({"message": "User registered successfully. Check your email for verification."}, status=201)
        return Response(serializer.errors, status=400)

class LoginView(APIView):
    @swagger_auto_schema(
        request_body=LoginSerializer,
        responses={200: openapi.Response(
            description="JWT tokens",
            examples={
                "application/json": {
                    "refresh": "string",
                    "access": "string"
                }
            }),
            400: "Validation error",
            401: "Invalid credentials"
        },
        operation_summary="Log in a user",
        operation_description="Logs in a user using email, password, and institution from subdomain."
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

        user = authenticate(username=user.username, password=password)
        if not user:
            return Response({"error": "Invalid credentials."}, status=401)

        # Generate JWT tokens
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
        request_body=PasswordResetRequestSerializer,
        responses={
            200: openapi.Response(description="Password reset link sent"),
            400: "Invalid input",
            404: "User not found"
        }
    )
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        user = User.objects.get(email=email)

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = token_generator.make_token(user)

        reset_url = request.build_absolute_uri(
            reverse('password-reset-confirm', kwargs={'uidb64': uid, 'token': token})
        )

        send_password_reset_email(user, reset_url)

        return Response({"detail": "Password reset link sent."}, status=status.HTTP_200_OK)
    
class PasswordResetConfirmView(APIView):
    @swagger_auto_schema(
        operation_summary="Confirm password reset",
        request_body=PasswordResetConfirmSerializer,
        manual_parameters=[
            openapi.Parameter('uidb64', openapi.IN_PATH, type=openapi.TYPE_STRING),
            openapi.Parameter('token', openapi.IN_PATH, type=openapi.TYPE_STRING),
        ],
        responses={
            200: openapi.Response(description="Password has been reset"),
            400: "Invalid input or token"
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
    def get(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)

            if default_token_generator.check_token(user, token):
                if not user.is_email_verified:
                    user.is_email_verified = True
                    user.save()
                    send_welcome_email(user)
                return Response({"message": "Email verified successfully."})
            return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)
        except Exception:
            return Response({"error": "Something went wrong."}, status=status.HTTP_400_BAD_REQUEST)
        

class ResendVerificationEmailView(APIView):
    def post(self, request):
        serializer = ResendEmailVerificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        institution = getattr(request, 'institution', None)

        try:
            user = User.objects.get(email=email, institution=institution)
        except User.DoesNotExist:
            return Response({"error": "User not found for this institution."}, status=404)

        if user.is_email_verified:
            return Response({"detail": "Email already verified."}, status=400)

        verification_url = generate_email_verification_link(request, user)
        send_verification_email(user, verification_url)

        return Response({"detail": "Verification email resent."}, status=status.HTTP_200_OK)
        

class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(request_body=LogoutSerializer)
    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"detail": "Logout successful."}, status=status.HTTP_205_RESET_CONTENT)
    

class ChangePasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        user = request.user
        user.set_password(serializer.validated_data['new_password'])
        user.save()

        return Response({"detail": "Password changed successfully."}, status=status.HTTP_200_OK)
    
class UserProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data)

    def put(self, request):
        serializer = UserProfileSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)