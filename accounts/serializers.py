from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from accounts.models import Role
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

User = get_user_model()
token_generator = PasswordResetTokenGenerator()


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['name', 'email', 'password', 'confirm_password']

    def validate(self, data):
        institution = self.context.get('institution')
        email = data.get('email')

        if User.objects.filter(email=email, institution=institution).exists():
            raise serializers.ValidationError({'email': "A user with this email already exists."})

        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError({'password': "Passwords do not match."})

        validate_password(data['password'])  # Will raise ValidationError if weak
        return data

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        return User.objects.create_user(
            email=validated_data['email'],
            name=validated_data['name'],
            password=validated_data['password'],
            institution=self.context['institution']
        )


class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ['id', 'name', 'permissions']


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, email):
        if not User.objects.filter(email=email).exists():
            raise serializers.ValidationError("No account found with this email.")
        return email


class ResendEmailVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()


class PasswordResetConfirmSerializer(serializers.Serializer):
    uidb64 = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({"password": "Passwords do not match."})

        validate_password(data['new_password'])  # raises ValidationError if weak
        return data

    def save(self):
        uid = force_str(urlsafe_base64_decode(self.validated_data['uidb64']))
        try:
            user = User.objects.get(pk=uid)
        except User.DoesNotExist:
            raise serializers.ValidationError({"uid": "Invalid UID."})

        if not token_generator.check_token(user, self.validated_data['token']):
            raise serializers.ValidationError({"token": "Invalid or expired token."})

        user.set_password(self.validated_data['new_password'])
        user.save(update_fields=['password'])


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Old password is incorrect.")
        return value

    def validate_new_password(self, value):
        validate_password(value)
        return value

    def save(self):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'name', 'email', 'role', 'institution']
        read_only_fields = ['email', 'role', 'institution']


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            token = RefreshToken(self.token)
            token.blacklist()
        except TokenError:
            raise serializers.ValidationError({"refresh": "Token is invalid or expired"})
