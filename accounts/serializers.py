from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from accounts.models import Role

token_generator = PasswordResetTokenGenerator()
User = get_user_model()

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['name','email', 'password', 'confirm_password']
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def validate(self, data):
        institution = self.context['institution']
        email = data.get('email')
        # Check for duplicate within the institution
        if User.objects.filter(email=email, institution=institution).exists():
            raise serializers.ValidationError({
                'email': f"A user with this email already exists."
            })
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        # Enforce password strength
        validate_password(data['password'], user=None)

        return data
    def create(self, validated_data):
        validated_data.pop('confirm_password')
        institution = self.context['institution']
        email = validated_data['email']
        password = validated_data['password']
        user = User.objects.create_user(email=email, institution=institution, password=password)
        return user

class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ['id', 'name', 'permissions']

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, email):
        if not User.objects.filter(email=email).exists():
            raise serializers.ValidationError("No account with this email.")
        return email
    
class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)
    uidb64 = serializers.CharField()
    token = serializers.CharField()

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        validate_password(data['new_password'], user=None)
        return data

    def save(self):
        uid = force_str(urlsafe_base64_decode(self.validated_data['uidb64']))
        user = User.objects.get(pk=uid)

        if not token_generator.check_token(user, self.validated_data['token']):
            raise serializers.ValidationError({"token": "Invalid or expired token."})

        from django.contrib.auth.password_validation import validate_password
        validate_password(self.validated_data['new_password'], user=user)

        user.set_password(self.validated_data['new_password'])
        user.save()