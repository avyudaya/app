# accounts/models.py
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db import models
import uuid

class Institution(models.Model):
    name = models.CharField(max_length=255, unique=True)
    subdomain = models.SlugField(unique=True)
    logo_url = models.URLField(blank=True, null=True)
    support_email = models.EmailField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

class CustomUserManager(BaseUserManager):
    def create_user(self, email, institution, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set.")
        if extra_fields.get('is_superuser', False):
            institution = None  # Super admin doesn't need institution
        elif not institution:
            raise ValueError("Users must have an institution.")
        email = self.normalize_email(email)
        username = str(uuid.uuid4())  # or combine email+institution ID
        student_role, _ = Role.objects.get_or_create(name='student')
        extra_fields.setdefault('role', student_role)
        user = self.model(email=email, institution=institution, username=username, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, institution, password=None, **extra_fields):
        super_admin_role, _ = Role.objects.get_or_create(name='super_admin')
        extra_fields.setdefault('role', super_admin_role)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_staff", True)
        return self.create_user(email, institution, password, **extra_fields)

class Role(models.Model):
    ROLE_CHOICES = [
        ('student', 'Student'),
        ('admin', 'Admin'),
        ('reviewer', 'Reviewer'),
        ('super_admin', 'Super Admin'),
    ]
    name = models.CharField(max_length=30, choices=ROLE_CHOICES, unique=True)
    permissions = models.JSONField(default=dict)

    def __str__(self):
        return self.name

class User(AbstractBaseUser, PermissionsMixin):
    institution = models.ForeignKey(Institution, on_delete=models.CASCADE, related_name='users',null=True, blank=True)
    email = models.EmailField()  # NOT unique
    username = models.CharField(max_length=255, unique=True)  # system-level ID (can be auto-gen)
    name = models.CharField(max_length=255, blank=False)
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)  

    objects = CustomUserManager()

    USERNAME_FIELD = 'username'   # <--- Changed here
    REQUIRED_FIELDS = ['email', 'institution']

    class Meta:
        unique_together = ('email', 'institution')  # application-level constraint

    def __str__(self):
        if self.role.name == 'super_admin':
            return f'{self.name} ({self.email}) (Super Admin)'
        return f'{self.name} ({self.email}) @ {self.institution.subdomain if self.institution else "No institution"}'
    
    def has_perm(self, perm_name: str) -> bool:
        """
        Check if the user's role has a specific permission.
        """
        if not self.role or not self.role.permissions:
            return False
        return self.role.permissions.get(perm_name, False)
    
    def has_perms(self, perm_names: list) -> bool:
        """
        Check if the user's role has all the specified permissions.
        """
        return all(self.has_perm(p) for p in perm_names)
