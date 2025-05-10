#!/bin/bash

# Load environment variables from the .env file
if [ -f .env ]; then
    source .env
else
    echo ".env file not found"
    exit 1
fi

# Ensure environment variables are set
if [ -z "$SUPER_USER_EMAIL" ] || [ -z "$SUPER_USER_PASSWORD" ]; then
    echo "Superuser email or password is not set in .env file."
    exit 1
fi

echo "⏩ Making migrations..."
python manage.py makemigrations

echo "🚀 Applying migrations..."
python manage.py migrate

echo "📥 Seeding roles..."
python manage.py seed_roles

echo "🏫 Seeding institutions..."
python manage.py seed_institutions

# 🔐 Create a superuser if it doesn't exist
echo "👤 Checking for existing superuser..."
python manage.py shell << EOF
from accounts.models import User
from django.contrib.auth import get_user_model

User = get_user_model()
print("🛠  Creating default superuser...")
User.objects.create_superuser(
    email="$SUPER_USER_EMAIL",
    password="$SUPER_USER_PASSWORD",
    institution=None
)
EOF

echo "✅ All setup complete!"
read -p "Press any key to exit..."
