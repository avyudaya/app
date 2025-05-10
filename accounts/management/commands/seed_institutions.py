from django.core.management.base import BaseCommand
from accounts.models import Institution

DEFAULT_INSTITUTIONS = [
    {'subdomain': 'missouri', 'name': 'Missouri'},
    {'subdomain': 'harvard', 'name': 'Harvard'},
    {'subdomain': 'yale', 'name': 'Yale'},
]

class Command(BaseCommand):
    help = 'Seed default institutions if they do not exist'

    def handle(self, *args, **kwargs):
        for inst in DEFAULT_INSTITUTIONS:
            obj, created = Institution.objects.get_or_create(
                subdomain=inst['subdomain'],
                defaults={'name': inst['name']}
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f"✅ Created institution: {obj.name}"))
            else:
                self.stdout.write(self.style.WARNING(f"Institution already exists: {obj.name}"))
