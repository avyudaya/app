from django.core.management.base import BaseCommand
from accounts.models import Institution

class Command(BaseCommand):
    help = 'Seed Institutions with sample data'

    def handle(self, *args, **kwargs):
        # Sample institutions to be added to the database
        institutions_data = [
            {
                'name': 'Missouri State University',
                'subdomain': 'missouri',
                'logo_url': 'https://a.espncdn.com/guid/c015a92b-9a44-a2d3-59da-a0e275d9b7e9/logos/primary_logo_on_black_color.png',
                'support_email': 'support@missouri.edu',
            },
            {
                'name': 'Harvard University',
                'subdomain': 'harvard',
                'logo_url': 'https://example.com/logos/harvard_logo.png',
                'support_email': 'support@harvard.edu',
            },
            {
                'name': 'Yale University',
                'subdomain': 'yale',
                'logo_url': 'https://example.com/logos/yale_logo.png',
                'support_email': 'support@yale.edu',
            },
        ]

        for institution_data in institutions_data:
            # Check if institution already exists
            institution, created = Institution.objects.get_or_create(
                name=institution_data['name'],
                subdomain=institution_data['subdomain'],
                defaults={
                    'logo_url': institution_data['logo_url'],
                    'support_email': institution_data['support_email']
                }
            )

            if created:
                self.stdout.write(self.style.SUCCESS(f'Successfully created institution: {institution.name}'))
            else:
                self.stdout.write(self.style.SUCCESS(f'Institution {institution.name} already exists'))
