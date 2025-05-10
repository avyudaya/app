from django.core.management.base import BaseCommand
from accounts.models import Role

class Command(BaseCommand):
    help = "Seed default roles and permissions into the Role model."

    def handle(self, *args, **kwargs):
        roles = [
            ('student', {}),
            ('admin', {
                'can_manage_applications': True,
                'can_view_reports': True,
            }),
            ('reviewer', {
                'can_review_applications': True,
                'can_comment': True,
            }),
            ('super_admin', {
                'can_manage_everything': True,
                'can_delete_users': True,
                'can_manage_roles': True,
            }),
        ]

        for role_name, permissions in roles:
            role, created = Role.objects.get_or_create(
                name=role_name,
                defaults={'permissions': permissions}
            )
            if not created:
                role.permissions = permissions  # Update existing roles if needed
                role.save()

        self.stdout.write(self.style.SUCCESS("✅ Roles seeded successfully."))
