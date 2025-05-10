from django.contrib import admin
from .models import Institution

class InstitutionAdmin(admin.ModelAdmin):
    list_display = ('name', 'subdomain', 'logo_url', 'support_email', 'created_at', 'updated_at')
    search_fields = ('name', 'subdomain', 'support_email')
    list_filter = ('created_at', 'updated_at')

    # Optional: To define editable fields on the admin panel
    fields = ('name', 'subdomain', 'logo_url', 'support_email')

    # Optional: Add date filtering options
    date_hierarchy = 'created_at'

# Register the Institution model with the customized admin class
admin.site.register(Institution, InstitutionAdmin)