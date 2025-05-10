from accounts.models import Institution

class InstitutionSubdomainMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        host = request.get_host().split(':')[0]
        subdomain = host.split('.')[0]

        try:
            request.institution = Institution.objects.get(subdomain=subdomain)
        except Institution.DoesNotExist:
            request.institution = None

        return self.get_response(request)