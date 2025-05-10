from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.urls import reverse
from django.contrib.auth.tokens import default_token_generator

def generate_email_verification_link(request, user):
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)

    return request.build_absolute_uri(
        reverse('verify-email', kwargs={'uidb64': uid, 'token': token})
    )
