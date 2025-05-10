from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django.conf import settings

def send_verification_email(user, verification_url):
    subject = "Verify your email address"
    to_email = [user.email]

    context = {
        'user': user,
        'verification_url': verification_url,
    }

    html_content = render_to_string('emails/email_verification.html', context)
    text_content = f"Hi {user.name},\nPlease verify your email by visiting the link: {verification_url}"

    msg = EmailMultiAlternatives(subject, text_content, settings.DEFAULT_FROM_EMAIL, to_email)
    msg.attach_alternative(html_content, "text/html")
    msg.send()


def send_password_reset_email(user, reset_url):
    subject = "Verify your email address"
    to_email = [user.email]

    context = {
        'user': user,
        'reset_url': reset_url,
    }

    html_content = render_to_string('emails/password_reset.html', context)
    text_content = f"Please reset your password here: {reset_url}"
    
    msg = EmailMultiAlternatives(subject, text_content, settings.DEFAULT_FROM_EMAIL, to_email)
    msg.attach_alternative(html_content, "text/html")
    msg.send()

def send_welcome_email(user):
    subject = "Welcome to AppPortal!"
    to_email = [user.email]
    subdomain = user.institution.subdomain if user.institution else "www"
    dashboard_url = f"https://{subdomain}.appportal.com/dashboard"
    html_content = render_to_string('emails/welcome.html', {
        'user': user,
        'institution': user.institution.name if user.institution else "AppPortal",
        "dashboard_url": dashboard_url
    })
    text_content = f"Hi {user.name},\nWelcome to the application. Please visit to use the application: {dashboard_url}"
    msg = EmailMultiAlternatives(subject, text_content, settings.DEFAULT_FROM_EMAIL, to_email)
    msg.attach_alternative(html_content, "text/html")
    msg.send()