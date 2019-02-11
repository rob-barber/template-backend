import base64

from django import forms
from django.conf import settings
from django.urls import reverse
from django.core import mail
from django.contrib.auth import get_user_model

from smtplib import SMTPException

from template_auth.services import OauthTokenGenerator

from sentry_sdk import capture_exception


class ForgotPasswordForm(forms.Form):
    email = forms.EmailField(label='Email', max_length=254)

    def send_mail(self, from_email):
        """
        Send a django.core.mail.EmailMultiAlternatives to `to_email`. This will only
        work after the form has been validated.

        :throws SMTPException:
        """

        email = self.cleaned_data['email']

        user = None
        user_model = get_user_model()

        try:
            user = user_model.objects.get(email=email)

        except user_model.DoesNotExist as e:
            capture_exception(e)

        except user_model.MultipleObjectsReturned as e:
            capture_exception(e)

        if user is None:
            return

        token_generator = OauthTokenGenerator()
        expires = token_generator.reset_password_expiration()
        oauth_token = token_generator.make_token_from_email(email, expires)

        # Base64 encode the user id
        user_id_bytes = str(user.id).encode('utf-8')
        base64_bytes = base64.b64encode(user_id_bytes)
        user_id = base64_bytes.decode()

        # Create the link that the user can use to navigate to the password reset screen
        link = settings.SERVER_BASE_URL + \
            reverse(
                'template_auth:password_reset',
                kwargs={
                    'uidb64': user_id,
                    'token': oauth_token
                }
            )

        subject = 'Account Recovery'
        message = f'Please click the link below to navigate to the password recovery page. \n\n {link}'
        html_message = '<p>Please click the link below to navigate to the password recovery page.</p><br/><br/>' + \
                       '<a href="' + link + '">' + link + '</a>'

        try:
            mail.send_mail(
                from_email=from_email,
                subject=subject,
                recipient_list=[email],
                message=message,
                html_message=html_message,
                fail_silently=False

            )
        except SMTPException as e:
            capture_exception(e)  # Update Sentry with the exception
            print(f'Send_email exception: {e}')
