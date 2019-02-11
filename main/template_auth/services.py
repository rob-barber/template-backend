from . import default_settings

from django.conf import settings
from django.utils import timezone
from django.core.mail import send_mail
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator

from smtplib import SMTPException

from oauthlib.common import generate_token
from oauth2_provider.models import Application, AccessToken

from sentry_sdk import capture_exception


def send_activation_email(user):
    """
    Sends an activation email to the user with a link that will direct them to the activation web page

    This function uses the Django Oauth Toolkit's token database for creating this temporary token.

    :param user: The user object containing the email address to send the email to.
    :return: True if successful, False otherwise.
    """

    if user.email is None:
        return False

    oauth_app = Application.objects.get(name=settings.APP_NAME)

    oauth_token = generate_token()

    AccessToken.objects.create(
        user=user,
        application=oauth_app,
        expires=timezone.now() + timezone.timedelta(seconds=default_settings.ACTIVATE_ACCOUNT_TOKEN_EXPIRE_SECONDS),
        token=oauth_token
    )

    # Use a reverse url lookup to set the link (this allows us to not worry about hard coding the url if it changes)
    link = settings.SERVER_BASE_URL + \
           reverse(
               'template_auth:user_activation',
               kwargs={'token': oauth_token},
               current_app=settings.APP_NAME)

    try:
        send_mail(
            from_email=settings.NO_REPLY_EMAIL,
            subject=settings.ACTIVATION_EMAIL_SUBJECT,
            recipient_list=[user.username],
            message='',
            html_message='<p>' + settings.ACTIVATION_EMAIL_MESSAGE + '</p><br/><br/>'
                         '<a href="' + link + '">' + link + '</a>',
            fail_silently=False,
        )
    except SMTPException:
        return False

    return True


def send_password_recovery_email(user):
    """
    Sends a password recovery email based upon the user parameter

    :param user: The user to send the recovery email for
    :return:
    """
    if user.email is None:
        return False

    # TODO: Set to correct app name when Oauth Toolkit is set up
    oauth_app = Application.objects.get(name=settings.APP_NAME)

    oauth_token = generate_token()

    AccessToken.objects.create(
        user=user,
        application=oauth_app,
        expires=timezone.now() + timezone.timedelta(seconds=settings.RESET_PASSWORD_TOKEN_EXPIRE_SECONDS),
        token=oauth_token
    )

    # Use a reverse url lookup to set the link (this allows us to not worry about hard coding the url if it changes)
    link = settings.SERVER_BASE_URL + \
           reverse(
               'template_auth:update_password',
               kwargs={'token': oauth_token},
               current_app='template_auth')

    try:
        send_mail(
            from_email= settings.NO_REPLY_EMAIL,
            subject='Test Company' + ' ' + 'Password Recovery',
            recipient_list=[user.username],
            message='Why do I need this????',
            html_message='<p>Please click the link below to navigate to the password recovery page.</p><br/><br/>'
                         '<a href="' + link + '">' + link + '</a>',
            fail_silently=False,
        )
    except SMTPException:
        return False

    return True


def validate_oauth_token(token):
    """
    Validates the token and returns the correct user if the token is valid.

    :param token: The oauth token to validate
    :return: The user object if the token is valid, None otherwise
    """
    if token is None:
        return None

    app = Application.objects.get(name=settings.APP_NAME)

    try:
        activation_token = AccessToken.objects.get(token=token, application=app)
    except AccessToken.DoesNotExist:
        return None # we cannot really go any further without the token

    now = timezone.now()

    if activation_token.expires < now:
        return None

    user = activation_token.user

    return user


class OauthPasswordResetTokenGenerator(PasswordResetTokenGenerator):
    """
    Used as the token generator for any view that needs to handle Oauth tokens rather than
    Django's built in tokens.
    """

    def make_token(self, user):
        """
        Return a token that can be used to do a password reset for the given user.
        :param user: The user object to connect the token to.
        :return: The new token
        """
        token_generator = OauthTokenGenerator()
        token_expiration = token_generator.reset_password_expiration()

        return OauthTokenGenerator().make_token(user, token_expiration)

    def check_token(self, user, token):
        """
        Check that a password reset token is correct for a given user
        :param user: The User object to use
        :param token: The token string representing the token
        :return: True if token is valid, False otherwise
        """
        return OauthTokenGenerator().check_token(user, token)


class OauthTokenGenerator:
    """
    This class is used to handle the creation and management of Oauth tokens for the system.

    This is mainly used for the mobile apps but is also used for activation and recovery tokens.
    """

    def _get_token_provider(self):
        """
        Returns the main token provider (oauth app) to use for handling oauth tokens etc...
        :return: The provider or None if an exception occurred
        """
        oauth_app = None

        try:
            # Get the registered Oauth Provider
            oauth_app = Application.objects.get(name=settings.OAUTH_APP_NAME)

        except Application.DoesNotExist as e:
            capture_exception(e)
            print(f'OauthToolkitHelper.get_token_provider: No Oauth Provider set')

        except Application.MultipleObjectsReturned as e:
            capture_exception(e)
            print(f'OauthToolkitHelper.get_token_provider: Duplicate Oauth Providers found')

        return oauth_app

    def reset_password_expiration(self):
        """
        Returns a datetime object that represents the expiration date of a reset password token
        created the moment this is called.
        :return: The expiration date time.
        """
        return timezone.now() + timezone.timedelta(seconds=settings.RESET_PASSWORD_TOKEN_EXPIRE_SECONDS)

    def make_token(self, user, expires):
        """
        Return a token that can be used to do a password reset for the given user.
        :param user: The user object to connect the token to.
        :param expires: The datetime to use as the expiration date of the token
        :return: The new token string
        """
        oauth_app = self._get_token_provider()

        if oauth_app is None:
            # An error occurred. Don't worry about messages here since we have already handled them in the try/catch
            return

        oauth_token = generate_token()  # The correctly configured token string value to use for the access token

        # Create a new AccessToken object in the Oauth table using the generated token as it's token value
        # This in turn allows the user to use this token.
        AccessToken.objects.create(
            user=user,
            application=oauth_app,
            expires=expires,
            token=oauth_token
        )

        return oauth_token

    def make_token_from_email(self, email, expires):
        """
        Return a token that can be used to do a password reset for the given user.
        :param email: The email of the user to create a token for.
        :param expires: The datetime to use as the expiration date of the token
        :return: The new token string or None if an error occured
        """

        user = None
        user_model = get_user_model()

        try:
            user = user_model.objects.get(email=email)

        except user_model.DoesNotExist as e:
            capture_exception(e)
            print(f'User with email {email} does not exist')

        return self.make_token(user, expires)

    def get_access_token(self, token):
        """
        Retrieves an AccessToken object from the database using the provided raw token string.

        :param token: Str, the string representation of the oauth token
        :return: The AccessToken object or None if an error occurred
        """

        oauth_app = self._get_token_provider()

        if oauth_app is None:
            return

        # Try and fetch the access token object from the database
        access_token = None

        try:
            access_token = AccessToken.objects.get(token=token, application=oauth_app)

        except AccessToken.DoesNotExist as e:
            capture_exception(e)
            print(f'User.get_from_auth_token: Access token does not exist in database')

        except AccessToken.MultipleObjectsReturned as e:
            capture_exception(e)
            print(f'User.get_from_auth_token: Duplicate access tokens found')

        return access_token

    def check_token(self, user, token):
        """
        Check that a token is correct for a given user as well as if the token is still valid
        :param user: The user object to use for the check
        :param token: The raw token string to use for the check
        :return: True if the token belongs is valid and belongs to the user, False otherwise
        """

        oauth_app = self._get_token_provider()

        if oauth_app is None:
            return False

        access_token = self.get_access_token(token)

        if access_token is None or access_token.is_expired():
            return False

        return user.id == access_token.user.id

