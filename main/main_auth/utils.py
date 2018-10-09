from django.utils import timezone
from django.conf import settings

def get_default_expiration_date():
    """
    The standard default expiration date is 30 days from the time of record creation
    :return: A date that is 30 days from when this function is called.
    """
    return timezone.now() + timezone.timedelta(seconds=settings.ACCESS_TOKEN_EXPIRE_SECONDS)
