import logging

from django.contrib.auth import get_user_model
from django.core.management import BaseCommand
from django.core.validators import validate_email

logger = logging.getLogger(__name__)
User = get_user_model()


class Command(BaseCommand):
    help = "Changes the value of the user's ldap field to True"

    def add_arguments(self, parser):
        parser.add_argument('username', type=str)
        parser.add_argument('email', type=str)

    def handle(self, *args, **options):
        username = options['username']
        email = options['email']
        self.stdout.write(f"Try to create superadmin ldap use with username {username} and email {email}")
        try:
            validate_email(email)  # raise error
            user = User(email=email, username=username, ldap_user=True)
            user.ldap_user = True
            user.save()
            self.stdout.write(self.style.SUCCESS(f"Success, user {user.username}  added to admin"))
        except Exception as e:
            self.stderr.write(self.style.ERROR(f"Error  {e}"))
