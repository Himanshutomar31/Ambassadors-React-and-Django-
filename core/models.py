from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.


class User(AbstractUser):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    is_ambassdor = models.BooleanField(default=True)
    username = None

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
