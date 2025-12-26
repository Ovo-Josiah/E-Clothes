from django.db import models
from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.base_user import AbstractBaseUser
from django.utils.translation import gettext_lazy as _

from authentications.managers import UserManager

# Create your models here.
class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique= True)
    first_name = models.CharField(_('firstname'), max_length=100)
    last_name = models.CharField(_('lastname'), max_length=100)
    phone_number = models.CharField(_('phone number'),max_length=20, blank=True)
    created_at = models.DateTimeField(_('created at'),auto_now_add= True, )
    is_active = models.BooleanField(_('active'), default=True )
    is_staff = models.BooleanField(_('staff status'), default=False)
    image = models.ImageField(upload_to='user_images/',null=True, blank=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name','last_name']


    class Meta:
        verbose_name_plural = "Users"

    def __str__(self):
        return f"{self.first_name} - {self.last_name}"