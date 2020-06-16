
from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model

from phonenumber_field.modelfields import PhoneNumberField
from django.core.validators import RegexValidator

# Create your models here.

class LoginInfo(models.Model):
    user = models.ForeignKey(User,on_delete=models.CASCADE)
    ip = models.CharField(max_length=60,blank=True)
    city = models.CharField(max_length=60,blank=True)
    latitude = models.FloatField(null=True, blank=True, default=None)
    longitude = models.FloatField(null=True, blank=True, default=None)
    phonenumber = models.CharField(null=True,max_length=17, blank=False,default=None)
    verified = models.BooleanField(null=True,default=False)
    fingerprint = models.CharField(max_length=64,blank=True,null=True)


