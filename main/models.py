from django.db import models

# Create your models here.

class Limit(models.Model):
    timelimit = models.IntegerField(default=2,blank=True,null=True)


class ForbiddenIP(models.Model):
    forbiddenIP = models.CharField(max_length=60,blank=True)

class DistanceLimit(models.Model):
    distanceLimit = models.IntegerField(default=10,blank=True,null=True)

class NumberOfLoginsLimit(models.Model):
   numberofLogins = models.IntegerField(default=5,blank=True,null=True)