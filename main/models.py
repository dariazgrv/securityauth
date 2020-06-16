from django.db import models

# Create your models here.

class Limit(models.Model):
    timelimit = models.IntegerField(default=2,blank=True,null=True)


class ForbiddenIP(models.Model):
    forbiddenIP = models.CharField(max_length=60,blank=True)

