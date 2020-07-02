from django.contrib import admin
from .models import Limit, ForbiddenIP,DistanceLimit, NumberOfLoginsLimit
# Register your models here.

admin.site.register(Limit)
admin.site.register(ForbiddenIP)
admin.site.register(DistanceLimit)
admin.site.register(NumberOfLoginsLimit)