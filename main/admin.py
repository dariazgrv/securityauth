from django.contrib import admin
from .models import Limit, ForbiddenIP
# Register your models here.

admin.site.register(Limit)
admin.site.register(ForbiddenIP)