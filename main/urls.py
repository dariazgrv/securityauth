from django.urls import path
from django.conf.urls import url
from django.conf import settings

from . import views

urlpatterns = [
    path("", views.home, name="home"),
    url(r'^logout/$', views.logout, name='logout')

]
