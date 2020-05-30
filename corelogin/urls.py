
from django.conf.urls import url
# from django.contrib.auth.views import LoginView
from django.urls import path
from . import views
from django.conf.urls import url, include




urlpatterns = [
    # url(r'^login/$', LoginView.as_view(template_name='corelogin/login.html'), name='login'),
    #url(r'^logout/$', auth_views.logout, name='logout'),
    # url(r'^login/$', views.login, name="login"),
    path("login/", views.corelogin, name="login"),
    path("2fsecure/<username>/<secureCode>", views.securelogin, name="securelogin"),




]
