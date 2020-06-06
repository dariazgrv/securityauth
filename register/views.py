from django.shortcuts import render, redirect
from .forms import RegisterForm, ExtraInfo
from django.contrib.gis.geoip2 import GeoIP2
from django.contrib.auth.models import User

from corelogin.models import LoginInfo


# Create your views here.

def register(request):
    ip = get_client_ip(request)
    city = get_client_city(ip)
    
    if request.method == "POST":
        form = RegisterForm(request.POST)
        phone_form  = ExtraInfo(request.POST)
        if form.is_valid() and phone_form.is_valid():
            form.save()
            id = User.objects.latest('id').id
            user = User.objects.get(pk=id)
            print(user)
            user.logininfo.ip = ip
            print("This is the iiiiiip: ",user.logininfo.ip)
            user.logininfo.latitude = city["latitude"]
            user.logininfo.longitude = city["longitude"]
            user.logininfo.city = city["city"]
            user.logininfo.phonenumber = phone_form.cleaned_data.get('phonenumber')
            user.logininfo.save()
            user.save()
            #phone_form.save()
            # logininfo = form.save(commit=False)
            # logininfo.user = request.user
            # logininfo.ip = ip
            # logininfo.latitude = city["latitude"]
            # logininfo.longitude = city["longitude"]
            # print("This is the login table info:",logininfo)
            # logininfo.save()



            return redirect("/login")
    else:
        form = RegisterForm()
        phone_form  = ExtraInfo(request.POST)
    return render(request, "register/register.html",{"form":form, 'phone_form': phone_form})

def get_client_ip(request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
                ip = x_forwarded_for.split(',')[0]
                # print(ip)
        else:
                ip = request.META.get('REMOTE_ADDR')
               
        return ip

def get_client_city(ip):
        g = GeoIP2()
        # lat,long = g.lat_lon('84.117.7.56')
        # print(lat)
        # print(long)
        city = g.city(ip)
        # print(city["latitude"])
        
        return city
        