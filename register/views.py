from django.shortcuts import render, redirect
from .forms import RegisterForm, ExtraInfo
from django.contrib.gis.geoip2 import GeoIP2
from django.contrib.auth.models import User

from corelogin.models import LoginInfo
import hashlib

# Create your views here.

def register(request):
    ip = get_client_ip(request)
    #ip = '84.117.7.60' #uncommnet for localhost
    city = get_client_city(ip)

    if request.method == "POST":
        form = RegisterForm(request.POST)
        phone_form  = ExtraInfo(request.POST)
        if form.is_valid() and phone_form.is_valid():
            form.save()
            id = User.objects.latest('id').id
            user = User.objects.get(pk=id)
            user.save()
            print(user)

            #device,os,browser info
            device = request.user_agent.device.family
            os = request.user_agent.os.family
            browser = request.user_agent.browser.family

            fingerprint_tuple = (device,os,browser)
            print(fingerprint_tuple)
            fingerprint = hashlib.sha256(str(fingerprint_tuple).encode('utf-8')).hexdigest()
            print(fingerprint)

            l = LoginInfo()

            l.user = user
            l.ip = ip
            l.latitude = city["latitude"]
            l.longitude = city["longitude"]
            l.city = city["city"]
            l.phonenumber = phone_form.cleaned_data.get('phonenumber')
            l.fingerprint = fingerprint_tuple
            l.save()

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
        # city = g.city('84.117.7.60')  #uncomment for localhost
        city = g.city(ip)
        # print(city["latitude"])
        
        return city
        