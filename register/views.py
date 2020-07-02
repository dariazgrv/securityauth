import itertools
from django.shortcuts import render, redirect
from .forms import RegisterForm, ExtraInfo
from django.contrib.gis.geoip2 import GeoIP2
from django.contrib.auth.models import User
from twilio.rest import Client
from corelogin.models import LoginInfo
import hashlib
import random

# Create your views here.

def generate_secure_code():
    choices = [''.join(x) for x in itertools.permutations('123456789', 5)]
    code = random.choice(choices)

    return code

code = generate_secure_code()


def encrypt_code(code):
    code = int(code) * 31
    code = str(code) + "SWRTDV"
    return code


def decrypt_code(code):
    code = str(code).replace("SWRTDV", "")
    code = (int(code)) // 31
    return code

def register(request):
    ip = get_client_ip(request)
    ip = '84.117.7.60' #uncommnet for localhost
    city = get_client_city(ip)

    if request.method == "POST":
        form = RegisterForm(request.POST)
        phone_form  = ExtraInfo(request.POST)
        if form.is_valid() and phone_form.is_valid():
            form.save()
            id = User.objects.latest('id').id
            user = User.objects.get(pk=id)
            user.is_active = False
            # Since Django 1.10, the default ModelBackend authentication backend does not allow users with is_active = False to log in.
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
            l.fingerprint = fingerprint
            l.save()

            global code
            secureCode = encrypt_code(code)
            return redirect('confirmphone', username=user.username, secureCode=secureCode)
            # return redirect("/login")
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
        #city = g.city('84.117.7.60')  #uncomment for localhost
        city = g.city(ip)

        return city


def confirmphone(request,username, secureCode):

    account_sid = "ACdc092be79e828046c8fdd2ecad1cb644"
    auth_token = "dff722b60ba909558d06dccc3d996e2c"
    client = Client(account_sid, auth_token)

    secureCode = decrypt_code(secureCode)
    secureCode = str(secureCode)
    print("AFTER DECRYPTION", secureCode)
    user = User.objects.get(username=username)
    print(user.email)

    id = User.objects.get(username=username).id
    user_id = User.objects.get(pk=id)

    phone = LoginInfo.objects.values().filter(user=user).last()['phonenumber']
    print(phone)
    # message = client.messages.create(
    #         body="Your authentication code is {}".format(secureCode),
    #         to="{}".format(phone),
    #         from_="+12025195154")
    # print(message.sid)

    if request.method == 'POST':

        print("Generated secure code is", secureCode)
        if secureCode is not None:
            phone_data = request.POST.dict()
            code = phone_data.get('Code')
            print(code)
            if code == secureCode:

                user.is_active = True
                LoginInfo.objects.values().filter(user=user).last()['verified'] = True
                user.save()
                return redirect("/login")

    return render(request, "register/confirmphone.html", {'username': username, 'secureCode': secureCode})
