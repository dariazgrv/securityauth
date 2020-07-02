import hashlib

from django.shortcuts import render,redirect, HttpResponseRedirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm
from django.urls import reverse
from django.contrib.gis.geoip2 import GeoIP2
from django.contrib.auth.models import User
import datetime
from twilio.rest import Client
from django.utils import timezone
from math import cos, asin, sqrt, pi
import random, itertools
from datetime import timedelta
from django.core.signing import TimestampSigner
import base64
from Crypto.Cipher import AES
import shodan
import random
import requests, json
from cachetools import TTLCache, cached
from main.models import Limit, ForbiddenIP, DistanceLimit, NumberOfLoginsLimit




# Create your views here.

#global var
from corelogin.models import LoginInfo

@cached(cache=TTLCache(maxsize=1024, ttl=60))
def generate_secure_code():
        choices = [''.join(x) for x in itertools.permutations('123456789', 5)]
        code = random.choice(choices)

        return code

def get_client_ip(request):
        api = shodan.Shodan('Ppv7mH72xsimqNde3Vq2MgaDyGEtScFm')
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
                ip = x_forwarded_for.split(',')[0]

                try:
                        api = shodan.Shodan('Ppv7mH....')
                        ipinfo = api.host(ip)
                        if 'tags' in ipinfo and 'vpn' in ipinfo['tags']:
                                print('{} is connecting from VPN'.format(ip))
                except shodan.APIError as e:
                        print('Error: {}'.format(e))

        else:
                ip = request.META.get('REMOTE_ADDR')
                try:

                        ipinfo = api.host(ip)
                        if 'tags' in ipinfo and 'vpn' in ipinfo['tags']:
                                print('{} is connecting from VPN'.format(ip))
                except shodan.APIError as e:
                        print('Error: {}'.format(e))

        return ip

def get_client_city(ip):
        g = GeoIP2()
        city = g.city(ip)

        return city
        

def get_client_last_login(username):
        last_login = User.objects.get(username=username).last_login
        date_joined = User.objects.get(username=username).date_joined
        # print('Hour is: ',last_login.hour)
        if last_login is not None:
                return last_login
        else:
                return date_joined
        #more elaborate comparison

def calculate_time_between_logins(now,last_login):


        date_time_difference = now - last_login
        date_time_difference_in_minutes = date_time_difference.seconds / 60
        print("Diferenta in minute dintre login-uri: ",date_time_difference_in_minutes)
        return date_time_difference_in_minutes


def calculate_score_of_trust(ip,username,limit,request):
        get_client_city(ip)
        user = User.objects.get(username=username)

        now  = timezone.now()

        last_login = get_client_last_login(username)  # get last login time

        previous_city = LoginInfo.objects.values().filter(user=user).last()['city']


        current_city = get_client_city(ip)["city"]

        current_lat = get_client_city(ip)["latitude"]
        current_lon = get_client_city(ip)["longitude"]

        previous_lat = LoginInfo.objects.values().filter(user=user).last()['latitude']

        previous_lon = LoginInfo.objects.values().filter(user=user).last()['longitude']
      
        time_between_logins = calculate_time_between_logins(now,last_login)

        distance = calculate_lat_long_distance(current_lat, current_lon, previous_lat, previous_lon)

        possible = can_user_travel_by_google_maps_estimations(current_lat, current_lon, previous_lat, previous_lon,
                                                             distance, time_between_logins)

        forbidden = ForbiddenIP.objects.filter(forbiddenIP=ip).exists()

        number_of_logins = LoginInfo.objects.filter(user=user).count()

        # device,os,browser info
        device = request.user_agent.device.family
        os = request.user_agent.os.family
        browser = request.user_agent.browser.family

        user_fingerprint = LoginInfo.objects.values().filter(user=user).last()['fingerprint']
        print(user_fingerprint)
        fingerprint_tuple = (device, os, browser)
        print(fingerprint_tuple)
        fingerprint = hashlib.sha256(str(fingerprint_tuple).encode('utf-8')).hexdigest()

        number_of_logins_limit = NumberOfLoginsLimit.objects.get(id=1).numberofLogins

        risk_score = 0


        if possible == False:
                risk_score = risk_score + 10

        if user_fingerprint != fingerprint:
                risk_score = risk_score + 10

        if time_between_logins < limit and number_of_logins > number_of_logins_limit:
                risk_score = risk_score + 10

        if forbidden == True:
                risk_score = 50 #interzis

        return risk_score


def can_user_travel_by_google_maps_estimations(lat1,lon1,lat2,lon2,distance,time_between_logins):
        api_key = 'AIzaSyCXgLbShg74qsdoOwpiP-TQkbWJsZBqd94'

        url = 'https://maps.googleapis.com/maps/api/distancematrix/json?'

        r = requests.get(url + 'origins=' + str(lat1) + ',' + str(lon1) +
                         '&destinations=' + str(lat2) + ',' + str(lon2) +
                         '&key=' + api_key)

        response_dict = r.json()

        kms = response_dict['rows'][0]['elements'][0]['distance']['value']
        time_estimated = response_dict['rows'][0]['elements'][0]['duration']['value']

        kms = kms * 0.001 #transformam metri in km
        time_estimated = time_estimated/60 #transformam din secunde in minute

        print("Timpul estimat de Google Maps in ore este: ", time_estimated/60)
        print("Distanta in km este: ", distance)
        print("Distanta in km calculata de Google Maps este: ", kms)
        print("Timpul dintre loginuri este:", time_between_logins)

        distance_limit = DistanceLimit.objects.get(id=1).distanceLimit #extragem limita de distanta impusa de Admin

        if distance - kms in range(-distance_limit,distance_limit) and time_between_logins >= time_estimated:
                return True
        return False


from math import cos, asin, sqrt, pi
def calculate_lat_long_distance(lat1,lon1,lat2,lon2):
        #Haversine formula
        r = pi / 180 #convertim gradele in radieni
        a = 0.5 - cos((lat2 - lat1) * r) / 2 + cos(lat1 * r) * cos(lat2 * r) * (1 - cos((lon2 - lon1) * r)) / 2
        return 12742 * asin(sqrt(a)) # 2 * R * arcsin(sqrt(a)) , unde R = 6371 = raza Pamantului

def corelogin(request):
        ip = get_client_ip(request)
        #allowed_IPs = ['192.168.10.10','127.0.0.1']
        #print(ip)
        #ip = '45.12.221.228' #uncomment for locahost

        # get_client_city(ip)
        # get_client_last_login(request)
        city = get_client_city(ip)

        if request.method == 'POST':
                form = AuthenticationForm(request=request, data=request.POST)
                if form.is_valid():
                        username = form.cleaned_data.get('username')
                        password = form.cleaned_data.get('password')

                        user = authenticate(username=username, password=password)
                        # returns a User object if the password is valid for the given username. 
                        # If the password is invalid, authenticate() returns None

                        get_client_last_login(username=username)
                        limit = Limit.objects.get(id=1).timelimit
                        print("TIme limit set by admin is: ",limit)
                        risk_score = calculate_score_of_trust(ip,username,limit, request)
                        print(username,"has a risk score of: ", risk_score)

                        if user is not None:

                                # # device,os,browser info
                                # device = request.user_agent.device.family
                                # os = request.user_agent.os.family
                                # browser = request.user_agent.browser.family
                                #
                                #
                                # user_fingerprint = LoginInfo.objects.values('fingerprint').filter(user=user).latest('fingerprint')['fingerprint']
                                # print(user_fingerprint)
                                # fingerprint_tuple = (device, os, browser)
                                # print(fingerprint_tuple)
                                # fingerprint = hashlib.sha256(str(fingerprint_tuple).encode('utf-8')).hexdigest()
                                #
                                #
                                # if user_fingerprint == fingerprint:
                                #         print("User device,os,browser is the same")
                                #
                                # else:
                                #         risk_score = risk_score + 10

                                #fingerprint END #####

                                if risk_score == 0:

                                        login(request,user)

                                        l = LoginInfo()

                                        l.user = user
                                        l.ip = ip
                                        l.latitude = city["latitude"]
                                        l.longitude = city["longitude"]
                                        l.city = city["city"]
                                        l.fingerprint = fingerprint
                                        l.save()
                                        return redirect("/")
                                else:
                                        if risk_score == 50:
                                                return redirect('forbidden')
                                        if risk_score > 0 and risk_score != 50:
                                                global code
                                                print("First code",code)
                                                secureCode= encrypt_code(code)
                                                return redirect('securelogin',username=username, secureCode=secureCode)
                                        else:
                                                messages.error(request, 'username or password not correct')
                                                return redirect('login')

        form = AuthenticationForm()
        return render(request=request, template_name = "corelogin/login.html",context={"form":form})


def encrypt_code(code):

        code = int(code) * 31
        code = str(code) + "EXKRGW"
        return code

def decrypt_code(code):
       code = str(code).replace("EXKRGW","")

       code = (int(code))//31
       return code

code = generate_secure_code()

def securelogin(request,username, secureCode):

        account_sid = "ACdc092be79e828046c8fdd2ecad1cb644"
        auth_token = "dff722b60ba909558d06dccc3d996e2c"

        secureCode = decrypt_code(secureCode)
        secureCode = str(secureCode)
        print("AFTER DECRYPTION", secureCode)
        user = User.objects.get(username=username)
        print(user.email)

        id = User.objects.get(username=username).id
        user_id = User.objects.get(pk=id)
        phone = LoginInfo.objects.values().filter(user=user).last()['phonenumber']
        print(phone)


        client = Client(account_sid, auth_token)

        # message = client.messages.create(
        #         body="Your authentication code is {}".format(secureCode),
        #         to="{}".format(phone),
        #         from_="+12025195154")
        #
        # print(message.sid)

        ip = get_client_ip(request)
        #ip = '195.181.167.148' #uncomment for local host
        city = get_client_city(ip)


        if request.method == 'POST':

                print("Generated secure code is", secureCode)
                if secureCode is not None:
                        login_data = request.POST.dict()
                        code = login_data.get('Code')
                        print(code)
                        if code == secureCode:
                                print(user.username)
                                l = LoginInfo()
                                l.user = user
                                l.ip = ip
                                l.latitude = city["latitude"]
                                l.longitude = city["longitude"]
                                l.city = city["city"]
                                l.save()

                                login(request, user)
                                return redirect("/")

        return render(request, "corelogin/securelogin.html", {'username': username,'secureCode': secureCode})

def frobidden(request):

        return render(request, "corelogin/forbidden.html")


