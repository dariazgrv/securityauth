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
from main.models import Limit, ForbiddenIP


# Create your views here.

#global var
from corelogin.models import LoginInfo


def generate_secure_code():
        choices = [''.join(x) for x in itertools.permutations('123456789', 5)]
        code = random.choice(choices)

        return code

def get_client_ip(request):
        api = shodan.Shodan('Ppv7mH72xsimqNde3Vq2MgaDyGEtScFm')
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
                ip = x_forwarded_for.split(',')[0]
                print(ip)
                try:

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
        # lat,long = g.lat_lon('84.117.7.56')
        # print(lat)
        # print(long)
        city = g.city(ip)
        print(city)

        return city
        

def get_client_last_login(username):
        last_login = User.objects.get(username=username).last_login
        date_joined = User.objects.get(username=username).date_joined
        # print('Hour is: ',last_login.hour)
        if last_login is not None:
                return last_login
        else:
                return date_joined
        #should add a more elaborate comparison

def calculate_time_between_logins(now,last_login):


        date_time_difference = now - last_login
        date_time_difference_in_minutes = date_time_difference.seconds / 60
        print("Diferenta in minute dintre login-uri: ",date_time_difference_in_minutes)
        return date_time_difference_in_minutes


def calculate_score_of_trust(ip,username,limit):
        get_client_city(ip)
        user = User.objects.get(username=username)
        print("WWwWWWWW USER IS", user)

        risk_score = 0

        now  = timezone.now()
        #now = datetime.datetime.now() #get current time of login attempt
        last_login = get_client_last_login(username)  # get last login time

        previous_city = LoginInfo.objects.values('city').filter(user=user).latest('city')['city']

        print("THE PREV CITY IIIIIIIIIIISSS", previous_city)
        current_city = get_client_city(ip)["city"]
        print(current_city)
        current_lat = get_client_city(ip)["latitude"]
        current_lon = get_client_city(ip)["longitude"]

        previous_lat = LoginInfo.objects.values('latitude').filter(user=user).earliest('latitude')['latitude']
        print("prev lat ", previous_lat)
        previous_lon = LoginInfo.objects.values('longitude').filter(user=user).earliest('longitude')['longitude']
        print("prev lon", previous_lon)
        time_between_logins = calculate_time_between_logins(now,last_login)

        distance = calculate_lat_long_distance(current_lat, current_lon, previous_lat, previous_lon)

        possible = can_user_trave_by_google_maps_estimations(current_lat, current_lon, previous_lat, previous_lon,
                                                             distance, time_between_logins)

        forbidden = ForbiddenIP.objects.filter(forbiddenIP=ip).exists()


        if forbidden == True:
                risk_score = risk_score + 10

        if possible == False:
                risk_score = risk_score + 10
                if time_between_logins < limit:
                        risk_score = risk_score + 10
        else:
                risk_score = 0

        # if current_city != previous_city : #daca orasul curent difera de cel anterior
        #         risk_score = risk_score + 10 #avem deja un risc de +10
        #         if time_between_logins < limit: #daca timpul intre login-uri este mai mic de 2 minute
        #                 # inseamnca ca intr-un timp scurt userul a incercat sa se logheze din 2
        #                 # orase diferite, deci riscul creste cu +10
        #                 risk_score = risk_score + 10
        #                 #deci vom calcula distanta, pt a vedea daca e posibil sa ajunga de la o locatia la alta in timpul dat
        #                 distance = calculate_lat_long_distance(current_lat,current_lon,previous_lat,previous_lon)
        #                 if distance > 100: #daca distanta e mai mare de 100km
        #                         risk_score = risk_score + 10 #riscul creste cu +10
        #                         possible = can_user_trave_by_google_maps_estimations(current_lat,current_lon,previous_lat,previous_lon,distance,time_between_logins)
        #                         #verificam daca era era posibil sa ajunga acolo in timpul dat
        #                         if possible == False: #iar daca nu era posibil fizic
        #                                 #trigger_2FA() il obligam sa se logheze prin 2FA
        #                                 risk_score = risk_score + 10 #pana acum ajunge la maxim 40 ?
        #         else:
        #                 distance = calculate_lat_long_distance(current_lat, current_lon, previous_lat, previous_lon)
        #                 possible = can_user_trave_by_google_maps_estimations(current_lat,current_lon,previous_lat,previous_lon,distance,time_between_logins)
        #                 if possible == False:
        #                         risk_score = risk_score + 10
        #
        #
        # else:
        #         risk_score = 0

        return risk_score


        # if distance is big and time difference between logins is small, deny access/ redirect to 2FA

def can_user_travel_there_in_that_amonut_of_time(distance,time_between_logins):
        if distance > 1000 and time_between_logins > 24:
                return True
        return False

def can_user_trave_by_google_maps_estimations(lat1,lon1,lat2,lon2,distance,time_between_logins):
        api_key = 'AIzaSyCXgLbShg74qsdoOwpiP-TQkbWJsZBqd94'

        # url variable store url
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

        if distance - kms in range(-10,10) and time_between_logins >= time_estimated:
                return True
        return False



def calculate_lat_long_distance(lat1,lon1,lat2,lon2):
        #using Haversine formula
        p = pi / 180
        a = 0.5 - cos((lat2 - lat1) * p) / 2 + cos(lat1 * p) * cos(lat2 * p) * (1 - cos((lon2 - lon1) * p)) / 2
        return 12742 * asin(sqrt(a))

def corelogin(request):
        ip = get_client_ip(request)
        #allowed_IPs = ['192.168.10.10','127.0.0.1']
        #print(ip)
        # ip = '195.181.167.148' #uncomment for locahost

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
                        risk_score = calculate_score_of_trust(ip,username,limit)
                        print(username,"has a risk score of: ", risk_score)

                        if user is not None:

                                # device,os,browser info
                                device = request.user_agent.device.family
                                os = request.user_agent.os.family
                                browser = request.user_agent.browser.family


                                user_fingerprint = LoginInfo.objects.values('fingerprint').filter(user=user).latest('fingerprint')['fingerprint']
                                print(user_fingerprint)
                                fingerprint_tuple = (device, os, browser)
                                print(fingerprint_tuple)
                                fingerprint = hashlib.sha256(str(fingerprint_tuple).encode('utf-8')).hexdigest()


                                if user_fingerprint == fingerprint_tuple:
                                        print("User device,os,browser is the same")
                                else:
                                        print("Fingerprint for this device", fingerprint)
                                #fingerprint END #####

                                if risk_score == 0:

                                        login(request,user)

                                        l = LoginInfo()

                                        l.user = user
                                        l.ip = ip
                                        l.latitude = city["latitude"]
                                        l.longitude = city["longitude"]
                                        l.city = city["city"]
                                        l.save()
                                        return redirect("/")
                                else:
                                        global code
                                        print("First code",code)
                                        # global signer
                                        # secureCode = signer.sign(str(code))
                                        # secureCode = secureCode.replace(code,"")
                                        #secureCode = base64.b64encode(code)
                                        secureCode= encrypt_code(code)
                                        return redirect('securelogin',username=username, secureCode=secureCode)

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
        #return render(request, "corelogin/securelogin.html", {'username': username})
        #return redirect("/2fsecure", username=username)


        account_sid = "ACdc092be79e828046c8fdd2ecad1cb644"
        auth_token = "dff722b60ba909558d06dccc3d996e2c"
        client = Client(account_sid, auth_token)

        #global code
        # global signer
        # repack = "{}:{}".format(code,secureCode)
        # secureCode = signer.unsign(repack)
        #secureCode = base64.b64decode(code)

        secureCode = decrypt_code(secureCode)
        secureCode = str(secureCode)
        print("AFTER DECRYPTION", secureCode)
        user = User.objects.get(username=username)
        print(user.email)

        id = User.objects.get(username=username).id
        user_id = User.objects.get(pk=id)
        phone = LoginInfo.objects.values('phonenumber').filter(user=user).latest('phonenumber')['phonenumber']
        print(phone)
        # message = client.messages.create(
        #         body="Your authentication code is {}".format(secureCode),
        #         to="{}".format(phone),
        #         from_="+12025195154")
        # print(message.sid)


        # print(type(code))
        # print("Code is",code)

        ip = get_client_ip(request)
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

