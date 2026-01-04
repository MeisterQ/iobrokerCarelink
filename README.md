# iobrokerCarelink
IoBroker Carelink Javascript

Script is based on this homeassistant custom integration: https://github.com/yo-han/Home-Assistant-Carelink

1. Run iobroker_carelink_login.py
2. Copy and paste javascript into your javascript instance and run it once.


After you run the python script and logged in into carelink, you will get an logindata.json file which consists of all needed carelink tokens.

The javascript will create all needed datapoints. In the first run you will get some warnings, but you can ignore them.
After all DPs are created, you need to go to 0_userdata.0.carelink.auth and enter all tokens and informations from the logindata.json.
Then you need to go to .cfg and enter your patientID (I guess its your Carelink Username but im not sure. Its working for me) and change the role from "carepartner" to "patient".

After this everything should be filled with data if you run it.

This script will poll the api every minute and extract data. It will refresh the refresh token every 45 minutes. If you not stop the script or javascript instance, it will always refresh the token and no interaction is needed.
If you stop it for a longer time, then you probably have to rerun the python script to get new tokens.

For the pythonscript you need this packages:
- requests (pip install requests)
- OpenSSL (pip install pyOpenSSL)
- seleniumwire (pip install selenium-wire)
- curlify (pip install curlify)
- blinker vertion 1.7.0 (pip install blinker==1.7.0) (Issue documented here: seleniumbase/SeleniumBase#2782)
