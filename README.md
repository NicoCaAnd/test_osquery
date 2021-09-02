This repository deals with Osquery table's files that will permit to collect data from recent Android ARM64 devices, for **experimental forensic purposes**.

# Description and objectives

Osquery is a multiplatform tool that collects data from the system. 
Android is not officialy supported by the Osquery project.

With some changes that have been merged, it is possible to build Osquery as an executable file that will run above the Android Java layer, at the system level on the device. 
All you need is to get Osquery code from its official Github repository, and make this command when calling CMake :
`cmake -DOSQUERY_TOOLCHAIN_SYSROOT=/usr/local/osquery-toolchain -DSTATICONLY=true ..`
You will find more details on this Blueprint post : https://github.com/osquery/osquery/issues/7144

It is important to note that Android **IS NOT officialy supported by the Osquery project**. Here it is just a proposal for **experimental purposes**.
We noted that, without modification, the binary built runs on a ARM64 Android system (with a recent Linux Kernel version >=4.9), and many GNU-Linux tables are available. 

Studying Android features and following the Osquery documentation, we can make some specific Android tables.
To get some relevant information on Android system, we made 3 types of tables : 
- one type parses *.xml* files ;
- one type parses *.db* files ;
- and an other type uses binaries on the device (such as *dumpsys* or *logcat*) and parses the output to get the data needed.

# Contents of this repository
In this repository, you will find the *.cpp* and *.table* files that represent Osquery tables for Android.
The *.cpp* files describe the way the collection of data is done, et and *.table* files provide the specifications for each *.cpp* file.

# List of tables

## android_dumpsys_app 
Uses the Android binary dumpsys with "package packages" option to get the list of Android apps with some information such as : nameApp, signature version, etc. Also you can check if some dangerous permissions are used (such as android.permissions.CAMERA or RECORD_AUDIO).

## android_dumpsys_app_perms 
This table also uses dumpsys to get all the permissions for each Android Apps.

## android_packages_app 
Reads the file /data/system/packages.xml to provide the list of the Android apps with some information (need to root the device).
![Capture_packages_xml](https://user-images.githubusercontent.com/85172899/131812759-c9ab5677-8cb2-436d-ac3d-9dbfccaf21f9.PNG)


## android_dumpsys_gsm 
This table uses dumpsys with the option telephony.registry to provide the list of the Balise Transmitter Stations that binded the device.
![Capture_bts_gsm](https://user-images.githubusercontent.com/85172899/131813911-cd763d51-44f7-4359-bb85-d51b02fbd55d.PNG)

## android_launcher_db
Provides apps information from a database file.
![Capture_launcher](https://user-images.githubusercontent.com/85172899/131815595-5b8331a1-4a12-4547-91bd-ca0a600b3eee.PNG)


## android_sms_db
Provides SMS infos reading a database file.
![Capture_sms](https://user-images.githubusercontent.com/85172899/131812835-a3e1fcbc-294e-43a0-b3e9-1c5ad9e10b8b.PNG)


## android_chrome_cookies_db
Gives some information about Chrome cookies reading a database file.

![Capture_chrome_cookies](https://user-images.githubusercontent.com/85172899/131815569-a7613e9d-44b6-423a-bf50-3bcb7de6c982.PNG)


