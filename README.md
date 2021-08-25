# test_osquery
## Osquery table files for Android
In this repository, you will find the .cpp and .table files which refer to Osquery tables for Android.
- android_dumpsys_app : uses the Android binary dumpsys with "package packages" option to get the list of Android apps with some information such as : nameApp, signature version, etc. Also you can check if some dangerous permissions are used (as android.permissions.CAMERA or RECORD_AUDIO);
- android_dumpsys_app_perms : this table also uses dumpsys to get all the permissions for each Android Apps ;
- android_packages_app : read the file /data/system/packages.xml to provide the list of the Android apps with some information (need to root the device) ;
- android_dumpsys_gsm : this table uses dumpsys with the option telephony.registry to provide the list of the Balise Transmitter Station that binded the device.
