# Description and Objective
Osquery is an very interesting tool that collects data from different types of system. 
Android is not officialy supported yet by the Osquery project.
I made some changes in the compilation toolchain in order to build a binary that will run above the Android Java layer, at the system level.
You read this my Blueprint post for more explanations : https://github.com/osquery/osquery/issues/7144
Here I put Osquery tables I make, in order to collect data from Android devices for forensic purposes.
I want to build 3 types of table for Android : 
- One type will read .xml files on the system to get relevant data ;
- One type will read .db files on the system to get data ;
- And an other type will use binaries on the device (as dumpsys or logcat) to get the data ;
# Contents of this repository
In this repository, you will find the .cpp and .table files which refer to Osquery tables for Android.
the .cpp files describe the way the collect of data is done, et and .table files provide the specifications for each .cpp file.
## List of tables
- android_dumpsys_app : uses the Android binary dumpsys with "package packages" option to get the list of Android apps with some information such as : nameApp, signature version, etc. Also you can check if some dangerous permissions are used (as android.permissions.CAMERA or RECORD_AUDIO);
- android_dumpsys_app_perms : this table also uses dumpsys to get all the permissions for each Android Apps ;
- android_packages_app : read the file /data/system/packages.xml to provide the list of the Android apps with some information (need to root the device) ;
- android_dumpsys_gsm : this table uses dumpsys with the option telephony.registry to provide the list of the Balise Transmitter Station that binded the device.
