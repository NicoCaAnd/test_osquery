# Description and objectives
Osquery is an very interesting multiplatform tool that collects data from the system. 
Android is not officialy supported yet by the Osquery project.
I made some changes in the compilation toolchain in order to build a binary that will run above the Android Java layer, at the system level on the device.
You will find more details on my Blueprint post : https://github.com/osquery/osquery/issues/7144
Here, I put Osquery tables I make, in order to collect data from Android devices for forensic purposes.
There are 3 types of usefull tables for Android : 
- one type parses .xml files on the system to get relevant data ;
- one type parses .db files on the system to get the information ;
- and an other type uses binaries on the device (such as *dumpsys* or *logcat*) and parses the output to get the data needed.
# Contents of this repository
In this repository, you will find the *.cpp* and *.table* files that represent Osquery tables for Android.
The *.cpp* files describe the way the collection of data is done, et and *.table* files provide the specifications for each *.cpp* file.
## List of tables
- android_dumpsys_app : uses the Android binary dumpsys with "package packages" option to get the list of Android apps with some information such as : nameApp, signature version, etc. Also you can check if some dangerous permissions are used (as android.permissions.CAMERA or RECORD_AUDIO);
- android_dumpsys_app_perms : this table also uses dumpsys to get all the permissions for each Android Apps ;
- android_packages_app : read the file /data/system/packages.xml to provide the list of the Android apps with some information (need to root the device) ;
- android_dumpsys_gsm : this table uses dumpsys with the option telephony.registry to provide the list of the Balise Transmitter Station that binded the device.
