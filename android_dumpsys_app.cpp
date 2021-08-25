/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/filesystem.hpp>
#include <osquery/filesystem/filesystem.h>
#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/process/process.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <vector>
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>

namespace osquery {
namespace tables {

using namespace std;

Status genPackageDumpsysApp(Row& r, QueryData& results) 
   {

	pid_t pid = fork();	//Firstly, we call the binary dumpsys and output it to a file in order to read it later
	std::string buff = "";
	if(pid == 0)
	{
		FILE *out = freopen("/data/local/tmp/logDump","w",stdout); //Redirection of stdout toward a file 'logDump' in order to read it
		if (!out)
			fprintf(stderr,"ERROR freopen: %s", strerror(errno));
		stdout = out;	
		if(system("dumpsys package packages")!=0) //Here we call the binary dumpsys with the options 'package packages'
		{
			fprintf(stderr,"Error while exec() : %s\n", strerror(errno));
		}
	}
	wait(0);
	std::ifstream ReadFile("/data/local/tmp/logDump");
	if(ReadFile)	//Reading the log file
	{
		std::string line;
		while(std::getline(ReadFile, line)) //Reading line by line
		{
			std::size_t found = line.find("Package ["); 
			if(found!=std::string::npos) //for each package line found, we need to get the name of the apk
			{
				vector<string> vectLine;
				stringstream ss(line);
				string subString;
				while(getline(ss, subString, ' '))
				{
					vectLine.push_back(subString);
				}
				for(auto i=vectLine.begin();i!=vectLine.end();i++)
				{
					if((*i).find("[")!=std::string::npos)
					{	
						(*i).erase(std::remove((*i).begin(),(*i).end(), '['),(*i).end()); //remove useless '['
						(*i).erase(std::remove((*i).begin(),(*i).end(), ']'),(*i).end()); //remove useless ']'
						r["nameApp"] = *i;						  //we get the name of the apk 
					}
				}
			}
			else if(line.find("userId=")!=std::string::npos)	
				r["userIdApp"] = line.substr(11);				//we get the userId
			else if(line.find("codePath")!=std::string::npos)	
				r["codePathApp"] = line.substr(13);				//we get the app path
			else if(line.find("dataDir")!=std::string::npos)	
				r["dataDirApp"] = line.substr(10);				//...
			else if(line.find("firstInstallTime")!=std::string::npos)	
				r["firstInstallTime"] = line.substr(21);			//...
			else if(line.find("lastUpdateTime")!=std::string::npos)		
				r["lastUpdateTime"] = line.substr(19);				//...
			else if(line.find("apkSigningVersion=")!=std::string::npos)
				r["sigVersion"] = line.substr(22);
			else if(line.find("android.permission.ACCEPT_HANDOVER")!=std::string::npos)	//Here are the dangerous permissions
				r["ACCEPT_HANDOVER"] = "True";	
			else if(line.find("android.pesmission.ACCESS_BACKGROUND_LOCATION")!=std::string::npos)	
				r["ACCESS_BACKGROUND_LOCATION"] = "True";
			else if(line.find("android.permission.ACCESS_COARSE_LOCATION")!=std::string::npos)	
				r["ACCESS_COARSE_LOCATION"] = "True";
			else if(line.find("android.permission.ACCESS_FINE_LOCATION")!=std::string::npos)	
				r["ACCESS_FINE_LOCATION"] = "True";
			else if(line.find("android.permission.ACCESS_MEDIA_LOCATION")!=std::string::npos)	
				r["ACCESS_MEDIA_LOCATION"] = "True";
			else if(line.find("android.permission.ACTIVITY_RECOGNITION")!=std::string::npos)	
				r["ACTIVITY_RECOGNITION"] = "True";
			else if(line.find("android.permission.ANSWER_PHONE_CALLS")!=std::string::npos)	
				r["ANSWER_PHONE_CALLS"] = "True";
			else if(line.find("android.permission.BLUETOOTH_ADVERTISE")!=std::string::npos)	
				r["BLUETOOTH_ADVERTISE"] = "True";
			else if(line.find("android.permission.BLUETOOTH_CONNECT")!=std::string::npos)	
				r["BLUETOOTH_CONNECT"] = "True";
			else if(line.find("android.permission.BLUETOOTH_SCAN")!=std::string::npos)	
				r["BLUETOOTH_SCAN"] = "True";
			else if(line.find("android.permission.BODY_SENSORS")!=std::string::npos)	
				r["BODY_SENSORS"] = "True";	
			else if(line.find("android.permission.CALL_PHONE")!=std::string::npos)	
				r["CALL_PHONE"] = "True";
			else if(line.find("android.permission.CAMERA")!=std::string::npos)	
				r["CAMERA"] = "True";
			else if(line.find("android.permission.GET_ACCOUNTS")!=std::string::npos)	
				r["GET_ACCOUNTS"] = "True";
			else if(line.find("android.permission.PROCESS_OUTGOING_CALLS")!=std::string::npos)	
				r["PROCESS_OUTGOING_CALLS"] = "True";
			else if(line.find("android.permission.READ_CALENDAR")!=std::string::npos)	
				r["READ_CALENDAR"] = "True";
			else if(line.find("android.permission.READ_CALL_LOG")!=std::string::npos)	
				r["READ_CALL_LOG"] = "True";
			else if(line.find("android.permission.READ_CONTACTS")!=std::string::npos)	
				r["READ_CONTACTS"] = "True";
			else if(line.find("android.permission.READ_EXTERNAL_STORAGE")!=std::string::npos)	
				r["READ_EXTERNAL_STORAGE"] = "True";
			else if(line.find("android.permission.READ_PHONE_NUMBERS")!=std::string::npos)	
				r["READ_PHONE_NUMBERS"] = "True";
			else if(line.find("android.permission.READ_PHONE_STATE")!=std::string::npos)	
				r["READ_PHONE_STATE"] = "True";	
			else if(line.find("android.permission.READ_SMS")!=std::string::npos)	
				r["READ_SMS"] = "True";
			else if(line.find("android.permission.RECEIVE_MMS")!=std::string::npos)	
				r["RECEIVE_MMS"] = "True";
			else if(line.find("android.permission.RECEIVE_SMS")!=std::string::npos)	
				r["RECEIVE_SMS"] = "True";
			else if(line.find("android.permission.RECEIVE_WAP_PUSH")!=std::string::npos)	
				r["RECEIVE_WAP_PUSH"] = "True";
			else if(line.find("android.permission.RECORD_AUDIO")!=std::string::npos)	
				r["RECORD_AUDIO"] = "True";
			else if(line.find("android.permission.SEND_SMS")!=std::string::npos)	
				r["SEND_SMS"] = "True";
			else if(line.find("android.permission.USE_SIP")!=std::string::npos)	
				r["USE_SIP"] = "True";
			else if(line.find("android.permission.UWB_RANGING")!=std::string::npos)	
				r["UWB_RANGING"] = "True";
			else if(line.find("android.permission.VIBRATE")!=std::string::npos)	
				r["VIBRATE"] = "True";
			else if(line.find("android.permission.WRITE_CALENDAR")!=std::string::npos)	
				r["WRITE_CALENDAR"] = "True";
			else if(line.find("android.permission.WRITE_CALL_LOG")!=std::string::npos)	
				r["WRITE_CALL_LOG"] = "True";
			else if(line.find("android.permission.WRITE_CONTACTS")!=std::string::npos)	
				r["WRITE_CONTACTS"] = "True";
			else if(line.find("android.permission.WRITE_EXTERNAL_STORAGE")!=std::string::npos)	
				r["WRITE_EXTERNAL_STORAGE"] = "True";
			else if(line.find("android.permission.WAKE_LOCK")!=std::string::npos)		//we add more permissions, not dangerous for the 
				r["WAKE_LOCK"] = "True";						//system but interesting for analisys
			else if(line.find("android.permission.SYSTEM_ALERT_WINDOW")!=std::string::npos)	
				r["SYSTEM_ALERT_WINDOW"] = "True";
			else if(line.find("android.permission.FOREGROUND")!=std::string::npos)	
				r["FOREGROUND"] = "True";
			else if(line.find("android.permission.RECEIVE_BOOT_COMPLETED")!=std::string::npos)	
				r["BOOT_COMPLETED"] = "True";
			else if(line.find("User 0:")!=std::string::npos)
				results.push_back(std::move(r));			//finaly we push the values into the table
			}
		}
	ReadFile.close();
	return Status::success();
}

QueryData genAndroidDumpsysApp(QueryContext& context) {
    QueryData results;
    	Row r;
    
    	auto s = genPackageDumpsysApp(r, results);
	if (!s.ok()) {
      	VLOG(1) << "Fail " << s.getMessage();
    	}
    	results.push_back(r);
  return results;
}
}
}
