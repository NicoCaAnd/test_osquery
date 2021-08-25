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

Status genPackage2(Row& r, QueryData& results) 
   {
   	int startPackage = 0;
	pid_t pid = fork();
	std::string buff = "";
	if(pid == 0)
	{
		FILE *out = freopen("/data/local/tmp/logDump","w",stdout);
		if (!out)
			fprintf(stderr,"ERROR freopen: %s", strerror(errno));
		stdout = out;	
		if(system("dumpsys package packages")!=0)
		{
			fprintf(stderr,"Error while exec() : %s\n", strerror(errno));
		}
	}
	wait(0);
	std::ifstream ReadFile("/data/local/tmp/logDump");
	if(ReadFile)
	{
		std::string line;
		//boost::trim(line);
		while(std::getline(ReadFile, line))
		{
			std::size_t found = line.find("Package [");
			if(found!=std::string::npos)
			{
				if(startPackage==1)
				{
					startPackage=0;
					results.push_back(std::move(r));
				}	
				startPackage = 1;
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
						(*i).erase(std::remove((*i).begin(),(*i).end(), '['),(*i).end());
						(*i).erase(std::remove((*i).begin(),(*i).end(), ']'),(*i).end());
						r["nameApp"] = *i;
					}
				}
			}
			else if(line.find("userId=")!=std::string::npos)	
				r["userIdApp"] = line.substr(11);	
			else if(line.find("codePath")!=std::string::npos)	
				r["codePathApp"] = line.substr(13);	
			else if(line.find("dataDir")!=std::string::npos)	
				r["dataDirApp"] = line.substr(10);	
			else if(line.find("firstInstallTime")!=std::string::npos)	
				r["firstInstallTime"] = line.substr(21);	
			else if(line.find("lastUpdateTime")!=std::string::npos)	
				r["lastUpdateTime"] = line.substr(19);
			else if(line.find("apkSigningVersion=")!=std::string::npos)
				r["sigVersion"] = line.substr(22);
                        else if((line.find(" android.permission.")!=std::string::npos)&&(line.find("granted=true")!=std::string::npos))
			{
				if(line.find("ACCEPT_HANDOVER")!=std::string::npos)	
					r["ACCEPT_HANDOVER"] = "True";	
				else if(line.find("ACCESS_BACKGROUND_LOCATION")!=std::string::npos)	
					r["ACCESS_BACKGROUND_LOCATION"] = "True";
				else if(line.find("ACCESS_COARSE_LOCATION")!=std::string::npos)	
					r["ACCESS_COARSE_LOCATION"] = "True";
				else if(line.find("ACCESS_FINE_LOCATION")!=std::string::npos)	
					r["ACCESS_FINE_LOCATION"] = "True";
				else if(line.find("ACCESS_MEDIA_LOCATION")!=std::string::npos)	
					r["ACCESS_MEDIA_LOCATION"] = "True";
				else if(line.find("ACTIVITY_RECOGNITION")!=std::string::npos)	
					r["ACTIVITY_RECOGNITION"] = "True";
				else if(line.find("ANSWER_PHONE_CALLS")!=std::string::npos)	
					r["ANSWER_PHONE_CALLS"] = "True";
				else if(line.find("BLUETOOTH_ADVERTISE")!=std::string::npos)	
					r["BLUETOOTH_ADVERTISE"] = "True";
				else if(line.find("BLUETOOTH_CONNECT")!=std::string::npos)	
					r["BLUETOOTH_CONNECT"] = "True";
				else if(line.find("BLUETOOTH_SCAN")!=std::string::npos)	
					r["BLUETOOTH_SCAN"] = "True";
				else if(line.find("BODY_SENSORS")!=std::string::npos)	
					r["BODY_SENSORS"] = "True";	
				else if(line.find("CALL_PHONE")!=std::string::npos)	
					r["CALL_PHONE"] = "True";
				else if(line.find("CAMERA")!=std::string::npos)	
					r["CAMERA"] = "True";
				else if(line.find("GET_ACCOUNTS")!=std::string::npos)	
					r["GET_ACCOUNTS"] = "True";
				else if(line.find("PROCESS_OUTGOING_CALLS")!=std::string::npos)	
					r["PROCESS_OUTGOING_CALLS"] = "True";
				else if(line.find("READ_CALENDAR")!=std::string::npos)	
					r["READ_CALENDAR"] = "True";
				else if(line.find("READ_CALL_LOG")!=std::string::npos)	
					r["READ_CALL_LOG"] = "True";
				else if(line.find("READ_CONTACTS")!=std::string::npos)	
					r["READ_CONTACTS"] = "True";
				else if(line.find("READ_EXTERNAL_STORAGE")!=std::string::npos)	
					r["READ_EXTERNAL_STORAGE"] = "True";
				else if(line.find("READ_PHONE_NUMBERS")!=std::string::npos)	
					r["READ_PHONE_NUMBERS"] = "True";
				else if(line.find("READ_PHONE_STATE")!=std::string::npos)	
					r["READ_PHONE_STATE"] = "True";	
				else if(line.find("READ_SMS")!=std::string::npos)	
					r["READ_SMS"] = "True";
				else if(line.find("RECEIVE_MMS")!=std::string::npos)	
					r["RECEIVE_MMS"] = "True";
				else if(line.find("RECEIVE_SMS")!=std::string::npos)	
					r["RECEIVE_SMS"] = "True";
				else if(line.find("RECEIVE_WAP_PUSH")!=std::string::npos)	
					r["RECEIVE_WAP_PUSH"] = "True";
				else if(line.find("RECORD_AUDIO")!=std::string::npos)	
					r["RECORD_AUDIO"] = "True";
				else if(line.find("SEND_SMS")!=std::string::npos)	
					r["SEND_SMS"] = "True";
				else if(line.find("USE_SIP")!=std::string::npos)	
					r["USE_SIP"] = "True";
				else if(line.find("UWB_RANGING")!=std::string::npos)	
					r["UWB_RANGING"] = "True";
				else if(line.find("VIBRATE")!=std::string::npos)	
					r["VIBRATE"] = "True";
				else if(line.find("WRITE_CALENDAR")!=std::string::npos)	
					r["WRITE_CALENDAR"] = "True";
				else if(line.find("RITE_CALL_LOG")!=std::string::npos)	
					r["WRITE_CALL_LOG"] = "True";
				else if(line.find("WRITE_CONTACTS")!=std::string::npos)	
					r["WRITE_CONTACTS"] = "True";
				else if(line.find("WRITE_EXTERNAL_STORAGE")!=std::string::npos)	
					r["WRITE_EXTERNAL_STORAGE"] = "True";
				else if(line.find("WAKE_LOCK")!=std::string::npos)	
					r["WAKE_LOCK"] = "True";
				else if(line.find("SYSTEM_ALERT_WINDOW")!=std::string::npos)	
					r["SYSTEM_ALERT_WINDOW"] = "True";
				else if(line.find("FOREGROUND")!=std::string::npos)	
					r["FOREGROUND"] = "True";
				else if(line.find("RECEIVE_BOOT_COMPLETED")!=std::string::npos)	
					r["BOOT_COMPLETED"] = "True";		
			}
		}
	}
	ReadFile.close();
	return Status::success();
}

QueryData genAndroidDumpsysApp(QueryContext& context) {
    QueryData results;
    	Row r;
    
    	auto s = genPackage2(r, results);
	if (!s.ok()) {
      	VLOG(1) << "Fail " << s.getMessage();
    	}
    	results.push_back(r);
  return results;
}
}
}
