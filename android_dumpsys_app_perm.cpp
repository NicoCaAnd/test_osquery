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

Status genPackageDumpAppPerm(Row& r, QueryData& results) 
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
			else if((line.find(" android.permission.")!=std::string::npos)&&(line.find("granted=true")!=std::string::npos))
			{
				vector<string> vectLine2;
				stringstream ss2(line);
				string subString2;
				while(getline(ss2, subString2, ' '))
				{
					vectLine2.push_back(subString2);
				}
				for(auto i=vectLine2.begin();i!=vectLine2.end();i++)
				{
					if((*i).find("android.permission")!=std::string::npos)
					{	
						(*i).erase(std::remove((*i).begin(),(*i).end(), ':'),(*i).end());	
						r["permsApp"] += (*i).substr(19)+'\n';
					}
				}
			}
		}
	}
	ReadFile.close();
	return Status::success();
}

QueryData genAndroidDumpsysAppPerm(QueryContext& context) {
    QueryData results;
    	Row r;
    
    	auto s = genPackageDumpAppPerm(r, results);
	if (!s.ok()) {
      	VLOG(1) << "Fail " << s.getMessage();
    	}
    	results.push_back(r);
  return results;
}
}
}
