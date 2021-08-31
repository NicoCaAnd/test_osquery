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


void split(const string &inputString, const char delimit, vector<string> &elements)
{
	stringstream ss(inputString);
	string subString;
	while(getline(ss, subString, delimit))
	{
			elements.push_back(subString);
	}
}

Status genPackage(Row& r, QueryData& results) 
   {
   	//int fd;
	pid_t pid = fork();
	std::string buff = "";
	if(pid == 0)
	{
		FILE *out = freopen("/data/local/tmp/logDump","w",stdout);	//redirection of stdout to a log file
		if (!out)
			fprintf(stderr,"ERROR freopen: %s", strerror(errno));
		stdout = out;	
		if(system("dumpsys telephony.registry")!=0)			//calling dumpsys with option
		{
			fprintf(stderr,"Error while exec() : %s\n", strerror(errno));
		}
	}
	wait(0);
	std::ifstream ReadFile("/data/local/tmp/logDump");
	if(ReadFile)
	{
		std::string line;
		boost::trim(line);
		while(std::getline(ReadFile, line))
		{
			std::size_t found = line.find("cellIdentity");
			if(found!=std::string::npos)
			{
				vector<string> vectLine;
				split(line, ' ', vectLine);
				results.push_back(std::move(r));
					
				for(auto i=vectLine.begin();i!=vectLine.end();i++) 
				{
					if((*i).find("2021-")!=std::string::npos)
						
						r["timeBalise"] = *i;				//Getting GSM informations
					else if((*i).find("mLac")!=std::string::npos)
						{std::string mL = (*i).substr(5);
						r["mLac"] = mL;}
					else if((*i).find("mCid")!=std::string::npos)
						{std::string mC = (*i).substr(5);
						r["mCid"] = mC;}
					else if((*i).find("mMcc")!=std::string::npos)
						{std::string mMn = (*i).substr(5);
						r["mMcc"] = mMn;}
					else if((*i).find("mMnc")!=std::string::npos)
						{std::string mMc = (*i).substr(5);
						r["mMnc"] = mMc;}
					else if((*i).find("mPsc")!=std::string::npos)
						{std::string mP = (*i).substr(5);
						r["mPsc"] = mP;}
					else if((*i).find("mUarfcn")!=std::string::npos)
						{std::string mU = (*i).substr(8);
						r["mUarfcn"] = mU;}
					else if((*i).find("mAlphaLong")!=std::string::npos)
						{std::string mAlpL = (*i).substr(11);
						r["mAlphaLong"] = mAlpL;}
					else if((*i).find("mAlphaShort")!=std::string::npos)
						{std::string mAlpS = (*i).substr(12);
						r["mAlphaShort"] = mAlpS;}
					else{
						continue;			//Jump to the next BTS registration
						}
				}
			}
		}
	ReadFile.close();
    	}
	return Status::success();
}

QueryData genAndroidDumpsysGsm(QueryContext& context) {
    QueryData results;
    	Row r;
    
    	auto s = genPackage(r, results);
	if (!s.ok()) {
      	VLOG(1) << "Fail " << s.getMessage();
    	}
    	results.push_back(r);
  return results;
}
}
}
