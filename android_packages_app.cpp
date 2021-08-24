/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/filesystem.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <tuple>
#include <osquery/filesystem/filesystem.h>
#include <boost/foreach.hpp>
#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/process/process.h>
#include <iostream>
#include <bitset>
#include <sstream>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;
using boost::property_tree::ptree;
namespace osquery {
namespace tables {

Status genPackage(const fs::path& nuspec, Row& r, QueryData& results) {
    pt::ptree propTree;
    std::string content;
    if (!readFile(nuspec, content).ok()) {
      return Status(1, "Failed to read nuspec:" + nuspec.string());
    }
    std::stringstream ss;
    ss << content;
    try {
      read_xml(ss, propTree);
    } catch (const pt::xml_parser::xml_parser_error& /* e */) {
      return Status(1, "Failed to parse nuspec xml");
    }
    
    BOOST_FOREACH(ptree::value_type const& topNodeChild, propTree.get_child( "packages" )) 
    { 
    	ptree subtree = topNodeChild.second;
	std::string installHex;
	if( topNodeChild.first == "package")
	{
		r["nameApp"] = subtree.get<std::string>("<xmlattr>.name"); 
		r["codePathApp"] = subtree.get<std::string>("<xmlattr>.codePath");
		try{r["userIdApp"] = subtree.get<std::string>("<xmlattr>.userId");
		}catch (const std::exception& ex) {}
		try{r["sharedUserIdApp"] = subtree.get<std::string>("<xmlattr>.sharedUserId");
    		}catch (const std::exception& ex) {}
		try{r["installDate"] = subtree.get<std::string>("<xmlattr>.it");
    		}catch (const std::exception& ex) {}
		try{r["lastUpDate"] = subtree.get<std::string>("<xmlattr>.ut");
    		}catch (const std::exception& ex) {}

	results.push_back(std::move(r));
	}
    }
    	return Status::success();
}

QueryData genAndroidPackagesApp(QueryContext& context) {
    QueryData results;

    auto nuspecPattern = "/data/system/packages.xml";
 
    std::vector<std::string> manifests;
    resolveFilePattern(nuspecPattern, manifests, GLOB_FILES);

  	for (const auto& pkg : manifests) {
    		Row r;
    		auto s = genPackage(pkg, r, results);
    		if (!s.ok()) {
      		VLOG(1) << "Failed to parse " << pkg << " with " << s.getMessage();
    	}
    	results.push_back(r);
  	}
  return results;
}
}
}
