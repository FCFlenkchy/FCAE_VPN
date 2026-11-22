#pragma once
#include <map>
#include <mutex>
#include <string>
namespace AppIconHints {
inline std::mutex mutex;
inline std::map<std::string,std::string> names;
inline void set(const std::string& path,const std::string& name){if(name.empty())return;std::lock_guard<std::mutex> lock(mutex);if(names.size()<8192)names[path]=name;}
inline std::string get(const std::string& path){std::lock_guard<std::mutex> lock(mutex);auto it=names.find(path);return it==names.end()?std::string{}:it->second;}
}
