#pragma once
#include "app_icon_hints.h"

// Read-only process inventory. Discovering an executable is NOT routing or
// authorizing it; enforcement providers must resolve identities independently.
#include <algorithm>
#include <atomic>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <sstream>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <shobjidl.h>
#elif defined(__linux__) && !defined(ANDROID)
#include <filesystem>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#elif defined(__APPLE__) && !defined(FCAE_IOS) && !defined(__IPHONE_OS_VERSION_MIN_REQUIRED)
#include <libproc.h>
#include <CoreFoundation/CoreFoundation.h>
#endif

namespace AppRouting {
inline std::string search_key(std::string text) {
    // Preserve UTF-8 bytes. Non-ASCII text still matches literally; Android's
    // adapter retains its existing Locale.ROOT Unicode folding implementation.
    for (char& c : text) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
    return text;
}
struct InventoryEntry { std::string id, label, search; };
struct InventoryResult { std::vector<InventoryEntry> entries; std::string status; };

// Installed entries are discovery hints, never privileged launch instructions.
// Never execute desktop-file Exec lines or resolve shell links through a UI prompt.
inline std::string path_utf8(const std::filesystem::path& path) { return path.u8string(); }
inline void installed_applications(const std::atomic<bool>& cancelled,
                                  const std::function<void(std::string,std::string)>& add) {
    std::vector<std::filesystem::path> roots;
#if defined(_WIN32)
    const HRESULT initialized=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    if (FAILED(initialized)) return;
    struct Uninit {~Uninit(){CoUninitialize();}} uninit;
    for (const KNOWNFOLDERID* id : {&FOLDERID_StartMenu,&FOLDERID_CommonStartMenu}) {
        PWSTR path=nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(*id,KF_FLAG_DONT_VERIFY,nullptr,&path))) {roots.emplace_back(path);CoTaskMemFree(path);}
    }
#elif defined(__linux__) && !defined(ANDROID)
    if (const char* home=std::getenv("HOME")) roots.emplace_back(std::filesystem::path(home)/".local/share/applications");
    if (const char* data=std::getenv("XDG_DATA_HOME")) if (*data=='/') roots.emplace_back(std::filesystem::path(data)/"applications");
    std::string dirs=std::getenv("XDG_DATA_DIRS")?std::getenv("XDG_DATA_DIRS"):"/usr/local/share:/usr/share";
    std::stringstream split(dirs);std::string dir;
    while(std::getline(split,dir,':')) if (!dir.empty()&&dir.front()=='/') roots.emplace_back(std::filesystem::path(dir)/"applications");
    roots.emplace_back("/var/lib/flatpak/exports/share/applications");
    roots.emplace_back("/var/lib/snapd/desktop/applications");
#elif defined(__APPLE__) && !defined(FCAE_IOS) && !defined(__IPHONE_OS_VERSION_MIN_REQUIRED)
    roots.emplace_back("/Applications");roots.emplace_back("/System/Applications");
    if(const char* home=std::getenv("HOME")) roots.emplace_back(std::filesystem::path(home)/"Applications");
#else
    (void)cancelled;(void)add;
    return;
#endif
    size_t visited=0;
    for(const auto& root:roots) {
        std::error_code error;
        std::filesystem::recursive_directory_iterator it(root,std::filesystem::directory_options::skip_permission_denied,error),end;
        while(!error && it!=end && visited++<16384 && !cancelled.load()) {
            auto path=it->path();
            if(it.depth()>5)it.disable_recursion_pending();
#if defined(_WIN32)
            if(search_key(path.extension().u8string())==".lnk") {
                IShellLinkW* link=nullptr;
                if(SUCCEEDED(CoCreateInstance(CLSID_ShellLink,nullptr,CLSCTX_INPROC_SERVER,IID_IShellLinkW,reinterpret_cast<void**>(&link)))) {
                    IPersistFile* file=nullptr;
                    if(SUCCEEDED(link->QueryInterface(IID_IPersistFile,reinterpret_cast<void**>(&file)))) {
                        if(SUCCEEDED(file->Load(path.c_str(),STGM_READ))) {
                            wchar_t target[32768]{};
                            if(SUCCEEDED(link->GetPath(target,32768,nullptr,SLGP_RAWPATH)) && *target) {
                                std::filesystem::path executable(target);
                                if(executable.is_absolute() && search_key(executable.extension().u8string())==".exe")add(path_utf8(executable),path_utf8(path.stem()));
                            }
                        }
                        file->Release();
                    }
                    link->Release();
                }
            }
#elif defined(__linux__) && !defined(ANDROID)
            if(path.extension()==".desktop") {
                // Elevated discovery must not follow an attacker-supplied link
                // into a device/FIFO, or block forever while shutdown joins us.
                std::string contents;
                const int fd=open(path.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
                if(fd>=0) {
                    struct stat st{};
                    if(fstat(fd,&st)==0&&S_ISREG(st.st_mode)&&st.st_size>=0&&st.st_size<=65536) {
                        char buffer[4096];ssize_t read_bytes;
                        while(contents.size()<65536&&!cancelled.load()&&(read_bytes=read(fd,buffer,sizeof(buffer)))>0)
                            contents.append(buffer,static_cast<size_t>(read_bytes));
                    }
                    close(fd);
                }
                std::istringstream input(contents);std::string line,name,exec,icon;bool group=false,hidden=false;size_t bytes=0;
                while(std::getline(input,line)&& (bytes+=line.size())<65536) {
                    if(!line.empty()&&line.back()=='\r')line.pop_back();
                    if(!line.empty()&&line.front()=='['){group=line=="[Desktop Entry]";continue;}
                    if(!group)continue;
                    if(line.rfind("Name=",0)==0)name=line.substr(5);
                    if(line.rfind("Exec=",0)==0)exec=line.substr(5);
                    if(line.rfind("Icon=",0)==0)icon=line.substr(5);
                    if(line=="Hidden=true" || line=="NoDisplay=true")hidden=true;
                }
                if(!hidden&&!exec.empty()) {
                    // A deliberately small parser for the executable token only.
                    // Flatpak/Snap/env wrappers require explicit process/helper selection.
                    std::string token;bool quoted=false,escape=false;
                    for(char c:exec) {
                        if(escape){token+=c;escape=false;continue;}
                        if(c=='\\'){escape=true;continue;}
                        if(c=='"'){quoted=!quoted;continue;}
                        if(!quoted&&(c==' '||c=='\t'))break;
                        token+=c;
                    }
                    if(!quoted&&!escape&&!token.empty()&&token.find('%')==std::string::npos) {
                        std::filesystem::path executable(token);
                        const auto base=executable.filename().string();
                        if(base!="flatpak"&&base!="snap"&&base!="env"&&base!="sh"&&base!="bash") {
                            if(!executable.is_absolute()) {
                                std::stringstream paths(std::getenv("PATH")?std::getenv("PATH"):"/usr/local/bin:/usr/bin:/bin");std::string directory;
                                while(std::getline(paths,directory,':')) {
                                    if(directory.empty()||directory.front()!='/')continue;
                                    auto candidate=std::filesystem::path(directory)/executable;
                                    if(std::filesystem::is_regular_file(candidate,error)){executable=candidate;break;}error.clear();
                                }
                            }
                            if(executable.is_absolute()){AppIconHints::set(path_utf8(executable),icon);add(path_utf8(executable),name.empty()?path_utf8(path.stem()):name);}
                        }
                    }
                }
            }
#elif defined(__APPLE__) && !defined(FCAE_IOS) && !defined(__IPHONE_OS_VERSION_MIN_REQUIRED)
            if(path.extension()==".app") {
                it.disable_recursion_pending();
                const auto text=path_utf8(path);
                CFURLRef url=CFURLCreateFromFileSystemRepresentation(nullptr,reinterpret_cast<const UInt8*>(text.data()),text.size(),true);
                CFBundleRef bundle=url?CFBundleCreate(nullptr,url):nullptr;
                if(bundle) {
                    CFURLRef executable=CFBundleCopyExecutableURL(bundle);
                    UInt8 bytes[32768]{};
                    if(executable&&CFURLGetFileSystemRepresentation(executable,true,bytes,sizeof(bytes)))add(reinterpret_cast<char*>(bytes),path_utf8(path.stem()));
                    if(executable)CFRelease(executable);
                    CFRelease(bundle);
                }
                if(url)CFRelease(url);
            }
#endif
            error.clear();it.increment(error);
        }
    }
}

inline InventoryResult running_applications(const std::atomic<bool>& cancelled) {
    constexpr size_t limit = 8192;
    InventoryResult result;
    std::map<std::string, InventoryEntry> unique;
    size_t inspected = 0;
    auto add = [&](std::string path) {
        if (path.empty() || path.size() > 32768) return;
        const auto slash = path.find_last_of("/\\");
        const std::string label = path.substr(slash == std::string::npos ? 0 : slash + 1);
        if (label.empty()) return;
        std::string key = path;
#if defined(_WIN32)
        key = search_key(key);
#endif
        unique.emplace(key, InventoryEntry{path, label, search_key(label + "\n" + path)});
    };
#if defined(_WIN32)
    struct Handle {
        HANDLE value;
        ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    };
    Handle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};
    if (snapshot.value == INVALID_HANDLE_VALUE) {
        result.status = "Windows could not enumerate processes. No routing changes were made.";
        return result;
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    for (BOOL ok = Process32FirstW(snapshot.value, &entry); ok && inspected++ < limit && !cancelled.load();
         ok = Process32NextW(snapshot.value, &entry)) {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID);
        if (!process) continue;
        wchar_t path[32768];
        DWORD size = 32768;
        const BOOL found = QueryFullProcessImageNameW(process, 0, path, &size);
        CloseHandle(process);
        if (!found) continue;
        const int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path, static_cast<int>(size), nullptr, 0, nullptr, nullptr);
        if (bytes <= 0) continue;
        std::string utf8(static_cast<size_t>(bytes), '\0');
        if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path, static_cast<int>(size), &utf8[0], bytes, nullptr, nullptr) == bytes)
            add(std::move(utf8));
    }
#elif defined(__linux__) && !defined(ANDROID)
    std::error_code error;
    std::filesystem::directory_iterator it("/proc", error), end;
    if (error) {
        result.status = "Cannot read /proc. No routing changes were made.";
        return result;
    }
    while (it != end && inspected++ < limit && !cancelled.load()) {
        const auto name = it->path().filename().string();
        if (!name.empty() && name.find_first_not_of("0123456789") == std::string::npos) {
            const auto path = std::filesystem::read_symlink(it->path() / "exe", error);
            if (!error) add(path.string());
        }
        error.clear();
        it.increment(error);
        if (error) break; // Permission/race failures never become a render-loop retry.
    }
#elif defined(__APPLE__) && !defined(FCAE_IOS) && !defined(__IPHONE_OS_VERSION_MIN_REQUIRED)
    const int bytes = proc_listpids(PROC_ALL_PIDS, 0, nullptr, 0);
    if (bytes <= 0) {
        result.status = "macOS could not enumerate processes. No routing changes were made.";
        return result;
    }
    std::vector<pid_t> pids(std::min(limit, static_cast<size_t>(bytes) / sizeof(pid_t) + 64));
    const int received = proc_listpids(PROC_ALL_PIDS, 0, pids.data(), static_cast<int>(pids.size() * sizeof(pid_t)));
    const size_t count = received > 0 ? std::min(pids.size(), static_cast<size_t>(received) / sizeof(pid_t)) : 0;
    for (size_t i = 0; i < count && !cancelled.load(); ++i) {
        ++inspected;
        if (pids[i] <= 0) continue;
        char path[PROC_PIDPATHINFO_MAXSIZE]{};
        if (proc_pidpath(pids[i], path, sizeof(path)) > 0) add(path);
    }
#else
    result.status = "Application enumeration is not available on this platform.";
    return result;
#endif
    installed_applications(cancelled,[&](std::string path,std::string label) {
        add(path);
        std::string key=path;
#if defined(_WIN32)
        key=search_key(key);
#endif
        auto found=unique.find(key);
        if(found!=unique.end()&&!label.empty()) {
            found->second.label=std::move(label);
            found->second.search=search_key(found->second.label+"\n"+path);
        }
    });
    for (auto& entry : unique) result.entries.push_back(std::move(entry.second));
    std::sort(result.entries.begin(), result.entries.end(), [](const InventoryEntry& a, const InventoryEntry& b) {
        const auto ka = search_key(a.label), kb = search_key(b.label);
        return ka == kb ? a.id < b.id : ka < kb;
    });
    result.status.clear();
    if (inspected >= limit) result.status = "Application list limit reached.";
    return result;
}

// One owned worker; no detached callbacks into a destroyed ImGui context.
// Destruction cancels the bounded scan and joins before UI shutdown continues.
class InventoryJob {
public:
    explicit InventoryJob(std::function<void()> wake) : wake_(std::move(wake)) {}
    ~InventoryJob() { cancelled_.store(true); if (worker_.joinable()) worker_.join(); }
    bool start() {
        if (worker_.joinable()) return false;
        cancelled_.store(false);
        done_.store(false);
        try { worker_ = std::thread([this] {
            InventoryResult value;
            try { value = running_applications(cancelled_); }
            catch (...) { value.status = "Application inventory failed. No routing changes were made."; }
            { std::lock_guard<std::mutex> lock(mutex_); result_ = std::move(value); }
            done_.store(true, std::memory_order_release);
            if (!cancelled_.load() && wake_) wake_();
        }); } catch (...) {
            result_ = {{}, "Could not start the application inventory worker. No routing changes were made."};
            done_.store(true, std::memory_order_release);
        }
        return true;
    }
    bool poll(InventoryResult& value) {
        if (!done_.load(std::memory_order_acquire)) return false;
        if (worker_.joinable()) worker_.join();
        { std::lock_guard<std::mutex> lock(mutex_); value = std::move(result_); }
        done_.store(false);
        return true;
    }
private:
    std::function<void()> wake_;
    std::thread worker_;
    std::mutex mutex_;
    std::atomic<bool> cancelled_{false}, done_{false};
    InventoryResult result_;
};
} // namespace AppRouting
