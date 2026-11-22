#import <UIKit/UIKit.h>
#import <NetworkExtension/NetworkExtension.h>
#import "Config.h"
#include "Platform.h"
#include "ui_render.h"
#include <mutex>

static std::mutex telemetry_mutex;
static FcaeTelemetry telemetry{};
static std::string live_listeners, regions;
static NETunnelProviderManager* manager;
static NSUInteger generation;
static uint64_t last_log;
static CFAbsoluteTime last_state_sync;
static bool requesting;
static NSUInteger poll_sequence;
static void report(NSError* error) {
    if (!error) return;
    NSString* detail=error.localizedDescription;
    if ([error.domain hasPrefix:@"NEVPN"] || [error.domain hasPrefix:@"NEConfiguration"]) {
        detail=[detail stringByAppendingString:@" Verify that both the app and its tunnel extension were signed with profiles granting packet-tunnel-provider. Free Apple ID/SideStore signing cannot grant the VPN entitlement."];
    }
    const char* message=detail.UTF8String;
    g_app.add_log(FCAE_LOG_ERROR,message);
    { std::lock_guard<std::mutex> lock(telemetry_mutex);
      telemetry.state=FCAE_STATE_ERROR;
      snprintf(telemetry.last_error,sizeof(telemetry.last_error),"%s",message); }
    ui_request_redraw();
}
const std::string& ios_data_dir() {
    static const std::string directory=[] {
        NSURL* root=FCAEContainer();
        if (!root) return std::string();
        return std::string(root.path.UTF8String);
    }();
    return directory;
}
bool ios_open_url(const char* url) {
    NSString* text=[NSString stringWithUTF8String:url];
    dispatch_async(dispatch_get_main_queue(), ^{
        [UIApplication.sharedApplication openURL:[NSURL URLWithString:text] options:@{} completionHandler:nil];
    });
    return true;
}
@interface FCAEVPN : NSObject
+ (void)setup;
+ (void)poll;
@end
@implementation FCAEVPN
+ (void)setup {
    [NETunnelProviderManager loadAllFromPreferencesWithCompletionHandler:^(NSArray<NETunnelProviderManager*>* managers,NSError* error){
        dispatch_async(dispatch_get_main_queue(), ^{
            if (error) { report(error); return; }
            NSString* identifier=FCAETunnelIdentifier();
            if (!identifier) {report(FCAEError(@"The signed app has no unambiguous embedded Packet Tunnel extension."));return;}
            for (NETunnelProviderManager* candidate in managers) {
                NETunnelProviderProtocol* proto=(NETunnelProviderProtocol*)candidate.protocolConfiguration;
                if ([proto isKindOfClass:NETunnelProviderProtocol.class] && [proto.providerBundleIdentifier isEqualToString:identifier]) {manager=candidate;break;}
            }
            if (!manager) manager=[NETunnelProviderManager new];
        });
    }];
}
+ (void)poll {
    if (!manager || UIApplication.sharedApplication.applicationState!=UIApplicationStateActive) return;
    const NEVPNStatus status=manager.connection.status;
    if (status!=NEVPNStatusConnected && status!=NEVPNStatusReasserting) {
        {
            std::lock_guard<std::mutex> lock(telemetry_mutex);
            if (status==NEVPNStatusConnecting) telemetry.state=FCAE_STATE_CONNECTING;
            else if (!requesting && telemetry.state!=FCAE_STATE_ERROR) telemetry.state=FCAE_STATE_DISCONNECTED;
        }
        if (status==NEVPNStatusDisconnected && !requesting) {
            NSDictionary* failure=[NSDictionary dictionaryWithContentsOfURL:FCAEErrorURL()];
            if ([failure[@"message"] isKindOfClass:NSString.class]) {
                [NSFileManager.defaultManager removeItemAtURL:FCAEErrorURL() error:nullptr];
                report(FCAEError(failure[@"message"]));
            }
        }
        return;
    }
    if (requesting) return;
    requesting=true;
    const NSUInteger token=generation;
    const NSUInteger sequence=++poll_sequence;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,3*NSEC_PER_SEC),dispatch_get_main_queue(), ^{
        if (token==generation && sequence==poll_sequence) requesting=false;
    });
    NETunnelProviderSession* session=(NETunnelProviderSession*)manager.connection;
    NSError* error=nil;
    const bool sync_state=last_state_sync==0 || CFAbsoluteTimeGetCurrent()-last_state_sync>=30;
    NSString* cursor=[NSString stringWithFormat:@"%llu%@",(unsigned long long)last_log,sync_state?@":state":@""];
    [session sendProviderMessage:[cursor dataUsingEncoding:NSUTF8StringEncoding] returnError:&error responseHandler:^(NSData* data){
        dispatch_async(dispatch_get_main_queue(), ^{
            if (token!=generation || sequence!=poll_sequence) return;
            requesting=false;
            if (!data) return;
            NSDictionary* snapshot=[NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:nullptr error:nullptr];
            if (![snapshot isKindOfClass:NSDictionary.class] || [snapshot[@"abi"] unsignedIntValue]!=FCAE_ABI_VERSION) return;
            NSError* stateError=nil;
            if (!FCAEImportState(snapshot[@"state"],&stateError)) {report(stateError);return;}
            if (snapshot[@"state"]) last_state_sync=CFAbsoluteTimeGetCurrent();
            NSData* bytes=snapshot[@"telemetry"];
            if ([bytes isKindOfClass:NSData.class] && bytes.length==sizeof(FcaeTelemetry)) {
                std::lock_guard<std::mutex> lock(telemetry_mutex);
                memcpy(&telemetry,bytes.bytes,sizeof(telemetry));
                if ([snapshot[@"listeners"] isKindOfClass:NSString.class]) live_listeners=[snapshot[@"listeners"] UTF8String];
                if ([snapshot[@"regions"] isKindOfClass:NSString.class]) regions=[snapshot[@"regions"] UTF8String];
            }
            for (NSDictionary* entry in snapshot[@"logs"]) {
                uint64_t sequence=[entry[@"id"] unsignedLongLongValue];
                if (sequence>last_log) {last_log=sequence;g_app.add_log([entry[@"level"] intValue],[entry[@"text"] UTF8String]);}
            }
            ui_request_redraw();
        });
    }];
    if (error) {requesting=false;report(error);}
}
@end

void ios_vpn_poll() {
    static dispatch_once_t once;
    dispatch_once(&once, ^{ [FCAEVPN setup]; });
    [FCAEVPN poll];
}
FcaeStatus ios_start(const FcaeConfig* config) {
    if (!config) return FCAE_NULL_ARGUMENT;
    if (config->mode!=FCAE_MODE_TUN || config->tun_engine>FCAE_TUN_ENGINE_HEV) {
        report(FCAEError(@"iOS requires TUN mode with tun2socks, Zeptun or HEV; PROXY-only mode is not supported."));
        return FCAE_INVALID_CONFIG;
    }
    if (!FCAEContainer()) {report(FCAEError(@"Cannot open the app data directory."));return FCAE_PERMISSION_DENIED;}
    NSDictionary* payload=FCAEEncode(*config); // Deep copy before the UI worker's config expires.
    if (!payload) {report(FCAEError(@"Configuration text must be valid UTF-8."));return FCAE_INVALID_CONFIG;}
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!manager) {report(FCAEError(@"VPN preferences are still loading; please try again."));return;}
        if (manager.routingMethod==NETunnelProviderRoutingMethodSourceApplication) {
            report(FCAEError(@"This is an OS-configured per-app VPN. FCAE will not overwrite its managed configuration with a consumer session. Start or update it through the deployment's managed VPN workflow."));
            return;
        }
        const NSUInteger token=++generation;
        requesting=true;
        NSError* error=nil;
        [NSFileManager.defaultManager removeItemAtURL:FCAEErrorURL() error:nullptr];
        NSData* data=[NSPropertyListSerialization dataWithPropertyList:payload format:NSPropertyListBinaryFormat_v1_0 options:0 error:&error];
        if (!data || ![data writeToURL:FCAESessionURL() options:NSDataWritingAtomic|NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication error:&error]) {
            requesting=false;report(error ?: FCAEError(@"Cannot save VPN session."));return;
        }
        NETunnelProviderProtocol* proto=[NETunnelProviderProtocol new];
        proto.providerBundleIdentifier=FCAETunnelIdentifier();
        if (!proto.providerBundleIdentifier.length) {requesting=false;report(FCAEError(@"The embedded VPN extension is missing after re-signing."));return;}
        proto.providerConfiguration=@{@"session":payload};
        proto.serverAddress=@"FCAE VPN";
        manager.protocolConfiguration=proto;
        manager.localizedDescription=@"FCAE VPN";
        manager.enabled=YES;
        {std::lock_guard<std::mutex> lock(telemetry_mutex);telemetry={};telemetry.state=FCAE_STATE_CONNECTING;}
        [manager saveToPreferencesWithCompletionHandler:^(NSError* failure){
            dispatch_async(dispatch_get_main_queue(), ^{
                if (token!=generation) return;
                if (failure) {requesting=false;report(failure);return;}
                [manager loadFromPreferencesWithCompletionHandler:^(NSError* loadError){
                    dispatch_async(dispatch_get_main_queue(), ^{
                        if (token!=generation) return;
                        requesting=false;
                        if (loadError) {report(loadError);return;}
                        NSError* startError=nil;
                        last_log=0;last_state_sync=0;
                        [manager.connection startVPNTunnelAndReturnError:&startError];
                        report(startError);
                    });
                }];
            });
        }];
    });
    return FCAE_OK;
}
FcaeStatus ios_stop() {
    dispatch_async(dispatch_get_main_queue(), ^{++generation;requesting=false;[manager.connection stopVPNTunnel];});
    return FCAE_OK;
}
FcaeStatus ios_telemetry(FcaeTelemetry* out) {
    if (!out) return FCAE_NULL_ARGUMENT;
    std::lock_guard<std::mutex> lock(telemetry_mutex);
    *out=telemetry;out->struct_size=sizeof(*out);out->abi_version=FCAE_ABI_VERSION;
    return FCAE_OK;
}
bool ios_tun_paused() {return false;}
FcaeStatus ios_tun_control() {return FCAE_BACKEND_UNAVAILABLE;}

extern "C" uint32_t ios_live_listeners(char* out,uint32_t capacity) {
    std::lock_guard<std::mutex> lock(telemetry_mutex);
    const uint32_t size=(uint32_t)live_listeners.size();
    if (!out || capacity<=size) return size+1;
    memcpy(out,live_listeners.c_str(),size+1);return size;
}
uint32_t ios_regions(char* out,uint32_t capacity) {
    std::lock_guard<std::mutex> lock(telemetry_mutex);
    if (out && capacity) snprintf(out,capacity,"%s",regions.c_str());
    return (uint32_t)regions.size();
}
