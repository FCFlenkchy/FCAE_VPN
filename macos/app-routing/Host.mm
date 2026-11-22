#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import <Security/Security.h>
#include "fcae.h"
#include <mutex>

static NSString* const FCProviderID=@"com.fc.fcaevpn.app-routing";
static NETransparentProxyManager* manager;
static NSString* ownerID;
static dispatch_queue_t controlQueue;
static std::mutex operation;

@interface FCOperation : NSObject
@property(strong) dispatch_semaphore_t semaphore;
@property(copy) NSString* message;
@property BOOL success;
@property(atomic) BOOL cancelled;
@property BOOL completed;
@property(strong) NSNumber* revision;
@end
@implementation FCOperation
- (instancetype)init{if((self=[super init])){_semaphore=dispatch_semaphore_create(0);_message=@"NetworkExtension did not complete the request";}return self;}
@end
static void FCComplete(FCOperation* op,BOOL success,NSString* message){
    if(op.completed)return;op.completed=YES;op.success=success;op.message=message;dispatch_semaphore_signal(op.semaphore);
}
static NSString* FCRequirement(NSString* path){
    SecStaticCodeRef code=nullptr;SecRequirementRef requirement=nullptr;CFStringRef text=nullptr;
    OSStatus status=SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:path],kSecCSDefaultFlags,&code);
    if(status==errSecSuccess)status=SecStaticCodeCheckValidity(code,kSecCSCheckAllArchitectures,nullptr);
    if(status==errSecSuccess)status=SecCodeCopyDesignatedRequirement(code,kSecCSDefaultFlags,&requirement);
    if(status==errSecSuccess)status=SecRequirementCopyString(requirement,kSecCSDefaultFlags,&text);
    if(requirement)CFRelease(requirement);if(code)CFRelease(code);
    if(status!=errSecSuccess){if(text)CFRelease(text);return nil;}
    return CFBridgingRelease(text);
}
static NSDictionary* FCSigningInfo(NSURL* url){
    SecStaticCodeRef code=nullptr;CFDictionaryRef info=nullptr;
    OSStatus status=SecStaticCodeCreateWithPath((__bridge CFURLRef)url,kSecCSDefaultFlags,&code);
    if(status==errSecSuccess)status=SecStaticCodeCheckValidity(code,kSecCSCheckAllArchitectures,nullptr);
    if(status==errSecSuccess)status=SecCodeCopySigningInformation(code,kSecCSSigningInformation,&info);
    if(code)CFRelease(code);if(status!=errSecSuccess){if(info)CFRelease(info);return nil;}return CFBridgingRelease(info);
}
static BOOL FCEntitled(NSDictionary* info){
    NSDictionary* entitlements=info[(__bridge NSString*)kSecCodeInfoEntitlementsDict];
    NSArray* values=entitlements[@"com.apple.developer.networking.networkextension"];
    return [values isKindOfClass:NSArray.class]&&[values containsObject:@"app-proxy-provider"];
}
static BOOL FCPreflight(){
    NSBundle* app=NSBundle.mainBundle;
    NSURL* extension=[app.builtInPlugInsURL URLByAppendingPathComponent:@"FCAEAppRouting.appex"];
    NSBundle* bundle=[NSBundle bundleWithURL:extension];
    if(![bundle.bundleIdentifier isEqual:FCProviderID])return NO;
    NSDictionary* host=FCSigningInfo(app.bundleURL);NSDictionary* child=FCSigningInfo(extension);
    NSString* team=host[(__bridge NSString*)kSecCodeInfoTeamIdentifier];
    // A valid signature alone is not proof that Apple granted the entitlement.
    // Provisioning/OS activation remains an independent, fallible start gate.
    return FCEntitled(host)&&FCEntitled(child)&&[team isKindOfClass:NSString.class]&&team.length&&[team isEqual:child[(__bridge NSString*)kSecCodeInfoTeamIdentifier]];
}
static BOOL FCOwned(NETransparentProxyManager* candidate){
    NETunnelProviderProtocol* proto=(NETunnelProviderProtocol*)candidate.protocolConfiguration;
    return [proto isKindOfClass:NETunnelProviderProtocol.class]&&[proto.providerBundleIdentifier isEqual:FCProviderID]&&[proto.providerConfiguration[@"schema"] isEqual:@1];
}
static void FCHeartbeat(FCOperation* op){
    if(op.cancelled){FCComplete(op,NO,@"App-routing request cancelled");return;}
    if(!manager||!FCOwned(manager)||![((NETunnelProviderProtocol*)manager.protocolConfiguration).providerConfiguration[@"owner"] isEqual:ownerID]){FCComplete(op,NO,@"No app-routing configuration is owned by this FCAE process");return;}
    if(manager.connection.status!=NEVPNStatusConnected){FCComplete(op,NO,@"The signed transparent-proxy provider is not connected");return;}
    NSData* request=[NSJSONSerialization dataWithJSONObject:@{@"schema":@1,@"revision":op.revision,@"owner":ownerID} options:0 error:nullptr];
    NSError* error=nil;
    [(NETunnelProviderSession*)manager.connection sendProviderMessage:request returnError:&error responseHandler:^(NSData* data){dispatch_async(controlQueue,^{
        if(op.cancelled){FCComplete(op,NO,@"App-routing status timed out");return;}
        NSDictionary* status=data.length<=4096?[NSJSONSerialization JSONObjectWithData:data options:0 error:nullptr]:nil;
        BOOL active=[status isKindOfClass:NSDictionary.class]&&[status[@"schema"] isEqual:@1]&&[status[@"revision"] isEqual:op.revision]&&[status[@"active"] isEqual:@YES];
        FCComplete(op,active,active?@"Signed transparent-proxy policy acknowledged":@"The extension did not acknowledge the requested policy revision");
    });}];
    if(error)FCComplete(op,NO,error.localizedDescription);
}
static void FCWaitStatus(FCOperation* op,BOOL stopped,NSUInteger attempts){
    if(op.cancelled){if(manager&&FCOwned(manager)&&[(((NETunnelProviderProtocol*)manager.protocolConfiguration).providerConfiguration)[@"owner"] isEqual:ownerID])[manager.connection stopVPNTunnel];FCComplete(op,NO,@"NetworkExtension activation timed out and was cancelled");return;}
    const NEVPNStatus status=manager.connection.status;
    if(stopped&&(status==NEVPNStatusDisconnected||status==NEVPNStatusInvalid)){FCComplete(op,YES,@"Transparent-proxy capture withdrawn");return;}
    if(!stopped&&status==NEVPNStatusConnected){FCHeartbeat(op);return;}
    if(!attempts){[manager.connection stopVPNTunnel];FCComplete(op,NO,@"NetworkExtension did not reach the required state; verify signing, provisioning and user approval");return;}
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,NSEC_PER_SEC/4),controlQueue,^{FCWaitStatus(op,stopped,attempts-1);});
}
static bool FCControl(const char* input,char* output,uint32_t capacity,void*){
    if(!input||!output||!capacity)return false;
    std::lock_guard<std::mutex> guard(operation);
    @autoreleasepool {
        NSString* text=[NSString stringWithUTF8String:input];NSData* bytes=[text dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary* request=bytes.length<=1048576?[NSJSONSerialization JSONObjectWithData:bytes options:0 error:nullptr]:nil;
        if(![request isKindOfClass:NSDictionary.class]||![request[@"schema"] isEqual:@1]||![request[@"revision"] isKindOfClass:NSNumber.class]){snprintf(output,capacity,"Invalid app-routing control request");return false;}
        FCOperation* op=[FCOperation new];op.revision=request[@"revision"];NSString* action=request[@"action"];
        if([action isEqual:@"status"])dispatch_async(controlQueue,^{FCHeartbeat(op);});
        else if([action isEqual:@"stop"])dispatch_async(controlQueue,^{
            if(!manager){FCComplete(op,YES,@"No transparent-proxy session is owned by this process");return;}
            NETunnelProviderProtocol* proto=(NETunnelProviderProtocol*)manager.protocolConfiguration;
            if(!FCOwned(manager)||![proto.providerConfiguration[@"owner"] isEqual:ownerID]||![proto.providerConfiguration[@"revision"] isEqual:op.revision]){FCComplete(op,NO,@"Refusing to stop a foreign app-routing session");return;}
            [manager.connection stopVPNTunnel];FCWaitStatus(op,YES,40);
        });
        else if([action isEqual:@"remove"])dispatch_async(controlQueue,^{
            [NETransparentProxyManager loadAllFromPreferencesWithCompletionHandler:^(NSArray<NETransparentProxyManager*>* entries,NSError* error){dispatch_async(controlQueue,^{
                if(error||op.cancelled){FCComplete(op,NO,error.localizedDescription?:@"Removal cancelled");return;}
                NETransparentProxyManager* candidate=nil;
                for(NETransparentProxyManager* entry in entries)if(FCOwned(entry)){if(candidate){FCComplete(op,NO,@"Multiple owned configurations exist; refusing ambiguous removal");return;}candidate=entry;}
                if(!candidate){FCComplete(op,YES,@"No FCAE transparent-proxy configuration remains");return;}
                if(candidate.connection.status!=NEVPNStatusDisconnected&&candidate.connection.status!=NEVPNStatusInvalid){FCComplete(op,NO,@"Disconnect the transparent proxy before removing its configuration");return;}
                [candidate removeFromPreferencesWithCompletionHandler:^(NSError* failure){dispatch_async(controlQueue,^{
                    if(!failure)manager=nil;
                    FCComplete(op,!failure,failure.localizedDescription?:@"Inactive FCAE transparent-proxy configuration removed; the signed extension remains part of the app bundle");
                });}];
            });}];
        });
        else if([action isEqual:@"start"]) {
            if(!FCPreflight()){snprintf(output,capacity,"The app and embedded extension need matching signatures, Apple-granted app-proxy-provider entitlements and valid provisioning");return false;}
            NSArray* paths=request[@"apps"];NSMutableArray* requirements=[NSMutableArray array];
            if(![paths isKindOfClass:NSArray.class]||paths.count>8192){snprintf(output,capacity,"Invalid application selector list");return false;}
            for(id path in paths){
                if(![path isKindOfClass:NSString.class]||![path isAbsolutePath]||[path length]>32768){snprintf(output,capacity,"Invalid executable path");return false;}
                NSString* requirement=FCRequirement(path);
                if(!requirement.length){snprintf(output,capacity,"A selected application has no valid code signature; it was not converted to an unsigned path rule");return false;}
                [requirements addObject:requirement];
            }
            NSString* own=FCRequirement(NSBundle.mainBundle.executablePath);
            if(!own.length){snprintf(output,capacity,"Cannot establish FCAE's own signing identity");return false;}
            NSDictionary* policy=@{@"schema":@1,@"revision":op.revision,@"mode":request[@"mode"]?:@0,@"requirements":requirements,@"ownRequirement":own,@"port":request[@"port"]?:@0,@"udp":request[@"udp"]?:@NO,@"owner":ownerID};
            dispatch_async(controlQueue,^{
                [NETransparentProxyManager loadAllFromPreferencesWithCompletionHandler:^(NSArray<NETransparentProxyManager*>* entries,NSError* error){dispatch_async(controlQueue,^{
                    if(error||op.cancelled){FCComplete(op,NO,error.localizedDescription?:@"Activation cancelled");return;}
                    manager=nil;
                    for(NETransparentProxyManager* entry in entries)if(FCOwned(entry)){if(manager){FCComplete(op,NO,@"Multiple FCAE transparent-proxy configurations exist; resolve them in system settings");return;}manager=entry;}
                    if(manager&&manager.connection.status!=NEVPNStatusDisconnected&&manager.connection.status!=NEVPNStatusInvalid){FCComplete(op,NO,@"An existing transparent-proxy session is still active; it was not replaced or adopted");return;}
                    if(!manager)manager=[NETransparentProxyManager new];
                    NETunnelProviderProtocol* proto=[NETunnelProviderProtocol new];proto.providerBundleIdentifier=FCProviderID;proto.serverAddress=@"FCAE app routing";proto.providerConfiguration=policy;
                    manager.protocolConfiguration=proto;manager.localizedDescription=@"FCAE per-app transparent proxy";manager.onDemandEnabled=NO;manager.onDemandRules=@[];manager.enabled=YES;
                    [manager saveToPreferencesWithCompletionHandler:^(NSError* failure){dispatch_async(controlQueue,^{
                        if(failure||op.cancelled){FCComplete(op,NO,failure.localizedDescription?:@"Activation cancelled");return;}
                        [manager loadFromPreferencesWithCompletionHandler:^(NSError* loadError){dispatch_async(controlQueue,^{
                            if(loadError||op.cancelled){FCComplete(op,NO,loadError.localizedDescription?:@"Activation cancelled");return;}
                            NSError* startError=nil;
                            if(![manager.connection startVPNTunnelAndReturnError:&startError]){FCComplete(op,NO,startError.localizedDescription?:@"NetworkExtension refused activation");return;}
                            FCWaitStatus(op,NO,60);
                        });}];
                    });}];
                });}];
            });
        } else {snprintf(output,capacity,"Unknown app-routing operation");return false;}
        const int64_t seconds=[action isEqual:@"status"]?4:25;
        if(dispatch_semaphore_wait(op.semaphore,dispatch_time(DISPATCH_TIME_NOW,seconds*NSEC_PER_SEC))!=0){op.cancelled=YES;snprintf(output,capacity,"NetworkExtension control timed out; activation will not be acknowledged");return false;}
        snprintf(output,capacity,"%s",op.message.UTF8String?:"NetworkExtension control failed");return op.success;
    }
}
// Called once before UI/runtime startup; no signature or disk work is performed
// on an ImGui render frame. Unsigned/ad-hoc builds retain the captured-flow path.
extern "C" void fcae_macos_ne_host_initialize(void){
    static dispatch_once_t once;dispatch_once(&once,^{
        ownerID=NSUUID.UUID.UUIDString;controlQueue=dispatch_queue_create("com.fc.fcaevpn.ne-control",DISPATCH_QUEUE_SERIAL);
        if(FCPreflight())fcae_app_routing_register_macos_ne(FCControl,nullptr);
    });
}
