#import "Config.h"
#import <type_traits>
// Re-signers can rename App Groups or omit them. A shared group is an
// optimization, not the IPC mechanism: the VPN profile carries the session.
NSURL* FCAEContainer() {
    static NSURL* directory;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSFileManager* files=NSFileManager.defaultManager;
        NSString* group=NSBundle.mainBundle.infoDictionary[@"FCAEAppGroup"];
        NSURL* root=group.length ? [files containerURLForSecurityApplicationGroupIdentifier:group] : nil;
        if (!root) root=[[files URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask].firstObject URLByAppendingPathComponent:@"FCAE" isDirectory:YES];
        if (root && [files createDirectoryAtURL:root withIntermediateDirectories:YES
            attributes:@{NSFileProtectionKey:NSFileProtectionCompleteUntilFirstUserAuthentication,NSFilePosixPermissions:@0700} error:nullptr]) directory=root;
    });
    return directory;
}
NSString* FCAETunnelIdentifier() {
    // Info.plist's original identifier is stale after SideStore re-signing.
    NSURL* plugins=NSBundle.mainBundle.builtInPlugInsURL;
    if (!plugins) return nil;
    NSString* identifier=nil;
    for (NSURL* url in [NSFileManager.defaultManager contentsOfDirectoryAtURL:plugins includingPropertiesForKeys:nil options:0 error:nullptr]) {
        if (![url.pathExtension isEqualToString:@"appex"]) continue;
        NSBundle* bundle=[NSBundle bundleWithURL:url];
        NSDictionary* extension=bundle.infoDictionary[@"NSExtension"];
        if (![extension[@"NSExtensionPointIdentifier"] isEqualToString:@"com.apple.networkextension.packet-tunnel"]) continue;
        if (identifier) return nil; // Never guess between multiple providers.
        identifier=bundle.bundleIdentifier;
    }
    return identifier;
}
// Only app-owned identity/account files may cross the sandbox boundary. Never
// copy arbitrary paths, logs, outside-container symlinks or the whole data directory.
static BOOL portablePath(NSString* path) {
    if (![path isKindOfClass:NSString.class] || path.isAbsolutePath) return NO;
    NSArray* parts=path.pathComponents;
    if ([parts containsObject:@".."] || [parts containsObject:@"."]) return NO;
    if (parts.count==1) return (path.length<=255 && [path.pathExtension isEqualToString:@"toml"]) || [path isEqualToString:@"psiphon_servers.txt"];
    if ([path isEqualToString:@"urnetwork/account.json"]) return YES;
    if ([path isEqualToString:@"firefox/relay.json"]) return YES;
    if (parts.count!=4 || ![parts[0] isEqualToString:@"firefox"] || ![parts[1] isEqualToString:@"accounts"]) return NO;
    NSCharacterSet* invalid=[[NSCharacterSet characterSetWithCharactersInString:@"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"] invertedSet];
    return [parts[2] length]>0 && [parts[2] rangeOfCharacterFromSet:invalid].location==NSNotFound
        && [@[@"account.json",@"credentials.json"] containsObject:parts[3]];
}
static NSURL* portableURL(NSString* path) {
    if (!portablePath(path)) return nil;
    NSURL* root=FCAEContainer().URLByResolvingSymlinksInPath;
    NSURL* url=[[root URLByAppendingPathComponent:path] URLByResolvingSymlinksInPath];
    return [url.path hasPrefix:[root.path stringByAppendingString:@"/"]] ? url : nil;
}
NSDictionary* FCAEExportState(const FcaeConfig& config) {
    NSMutableArray* paths=[NSMutableArray arrayWithArray:@[@"aether.toml",@"aether-masque.toml",@"aether-wireguard.toml",@"psiphon_servers.txt",@"firefox/relay.json",@"urnetwork/account.json"]];
    if (config.config_path && *config.config_path) {
        NSString* identity=[NSString stringWithUTF8String:config.config_path];
        if (identity && ![paths containsObject:identity.lastPathComponent]) [paths addObject:identity.lastPathComponent];
    }
    if (config.firefox.account_id && *config.firefox.account_id) {
        NSString* account=[NSString stringWithUTF8String:config.firefox.account_id];
        if (account) for (NSString* file in @[@"account.json",@"credentials.json"])
            [paths addObject:[NSString stringWithFormat:@"firefox/accounts/%@/%@",account,file]];
    }
    NSMutableDictionary* result=[NSMutableDictionary dictionary];
    NSUInteger total=0;
    for (NSString* path in paths) {
        NSURL* url=portableURL(path);if (!url) continue;
        NSDictionary* attributes=[NSFileManager.defaultManager attributesOfItemAtPath:url.path error:nullptr];
        if (![attributes[NSFileType] isEqualToString:NSFileTypeRegular] || [attributes[NSFileSize] unsignedLongLongValue]>256*1024) continue;
        NSData* bytes=[NSData dataWithContentsOfURL:url options:NSDataReadingMappedIfSafe error:nullptr];
        NSDate* date=attributes[NSFileModificationDate];
        if (!bytes || bytes.length>256*1024 || total+bytes.length>512*1024 || !date) continue;
        result[path]=@{@"bytes":bytes,@"date":date};total+=bytes.length;
    }
    return result;
}
BOOL FCAEImportState(NSDictionary* state,NSError** error) {
    if (!state) return YES; // Older shared-container session.
    if (![state isKindOfClass:NSDictionary.class] || state.count>16) {
        if (error) *error=FCAEError(@"Invalid portable VPN state.");return NO;
    }
    NSUInteger total=0;
    // Validate the entire snapshot before writing anything.
    for (NSString* path in state) {
        id record=state[path];
        if (!portableURL(path) || ![record isKindOfClass:NSDictionary.class]
            || ![record[@"bytes"] isKindOfClass:NSData.class] || ![record[@"date"] isKindOfClass:NSDate.class]
            || [record[@"bytes"] length]>256*1024 || (total+=[record[@"bytes"] length])>512*1024) {
            if (error) *error=FCAEError(@"Invalid portable VPN state file.");return NO;
        }
    }
    for (NSString* path in state) {
        NSURL* url=portableURL(path);NSDictionary* record=state[path];
        NSDate* local=[NSFileManager.defaultManager attributesOfItemAtPath:url.path error:nullptr][NSFileModificationDate];
        // A saved VPN profile must not overwrite credentials renewed by the
        // extension or newer edits made in the app since the last connect.
        if (local && [local compare:record[@"date"]]!=NSOrderedAscending) continue;
        if (![NSFileManager.defaultManager createDirectoryAtURL:url.URLByDeletingLastPathComponent withIntermediateDirectories:YES
            attributes:@{NSFileProtectionKey:NSFileProtectionCompleteUntilFirstUserAuthentication,NSFilePosixPermissions:@0700} error:error]
            || ![record[@"bytes"] writeToURL:url options:NSDataWritingAtomic|NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication error:error]
            || ![NSFileManager.defaultManager setAttributes:@{NSFileModificationDate:record[@"date"],NSFilePosixPermissions:@0600} ofItemAtPath:url.path error:error]) return NO;
    }
    return YES;
}
NSURL* FCAESessionURL() { return [FCAEContainer() URLByAppendingPathComponent:@"session.plist"]; }
NSURL* FCAEErrorURL() { return [FCAEContainer() URLByAppendingPathComponent:@"last-error.plist"]; }
NSError* FCAEError(NSString* message) {
    return [NSError errorWithDomain:@"FCAE" code:1 userInfo:@{NSLocalizedDescriptionKey:message ?: @"Unknown VPN error"}];
}
NSDictionary* FCAEEncode(const FcaeConfig& c) {
    NSMutableDictionary* result = [NSMutableDictionary dictionaryWithObject:@(FCAE_ABI_VERSION) forKey:@"abi"];
#define NUM(field) result[@#field] = [NSData dataWithBytes:&c.field length:sizeof(c.field)];
#define STR(field) if (c.field) { NSString* text=[NSString stringWithUTF8String:c.field]; if (!text) return nil; result[@#field]=text; }
#include "ConfigFields.inc"
#undef NUM
#undef STR
    NSMutableArray* chain = [NSMutableArray array];
    for (uint32_t i=0; c.chain.hops && i<c.chain.hop_count; ++i) {
        const auto& hop = c.chain.hops[i];
        NSString* reference=hop.config_ref?[NSString stringWithUTF8String:hop.config_ref]:@"";
        if (!reference) return nil;
        [chain addObject:@{@"backend":@(hop.backend), @"protocol":@(hop.protocol), @"h2":@(hop.h2_enabled),
            @"ref":reference}];
    }
    result[@"hops"] = chain;
    result[@"state"] = FCAEExportState(c);
    return result;
}
@implementation FCAEConfig {
    NSDictionary* _storage;
}
- (instancetype)initWithDictionary:(NSDictionary*)dictionary {
    if (!(self=[super init])) return nil;
    if (![dictionary isKindOfClass:NSDictionary.class] || [dictionary[@"abi"] unsignedIntValue]!=FCAE_ABI_VERSION) return nil;
    NSMutableDictionary* local=[dictionary mutableCopy];
    NSURL* root=FCAEContainer();if (!root) return nil;
    // Absolute paths from the containing app cannot be opened by the provider
    // after re-signing without a shared App Group. Rebase app-owned paths only.
    NSString* path=local[@"config_path"];
    if ([path isKindOfClass:NSString.class] && path.length) {
        if (!portablePath(path.lastPathComponent)) return nil;
        local[@"config_path"]=[[root URLByAppendingPathComponent:path.lastPathComponent] path];
    }
    local[@"data_dir"]=root.path;
    local[@"psiphon.data_root_dir"]=[[root URLByAppendingPathComponent:@"psiphon" isDirectory:YES] path];
    local[@"tor.state_dir"]=[[root URLByAppendingPathComponent:@"tor" isDirectory:YES] path];
    _storage=[local copy];
    fcae_config_default(&value);
#define NUM(field) { NSData* data=_storage[@#field]; \
    if (![data isKindOfClass:NSData.class] || data.length!=sizeof(value.field)) return nil; \
    if constexpr(std::is_same_v<decltype(value.field),bool>) { if (*(const uint8_t*)data.bytes>1) return nil; } \
    memcpy(&value.field,data.bytes,sizeof(value.field)); }
#define STR(field) { NSString* text=_storage[@#field]; \
    if (text && ![text isKindOfClass:NSString.class]) return nil; value.field=text.UTF8String; }
#include "ConfigFields.inc"
#undef NUM
#undef STR
    NSArray* chain=_storage[@"hops"];
    if (![chain isKindOfClass:NSArray.class] || chain.count>1000) return nil;
    for (NSDictionary* item in chain) {
        if (![item isKindOfClass:NSDictionary.class] || ![item[@"ref"] isKindOfClass:NSString.class]) return nil;
        FcaeChainHop hop{};
        hop.backend=(FcaeBackend)[item[@"backend"] intValue];
        hop.protocol=(FcaeProtocol)[item[@"protocol"] intValue];
        hop.h2_enabled=[item[@"h2"] boolValue];
        hop.config_ref=[item[@"ref"] UTF8String];
        hops.push_back(hop);
    }
    value.chain.hops=hops.empty()?nullptr:hops.data();
    value.chain.hop_count=(uint32_t)hops.size();
    // Descriptors cannot cross processes. The provider supplies a fresh adapter.
    value.tun_fd=-1;
    return self;
}
@end
