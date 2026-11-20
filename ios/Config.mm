#import "Config.h"
#import <type_traits>
NSURL* FCAEContainer() {
    NSString* group = NSBundle.mainBundle.infoDictionary[@"FCAEAppGroup"];
    return [NSFileManager.defaultManager containerURLForSecurityApplicationGroupIdentifier:group];
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
    return result;
}
@implementation FCAEConfig {
    NSDictionary* _storage;
}
- (instancetype)initWithDictionary:(NSDictionary*)dictionary {
    if (!(self=[super init])) return nil;
    if (![dictionary isKindOfClass:NSDictionary.class] || [dictionary[@"abi"] unsignedIntValue]!=FCAE_ABI_VERSION) return nil;
    _storage=[dictionary copy];
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
