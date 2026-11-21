#pragma once
#import <Foundation/Foundation.h>
#include "fcae.h"
#include <vector>
NSURL* FCAEContainer();
NSString* FCAETunnelIdentifier();
NSDictionary* FCAEExportState(const FcaeConfig& config);
BOOL FCAEImportState(NSDictionary* state, NSError** error);
NSURL* FCAESessionURL();
NSURL* FCAEErrorURL();
NSError* FCAEError(NSString* message);
NSDictionary* FCAEEncode(const FcaeConfig& config);
@interface FCAEConfig : NSObject {
@public
    FcaeConfig value;
    std::vector<FcaeChainHop> hops;
}
- (instancetype)initWithDictionary:(NSDictionary*)dictionary;
@end
