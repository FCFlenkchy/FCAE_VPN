#pragma once
#import <Foundation/Foundation.h>
#include "fcae.h"
#include <vector>
NSURL* FCAEContainer();
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
