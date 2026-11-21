#import <NetworkExtension/NetworkExtension.h>
#import "Config.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <cstdlib>
#include <mutex>
#include <deque>
#include <string>

extern "C" void fcae_sponsor_set_ui_active(bool);
extern "C" uint32_t fcae_live_listeners(char*,uint32_t);

struct LogEntry { uint64_t id; int level; std::string text; };
static std::mutex log_mutex;
static std::deque<LogEntry> logs;
static uint64_t log_sequence;
static void core_log(FcaeLogLevel level,const char* message,void*) {
    std::lock_guard<std::mutex> lock(log_mutex);
    if (logs.size()==128) logs.pop_front();
    logs.push_back({++log_sequence,(int)level,message?message:""});
}
@interface FCAEPacketTunnel : NEPacketTunnelProvider
@end
@implementation FCAEPacketTunnel {
    dispatch_queue_t _queue;
    dispatch_source_t _reader;
    dispatch_source_t _monitor;
    int _engine;
    int _peer;
    BOOL _active;
    BOOL _configured;
    NSUInteger _generation;
    NSDate* _deadline;
    FCAEConfig* _config;
    void (^_completion)(NSError*);
}
- (instancetype)init {
    if ((self=[super init])) {
        _queue=dispatch_queue_create("com.fc.fcaevpn.packet-flow",DISPATCH_QUEUE_SERIAL);
        _engine=_peer=-1;
    }
    return self;
}
- (void)recordError:(NSError*)error {
    NSData* data=[NSPropertyListSerialization dataWithPropertyList:@{@"message":error.localizedDescription ?: @"VPN failed"}
        format:NSPropertyListBinaryFormat_v1_0 options:0 error:nullptr];
    [data writeToURL:FCAEErrorURL() options:NSDataWritingAtomic|NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication error:nullptr];
}
- (void)reject:(NSError*)error {[self recordError:error];[self finishStart:error];}
- (void)finishStart:(NSError*)error {
    void (^completion)(NSError*)=_completion;
    _completion=nil;
    if (completion) completion(error);
}
- (void)cleanup {
    _active=NO;++_generation;
    if (_monitor) {dispatch_source_cancel(_monitor);_monitor=nil;}
    fcae_stop_begin();
    fcae_stop();
    fcae_set_tun_fd(-1);
    if (_engine>=0) {close(_engine);_engine=-1;}
    if (_reader) {dispatch_source_cancel(_reader);_reader=nil;}
    else if (_peer>=0) close(_peer);
    _peer=-1;
    _config=nil;
}
- (void)fail:(NSError*)error {
    [self recordError:error];
    const BOOL starting=_completion!=nil;
    [self cleanup];
    if (starting) [self finishStart:error];
    else [self cancelTunnelWithError:error];
}
- (void)readFlow:(NSUInteger)generation {
    __weak FCAEPacketTunnel* weak=self;
    [self.packetFlow readPacketsWithCompletionHandler:^(NSArray<NSData*>* packets,NSArray<NSNumber*>* protocols){
        FCAEPacketTunnel* owner=weak;
        if (!owner) return;
        dispatch_async(owner->_queue, ^{
            if (!owner->_active || generation!=owner->_generation) return;
            for (NSUInteger i=0;i<packets.count;i++) {
                NSData* packet=packets[i];
                if (!packet.length || packet.length>9000) continue;
                // All three Darwin fd engines use the same four-byte address-family header.
                const uint8_t version=(*(const uint8_t*)packet.bytes)>>4;
                if (version!=4 && version!=6) continue;
                uint32_t family=htonl(version==6?AF_INET6:AF_INET);
                struct iovec vector[2]={{&family,sizeof(family)},{(void*)packet.bytes,packet.length}};
                struct msghdr msg{};msg.msg_iov=vector;msg.msg_iovlen=2;
                ssize_t sent;
                do {sent=sendmsg(owner->_peer,&msg,0);} while (sent<0 && errno==EINTR);
                // Bounded kernel buffers drop packets under load instead of growing an unbounded queue.
                if (sent<0 && errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=ENOBUFS) {
                    [owner fail:FCAEError(@"The packet-flow adapter could not deliver a packet.")];return;
                }
            }
            [owner readFlow:generation];
        });
    }];
}
- (void)startTunnelWithOptions:(NSDictionary<NSString*,NSObject*>*)options completionHandler:(void (^)(NSError*))completionHandler {
    dispatch_async(_queue, ^{
        if (self->_active) {completionHandler(FCAEError(@"VPN is already starting or running."));return;}
        self->_completion=[completionHandler copy];
        NETunnelProviderProtocol* proto=(NETunnelProviderProtocol*)self.protocolConfiguration;
        NSDictionary* payload=proto.providerConfiguration[@"session"];
        if (!payload) payload=[NSDictionary dictionaryWithContentsOfURL:FCAESessionURL()];
        NSError* stateError=nil;
        if (![payload isKindOfClass:NSDictionary.class] || !FCAEImportState(payload[@"state"],&stateError)) {
            [self reject:stateError ?: FCAEError(@"Missing VPN session; open FCAE and connect again.")];return;
        }
        self->_config=[[FCAEConfig alloc] initWithDictionary:payload];
        if (!FCAEContainer() || !self->_config || self->_config->value.mode!=FCAE_MODE_TUN ||
                self->_config->value.tun_engine>FCAE_TUN_ENGINE_HEV) {
            [self reject:FCAEError(@"Missing/incompatible session; open FCAE and connect again.")];return;
        }
        const auto& config=self->_config->value;
        if (config.dns.mode!=FCAE_DNS_UDP) {
            [self reject:FCAEError(@"This iOS adapter currently requires UDP DNS; DoH for system DNS is not implemented.")];return;
        }
        if (config.dns.server && *config.dns.server) {
            NSString* endpoint=[NSString stringWithUTF8String:config.dns.server];
            NSURLComponents* parsed=[NSURLComponents componentsWithString:[@"udp://" stringByAppendingString:endpoint]];
            NSString* host=[parsed.host stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"[]"]];
            uint8_t address[16];
            if ((!host.length) || (parsed.port && parsed.port.intValue!=53) ||
                    (inet_pton(AF_INET,host.UTF8String,address)!=1 && inet_pton(AF_INET6,host.UTF8String,address)!=1)) {
                [self reject:FCAEError(@"iOS system DNS requires a numeric IPv4/IPv6 resolver on port 53.")];return;
            }
        }
        FcaeInitOptions init{};init.struct_size=sizeof(init);init.abi_version=FCAE_ABI_VERSION;
        init.log_cb=core_log;init.max_log_level=FCAE_LOG_INFO;
        if (fcae_init(&init)!=FCAE_OK) {[self reject:FCAEError([NSString stringWithUTF8String:fcae_last_error()])];return;}
        fcae_sponsor_set_ui_active(false);
        int pair[2];
        if (socketpair(AF_UNIX,SOCK_DGRAM,0,pair)!=0) {[self reject:FCAEError(@"Cannot create packet-flow adapter.")];return;}
        self->_engine=pair[0];self->_peer=pair[1];
        const int flags=fcntl(pair[1],F_GETFL,0);
        if (flags<0 || fcntl(pair[1],F_SETFL,flags|O_NONBLOCK)<0) {[self fail:FCAEError(@"Cannot configure packet adapter.")];return;}
        self->_active=YES;self->_configured=NO;++self->_generation;
        const NSUInteger generation=self->_generation;
        const int peer=pair[1];
        self->_reader=dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,peer,0,self->_queue);
        dispatch_source_set_cancel_handler(self->_reader, ^{close(peer);});
        __weak FCAEPacketTunnel* weak=self;
        dispatch_source_set_event_handler(self->_reader, ^{
            FCAEPacketTunnel* owner=weak;if (!owner || !owner->_active) return;
            uint8_t bytes[9004];
            NSMutableArray* packets=[NSMutableArray array];
            NSMutableArray* protocols=[NSMutableArray array];
            // Limit each turn so telemetry, stop and incoming packets cannot starve.
            for (int count=0;count<64;count++) {
                ssize_t length=recv(peer,bytes,sizeof(bytes),0);
                if (length<0 && errno==EINTR) {--count;continue;}
                if (length<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) break;
                if (length<=4) {if(length<0)[owner fail:FCAEError(@"Packet adapter read failed.")];break;}
                const uint8_t version=bytes[4]>>4;
                if (version!=4 && version!=6) continue;
                NSData* packet=[NSData dataWithBytes:bytes+4 length:length-4];
                [packets addObject:packet];[protocols addObject:@(version==6?AF_INET6:AF_INET)];
            }
            if (owner->_active && packets.count) [owner.packetFlow writePackets:packets withProtocols:protocols];
        });
        dispatch_resume(self->_reader);
        if (fcae_set_tun_fd(pair[0])!=FCAE_OK || fcae_start(&self->_config->value)!=FCAE_OK) {
            [self fail:FCAEError([NSString stringWithUTF8String:fcae_last_error()])];return;
        }
        [self readFlow:generation];
        self->_deadline=[NSDate dateWithTimeIntervalSinceNow:90];
        self->_monitor=dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,self->_queue);
        dispatch_source_set_timer(self->_monitor,dispatch_time(DISPATCH_TIME_NOW,0),250*NSEC_PER_MSEC,25*NSEC_PER_MSEC);
        dispatch_source_set_event_handler(self->_monitor, ^{
            FCAEPacketTunnel* owner=weak;if (!owner || !owner->_active) return;
            FcaeTelemetry t{};t.struct_size=sizeof(t);t.abi_version=FCAE_ABI_VERSION;
            if (fcae_get_telemetry(&t)!=FCAE_OK) return;
            if (t.state==FCAE_STATE_ERROR || (!owner->_completion && t.state==FCAE_STATE_DISCONNECTED)
                    || (owner->_completion && owner->_deadline.timeIntervalSinceNow<0)) {
                [owner fail:FCAEError(t.last_error[0]?[NSString stringWithUTF8String:t.last_error]:@"VPN connection timed out.")];return;
            }
            if (t.state!=FCAE_STATE_CONNECTED || owner->_configured) return;
            owner->_configured=YES;
            NEPacketTunnelNetworkSettings* network=[[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:@"198.18.0.1"];
            network.MTU=@(owner->_config->value.tun_mtu ?: 1500);
            NEIPv4Settings* v4=[[NEIPv4Settings alloc] initWithAddresses:@[@"198.18.0.2"] subnetMasks:@[@"255.255.255.252"]];
            v4.includedRoutes=@[NEIPv4Route.defaultRoute];
            if (!(owner->_config->value._reserved[0]&FCAE_CONFIG_TUN_ROUTE_PRIVATE))
                v4.excludedRoutes=@[[[NEIPv4Route alloc] initWithDestinationAddress:@"10.0.0.0" subnetMask:@"255.0.0.0"],
                    [[NEIPv4Route alloc] initWithDestinationAddress:@"172.16.0.0" subnetMask:@"255.240.0.0"],
                    [[NEIPv4Route alloc] initWithDestinationAddress:@"192.168.0.0" subnetMask:@"255.255.0.0"],
                    [[NEIPv4Route alloc] initWithDestinationAddress:@"100.64.0.0" subnetMask:@"255.192.0.0"]];
            network.IPv4Settings=v4;
            NEIPv6Settings* v6=[[NEIPv6Settings alloc] initWithAddresses:@[@"fd00:fc::2"] networkPrefixLengths:@[@64]];
            v6.includedRoutes=@[NEIPv6Route.defaultRoute];
            network.IPv6Settings=v6;
            NSString* resolver=@"1.1.1.1";
            if (owner->_config->value.dns.server && *owner->_config->value.dns.server) {
                NSString* endpoint=[NSString stringWithUTF8String:owner->_config->value.dns.server];
                NSURLComponents* parsed=[NSURLComponents componentsWithString:[@"udp://" stringByAppendingString:endpoint]];
                if (parsed.host.length) resolver=[parsed.host stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"[]"]];
            }
            NEDNSSettings* dns=[[NEDNSSettings alloc] initWithServers:@[resolver]];
            dns.matchDomains=@[@""];network.DNSSettings=dns;
            [owner setTunnelNetworkSettings:network completionHandler:^(NSError* error){
                FCAEPacketTunnel* current=weak;
                if (!current) return;
                dispatch_async(current->_queue, ^{
                    if (!current->_active || generation!=current->_generation) return;
                    if (error) [current fail:error]; else [current finishStart:nil];
                });
            }];
        });
        dispatch_resume(self->_monitor);
    });
}
- (void)stopTunnelWithReason:(NEProviderStopReason)reason completionHandler:(void (^)(void))completionHandler {
    dispatch_async(_queue, ^{
        [self cleanup];[self finishStart:FCAEError(@"VPN start was cancelled.")];completionHandler();
    });
}
- (void)handleAppMessage:(NSData*)message completionHandler:(void (^)(NSData*))completionHandler {
    if (!completionHandler) return;
    dispatch_async(_queue, ^{
        FcaeTelemetry telemetry{};telemetry.struct_size=sizeof(telemetry);telemetry.abi_version=FCAE_ABI_VERSION;
        fcae_get_telemetry(&telemetry);
        NSString* cursor=message.length<=32?[[NSString alloc] initWithData:message encoding:NSUTF8StringEncoding]:nil;
        const uint64_t since=strtoull(cursor.UTF8String ?: "0",nullptr,10);
        NSMutableArray* entries=[NSMutableArray array];
        {std::lock_guard<std::mutex> lock(log_mutex);
            for (const auto& log:logs) if (log.id>since) [entries addObject:@{@"id":@(log.id),@"level":@(log.level),@"text":[NSString stringWithUTF8String:log.text.c_str()] ?: @""}];}
        const uint32_t needed=fcae_live_listeners(nullptr,0);
        std::vector<char> listeners(needed && needed<=65536?needed:1,0);
        if (needed<=listeners.size()) fcae_live_listeners(listeners.data(),(uint32_t)listeners.size());
        char regions[4096]{};fcae_psiphon_regions(regions,sizeof(regions));
        NSMutableDictionary* result=[@{@"listeners":[NSString stringWithUTF8String:listeners.data()] ?: @"",
            @"regions":[NSString stringWithUTF8String:regions] ?: @"", @"abi":@(FCAE_ABI_VERSION),@"telemetry":[NSData dataWithBytes:&telemetry length:sizeof(telemetry)],@"logs":entries} mutableCopy];
        if (self->_config && [cursor hasSuffix:@":state"]) result[@"state"]=FCAEExportState(self->_config->value);
        completionHandler([NSPropertyListSerialization dataWithPropertyList:result format:NSPropertyListBinaryFormat_v1_0 options:0 error:nullptr]);
    });
}
@end
