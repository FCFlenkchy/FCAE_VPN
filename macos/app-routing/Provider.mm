#import <NetworkExtension/NetworkExtension.h>
#import <Network/Network.h>
#import <Security/Security.h>
#include <arpa/inet.h>

// A separate, entitlement-gated transparent proxy. This provider never opens a
// packet tunnel and never installs default IP routes. Declined flows therefore
// remain OS-owned; they are not advertised as bypass while another FCAE TUN runs.
static NSError* FCError(NSString* message) {
    return [NSError errorWithDomain:@"FCAE.AppRouting" code:1 userInfo:@{NSLocalizedDescriptionKey:message}];
}
static dispatch_data_t FCDispatchData(NSData* data) {
    void* copy=malloc(data.length ?: 1);
    if(!copy)return nil;
    memcpy(copy,data.bytes,data.length);
    return dispatch_data_create(copy,data.length,dispatch_get_global_queue(QOS_CLASS_UTILITY,0),^{free(copy);});
}
static NSData* FCData(dispatch_data_t data) {
    if(!data)return nil;
    const void* bytes=nullptr;size_t size=0;
    dispatch_data_t mapped=dispatch_data_create_map(data,&bytes,&size);
    NSData* result=[NSData dataWithBytes:bytes length:size];
    (void)mapped;return result;
}
static NSData* FCAddress(NWHostEndpoint* endpoint) {
    if(![endpoint isKindOfClass:NWHostEndpoint.class])return nil;
    NSScanner* scanner=[NSScanner scannerWithString:endpoint.port];int number=0;
    if(![scanner scanInt:&number]||!scanner.isAtEnd||number<1||number>65535)return nil;
    NSMutableData* result=[NSMutableData data];uint8_t bytes[16];
    NSString* hostname=[endpoint.hostname stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"[]"]];
    if(inet_pton(AF_INET,hostname.UTF8String,bytes)==1) {uint8_t kind=1;[result appendBytes:&kind length:1];[result appendBytes:bytes length:4];}
    else if(inet_pton(AF_INET6,hostname.UTF8String,bytes)==1) {uint8_t kind=4;[result appendBytes:&kind length:1];[result appendBytes:bytes length:16];}
    else {NSData* name=[hostname dataUsingEncoding:NSUTF8StringEncoding];if(!name.length||name.length>255)return nil;uint8_t head[2]={3,(uint8_t)name.length};[result appendBytes:head length:2];[result appendData:name];}
    uint8_t port[2]={(uint8_t)(number>>8),(uint8_t)number};[result appendBytes:port length:2];return result;
}
// Decode one SOCKS address; reject truncated encodings and invalid UTF-8.
static NWHostEndpoint* FCDecodeAddress(NSData* packet,NSUInteger start,NSUInteger* consumed) {
    if(start>=packet.length)return nil;
    const uint8_t* p=(const uint8_t*)packet.bytes+start;NSUInteger left=packet.length-start,n=0,head=1;NSString* host=nil;char text[INET6_ADDRSTRLEN]{};
    if(p[0]==1)n=4;else if(p[0]==4)n=16;else if(p[0]==3){if(left<2)return nil;head=2;n=p[1];if(!n)return nil;}else return nil;
    if(left<head+n+2)return nil;
    if(p[0]==3)host=[[NSString alloc] initWithBytes:p+head length:n encoding:NSUTF8StringEncoding];
    else if(inet_ntop(p[0]==1?AF_INET:AF_INET6,p+head,text,sizeof(text)))host=[NSString stringWithUTF8String:text];
    const unsigned port=((unsigned)p[head+n]<<8)|p[head+n+1];
    if(!host.length||!port)return nil;
    *consumed=head+n+2;return [NWHostEndpoint endpointWithHostname:host port:[NSString stringWithFormat:@"%u",port]];
}

@interface FCRelay : NSObject
@property(strong) NEAppProxyFlow* flow;
@property(strong) dispatch_queue_t queue;
@property(strong) nw_connection_t control;
@property(strong) nw_connection_t datagrams;
@property(copy) void (^finished)(FCRelay*);
@property BOOL closed;
@property BOOL udp;
@property BOOL udpAllowed;
@property BOOL opened;
@property BOOL appEOF;
@property BOOL networkEOF;
@property NSUInteger token;
- (void)startPort:(NSString*)port queue:(dispatch_queue_t)queue;
- (void)close:(NSError*)error;
@end
@implementation FCRelay
- (void)close:(NSError*)error {
    if(_closed)return;_closed=YES;++_token;
    if(_control)nw_connection_cancel(_control);
    if(_datagrams)nw_connection_cancel(_datagrams);
    [_flow closeReadWithError:error];[_flow closeWriteWithError:error];
    if(_finished){void(^done)(FCRelay*)=_finished;_finished=nil;done(self);}
    _control=nil;_datagrams=nil;
}
- (void)send:(NSData*)data connection:(nw_connection_t)connection done:(void(^)(NSError*))done {
    if(_closed)return;
    dispatch_data_t payload=FCDispatchData(data);
    if(!payload){[self close:FCError(@"Relay allocation failed")];return;}
    __weak FCRelay* weak=self;
    nw_connection_send(connection,payload,NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT,true,^(nw_error_t error){
        FCRelay* owner=weak;if(!owner||owner.closed)return;
        if(error){[owner close:FCError(@"Exit-chain write failed")];return;}done(nil);
    });
}
- (void)read:(NSUInteger)count buffer:(NSMutableData*)buffer done:(void(^)(NSData*))done {
    if(_closed||count>512||buffer.length>count){[self close:FCError(@"Invalid SOCKS response")];return;}
    if(buffer.length==count){done(buffer);return;}
    __weak FCRelay* weak=self;
    nw_connection_receive(_control,1,(uint32_t)(count-buffer.length),^(dispatch_data_t content,nw_content_context_t context,bool complete,nw_error_t error){
        FCRelay* owner=weak;if(!owner||owner.closed)return;
        NSData* data=FCData(content);
        if(error||!data.length){[owner close:FCError(@"Exit-chain handshake ended")];return;}
        [buffer appendData:data];[owner read:count buffer:buffer done:done];
    });
}
- (void)read:(NSUInteger)count done:(void(^)(NSData*))done {[self read:count buffer:[NSMutableData data] done:done];}
- (void)startPort:(NSString*)port queue:(dispatch_queue_t)queue {
    _queue=queue;_udp=[_flow isKindOfClass:NEAppProxyUDPFlow.class];
    if(_udp&&!_udpAllowed){[self close:FCError(@"The selected exit chain cannot carry UDP")];return;}
    nw_parameters_t parameters=nw_parameters_create_secure_tcp(NW_PARAMETERS_DISABLE_PROTOCOL,NW_PARAMETERS_DEFAULT_CONFIGURATION);
    _control=nw_connection_create(nw_endpoint_create_host("127.0.0.1",port.UTF8String),parameters);
    nw_connection_set_queue(_control,queue);
    __weak FCRelay* weak=self;
    nw_connection_set_state_changed_handler(_control,^(nw_connection_state_t state,nw_error_t error){
        FCRelay* owner=weak;if(!owner||owner.closed)return;
        if(state==nw_connection_state_failed||state==nw_connection_state_cancelled){[owner close:FCError(@"Exit-chain connection lost")];return;}
        if(state!=nw_connection_state_ready)return;
        const uint8_t hello[3]={5,1,0};
        [owner send:[NSData dataWithBytes:hello length:3] connection:owner.control done:^(NSError*){
            [owner read:2 done:^(NSData* response){
                const uint8_t* p=(const uint8_t*)response.bytes;
                if(p[0]!=5||p[1]!=0){[owner close:FCError(@"Exit chain requires unsupported SOCKS authentication")];return;}
                [owner request];
            }];
        }];
    });
    nw_connection_start(_control);
    const NSUInteger token=++_token;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,10*NSEC_PER_SEC),queue,^{
        FCRelay* owner=weak;if(owner&&!owner.closed&&owner.token==token)[owner close:FCError(@"Exit-chain handshake timed out")];
    });
}
- (void)request {
    uint8_t head[3]={5,(uint8_t)(_udp?3:1),0};NSMutableData* request=[NSMutableData dataWithBytes:head length:3];
    NSData* address;
    if(_udp){const uint8_t zero[7]={1,0,0,0,0,0,0};address=[NSData dataWithBytes:zero length:7];}
    else address=FCAddress((NWHostEndpoint*)((NEAppProxyTCPFlow*)_flow).remoteEndpoint);
    if(!address){[self close:FCError(@"Unsupported flow endpoint")];return;}[request appendData:address];
    __weak FCRelay* weak=self;
    [self send:request connection:_control done:^(NSError*){
        [weak read:4 done:^(NSData* response){
            FCRelay* owner=weak;if(!owner||owner.closed)return;
            const uint8_t* p=(const uint8_t*)response.bytes;
            if(p[0]!=5||p[1]!=0||p[2]!=0){[owner close:FCError(@"Exit chain rejected the flow")];return;}
            const uint8_t type=p[3];
            if(type==1||type==4)[owner bound:type count:(type==1?6:18)];
            else if(type==3)[owner read:1 done:^(NSData* length){const uint8_t n=*(const uint8_t*)length.bytes;if(!n){[owner close:FCError(@"Invalid SOCKS relay address")];return;}[owner bound:type count:(NSUInteger)n+2];}];
            else [owner close:FCError(@"Invalid SOCKS relay address")];
        }];
    }];
}
- (void)bound:(uint8_t)type count:(NSUInteger)count {
    __weak FCRelay* weak=self;
    [self read:count done:^(NSData* response){
        FCRelay* owner=weak;if(!owner||owner.closed)return;
        if(!owner.udp){[owner open];return;}
        NSMutableData* address=[NSMutableData dataWithBytes:&type length:1];
        if(type==3){uint8_t n=(uint8_t)(count-2);[address appendBytes:&n length:1];}[address appendData:response];
        NSUInteger consumed=0;NWHostEndpoint* endpoint=FCDecodeAddress(address,0,&consumed);
        if(!endpoint){[owner close:FCError(@"Invalid SOCKS UDP association")];return;}
        NSString* host=endpoint.hostname;
        if([host isEqual:@"0.0.0.0"]||[host isEqual:@"::"])host=@"127.0.0.1";
        // Never send a protected datagram to a remotely supplied physical relay.
        if(![host isEqual:@"127.0.0.1"]&&![host isEqual:@"::1"]){[owner close:FCError(@"SOCKS UDP relay must be loopback")];return;}
        owner.datagrams=nw_connection_create(nw_endpoint_create_host(host.UTF8String,endpoint.port.UTF8String),nw_parameters_create_secure_udp(NW_PARAMETERS_DISABLE_PROTOCOL,NW_PARAMETERS_DEFAULT_CONFIGURATION));
        nw_connection_set_queue(owner.datagrams,owner.queue);
        nw_connection_set_state_changed_handler(owner.datagrams,^(nw_connection_state_t state,nw_error_t error){
            FCRelay* relay=weak;if(!relay||relay.closed)return;
            if(state==nw_connection_state_failed||state==nw_connection_state_cancelled)[relay close:FCError(@"UDP exit association lost")];
            else if(state==nw_connection_state_ready)[relay open];
        });
        nw_connection_start(owner.datagrams);
        nw_connection_receive(owner.control,1,1,^(dispatch_data_t,nw_content_context_t,bool,nw_error_t){[weak close:FCError(@"UDP control association ended")];});
    }];
}
- (void)open {
    if(_opened||_closed)return;_opened=YES;
    __weak FCRelay* weak=self;
    [_flow openWithLocalEndpoint:nil completionHandler:^(NSError* error){
        FCRelay* owner=weak;if(!owner)return;
        dispatch_async(owner.queue,^{if(owner.closed)return;if(error){[owner close:error];return;}++owner.token;if(owner.udp){[owner readUDP];[owner receiveUDP];}else{[owner readTCP];[owner receiveTCP];}});
    }];
}
- (void)readTCP {
    if(_closed)return;__weak FCRelay* weak=self;
    [(NEAppProxyTCPFlow*)_flow readDataWithCompletionHandler:^(NSData* data,NSError* error){
        FCRelay* owner=weak;if(!owner)return;dispatch_async(owner.queue,^{
            if(owner.closed)return;
            if(error){[owner close:error];return;}
            if(!data.length){
                owner.appEOF=YES;[owner.flow closeReadWithError:nil];
                nw_connection_send(owner.control,nil,NW_CONNECTION_FINAL_MESSAGE_CONTEXT,true,^(nw_error_t e){FCRelay* relay=weak;if(!relay||relay.closed)return;if(e)[relay close:FCError(@"TCP half-close failed")];else if(relay.networkEOF)[relay close:nil];});return;
            }
            [owner send:data connection:owner.control done:^(NSError*){[weak readTCP];}];
        });
    }];
}
- (void)receiveTCP {
    if(_closed)return;__weak FCRelay* weak=self;
    nw_connection_receive(_control,1,65536,^(dispatch_data_t content,nw_content_context_t context,bool complete,nw_error_t error){
        FCRelay* owner=weak;if(!owner||owner.closed)return;NSData* data=FCData(content);
        if(error){[owner close:FCError(@"Exit-chain read failed")];return;}
        void(^advance)(void)=^{
            if(complete||!data.length){owner.networkEOF=YES;[owner.flow closeWriteWithError:nil];if(owner.appEOF)[owner close:nil];}
            else [owner receiveTCP];
        };
        if(!data.length){advance();return;}
        [(NEAppProxyTCPFlow*)owner.flow writeData:data withCompletionHandler:^(NSError* failure){dispatch_async(owner.queue,^{if(failure)[owner close:failure];else advance();});}];
    });
}
- (void)readUDP {
    if(_closed)return;__weak FCRelay* weak=self;
    [(NEAppProxyUDPFlow*)_flow readDatagramsWithCompletionHandler:^(NSArray<NSData*>* data,NSArray<NWEndpoint*>* endpoints,NSError* error){
        FCRelay* owner=weak;if(!owner)return;dispatch_async(owner.queue,^{
            if(error||data.count!=endpoints.count||data.count>256){[owner close:error?:FCError(@"Invalid UDP flow batch")];return;}
            if(!data.count){[owner close:nil];return;}[owner sendUDPBatch:data endpoints:endpoints index:0];
        });
    }];
}
- (void)sendUDPBatch:(NSArray<NSData*>*)data endpoints:(NSArray<NWEndpoint*>*)endpoints index:(NSUInteger)index {
    if(_closed)return;if(index==data.count){[self readUDP];return;}
    NSData* address=FCAddress((NWHostEndpoint*)endpoints[index]);
    if(!address||data[index].length>65507-address.length-3){[self close:FCError(@"Unsupported UDP endpoint or datagram length")];return;}
    const uint8_t head[3]={0,0,0};NSMutableData* packet=[NSMutableData dataWithBytes:head length:3];[packet appendData:address];[packet appendData:data[index]];
    __weak FCRelay* weak=self;
    [self send:packet connection:_datagrams done:^(NSError*){[weak sendUDPBatch:data endpoints:endpoints index:index+1];}];
}
- (void)receiveUDP {
    if(_closed)return;__weak FCRelay* weak=self;
    nw_connection_receive_message(_datagrams,^(dispatch_data_t content,nw_content_context_t context,bool complete,nw_error_t error){
        FCRelay* owner=weak;if(!owner||owner.closed)return;
        NSData* packet=FCData(content);
        if(error){[owner close:FCError(@"UDP exit read failed")];return;}
        if(packet.length<4){[owner receiveUDP];return;}
        const uint8_t* p=(const uint8_t*)packet.bytes;NSUInteger count=0;
        NWHostEndpoint* endpoint=FCDecodeAddress(packet,3,&count);
        if(p[0]||p[1]||p[2]||!endpoint){[owner receiveUDP];return;}
        NSData* payload=[packet subdataWithRange:NSMakeRange(3+count,packet.length-3-count)];
        [(NEAppProxyUDPFlow*)owner.flow writeDatagrams:@[payload] sentByEndpoints:@[endpoint] completionHandler:^(NSError* failure){dispatch_async(owner.queue,^{if(failure)[owner close:failure];else [owner receiveUDP];});}];
    });
}
@end

@interface FCAETransparentProxy : NETransparentProxyProvider
@end
@implementation FCAETransparentProxy {
    dispatch_queue_t _queue;
    NSMutableSet<FCRelay*>* _flows;
    NSArray<NSString*>* _requirements;
    NSString* _ownRequirement;
    NSString* _port;
    NSNumber* _revision;
    NSString* _owner;
    NSUInteger _generation;
    NSUInteger _mode;
    BOOL _udp;
    BOOL _ready;
    BOOL _confirmed;
    dispatch_source_t _watchdog;
    CFAbsoluteTime _heartbeat;
}
- (instancetype)init {if((self=[super init])){_queue=dispatch_queue_create("com.fc.fcaevpn.app-routing",DISPATCH_QUEUE_SERIAL);_flows=[NSMutableSet set];}return self;}
- (BOOL)validCode:(SecCodeRef)code requirement:(NSString*)text {
    if(!code||!text.length)return NO;SecRequirementRef requirement=nullptr;
    if(SecRequirementCreateWithString((__bridge CFStringRef)text,kSecCSDefaultFlags,&requirement)!=errSecSuccess)return NO;
    BOOL valid=SecCodeCheckValidity(code,kSecCSDefaultFlags,requirement)==errSecSuccess;CFRelease(requirement);return valid;
}
- (void)startProxyWithOptions:(NSDictionary<NSString*,id>*)options completionHandler:(void (^)(NSError*))completion {
    dispatch_async(_queue,^{
        const NSUInteger generation=++self->_generation;
        NSDictionary* policy=((NETunnelProviderProtocol*)self.protocolConfiguration).providerConfiguration;
        NSArray* requirements=policy[@"requirements"];NSNumber* mode=policy[@"mode"];NSNumber* revision=policy[@"revision"];
        NSString* own=policy[@"ownRequirement"];NSNumber* port=policy[@"port"];
        if(![policy[@"schema"] isEqual:@1]||![requirements isKindOfClass:NSArray.class]||requirements.count>8192||
           ![mode isKindOfClass:NSNumber.class]||(mode.unsignedIntegerValue!=1&&mode.unsignedIntegerValue!=2)||
           ![policy[@"owner"] isKindOfClass:NSString.class]||![policy[@"owner"] length]||![revision isKindOfClass:NSNumber.class]||![own isKindOfClass:NSString.class]||!own.length||
           ![port isKindOfClass:NSNumber.class]||port.unsignedIntegerValue<1||port.unsignedIntegerValue>65535||
           (mode.unsignedIntegerValue==1&&!requirements.count)) {completion(FCError(@"Invalid signed app-routing policy"));return;}
        for(id requirement in requirements){SecRequirementRef parsed=nullptr;
            if(![requirement isKindOfClass:NSString.class]||[requirement length]>32768||SecRequirementCreateWithString((__bridge CFStringRef)requirement,kSecCSDefaultFlags,&parsed)!=errSecSuccess){completion(FCError(@"Invalid application signing requirement"));return;}
            CFRelease(parsed);
        }
        self->_requirements=[requirements copy];self->_ownRequirement=[own copy];self->_mode=mode.unsignedIntegerValue;
        self->_port=port.stringValue;self->_revision=revision;self->_owner=[policy[@"owner"] copy];self->_udp=[policy[@"udp"] boolValue];
        NETransparentProxyNetworkSettings* settings=[[NETransparentProxyNetworkSettings alloc] initWithTunnelRemoteAddress:@"127.0.0.1"];
        // Match outgoing TCP/UDP for both IP families. DNS remains shared OS
        // infrastructure; the UI must not advertise per-app DNS isolation.
        settings.includedNetworkRules=@[[[NENetworkRule alloc] initWithRemoteNetwork:nil remotePrefix:0 localNetwork:nil localPrefix:0 protocol:NENetworkRuleProtocolTCP direction:NETrafficDirectionOutbound],[[NENetworkRule alloc] initWithRemoteNetwork:nil remotePrefix:0 localNetwork:nil localPrefix:0 protocol:NENetworkRuleProtocolUDP direction:NETrafficDirectionOutbound]];
        __weak FCAETransparentProxy* startOwner=self;
        [self setTunnelNetworkSettings:settings completionHandler:^(NSError* error){FCAETransparentProxy* owner=startOwner;if(!owner){completion(FCError(@"Provider disappeared during start"));return;}dispatch_async(owner->_queue,^{
            FCAETransparentProxy* self=owner;
            if(generation!=self->_generation){completion(FCError(@"Provider activation was cancelled"));return;}
            if(error){completion(error);return;}self->_confirmed=NO;self->_ready=YES;self->_heartbeat=CFAbsoluteTimeGetCurrent();
            self->_watchdog=dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,self->_queue);
            dispatch_source_set_timer(self->_watchdog,dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC),2*NSEC_PER_SEC,NSEC_PER_SEC/4);
            __weak FCAETransparentProxy* weak=self;
            dispatch_source_set_event_handler(self->_watchdog,^{FCAETransparentProxy* owner=weak;if(owner&&CFAbsoluteTimeGetCurrent()-owner->_heartbeat>12){[owner finish];[owner cancelProxyWithError:FCError(@"FCAE exit-chain owner stopped responding")];}});
            dispatch_resume(self->_watchdog);completion(nil);
        });}];
    });
}
- (void)finish {
    ++_generation;_ready=NO;_confirmed=NO;if(_watchdog){dispatch_source_cancel(_watchdog);_watchdog=nil;}
    for(FCRelay* relay in _flows.allObjects)[relay close:FCError(@"Application routing stopped")];[_flows removeAllObjects];
}
- (void)stopProxyWithReason:(NEProviderStopReason)reason completionHandler:(void (^)(void))completion {dispatch_async(_queue,^{[self finish];completion();});}
- (BOOL)handleNewFlow:(NEAppProxyFlow*)flow {
    // Synchronously decide before returning from the platform hook; all mutable
    // policy/lifecycle state otherwise stays on the provider's owned queue.
    __block BOOL handled=YES;
    dispatch_sync(_queue,^{
        if(!self->_ready||!self->_confirmed){[flow closeReadWithError:FCError(@"Provider not ready")];[flow closeWriteWithError:FCError(@"Provider not ready")];return;}
        NSData* token=flow.metaData.sourceAppAuditToken;SecCodeRef code=nullptr;
        if([token isKindOfClass:NSData.class]&&token.length==32)SecCodeCopyGuestWithAttributes(nullptr,(__bridge CFDictionaryRef)@{(__bridge NSString*)kSecGuestAttributeAudit:token},kSecCSDefaultFlags,&code);
        if([self validCode:code requirement:self->_ownRequirement])handled=NO;
        else {
            BOOL selected=NO;
            for(NSString* requirement in self->_requirements)if([self validCode:code requirement:requirement]){selected=YES;break;}
            // Unknown owner is conservatively VPN-required, never inferred from
            // a PID, source-IP guess, unsigned path or app-provided bundle ID.
            BOOL identityKnown=code&&SecCodeCheckValidity(code,kSecCSDefaultFlags,nullptr)==errSecSuccess;
            BOOL vpn=!identityKnown || (self->_mode==1?selected:!selected);
            if(!vpn)handled=NO;
            else if(self->_flows.count>=256||(![flow isKindOfClass:NEAppProxyTCPFlow.class]&&![flow isKindOfClass:NEAppProxyUDPFlow.class])) {
                [flow closeReadWithError:FCError(@"App-routing flow capacity or protocol unsupported")];[flow closeWriteWithError:FCError(@"App-routing flow capacity or protocol unsupported")];
            } else {
                FCRelay* relay=[FCRelay new];relay.flow=flow;relay.udpAllowed=self->_udp;
                __weak FCAETransparentProxy* weak=self;relay.finished=^(FCRelay* done){FCAETransparentProxy* owner=weak;if(owner)[owner->_flows removeObject:done];};
                [self->_flows addObject:relay];[relay startPort:self->_port queue:self->_queue];
            }
        }
        if(code)CFRelease(code);
    });return handled;
}
- (void)handleAppMessage:(NSData*)message completionHandler:(void (^)(NSData*))completion {
    dispatch_async(_queue,^{
        NSDictionary* request=message.length<=4096?[NSJSONSerialization JSONObjectWithData:message options:0 error:nullptr]:nil;
        BOOL matches=[request isKindOfClass:NSDictionary.class]&&[request[@"revision"] isEqual:self->_revision]&&[request[@"schema"] isEqual:@1]&&[request[@"owner"] isEqual:self->_owner];
        if(matches&&self->_ready){self->_heartbeat=CFAbsoluteTimeGetCurrent();self->_confirmed=YES;}
        if(completion)completion([NSJSONSerialization dataWithJSONObject:@{@"schema":@1,@"revision":self->_revision?:@0,@"active":@(matches&&self->_ready),@"flows":@(self->_flows.count)} options:0 error:nullptr]);
    });
}
@end
