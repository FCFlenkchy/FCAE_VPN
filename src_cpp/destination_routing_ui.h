#pragma once
#include "ui_render.h"
#include "ui_text_input.h"

// Shared editor: Android package inventory is deliberately not involved in
// destination matching. Packet and flow bridges receive the same policy.
inline void destination_routing_ui() {
    if(!ImGui::CollapsingHeader("Destination split tunneling"))return;
    const bool available=fcae_destination_routing_available();
    if(!available)ImGui::TextWrapped("This build has no embedded destination router. Saved rules are retained; turn them off to connect with this build.");
    ImGui::TextWrapped("Applies to captured VPN traffic only, on reconnect. OS-excluded apps and LAN exclusions remain outside capture. DNS ports 53/853 stay on the configured VPN exit. VPN means the existing exit chain, including its native rules.");
    ImGui::TextWrapped("Domains use observable SOCKS, TLS, HTTP or QUIC hostnames, not shared destination IPs. Encrypted or missing hostnames cannot match. Include mode keeps unknown-host traffic on the VPN when domain rules exist. *.example.com matches subdomains, not example.com.");
    static char target[1025]={}, ports[1025]={}, error[1024]={};
    static int kind=0,protocol=0;
    static const char* kinds[]={"IP / CIDR","Domain / wildcard","Port only"};
    static const char* protocols[]={"TCP + UDP","TCP","UDP"};
    static const char* kind_keys[]={"ip","domain","port"};
    static const char* protocol_keys[]={"both","tcp","udp"};
    static const char* modes[]={"Off","Include matches in VPN","Exclude matches from VPN"};
    ImGui::BeginDisabled(!available);
    int mode=g_app.destination_mode;
    if(ImGui::Combo("Destination mode",&mode,modes,3)) {
        int previous=g_app.destination_mode;g_app.destination_mode=mode;
        if(fcae_destination_rules_validate(g_app.destination_policy_json().c_str(),error,sizeof(error))!=FCAE_OK)g_app.destination_mode=previous;
    }
    ImGui::Combo("Rule type",&kind,kinds,3);
    if(kind!=2)UiText::InputTextWithHint("Target",kind==0?"192.0.2.1 or 192.0.2.0/24":"example.com or *.example.com",target,sizeof(target));
    UiText::InputTextWithHint("Ports",kind==2?"443 or 8000-8080 or 53,443":"Empty = all ports; e.g. 443,8000-8080",ports,sizeof(ports));
    ImGui::Combo("Protocol",&protocol,protocols,3);
    if(ImGui::Button("Add destination rule")) {
        auto safe=[](const char* text){for(const unsigned char* p=(const unsigned char*)text;*p;++p)if(*p<' '||*p=='|'||*p==127)return false;return true;};
        std::string previous=g_app.destination_rows;
        std::string row=std::string(kind_keys[kind])+"|"+protocol_keys[protocol]+"|"+ports+"|"+(kind==2?"":target)+"\n";
        if(!safe(target)||!safe(ports))snprintf(error,sizeof(error),"Control characters and | are not allowed.");
        else if(previous.size()+row.size()>=sizeof(g_app.destination_rows))snprintf(error,sizeof(error),"Destination storage is full.");
        else {
            snprintf(g_app.destination_rows,sizeof(g_app.destination_rows),"%s",(previous+row).c_str());
            if(fcae_destination_rules_validate(g_app.destination_policy_json().c_str(),error,sizeof(error))!=FCAE_OK)snprintf(g_app.destination_rows,sizeof(g_app.destination_rows),"%s",previous.c_str());
            else {target[0]=ports[0]=0;}
        }
    }
    std::string rows=g_app.destination_rows;size_t start=0;int index=0;
    while(start<rows.size()) {
        size_t end=rows.find('\n',start);if(end==std::string::npos)end=rows.size();
        auto row=rows.substr(start,end-start);
        ImGui::PushID(index++);
        if(ImGui::SmallButton("Remove")) {
            auto remaining=rows.substr(0,start)+(end<rows.size()?rows.substr(end+1):"");
            // Removing the last include rule disables the destination policy.
            if(remaining.empty())g_app.destination_mode=0;
            snprintf(g_app.destination_rows,sizeof(g_app.destination_rows),"%s",remaining.c_str());
        }
        ImGui::SameLine();ImGui::TextWrapped("%s",row.c_str());ImGui::PopID();start=end+1;
    }
    ImGui::EndDisabled();
    if(error[0])ImGui::TextWrapped("%s",error);
}
