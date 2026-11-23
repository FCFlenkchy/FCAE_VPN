#pragma once
#include "ui_render.h"
#include "ui_text_input.h"

inline void destination_routing_ui() {
    constexpr const char* title="Destinations##destination_picker";
    if(ImGui::Button("Add destination"))ImGui::OpenPopup(title);
    auto* viewport=ImGui::GetMainViewport();
    const ImVec2 room(std::max(1.0f,viewport->WorkSize.x-24),std::max(1.0f,viewport->WorkSize.y-24));
    ImGui::SetNextWindowPos(viewport->GetWorkCenter(),ImGuiCond_Always,ImVec2(0.5f,0.5f));
    ImGui::SetNextWindowSize(ImVec2(std::min(640.0f,room.x),std::min(620.0f,room.y)),ImGuiCond_Always);
    ImGui::SetNextWindowSizeConstraints(ImVec2(1,1),room);
    bool opened=true;
    if(!ImGui::BeginPopupModal(title,&opened,ImGuiWindowFlags_NoCollapse|ImGuiWindowFlags_NoMove|ImGuiWindowFlags_NoResize))return;
    static char target[1025]={},ports[1025]={},error[1024]={};
    static int kind=0,protocol=0,editing=-1;
    static std::string editing_row;
    static const char* kinds[]={"IP / CIDR","Domain / wildcard","Port only"};
    static const char* protocols[]={"TCP + UDP","TCP","UDP"};
    static const char* kind_keys[]={"ip","domain","port"};
    static const char* protocol_keys[]={"both","tcp","udp"};
    static const char* modes[]={"Off", "Include matches (whitelist)", "Exclude matches (blacklist)"};
    const bool available=fcae_destination_routing_available();
    if(!available)ImGui::TextDisabled("Destination routing unavailable in this build.");
    ImGui::BeginChild("##destination_body",ImVec2(0,-ImGui::GetFrameHeightWithSpacing()),ImGuiChildFlags_None);
    ImGui::TextUnformatted("Destination split tunneling");
    ImGui::SetNextItemWidth(-1);
    int mode=g_app.destination_mode;
    if(ImGui::Combo("##destination_mode",&mode,modes,3)) {
        int previous=g_app.destination_mode;g_app.destination_mode=mode;
        if(mode!=0 && !available){g_app.destination_mode=previous;snprintf(error,sizeof(error),"Destination routing is unavailable; Off remains available.");}
        else if(mode!=0 && fcae_destination_rules_validate(g_app.destination_policy_json().c_str(),error,sizeof(error))!=FCAE_OK)g_app.destination_mode=previous;
        else error[0]=0;
        mode=g_app.destination_mode;
    }
    ImGui::Separator();
    ImGui::BeginDisabled(!available);
    ImGui::Combo("Rule type",&kind,kinds,3);
    if(kind!=2)UiText::InputTextWithHint("Target",kind==0?"192.0.2.1 or 192.0.2.0/24":"example.com or *.example.com",target,sizeof(target));
    UiText::InputTextWithHint("Ports","Empty = all ports; e.g. 443,8000-8080",ports,sizeof(ports));
    ImGui::Combo("Protocol",&protocol,protocols,3);
    if(ImGui::Button(editing<0?"Add rule":"Save rule")) {
        auto safe=[](const char* text){for(const unsigned char* p=(const unsigned char*)text;*p;++p)if(*p<' '||*p=='|'||*p==127)return false;return true;};
        std::string previous=g_app.destination_rows,next;
        std::string row=std::string(kind_keys[kind])+"|"+protocol_keys[protocol]+"|"+ports+"|"+(kind==2?"":target)+"\n";
        bool found=editing<0;size_t start=0;int index=0;
        while(start<previous.size()) {
            auto end=previous.find('\n',start);if(end==std::string::npos)end=previous.size();
            auto old=previous.substr(start,end-start);
            if(index++==editing){if(old==editing_row){next+=row;found=true;}}
            else next+=old+"\n";
            start=end+1;
        }
        if(editing<0)next+=row;
        if(!found)snprintf(error,sizeof(error),"Rule changed; select Edit again.");
        else if(!safe(target)||!safe(ports))snprintf(error,sizeof(error),"Invalid characters in rule.");
        else if(next.size()>=sizeof(g_app.destination_rows))snprintf(error,sizeof(error),"Destination storage is full.");
        else {
            snprintf(g_app.destination_rows,sizeof(g_app.destination_rows),"%s",next.c_str());
            if(fcae_destination_rules_validate(g_app.destination_policy_json().c_str(),error,sizeof(error))!=FCAE_OK)snprintf(g_app.destination_rows,sizeof(g_app.destination_rows),"%s",previous.c_str());
            else {target[0]=ports[0]=0;editing=-1;editing_row.clear();}
        }
    }
    if(editing>=0){ImGui::SameLine();if(ImGui::Button("Cancel edit")){editing=-1;editing_row.clear();target[0]=ports[0]=error[0]=0;}}
    if(error[0])ImGui::TextWrapped("%s",error);
    ImGui::Separator();
    std::string rows=g_app.destination_rows;size_t start=0;int index=0;
    while(start<rows.size()) {
        size_t end=rows.find('\n',start);if(end==std::string::npos)end=rows.size();
        auto row=rows.substr(start,end-start);auto a=row.find('|');auto b=a==std::string::npos?a:row.find('|',a+1);auto c=b==std::string::npos?b:row.find('|',b+1);
        ImGui::PushID(index);
        if(ImGui::SmallButton("Edit")&&c!=std::string::npos){
            kind=row.substr(0,a)=="domain"?1:row.substr(0,a)=="port"?2:0;
            auto proto=row.substr(a+1,b-a-1);protocol=proto=="tcp"?1:proto=="udp"?2:0;
            snprintf(ports,sizeof(ports),"%s",row.substr(b+1,c-b-1).c_str());snprintf(target,sizeof(target),"%s",row.substr(c+1).c_str());
            editing=index;editing_row=row;error[0]=0;
        }
        ImGui::SameLine();
        if(ImGui::SmallButton("Remove")) {
            auto remaining=rows.substr(0,start)+(end<rows.size()?rows.substr(end+1):"");
            snprintf(g_app.destination_rows,sizeof(g_app.destination_rows),"%s",remaining.c_str());
            editing=-1;editing_row.clear();target[0]=ports[0]=error[0]=0;
        }
        ImGui::SameLine();
        if(c!=std::string::npos){
            auto name=row.substr(c+1);if(name.empty())name="All destinations";
            auto selected_ports=row.substr(b+1,c-b-1);if(selected_ports.empty())selected_ports="all ports";
            auto proto=row.substr(a+1,b-a-1);if(proto=="both")proto="TCP + UDP";
            ImGui::TextWrapped("%s · %s · %s",name.c_str(),selected_ports.c_str(),proto.c_str());
        } else ImGui::TextUnformatted("Invalid saved rule");
        ImGui::PopID();start=end+1;++index;
    }
    ImGui::EndDisabled();ImGui::EndChild();
    if(ImGui::Button("Close"))ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}
