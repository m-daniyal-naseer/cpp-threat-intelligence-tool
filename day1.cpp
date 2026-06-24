#include<nlohmann/json.hpp>

#include<iostream>
#include<vector>
#include<sstream>
#include<fstream>
#include<curl/curl.h>
using json = nlohmann::json;
using namespace std;
class Threat{
    private:
    string Ip;
    string Level;
    public:
    void setdata (string p,string level)
    {
        Level = level;
        Ip = p;
    }
    void display()
    {
        cout<<"IP:"<<Ip<<endl;
        cout<<"threat level:"<<Level<<endl;
    }
    string getip ()
    {
        return Ip;
    }
    string getlvl ()
    {
        return Level;
    }


};
    bool isvalidip (string ip)
{
    stringstream ss(ip);
    string part;
    int count = 0;

    while(getline(ss, part, '.')) {
        count++;
        int num = stoi(part);
        if(num < 0 || num > 255) {
            cout << "Invalid IP!" << endl;
            return false;
        }
    }

    if(count != 4) {
        cout << "Wrong format!" << endl;
        return false;
    }

    return true;
}


size_t WriteCallback(void* contents, size_t size, size_t nmemb, string* output) {
    output->append((char*)contents, size * nmemb);
    return size * nmemb;
}
string checkip(string ip)
{
    CURL* curl;
    string response;
    curl = curl_easy_init();
     if(curl) {
        string url = "https://api.abuseipdb.com/api/v2/check?ipAddress=" + ip;
        string apikey = "your abuseip api key here"; 

        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, ("Key: " + apikey).c_str());
        headers = curl_slist_append(headers, "Accept: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        try{
     json data = json::parse(response);
     int score = data["data"]["abuseConfidenceScore"];
     string country = data["data"]["countryCode"];
     int reports = data["data"]["totalReports"];
     cout<<endl<<"----------------------------"<<endl;
 
     cout << "Abuse Score: " << score << "/100" << endl;
     cout << "Country: " << country << endl;
     cout << "Total Reports: " << reports << endl;
     cout<<endl<<"----------------------------"<<endl;

     if(score > 75) return "HIGH";
     else if(score > 25) return "MEDIUM";
     else return "LOW";

     }
     catch(...){
    cout<<"the check ip is unable to get response!"<<endl;
    cout<<endl<<"----------------------------"<<endl;
    return "UNKNOWN";
}
     if(ip.substr(0,4) == "192." || ip.substr(0,3) == "10." || ip.substr(0,8) == "172.16.") {
    cout << "Private IP skipping external check." << endl;
    cout<<endl<<"----------------------------"<<endl;
    return "private"; 
   
}
     }
     return "UNKNOWN";
     

}
void getlocation (string ip)
{
    CURL* curl;
    string response;
    curl = curl_easy_init();
    if(curl) {  
    string apikey ="your apikey for ipstack";
    string url = "http://api.ipstack.com/"+ip+"?access_key="+ apikey;

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        curl_easy_perform(curl);
        
        curl_easy_cleanup(curl);
        try{ 
        json data = json::parse(response);
        if(data.contains("country_name") && !data["country_name"].is_null())
        {
        
         string countryname =data["country_name"];
         string city =data["city"];
         string zip =data["zip"];
         string isp =data["connection"]["isp"];
         cout << "Country: " << countryname << endl;
         cout << "City: " << city << endl;
         cout << "Zip: " << zip << endl;
         cout<<"isp:"<<isp<<endl;
         cout<<endl<<"----------------------------"<<endl;
        }
        else
        {
            cout<<"could not retrieve location data"<<endl;
            cout<<endl<<"----------------------------"<<endl;
        }
    }
    catch(...){
        cout<<"the location response is empty or invalid"<<endl;
        cout<<endl<<"----------------------------"<<endl;
    }

    }
    
    if(ip.substr(0,4) == "192." || ip.substr(0,3) == "10." || ip.substr(0,8) == "172.16.") {
    cout << "Private IP skipping external check." << endl;
    cout<<endl<<"----------------------------"<<endl;
    return; 

}
     

}
string checkvirustotal(string ip)
{
    CURL* curl;
    string response;
    curl = curl_easy_init();
     if(curl) {
        string url = "https://www.virustotal.com/api/v3/ip_addresses/" + ip;
        string x_apikey = "your virustotal apikey here"; 

        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, ("x-apikey: " + x_apikey).c_str());
        headers = curl_slist_append(headers, "Accept: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        

        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
       

       try{
        json data = json::parse(response);
        int malicious = data["data"]["attributes"]["last_analysis_stats"]["malicious"];
        int suspicious = data["data"]["attributes"]["last_analysis_stats"]["suspicious"];
        int harmless = data["data"]["attributes"]["last_analysis_stats"]["harmless"];

        cout << "VirusTotal Results:" << endl;
        cout << "Malicious: " << malicious << endl;
        cout << "Suspicious: " << suspicious << endl;
        cout << "Harmless: " << harmless << endl;

        if(malicious > 5) return "HIGH";
        else if(malicious > 0) return "MEDIUM";
        else return "LOW";
 
    }
   catch(...)
    {
        cout<<"checkvirustotal didnot return anything!"<<endl;
        cout<<endl<<"----------------------------"<<endl;
        return "unknown";

    }
    }
    return "unknown";
}
        
int main ()
{
  string ip,lvl;
 vector <Threat> threat;
  int n,choice;
 do{ 

   cout << "\n=====================================" << endl;
cout << "     THREAT INTELLIGENCE SYSTEM" << endl;
cout << "=====================================" << endl;
cout << "1. Add Threat" << endl;
cout << "2. Display All" << endl;
cout << "3. Search by IP" << endl;
cout << "4. Delete Threat" << endl;
cout << "5. Filter by Level" << endl;
cout << "7. Exit" << endl;
cout << "=====================================" << endl;
cout << "Enter choice: ";
cin>>choice;
switch(choice){
    case 1:
    {
    cout<<"ADD New Threat:"<<endl;
    cout<<"enter IP:";
    cin>>ip;
    if(!isvalidip(ip)){
        break;
    }
    lvl = checkip(ip);
    getlocation(ip);
    string vtlevel = checkvirustotal(ip);

    
    if(lvl == "HIGH" || vtlevel == "HIGH") lvl="HIGH";
    else if(lvl =="MEDIUM" || vtlevel == "MEDIUM") lvl="MEDIUM";
    else lvl="LOW";
    cout<<"Final Verdict:"<<lvl<<endl;
    Threat t;
    t.setdata(ip, lvl );
    threat.push_back(t);
    ofstream file("Threats.txt",ios::app);
    file<<ip<<endl<<lvl<<endl;
    file.close();
    break;
}

case 2: {
    cout << "\n--- All Stored Threats ---" << endl;
    if(threat.empty())
    {
        cout<<"No Threat stored!"<<endl;
        cout<<endl<<"----------------------------"<<endl;
    }
    else{
    int count = threat.size();
    for (int i = 0; i < count; i++)
    {
       threat[i].display();
       cout<<endl<<"----------------------------"<<endl;
    }
    
}
break;
}
case 3:{
    if(threat.empty()) {
    cout << "No threats stored yet." << endl;
    cout<<endl<<"----------------------------"<<endl;
    break;
}
else{
string sip;
cout<<"enter the ip you want to search:"<<endl;
cin>>sip;
bool check=false;
for(int i=0;i<threat.size();i++)
{
    if(sip==threat[i].getip())
    {
        cout<<sip<<endl;
        cout<<threat[i].getlvl();
        cout<<endl;
        check=true;
        cout<<endl<<"----------------------------"<<endl;
    }
}
if(check!=true)
{
    cout<<"not found"<<endl;
    cout<<endl<<"----------------------------"<<endl;
}
}
break;

}
case 4:{
    if(threat.empty()) {
    cout << "No threats stored yet." << endl;
    cout<<endl<<"----------------------------"<<endl;
    break;
}
else{
string eip;
cout<<"enter the ip you want to erase:"<<endl;
cin>>eip;
bool check=false;
for(int i=0;i<threat.size();i++)
{
    if(eip==threat[i].getip())
    {
     threat.erase(threat.begin()+i);
        cout<<endl;
        check=true;
        cout<<endl<<"----------------------------"<<endl;
    }
}
if(check!=true)
{
    cout<<"not found"<<endl;
    cout<<endl<<"----------------------------"<<endl;
}
}
break;

}
case 5:
{
    if(threat.empty()) {
    cout << "No threats stored yet." << endl;
    cout<<endl<<"----------------------------"<<endl;
    break;
}
else{
    string slvl;
    bool check=false;
    cout<<"enter threat level for search:"<<endl;
    cin>>slvl;
    for(int i=0;i<threat.size();i++)
    {
        if(slvl==threat[i].getlvl())
        {
            cout<<threat[i].getip()<<endl<<threat[i].getlvl()<<endl;
            check=true;
            cout<<endl<<"----------------------------"<<endl;
        }
    }
    if(!check)
    {
        cout<<"no match found"<<endl;
        cout<<endl<<"----------------------------"<<endl;
    }
}
    break;
}
case 7:
 cout<<"Exiting..."<<endl;
 break;
default:
cout<<"Invalid input"<<endl;    
}
cout<<endl<<"           ------------------END OF REPORT----------------------"<<endl;
}

while(choice!=7);
     return 0;
}