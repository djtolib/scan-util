#include <iostream>
#include <filesystem>
#include <fstream>
#include <ctime>
using namespace  std;

int main(int argc, char** argv) {

    //Timing
    struct timespec t_begin, t_end;
    clock_gettime(CLOCK_REALTIME, &t_begin);

    filesystem::path path = argv[1];
    if(!is_directory(path)){
        cout<<"Directory is not exists."<<endl;
        return 1;
    }

    string command_unix_suspicious, command_js_suspicious, command_mac_suspicious;

    // Unix
    command_unix_suspicious.append(R"(grep -l  "rm -rf ~/Documents" )");
    command_unix_suspicious.append(path.string());
    command_unix_suspicious.append(R"(/* 2>errs | wc -l > out.tmp )");

    //JavaScript
    command_js_suspicious.append(R"(grep -l  "<script>evil_script()</script>" )");
    command_js_suspicious.append(path.string());
    command_js_suspicious.append(R"(/*.js 2>errs | wc -l >> out.tmp )");

    //Mac
    command_mac_suspicious.append(
            "grep -l  \"system(\\\"launchctl load /Library/LaunchAgents/com.malware.agent\\\")\" ");
    command_mac_suspicious.append(path.string());
    command_mac_suspicious.append(R"(/* 2>errs | wc -l >> out.tmp )");

    // Executing my pretty commands:)
    system(command_unix_suspicious.c_str());
    system(command_js_suspicious.c_str());
    system(command_mac_suspicious.c_str());

    // Count of errors(e.g permission denied)
    system("cat errs | wc -l  >> out.tmp");

    // Reading results from file
    ifstream myfile("out.tmp");
    string mac_count, unix_count, js_count, err_count;

    getline(myfile, unix_count);
    getline(myfile, js_count);
    getline(myfile, mac_count);
    getline(myfile, err_count);

    myfile.close();

    int total_count = stoi(unix_count) + stoi(js_count) + stoi(mac_count) + stoi(err_count);

    clock_gettime(CLOCK_REALTIME, &t_end);
    long total_second = t_end.tv_sec - t_begin.tv_sec;
    int secs = total_second % 60;
    int mins = (total_second / 60) % 60;
    int hours = mins / 60;

    cout<<"====== Scan result ======"<<endl
    <<"Processed files: "<<total_count<<endl
    <<"JS detects: "<<js_count<<endl
    <<"Unix detects: "<<unix_count<<endl
    <<"macOS detects: "<<mac_count<<endl
    <<"Errors: "<<err_count<<endl
    <<"Execution time: "<<setfill('0')<<setw(2)<<hours<<":"<<setfill('0')<<setw(2)<<mins<<":"
        <<setfill('0')<<setw(2)<<secs<<endl
    <<"========================="<<endl;
    return 0;
}
