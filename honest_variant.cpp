#include <iostream>
#include <filesystem>
#include <fstream>
#include <chrono>

using namespace std;

int main(int argc, char** argv) {

    //Timing
    auto begin = chrono::high_resolution_clock::now();

    filesystem::path path = argv[1];
    if(!is_directory(path)){
        cout<<"Directory is not exists."<<endl;
        return 1;
    }

    ifstream file;
    string line;
    int unix_suspicious = 0, js_suspicious = 0, mac_suspicious = 0, errors = 0, total_count = 0;

    for(auto &p : filesystem::directory_iterator(path)) {
        if (!p.is_directory()) {
            ++total_count;
            file.open(p.path(), ios_base::in);
            if (file.is_open()) {
                while (getline(file, line)) {
                    if (line.find("rm -rf ~/Documents") != string::npos) {
                        ++unix_suspicious;
                        break;
                    }
                    if (line.find("system(\"launchctl load /Library/LaunchAgents/com.malware.agent\")") !=
                        string::npos) {
                        ++mac_suspicious;
                        break;
                    }
                    if (p.path().extension().string() == ".js" &&
                        line.find("<script>evil_script()</script>") != string::npos) {
                        ++js_suspicious;
                        break;
                    }
                }
                file.close();
            }
            else ++errors;
        }// end of not directory if
    }// end of for

    auto end = chrono::high_resolution_clock::now();

    // Chrono plays
    int secs = chrono::duration_cast<chrono::seconds>(end - begin).count() % 60;
    int mins = chrono::duration_cast<chrono::minutes>(end - begin).count()  % 60;
    int hours = chrono::duration_cast<chrono::hours>(end - begin).count() ;

    // Outputting
    cout<<"====== Scan result ======"<<endl
        <<"Processed files: "<< total_count<<endl
        <<"JS detects: "<<js_suspicious<<endl
        <<"Unix detects: "<<unix_suspicious<<endl
        <<"macOS detects: "<<mac_suspicious<<endl
        <<"Errors: "<<errors<<endl
        <<"Execution time: "<<setfill('0')<<setw(2)<<hours<<":"<<setfill('0')<<setw(2)<<mins<<":"
        <<setfill('0')<<setw(2)<<secs<<endl
        <<"========================="<<endl;

}
