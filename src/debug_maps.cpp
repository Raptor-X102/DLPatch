#include <iostream>
#include <fstream>
#include <string>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pid>" << std::endl;
        return -1;
    }

    pid_t pid = atoi(argv[1]);
    std::string maps_path = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream file(maps_path);
    std::string line;

    std::cout << "Contents of /proc/" << pid << "/maps:\n";
    while (std::getline(file, line)) {
        if (line.find(".so") != std::string::npos) {
            std::cout << line << std::endl;
        }
    }

    return 0;
}
