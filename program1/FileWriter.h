#include <fstream>
#include <iostream>

class FileWriter {
private:
    std::ofstream fout;
public:
    FileWriter(const char* name, std::ios_base::openmode mode = std::ios_base::out) {
        fout.open(name, mode);
        if (!fout.is_open()) {
            std::cout << "Can't open file\n";
        }
    }
    template<typename T>
    std::ostream& operator<<(T& data) {
        fout << data;
        return fout;   
    }

    ~FileWriter() {
        if (fout.is_open())
            fout.close();
    }
};