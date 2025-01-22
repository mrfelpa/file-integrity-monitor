#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <iomanip>
#include <sys/stat.h>
#include <ctime>

class FileIntegrityMonitor {
private:
    struct FileInfo {
        std::string path;
        std::string hash;
        std::chrono::system_clock::time_point lastCheck;
        uintmax_t size;
        time_t modTime;
    };

    std::unordered_map<std::string, FileInfo> fileRegistry;
    std::mutex registryMutex;
    std::vector<std::string> criticalPaths;
    bool isRunning;
    int scanIntervalSeconds;

    uintmax_t getFileSize(const std::string& filePath) {
        struct stat statbuf;
        if (stat(filePath.c_str(), &statbuf) != 0) {
            return 0;
        }
        return statbuf.st_size;
    }

    time_t getLastModifiedTime(const std::string& filePath) {
        struct stat statbuf;
        if (stat(filePath.c_str(), &statbuf) != 0) {
            return 0;
        }
        return statbuf.st_mtime;
    }

    bool fileExists(const std::string& filePath) {
        struct stat statbuf;
        return (stat(filePath.c_str(), &statbuf) == 0);
    }

    std::string calculateSimpleHash(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) {
            std::cerr << "Erro ao abrir arquivo: " << filePath << std::endl;
            return "";
        }

        const size_t bufferSize = 8192;
        char buffer[bufferSize];
        uint64_t hash = 0x1505; 

        while (file.read(buffer, bufferSize)) {
            size_t count = file.gcount();
            for (size_t i = 0; i < count; ++i) {
                hash ^= static_cast<uint64_t>(buffer[i]) << 8;
                hash = (hash << 7) | (hash >> 57); 
                hash *= 0x100000001b3; 
        }

        std::stringstream ss;
        ss << std::hex << std::setfill('0') << std::setw(16) << hash;
        return ss.str();
    }

    bool hasFileChanged(const std::string& path, const FileInfo& oldInfo) {
        try {
            auto currentSize = getFileSize(path);
            auto currentTime = getLastModifiedTime(path);

            // Primeiro verifica mudanças no tamanho e timestamp
            if (currentSize != oldInfo.size || currentTime != oldInfo.modTime) {
                return true;
            }

            // Se houver mudança nos metadados, calcula o hash
            std::string currentHash = calculateSimpleHash(path);
            return currentHash != oldInfo.hash;
        }
        catch (const std::exception& e) {
            std::cerr << "Erro ao verificar arquivo " << path << ": " << e.what() << std::endl;
            return true; 
        }
    }

public:
    FileIntegrityMonitor(const std::vector<std::string>& paths, int interval = 60)
        : criticalPaths(paths), isRunning(false), scanIntervalSeconds(interval) {
        initializeRegistry();
    }

    void initializeRegistry() {
        std::lock_guard<std::mutex> lock(registryMutex);
        for (const auto& path : criticalPaths) {
            if (fileExists(path)) {
                FileInfo info{
                    path,
                    calculateSimpleHash(path),
                    std::chrono::system_clock::now(),
                    getFileSize(path),
                    getLastModifiedTime(path)
                };
                fileRegistry[path] = info;
                std::cout << "Arquivo registrado: " << path << std::endl;
            }
            else {
                std::cerr << "Arquivo não encontrado: " << path << std::endl;
            }
        }
    }

    void start() {
        isRunning = true;
        std::cout << "Iniciando monitoramento de arquivos..." << std::endl;

        while (isRunning) {
            checkIntegrity();
            std::this_thread::sleep_for(std::chrono::seconds(scanIntervalSeconds));
        }
    }

    void stop() {
        isRunning = false;
        std::cout << "Parando monitoramento de arquivos..." << std::endl;
    }

    void checkIntegrity() {
        std::lock_guard<std::mutex> lock(registryMutex);

        for (auto& pair : fileRegistry) {
            const std::string& path = pair.first;
            FileInfo& info = pair.second;

            if (!fileExists(path)) {
                std::cerr << "ALERTA: Arquivo removido ou inacessível: " << path << std::endl;
                continue;
            }

            if (hasFileChanged(path, info)) {
                std::cout << "ALERTA: Alteração detectada em: " << path << std::endl;

                info.hash = calculateSimpleHash(path);
                info.lastCheck = std::chrono::system_clock::now();
                info.size = getFileSize(path);
                info.modTime = getLastModifiedTime(path);
            }
        }
    }

    bool addFile(const std::string& path) {
        if (!fileExists(path)) {
            std::cerr << "Arquivo não existe: " << path << std::endl;
            return false;
        }

        std::lock_guard<std::mutex> lock(registryMutex);
        try {
            FileInfo info{
                path,
                calculateSimpleHash(path),
                std::chrono::system_clock::now(),
                getFileSize(path),
                getLastModifiedTime(path)
            };

            fileRegistry[path] = info;
            std::cout << "Novo arquivo adicionado ao monitoramento: " << path << std::endl;
            return true;
        }
        catch (const std::exception& e) {
            std::cerr << "Erro ao adicionar arquivo: " << e.what() << std::endl;
            return false;
        }
    }
};

int main() {
    try {
      
        std::vector<std::string> paths = {
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\Windows\\System32\\drivers\\etc\\services"
        };

        FileIntegrityMonitor monitor(paths, 60);

        // Inicia o monitoramento
        monitor.start();
    }
    catch (const std::exception& e) {
        std::cerr << "Erro: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
