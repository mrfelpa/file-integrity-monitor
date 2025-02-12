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
#include <filesystem>
#include <stdexcept>
#include <csignal>
#include <future>
#include <random>
#include <algorithm>

namespace fs = std::filesystem;

class ConfigurationError : public std::runtime_error {
public:
    ConfigurationError(const std::string& message) : std::runtime_error(message) {}
};

class HashMismatchError : public std::runtime_error {
public:
    HashMismatchError(const std::string& message) : std::runtime_error(message) {}
};


class FileIntegrityMonitor {
private:
    struct FileInfo {
        std::string hash;
        std::uintmax_t size;
        std::time_t modTime;
    };

    std::unordered_map<std::string, FileInfo> fileRegistry;
    std::mutex registryMutex;
    std::vector<std::string> criticalPaths;
    bool isRunning;
    int scanIntervalSeconds;
    std::ofstream logFile;
    std::string logFilePath;
    std::hash<std::string> stringHasher;
    std::random_device rd;
    std::mt19937 gen;
    std::uniform_int_distribution<> distrib;

    void logMessage(const std::string& message) {
        std::lock_guard<std::mutex> lock(registryMutex);
        auto now = std::chrono::system_clock::now();
        auto now_c = std::chrono::system_clock::to_time_t(now);
        std::tm now_tm = *std::localtime(&now_c);
        logFile << "[" << std::put_time(&now_tm, "%Y-%m-%d %H:%M:%S") << "] " << message << std::endl;
        std::cerr << "[" << std::put_time(&now_tm, "%Y-%m-%d %H:%M:%S") << "] " << message << std::endl;

    }


    std::uintmax_t getFileSize(const std::string& filePath) {
        try {
            return fs::file_size(filePath);
        } catch (const fs::filesystem_error& e) {
            logMessage("Error getting file size for " + filePath + ": " + e.what());
            return 0;
        }
    }

    std::time_t getLastModifiedTime(const std::string& filePath) {
        try {
            return fs::last_write_time(filePath).time_since_epoch().count() / std::chrono::system_clock::period::den;
        } catch (const fs::filesystem_error& e) {
             logMessage("Error getting last modified time for " + filePath + ": " + e.what());
            return 0;
        }
    }


    bool fileExists(const std::string& filePath) {
        return fs::exists(filePath);
    }


    std::string calculateHash(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) {
            logMessage("Error opening file: " + filePath);
            throw std::runtime_error("Failed to open file for hashing: " + filePath);
        }

        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string content = buffer.str();
        size_t hashValue = stringHasher(content);
        std::stringstream ss;
        ss << std::hex << hashValue;
        return ss.str();
    }


    bool hasFileChanged(const std::string& path, const FileInfo& oldInfo) {
        try {
            std::uintmax_t currentSize = getFileSize(path);
            std::time_t currentTime = getLastModifiedTime(path);

            if (currentSize != oldInfo.size || currentTime != oldInfo.modTime) {
                return true;
            }

            std::string currentHash = calculateHash(path);
            return currentHash != oldInfo.hash;
        } catch (const std::exception& e) {
             logMessage("Error checking file " + path + ": " + e.what());
            return true;
        }
    }

    void handleFileChange(const std::string& path) {
        logMessage("ALERT: Change detected in: " + path);
    }

    void handleFileRemoval(const std::string& path) {
         logMessage("ALERT: File removed or inaccessible: " + path);
    }

    void reinitializeFile(const std::string& path) {
        try {
            if (!fileExists(path)) {
                 logMessage("ALERT: File disappeared: " + path);
                fileRegistry.erase(path);
                return;
            }

            FileInfo info;
            info.hash = calculateHash(path);
            info.size = getFileSize(path);
            info.modTime = getLastModifiedTime(path);

            fileRegistry[path] = info;
             logMessage("File re-initialized: " + path);

        } catch (const std::exception& e) {
            logMessage("Error re-initializing file " + path + ": " + e.what());
        }
    }

    bool isPathSafe(const std::string& path) {
        if (path.empty()) return false;
        if (path.find("..") != std::string::npos) return false;
        if (path.find(":") != std::string::npos && path.find("C:") == std::string::npos) return false;
        return true;
    }



public:
    FileIntegrityMonitor(const std::vector<std::string>& paths, int interval = 60, const std::string& logPath = "fim.log")
        : criticalPaths(paths), isRunning(false), scanIntervalSeconds(interval), logFilePath(logPath),
          gen(rd()), distrib(1, 100) {
         logFile.open(logFilePath, std::ios::app);
        if (!logFile.is_open()) {
            throw ConfigurationError("Failed to open log file: " + logFilePath);
        }

        for (const auto& path : criticalPaths) {
            if (!isPathSafe(path)) {
                throw ConfigurationError("Unsafe path detected: " + path);
            }
        }

        initializeRegistry();
    }

    ~FileIntegrityMonitor() {
        stop();
        if (logFile.is_open()) {
            logFile.close();
        }
    }



    void initializeRegistry() {
        std::lock_guard<std::mutex> lock(registryMutex);
        for (const auto& path : criticalPaths) {
            try {
                if (fileExists(path)) {
                    FileInfo info;
                    info.hash = calculateHash(path);
                    info.size = getFileSize(path);
                    info.modTime = getLastModifiedTime(path);
                    fileRegistry[path] = info;
                     logMessage("File registered: " + path);
                } else {
                     logMessage("File not found: " + path);
                }
            } catch (const std::exception& e) {
                 logMessage("Error initializing file " + path + ": " + e.what());
            }
        }
    }

    void start() {
        if (isRunning) return;

        isRunning = true;
         logMessage("Starting file monitoring...");

        std::thread monitoringThread([this]() {
            while (isRunning) {
                try {
                    checkIntegrity();
                } catch (const std::exception& e) {
                     logMessage("Exception during integrity check: " + std::string(e.what()));
                }
                std::this_thread::sleep_for(std::chrono::seconds(scanIntervalSeconds));
            }
        });

        monitoringThread.detach();
    }

    void stop() {
        if (!isRunning) return;
        isRunning = false;
         logMessage("Stopping file monitoring...");
    }


    void checkIntegrity() {
        std::lock_guard<std::mutex> lock(registryMutex);

        std::vector<std::string> filesToCheck;
        for (const auto& pair : fileRegistry) {
            filesToCheck.push_back(pair.first);
        }

        for (const auto& path : filesToCheck) {
            auto it = fileRegistry.find(path);
            if (it == fileRegistry.end()) continue;

            FileInfo& info = it->second;

            if (!fileExists(path)) {
                handleFileRemoval(path);
                fileRegistry.erase(it);
                continue;
            }

            if (hasFileChanged(path, info)) {
                handleFileChange(path);
                reinitializeFile(path);
            }
        }
    }


    bool addFile(const std::string& path) {
        if (!isPathSafe(path)) {
             logMessage("Unsafe path, cannot add file: " + path);
            return false;
        }

        if (!fileExists(path)) {
             logMessage("File does not exist: " + path);
            return false;
        }

        std::lock_guard<std::mutex> lock(registryMutex);
        try {
            FileInfo info;
            info.hash = calculateHash(path);
            info.size = getFileSize(path);
            info.modTime = getLastModifiedTime(path);

            fileRegistry[path] = info;
             logMessage("New file added to monitoring: " + path);
            return true;
        } catch (const std::exception& e) {
             logMessage("Error adding file: " + std::string(e.what()));
            return false;
        }
    }
};



bool shouldExit = false;

void signalHandler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cerr << "Signal received, exiting..." << std::endl;
        shouldExit = true;
    }
}


int main() {
    try {
        std::signal(SIGINT, signalHandler);
        std::signal(SIGTERM, signalHandler);

        std::vector<std::string> paths;
        paths.push_back("/etc/hosts");
        paths.push_back("/etc/services");
        paths.push_back("/etc/passwd");

        FileIntegrityMonitor monitor(paths, 60, "fim.log");

        monitor.start();

        while (!shouldExit) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        monitor.stop();

    } catch (const ConfigurationError& e) {
        std::cerr << "Configuration error: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Unhandled exception: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
