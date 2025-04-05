#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <sqlite3.h>  // SQLite database handling
#include <ctime>      // Time handling for logging/timing
#include <chrono>     // More precise timing
#include <zlib.h>     // For data compression (like zlib in Python)
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>
#include <openssl/sha.h>  // For hashing (hashlib equivalent)
#include <b64/encode.h>
#include <b64/decode.h>
#include <stdexcept>
#include <sys/stat.h>  // For checking file size and existence
#include <unistd.h>  // For getcwd function
#include <windows.h>   // For GetModuleFileName
#include <tlhelp32.h>
#include <set>
#include <unordered_map>
#include <algorithm>
#include <iomanip>
#include <variant>
#include <utility> // For std::pair
#include <cmath> // For std::round
#include <numeric> // For std::accumulate
#include <thread>
#include <atomic>
#include <limits>
#include <conio.h> // For _kbhit() and _getch() on Windows
#include <filesystem>

const int move_times_limit = 11000;
// Global variable
time_t pbs_meta_data = 0;
bool DONT_ACTUALLY_INTERACT_WITH_SERVER = false;
bool slidysim_is_dead = false;
std::string db_file_path = "pbdb.db"; // Specify your database file path

// Function to trim trailing spaces from a string
std::string trim_trailing_spaces(const std::string &str) {
    std::string result = str;
    result.erase(std::find_if(result.rbegin(), result.rend(),
        [](unsigned char ch) { return !std::isspace(ch); }).base(), result.end());
    return result;
}

void disableQuickEditMode() {
    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    
    // Check if we can get the console mode, then disable Quick Edit mode
    if (GetConsoleMode(hInput, &mode)) {
        mode &= ~ENABLE_QUICK_EDIT_MODE;
        SetConsoleMode(hInput, mode);
    }
}

void createIndex() {
    sqlite3* db = nullptr;
    int rc = sqlite3_open("solves.db", &db);

    if (rc != SQLITE_OK) {
        // Handle error if the database fails to open
        return; // Or log the error
    }

    const std::string createIndexesSQL = R"(
        CREATE INDEX IF NOT EXISTS idx_solves_timestamp ON solves(timestamp);
        CREATE INDEX IF NOT EXISTS idx_single_solves_id_time_moves ON single_solves(id, time, moves);
    )";

    char* errMsg = nullptr;
    
    // Execute the SQL commands to create indexes
    rc = sqlite3_exec(db, createIndexesSQL.c_str(), nullptr, nullptr, &errMsg);
    
    if (rc != SQLITE_OK) {
        // Handle error if index creation fails
        sqlite3_free(errMsg); // Free the error message
        // You can log the error message here
    }

    // Close the database connection
    sqlite3_close(db);
}

std::string getMoveTimes(int time, int moves, const std::string& timestamp, int avglen, int solve_type) {
    sqlite3* db;
    sqlite3_stmt* stmt;
    std::string result = "[";  // Start the result with an opening bracket

    // Open the SQLite database
    if (sqlite3_open("solves.db", &db) != SQLITE_OK) {
        std::cerr << "Cannot open database: " << sqlite3_errmsg(db) << std::endl;
        return result + "]"; // Return empty brackets on failure
    }

    // Prepare the SQL query based on the avglen parameter
    std::string sql;
    if (avglen == 1 && solve_type == 1){
        sql = "WITH solve_info AS ("
        "    SELECT single_start_id, single_end_id "
        "    FROM solves "
        "    WHERE timestamp = ?"
        "), "
        "single_solves_info AS ("
        "    SELECT id, move_times_start_id, move_times_end_id "
        "    FROM single_solves "
        "    WHERE id BETWEEN (SELECT single_start_id FROM solve_info) "
        "                  AND (SELECT single_end_id FROM solve_info) "
        "                  AND time = ?"
        "                  AND moves = ?"
        ") "
        "SELECT GROUP_CONCAT(mt.time, ',') AS move_times "
        "FROM single_solves_info ssi "
        "JOIN move_times mt ON mt.id BETWEEN ssi.move_times_start_id AND ssi.move_times_end_id "
        "GROUP BY ssi.id;";
    } else if (avglen == 1) {
        sql = "WITH solve_info AS ("
            "    SELECT single_start_id, single_end_id "
            "    FROM solves "
            "    WHERE time = ? AND moves = ? AND timestamp = ?"
            "), "
            "single_solves_info AS ("
            "    SELECT id, move_times_start_id, move_times_end_id "
            "    FROM single_solves "
            "    WHERE id BETWEEN (SELECT single_start_id FROM solve_info) "
            "                  AND (SELECT single_end_id FROM solve_info) "
            ") "
            "SELECT "
            "       GROUP_CONCAT(mt.time, ',') AS move_times "
            "FROM single_solves_info ssi "
            "JOIN move_times mt ON mt.id BETWEEN ssi.move_times_start_id AND ssi.move_times_end_id "
            "GROUP BY ssi.id;";

    } else if (avglen == 5 || avglen == 12 || avglen == 50 || avglen == 100) {
        int limitN = avglen - 1;
        sql = "WITH solve_info AS ("
              "    SELECT single_start_id, single_end_id "
              "    FROM solves "
              "    WHERE time = ? AND moves = ? AND timestamp = ?"
              "), "
              "previous_solves AS ("
              "    SELECT single_start_id, single_end_id "
              "    FROM solves "
              "    WHERE id < (SELECT id FROM solves WHERE time = ? AND moves = ? AND timestamp = ?) "
              "    ORDER BY id DESC "
              "    LIMIT " + std::to_string(limitN) + " "
              "), "
              "combined_solves AS ("
              "    SELECT * FROM previous_solves "
              "    UNION ALL "
              "    SELECT * FROM solve_info "
              ") "
              "SELECT "
              "    GROUP_CONCAT(mt.time, ',') AS move_times "
              "FROM combined_solves cs "
              "JOIN single_solves ss ON ss.id BETWEEN cs.single_start_id AND cs.single_end_id "
              "JOIN move_times mt ON mt.id BETWEEN ss.move_times_start_id AND ss.move_times_end_id "
              "GROUP BY cs.single_start_id, cs.single_end_id;";
    } else {
        sqlite3_close(db);
        return result + "]"; // Return empty brackets for invalid avglen
    }

    // Prepare the statement
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return result + "]";
    }

     // Bind the parameters
    if (avglen == 1 && solve_type == 1){
        sqlite3_bind_text(stmt, 1, timestamp.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 2, time);
        sqlite3_bind_int(stmt, 3, moves);
    }
    else if (avglen == 1) {
        sqlite3_bind_int(stmt, 1, time);
        sqlite3_bind_int(stmt, 2, moves);
        sqlite3_bind_text(stmt, 3, timestamp.c_str(), -1, SQLITE_STATIC);
    } else {
        sqlite3_bind_int(stmt, 1, time);
        sqlite3_bind_int(stmt, 2, moves);
        sqlite3_bind_text(stmt, 3, timestamp.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 4, time);
        sqlite3_bind_int(stmt, 5, moves);
        sqlite3_bind_text(stmt, 6, timestamp.c_str(), -1, SQLITE_STATIC);
    }
    // Execute the statement and process the results
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* moveTimes = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (moveTimes) {
            result += moveTimes;
            result += ";";  // Separate move times with semicolons
        }
    }

    // Clean up
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    if (result.length() > 1) {
        result.pop_back();  // Remove the last semicolon
    }
    result += "]";  // Close the result with a bracket

    return result;  // Return the concatenated move times
}

void printSeparator(const std::string& title) {
    // Define the fixed total width of the separator line
    const int totalWidth = 48;
    
    // Calculate the padding, accounting for the title and borders
    int padding = (totalWidth - title.length() - 4) / 2; // 4 accounts for "||" borders

    // If the title is too long, throw an error
    if (padding < 0) {
        throw std::runtime_error("Title is too long to fit in the separator line.");
    }

    // Create the top and bottom separator lines
    std::string separator(totalWidth, '=');
    
    // Format the title line with padding and borders
    std::string formattedTitle = "||" + std::string(padding, ' ') + title + std::string(padding, ' ');
    
    // If the length of the title plus padding is odd, add an extra space for alignment
    if (formattedTitle.length() + 2 < totalWidth) {
        formattedTitle += ' ';
    }

    formattedTitle += "||";
    
    std::string emptyLine = "||" + std::string(totalWidth - 4, ' ') + "||"; // Adjusted for borders
    
    // Print the separator and the formatted title with empty lines
    std::cout << separator << std::endl;
    std::cout << emptyLine << std::endl;
    std::cout << formattedTitle << std::endl;
    std::cout << emptyLine << std::endl;
    std::cout << separator << std::endl;
}

struct ResultEntry {
    int size_n;                   // int
    int size_m;                   // int
    int solve_type;               // int
    int marathon_length;          // int
    int display_type;             // int
    int average_type;             // int
    int control_type;             // int
    int pb_type;                  // int
    int main_time;                // int
    int main_moves;               // int
    int main_tps;                 // int (multiplied by 1000)
    std::vector<std::string> single_solutions; // vector of strings
    std::vector<float> single_times;           // vector of floats
    std::vector<float> single_moves;           // vector of floats
    std::vector<float> single_tps;             // vector of floats
    std::string final_timestamp;               // string
    std::vector<float> bld_memo;               // vector of floats
};

const int BLACK = 0;          // Black
const int DARK_BLUE = 1;      // Dark Blue
const int DARK_GREEN = 2;      // Dark Green
const int DARK_CYAN = 3;      // Dark Cyan
const int DARK_RED = 4;       // Dark Red
const int DARK_MAGENTA = 5;   // Dark Magenta
const int DARK_YELLOW = 6;    // Dark Yellow
const int LIGHT_GRAY = 7;     // Light Gray
const int DARK_GRAY = 8;      // Dark Gray
const int LIGHT_BLUE = 9;     // Light Blue
const int LIGHT_GREEN = 10;    // Light Green
const int LIGHT_CYAN = 11;    // Light Cyan
const int LIGHT_RED = 12;     // Light Red
const int LIGHT_MAGENTA = 13; // Light Magenta
const int LIGHT_YELLOW = 14;  // Light Yellow
const int WHITE = 15;         // White

// Function to check if a file exists
bool FileExists(const std::string& filename) {
    DWORD fileAttr = GetFileAttributes(filename.c_str());
    return (fileAttr != INVALID_FILE_ATTRIBUTES && !(fileAttr & FILE_ATTRIBUTE_DIRECTORY));
}

// Function to monitor the process
void monitorProcess(HANDLE processHandle) {
    // Wait for the process to close
    WaitForSingleObject(processHandle, INFINITE);
    // Close the handle after the process ends
    CloseHandle(processHandle);

    // Close the console window (or you could just minimize it)
    HWND hwnd = GetConsoleWindow();
    if (hwnd) {
        slidysim_is_dead = true;
    }
}

// Function to check if the process is already running
bool IsProcessRunning(const std::string& processName) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    if (Process32First(snapshot, &entry)) {
        do {
            if (_stricmp(entry.szExeFile, processName.c_str()) == 0) {
                CloseHandle(snapshot);
                return true;
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return false;
}

// Function to run the executable and minimize the current window
void runAndHide() {
    std::string executablePath = "slidysim.exe";

    // Check if the executable exists
    if (FileExists(executablePath)) {
        // Check if the process is already running
        if (IsProcessRunning("slidysim.exe")) {
            std::cout << "Slidysim already running. " << std::endl;
            HWND hwnd = GetConsoleWindow();
            if (hwnd) {
                // Minimize the console window
                ShowWindow(hwnd, SW_MINIMIZE);
            }
            return;
        }

        // Prepare to start the process
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;

        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));

        // Create the process
        if (CreateProcessA(executablePath.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            // Get the handle of the current console window
            HWND hwnd = GetConsoleWindow();
            if (hwnd) {
                // Minimize the console window
                ShowWindow(hwnd, SW_MINIMIZE);
            }

            // Start a thread to monitor the process
            std::thread monitorThread(monitorProcess, pi.hProcess);
            monitorThread.detach(); // Detach the thread to run independently
        } else {
            std::cout << "Failed to start process: " << GetLastError() << std::endl;
        }
    } else {
        std::cout << "Executable not found: " << executablePath << std::endl;
    }
}

void setConsoleColor(int color) {
    // Get the console handle
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    // Set the text color
    SetConsoleTextAttribute(hConsole, color);
}

std::string global_username; // Global variable to store the username

std::string base64_encode(const std::string &in) {
    std::ostringstream oss; // Create an output string stream
    std::istringstream iss(in); // Create an input string stream from the input
    base64::encoder encoder; // Create a Base64 encoder
    
    encoder.encode(iss, oss); // Encode from input stream to output stream
    return oss.str(); // Return the resulting string
}

std::string base64_decode(const std::string &in) {
    std::ostringstream oss; // Create an output string stream
    std::istringstream iss(in); // Create an input string stream from the input
    base64::decoder decoder; // Create a Base64 decoder
    
    decoder.decode(iss, oss); // Decode from input stream to output stream
    return oss.str(); // Return the resulting string
}

bool logout() {
    const std::string filename = "credentials.dat";

    // Check if the file exists
    if (std::filesystem::exists(filename)) {
        // Attempt to delete the file
        try {
            std::filesystem::remove(filename);
            return true; // File deleted successfully
        } catch (const std::filesystem::filesystem_error& e) {
            std::cerr << "Error deleting file: " << e.what() << std::endl;
            return false; // Error occurred during deletion
        }
    } else {
        std::cout << "File does not exist." << std::endl;
        return false; // File does not exist
    }
}

bool check_credentials(const std::string &auth_header) {
    const std::string url = "https://slidysim.ru";
    const std::string endpoint = "/api/protected";

    // Set up the client and headers
    httplib::Client client(url.c_str());
    httplib::Headers headers = {
        {"Authorization", auth_header}
    };

    // Make the GET request
    auto res = client.Get(endpoint.c_str(), headers);

    // Check the response
    if (res) {
        if (res->status == 200) {
            std::cout << res->body << std::endl; // Print response body
            return true; // Authorized
        } else {
            std::cerr << "Error: HTTP status " << res->status << " - " << res->body << std::endl;
        }
    } else {
        std::cerr << "Error: " << res.error() << std::endl;
    }
    return false; // Not authorized
}

bool check_from_file() {
    std::string auth_header;
    std::cout << "\n\n\nPlease wait, trying to authorize you..." << std::endl;
    // Try to open the credentials.dat file
    std::ifstream credentialsfile("credentials.dat");
    if (credentialsfile) {
        std::getline(credentialsfile, auth_header);
        credentialsfile.close();

        // Check the credentials using the loaded header
        if (check_credentials(trim_trailing_spaces(auth_header))) {
            // Decode the auth_header to get username
            std::string encoded_credentials = auth_header.substr(6); // Remove "Basic " prefix
            std::string decoded_credentials = base64_decode(encoded_credentials);

            // Split the decoded credentials to get username
            size_t delimiter_pos = decoded_credentials.find(':');
            if (delimiter_pos != std::string::npos) {
                global_username = decoded_credentials.substr(0, delimiter_pos); // Save username in the global variable
            }
            return true; // Success
        }
    } else {
        std::cerr << "Could not find authorization file. Please login." << std::endl;
        std::cerr << "\nIf you don't have an account yet,\nplease contact @vovker or @dphdmn\nin discord for details." << std::endl;
    }
    return false; // File not found or not authorized
}

bool authorize_user() {
    std::string username;
    std::string password;

    // Prompt user for username
    std::cout << "Enter username: ";
    std::getline(std::cin, username);
    global_username = username; // Save username in the global variable

    // Prompt user for password
    std::cout << "Enter password: ";
    char ch;
    while ((ch = _getch()) != '\r') { // Read until Enter is pressed
        if (ch == '\b') { // Handle backspace
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b"; // Erase the last character on backspace
            }
        } else {
            password.push_back(ch);
            std::cout << '*'; // Show asterisks for password input
        }
    }
    std::cout << std::endl; // Move to the next line after password input

    // Prepare the credentials
    std::string credentials = username + ":" + password;
    std::string encoded_credentials = base64_encode(credentials);
    std::string auth_header = trim_trailing_spaces("Basic " + encoded_credentials);

    // Check credentials
    if (check_credentials(auth_header)) {
        std::cout << "You are authorized!" << std::endl;

        // Write to credentials.dat
        std::ofstream credentialsfile("credentials.dat");
        if (credentialsfile) {
            credentialsfile << auth_header;
            credentialsfile.close();
            return true; // Success
        } else {
            std::cerr << "Error: Unable to create credentials.dat" << std::endl;
            return false; // Failed to write file
        }
    } else {
        std::cout << "You are NOT authorized!" << std::endl;
        return false; // Not authorized
    }
}

bool deleteDatabase() {
    const std::string dbFilename = "pbdb.db";
    setConsoleColor(DARK_RED);
    std::cout << "This operation will only affect\nthe custom PBs database file." << std::endl;
    std::cout << "Your Slidysim PBs file will Never be\naffected by this program. Don't worry." << std::endl;
    std::cout << "You might need this deletion function\nto parse PBs file from scratch." << std::endl;
    std::cout << "For example, to reupload scores to the server." << std::endl;
    std::cout << "(Don't use this function if you\ndon't know what you are doing!)"<< std::endl;
    std::cout << "Type 'DELETE' to confirm wiping DB." << std::endl;
    
    std::string confirmation;
    std::cin >> confirmation;
    if (confirmation != "DELETE") {
        std::cout << "Deletion cancelled." << std::endl;
        return false;
    }
    setConsoleColor(LIGHT_GRAY);
    std::cout << "Fine! Let's delete your Database file..."<< std::endl;
    sqlite3* db;
        if (sqlite3_open(db_file_path.c_str(), &db) == SQLITE_OK) {
            sqlite3_close(db); //closing db if its still opened because of stupid bug
        }
    if (std::filesystem::exists(dbFilename)) {
        try {
            std::filesystem::remove(dbFilename);
            pbs_meta_data = 0;
            return true;
        } catch (const std::filesystem::filesystem_error&) {
            return false;
        }
    }
    else{
        std::cout << "You did not have a DB at all\nor it was already deleted." << std::endl;
    }
    return false;
}


bool wipe_scores() {
    const std::string url = "https://slidysim.ru";
    const std::string endpoint = "/api/deleteScores";

    // Ask user for confirmation
    setConsoleColor(DARK_RED);
    std::string confirmation;
    std::cout << "Type 'DELETE' to confirm wiping scores."<< std::endl;
    std::cout << "(It will not affect your local files,\nonly server-side scores will be deleted) "<< std::endl;
    std::cout << "(Don't use this function if you\ndon't know what you are doing!)"<< std::endl;
    std::cin >> confirmation;
    setConsoleColor(LIGHT_GRAY);
    // Check if the user input matches "DELETE"
    if (confirmation != "DELETE") {
        std::cerr << "Operation canceled.\nYou must type 'DELETE' to proceed." << std::endl;
        return false;
    }
    std::cout << "Fine! Let's delete your scores..."<< std::endl;
    // Read the authorization token from 'credentials.dat'
    std::ifstream file("credentials.dat");
    if (!file) {
        std::cerr << "Error: Unable to open credentials.dat" << std::endl;
        return false;
    }
    std::string token;
    std::getline(file, token);
    file.close();

    // Set up the client and the headers
    httplib::Client client(url.c_str());
    httplib::Headers headers = {
        {"Authorization", token}
    };

    // Make the POST request
    auto res = client.Post(endpoint.c_str(), headers);

    // Check the response
    if (res) {
        if (res->status == 200) {
            std::cout << "Scores wiped successfully" << std::endl;
            return true;
        } else {
            std::cerr << "Error: HTTP status " << res->status << " - " << res->body << std::endl;
        }
    } else {
        std::cerr << "Error: " << res.error() << std::endl;
    }

    return false;
}

// Function to check if the file has changed
bool hasFileChanged(const std::string& pb_file) {
    struct stat file_stat;

    // Get metadata of the file (last time it was changed)
    if (stat(pb_file.c_str(), &file_stat) != 0) {
        std::cerr << "Could not access Slidysim PB file.\nPlease make sure you are running this\nFrom your Slidysim folder.\n";
        return false;
    }

    // Check the modification time of the file
    time_t last_modified = file_stat.st_mtime;

    // Compare to last saved metadata
    if (pbs_meta_data != 0 && pbs_meta_data == last_modified) {
        std::cout << "[NO NEW PBs].\n";
        return false;
    }

    // Update the global metadata value and return true if file has changed
    pbs_meta_data = last_modified;
    return true;
}

bool update_uploaded_status(const std::string& db_name) {
    sqlite3* db;
    char* err_msg = nullptr;

    // Open the database
    if (sqlite3_open(db_name.c_str(), &db) != SQLITE_OK) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    // Update the uploaded status
    const char* sql = "UPDATE resultstable SET uploaded = '1'";
    if (sqlite3_exec(db, sql, nullptr, nullptr, &err_msg) != SQLITE_OK) {
        std::cerr << "[CRITICAL!] An error occurred while\ntrying to update uploaded status in db: " << err_msg << std::endl;
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return false;
    }

    // Commit changes and close the database
    sqlite3_close(db);
    return true;
}

bool upload_pbs_to_server(std::string serialized_data) {
    // Read the authorization token from 'credentials.dat'
    std::ifstream file("credentials.dat");
    if (!file.is_open()) {
        std::cerr << "Failed to open credentials.dat" << std::endl;
        return false;
    }

    std::string token;
    std::getline(file, token);
    file.close();

    // Create an HTTP client
    httplib::Client cli("https://slidysim.ru");

    // Set up headers
    httplib::Headers headers = {
        { "Authorization", token },
        { "Content-Type", "text/plain" }
    };

    if (!serialized_data.empty() && serialized_data.back() == ';') {
        serialized_data.pop_back();  // Remove trailing semicolon if it exists
    }

    const int maxRetries = 10;
    int attempt = 0;

    while (attempt < maxRetries) {
        // Make the POST request
        auto res = cli.Post("/api/addScores", headers, serialized_data, "text/plain");

        // Check for response status
        if (res && res->status == 200) {
            // Check the response content
            if (res->body == "Added scores successfully") {
                std::cout << "\n[Some part of PBs uploaded...]" << std::endl;
                return true;
            } else {
                std::cout << "\nFailed to upload personal bests.\nResponse: " << res->body << std::endl;
                return false;
            }
        } else {
            attempt++;
            std::cerr << "\nRequest failed with status code: " 
                      << (res ? std::to_string(res->status) : "No response") 
                      << ". Retry " << attempt << " of " << maxRetries << "..." << std::endl;

            // Optionally, add a delay before retrying
            std::this_thread::sleep_for(std::chrono::seconds(5)); // Wait for 5 seconds
        }
    }

    std::cerr << "\nAll attempts to upload personal bests failed after " << maxRetries << " retries." << std::endl;
    return false;
}

std::string compress_string(const std::string& input_string) {
    uLongf compressed_length = compressBound(input_string.size());
    std::vector<unsigned char> compressed_data(compressed_length);
    if (compress(compressed_data.data(), &compressed_length, 
                 reinterpret_cast<const Bytef*>(input_string.data()), input_string.size()) != Z_OK) {
        throw std::runtime_error("Compression failed");
    }
    std::ostringstream oss;
    std::istringstream iss(std::string(reinterpret_cast<char*>(compressed_data.data()), compressed_length));
    base64::encoder encoder;
    encoder.encode(iss, oss);
    return oss.str();
}

std::tuple<int, int, int, int, int, int, int, int, int, int, int, std::string, std::string, int, int>
processResultEntry(const ResultEntry& entry) {
    // Prepare solutions_data
    std::ostringstream solutionsStream;
    std::ostringstream timesStream;
    std::ostringstream movesStream;
    std::ostringstream tpsStream;
    std::ostringstream bldStream;
    for (const auto& solution : entry.single_solutions) {
        solutionsStream << solution << ",";
    }
    std::string solutions = solutionsStream.str();
    if (!solutions.empty()) solutions.pop_back(); 
    for (const auto& time : entry.single_times) {
        timesStream << std::fixed << std::setprecision(3) << time/1000 << ",";
    }
    std::string times = timesStream.str();
    if (!times.empty()) times.pop_back();
    for (const auto& move : entry.single_moves) {
        movesStream << std::fixed << std::setprecision(0) << move/1000 << ",";
    }
    std::string moves = movesStream.str();
    if (!moves.empty()) moves.pop_back();
    for (const auto& tps : entry.single_tps) {
        tpsStream << std::fixed << std::setprecision(3) << tps << ",";
    }
    std::string tps = tpsStream.str();
    if (!tps.empty()) tps.pop_back();
    for (const auto& bld : entry.bld_memo) {
        bldStream << std::fixed << std::setprecision(3) << (bld) << ",";
    }
    std::string bld_data = bldStream.str();
    if (!bld_data.empty()) bld_data.pop_back();

   //GET MOVE TIMES STARTS
    std::string moveTimes = "";
    if (!entry.single_solutions.empty()) {
        if (solutions.size() < move_times_limit){
            int avglen = entry.average_type;
            int time_prepared;
            int moves_prepared;
            if (avglen > 1){
                time_prepared = entry.single_times.back();
                moves_prepared = entry.single_moves.back();
            } else{
                time_prepared = entry.main_time;
                moves_prepared = entry.main_moves;
            }
            std::string timestamp = entry.final_timestamp;
            
            moveTimes = getMoveTimes(time_prepared, moves_prepared, timestamp, avglen, entry.solve_type);
        }
    }
    //GET MOVE TIMES ENDS
    std::string solutions_data = solutions + ";" + times + ";" + moves + ";" + tps + ";" + bld_data + ";" + moveTimes;
    int uploaded = 0;
    int solve_data_available = entry.single_times.empty() ? 0 : 1;
    if (solve_data_available == 0) {
        solutions_data = "-1";
    } else {
        solutions_data = compress_string(solutions_data);
    }
    return std::make_tuple(
        entry.size_n,
        entry.size_m,
        entry.solve_type,
        entry.marathon_length,
        entry.display_type,
        entry.average_type,
        entry.control_type,
        entry.pb_type,
        entry.main_time,
        entry.main_moves,
        entry.main_tps,
        solutions_data,
        entry.final_timestamp,
        uploaded,
        solve_data_available
    );
}

// Function to insert a vector of ResultEntry into the database
void insertResults(const std::string& dbName, const std::vector<ResultEntry>& entries) {
    sqlite3* db;
    if (sqlite3_open(dbName.c_str(), &db) != SQLITE_OK) {
        std::cerr << "Can't open database:\n" << sqlite3_errmsg(db) << "\n";
        return;
    }

    // Begin transaction
    sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);

    const char* insert_sql = R"(
        INSERT INTO resultstable (
            size_n, size_m, solve_type, marathon_length, display_type, average_type, mouse_control,
            pb_type, time, moves, tps, solutions_data, timestamp, uploaded, solve_data_available
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    )";

    const char* delete_sql = R"(
        DELETE FROM resultstable 
        WHERE size_n = ? AND size_m = ? AND solve_type = ? AND marathon_length = ? AND display_type = ? 
              AND average_type = ? AND mouse_control = ? AND pb_type = ?;
    )";

    sqlite3_stmt* insert_stmt;
    sqlite3_stmt* delete_stmt;

    // Prepare statements
    sqlite3_prepare_v2(db, delete_sql, -1, &delete_stmt, nullptr);
    sqlite3_prepare_v2(db, insert_sql, -1, &insert_stmt, nullptr);
   

    for (const auto& entry : entries) {
        // Process and bind values for the insert query
        auto processed_result = processResultEntry(entry);
        // Bind for deletion
        sqlite3_bind_int(delete_stmt, 1, std::get<0>(processed_result));
        sqlite3_bind_int(delete_stmt, 2, std::get<1>(processed_result));
        sqlite3_bind_int(delete_stmt, 3, std::get<2>(processed_result));
        sqlite3_bind_int(delete_stmt, 4, std::get<3>(processed_result));
        sqlite3_bind_int(delete_stmt, 5, std::get<4>(processed_result));
        sqlite3_bind_int(delete_stmt, 6, std::get<5>(processed_result));
        sqlite3_bind_int(delete_stmt, 7, std::get<6>(processed_result));
        sqlite3_bind_int(delete_stmt, 8, std::get<7>(processed_result));

        // Execute the delete
        sqlite3_step(delete_stmt);
        sqlite3_reset(delete_stmt); // Reset for next entry

        
        sqlite3_bind_int(insert_stmt, 1, std::get<0>(processed_result));
        sqlite3_bind_int(insert_stmt, 2, std::get<1>(processed_result));
        sqlite3_bind_int(insert_stmt, 3, std::get<2>(processed_result));
        sqlite3_bind_int(insert_stmt, 4, std::get<3>(processed_result));
        sqlite3_bind_int(insert_stmt, 5, std::get<4>(processed_result));
        sqlite3_bind_int(insert_stmt, 6, std::get<5>(processed_result));
        sqlite3_bind_int(insert_stmt, 7, std::get<6>(processed_result));
        sqlite3_bind_int(insert_stmt, 8, std::get<7>(processed_result));
        sqlite3_bind_int(insert_stmt, 9, std::get<8>(processed_result));
        sqlite3_bind_int(insert_stmt, 10, std::get<9>(processed_result));
        sqlite3_bind_int(insert_stmt, 11, std::get<10>(processed_result));
        sqlite3_bind_text(insert_stmt, 12, std::get<11>(processed_result).c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(insert_stmt, 13, std::get<12>(processed_result).c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(insert_stmt, 14, std::get<13>(processed_result));
        sqlite3_bind_int(insert_stmt, 15, std::get<14>(processed_result));

        // Execute the insert statement
        sqlite3_step(insert_stmt);
        sqlite3_reset(insert_stmt); // Reset for next entry
    }

     //Finalize the statements
    sqlite3_finalize(delete_stmt);
    sqlite3_finalize(insert_stmt);
    

    // Commit transaction
    sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);

    // Close the database
    sqlite3_close(db);
}

// Logger class for improved printing and timing
class Logger {
public:
    Logger() {
        start_time = std::chrono::high_resolution_clock::now();
    }

    void log(const std::string& message) {
        auto now = std::chrono::high_resolution_clock::now();
        auto time_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
        std::cout << "[" << time_elapsed << " ms] " << message << std::endl;
    }

    void reset_timer() {
        start_time = std::chrono::high_resolution_clock::now();
    }

private:
    std::chrono::high_resolution_clock::time_point start_time;
};

void createDatabase(const std::string& db_file_path, const std::vector<std::string>& hashes) {
    sqlite3* db;
    char* errorMessage = nullptr;

    // Open database
    if (sqlite3_open(db_file_path.c_str(), &db) != SQLITE_OK) {
        std::cerr << "Can't open database:\n" << sqlite3_errmsg(db) << std::endl;
        return;
    }

    // Create score_hashes table
    const char* createScoreHashesTable = R"(
        CREATE TABLE IF NOT EXISTS score_hashes (score_hash TEXT PRIMARY KEY);
    )";

    if (sqlite3_exec(db, createScoreHashesTable, nullptr, nullptr, &errorMessage) != SQLITE_OK) {
        std::cerr << "SQL error: " << errorMessage << std::endl;
        sqlite3_free(errorMessage);
    }

    // Start transaction
    if (sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, &errorMessage) != SQLITE_OK) {
        std::cerr << "SQL error: " << errorMessage << std::endl;
        sqlite3_free(errorMessage);
    }

    // Prepare insert statement
    const char* insertScoreHash = "INSERT OR IGNORE INTO score_hashes (score_hash) VALUES (?);";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, insertScoreHash, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement:\n" << sqlite3_errmsg(db) << std::endl;
    }

    for (const auto& hash_value : hashes) {
        sqlite3_bind_text(stmt, 1, hash_value.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "Failed to execute statement:\n" << sqlite3_errmsg(db) << std::endl;
        }
        sqlite3_reset(stmt);
    }

    sqlite3_finalize(stmt);

    // Commit transaction
    if (sqlite3_exec(db, "COMMIT;", nullptr, nullptr, &errorMessage) != SQLITE_OK) {
        std::cerr << "SQL error: " << errorMessage << std::endl;
        sqlite3_free(errorMessage);
    }

    // Create resultstable table
    const char* createResultsTable = R"(
        CREATE TABLE IF NOT EXISTS resultstable (
            size_n INT,
            size_m INT,
            solve_type INT,
            marathon_length INT,
            display_type INT,
            average_type INT,
            mouse_control INT,
            pb_type INT,
            time INT,
            moves INT,
            tps INT,
            solutions_data TEXT,
            timestamp INT,
            uploaded INTEGER,
            solve_data_available TEXT
        );
    )";

    if (sqlite3_exec(db, createResultsTable, nullptr, nullptr, &errorMessage) != SQLITE_OK) {
        std::cerr << "SQL error: " << errorMessage << std::endl;
        sqlite3_free(errorMessage);
    }

    // Create index on resultstable
    const char* createIndex = R"(
        CREATE INDEX IF NOT EXISTS idx_resultstable_fields ON resultstable (
            size_n, size_m, solve_type, marathon_length, display_type, average_type, mouse_control, pb_type
        );
    )";

    if (sqlite3_exec(db, createIndex, nullptr, nullptr, &errorMessage) != SQLITE_OK) {
        std::cerr << "SQL error: " << errorMessage << std::endl;
        sqlite3_free(errorMessage);
    }

    // Close database
    sqlite3_close(db);
}


std::set<std::string> readHashesFromDB(const std::string& db_file_path) {
    sqlite3* db;
    sqlite3_stmt* stmt;
    std::set<std::string> existing_hashes;

    if (sqlite3_open(db_file_path.c_str(), &db) != SQLITE_OK) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return existing_hashes; // Return empty set on error
    }

    const char* sql = "SELECT score_hash FROM score_hashes;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        if (sqlite3_errmsg(db) != nullptr && std::string(sqlite3_errmsg(db)).find("no such table") != std::string::npos) {
            return existing_hashes; // Return empty set if table doesn't exist
        }
        std::cerr << "SQL error: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return existing_hashes;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        existing_hashes.insert(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return existing_hashes;
}

// Function to encode types of solves
int encode_string(const std::string& input_string, const std::string& map_type) {
    // Maps for different types
    static const std::unordered_map<std::string, int> solve_type_map = {
        {"Standard", 1},
        {"2-N relay", 2},
        {"BLD", 3},
        {"Everything-up-to relay", 4},
        {"Height relay", 5},
        {"Width relay", 6},
        {"Marathon", 7}
    };

    static const std::unordered_map<std::string, int> pb_type_map = {
        {"time", 1},
        {"move", 2},
        {"tps", 3}
    };

    static const std::unordered_map<std::string, int> display_type_map = {
        {"Adjacent sum", 1},
        {"Adjacent tiles", 2},
        {"Chess", 3},
        {"Fading tiles", 4},
        {"Fringe minimal", 5},
        {"Incremental vectors", 6},
        {"Inverse permutation", 7},
        {"Inverse vectors", 8},
        {"Last move", 9},
        {"Manhattan", 10},
        {"Maximal unsolved", 11},
        {"Minesweeper", 12},
        {"Minimal", 13},
        {"Minimal unsolved", 14},
        {"RGB", 15},
        {"Row minimal", 16},
        {"Rows and columns", 17},
        {"Standard", 18},
        {"Vanish on solved", 19},
        {"Vectors", 20}
    };

    const std::unordered_map<std::string, const std::unordered_map<std::string, int>&> maps = {
        {"solve_type", solve_type_map},
        {"pb_type", pb_type_map},
        {"display_type", display_type_map}
    };

    auto it = maps.find(map_type);
    if (it != maps.end()) {
        const auto& target_map = it->second;
        auto map_it = target_map.find(input_string);
        if (map_it != target_map.end()) {
            return map_it->second;
        }
    }

    return -1;
}

// Function to decompress data
std::string decompress_data(const std::string& compressed_data) {
    // Skip the first 8 characters
    std::string data_to_decompress = compressed_data.substr(8);
    
    // Convert hex string to bytes
    size_t len = data_to_decompress.length();
    size_t byte_len = len / 2;
    std::vector<unsigned char> compressed_bytes(byte_len);

    for (size_t i = 0; i < byte_len; ++i) {
        std::string byte_string = data_to_decompress.substr(i * 2, 2);
        compressed_bytes[i] = static_cast<unsigned char>(std::stoul(byte_string, nullptr, 16));
    }

    // Decompress the data
    z_stream stream;
    std::vector<char> buffer(4096); // Temporary buffer for decompression

    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    stream.avail_in = static_cast<uInt>(compressed_bytes.size());
    stream.next_in = compressed_bytes.data();

    if (inflateInit(&stream) != Z_OK) {
        throw std::runtime_error("Failed to initialize zlib");
    }

    std::string decompressed_data;
    do {
        stream.avail_out = static_cast<uInt>(buffer.size());
        stream.next_out = reinterpret_cast<Bytef*>(buffer.data());

        int result = inflate(&stream, Z_NO_FLUSH);
        if (result == Z_STREAM_ERROR || result == Z_DATA_ERROR || result == Z_MEM_ERROR) {
            inflateEnd(&stream);
            throw std::runtime_error("Decompression failed");
        }

        size_t have = buffer.size() - stream.avail_out;
        decompressed_data.append(buffer.data(), have);
    } while (stream.avail_out == 0);

    inflateEnd(&stream);
    return decompressed_data;
}
// Function to compute SHA256 hash
std::string sha256(const std::string& str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(str.c_str()), str.size(), hash);
    std::ostringstream oss;
    for (const auto& byte : hash) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

// Main parse function
std::pair<std::vector<ResultEntry>, std::vector<std::string>> parse_data_from_pb(const std::set<std::string>& hashes, const std::vector<std::string>& lines) {
    std::vector<ResultEntry> results;
    std::vector<std::string> new_hashes; // Use set for new_hashes

    for (size_t index = 1; index < lines.size(); ++index) {
        std::string line = lines[index];
        std::string line_hash = sha256(line);

        if (hashes.find(line_hash) != hashes.end()) {
            continue; // Skip if the hash already exists
        }

        new_hashes.push_back(line_hash);
        std::vector<std::string> parts;
        std::stringstream ss(line);
        std::string part;

        while (std::getline(ss, part, ',')) {
            parts.push_back(part);
        }
        // Extract data from parts
        int size_n = std::stoi(parts[0]);
        int size_m = std::stoi(parts[1]);
        std::string solve_type_tmp = parts[2];
        int solve_type;

        int marathon_length = 1;
        if (solve_type_tmp.find("Marathon") != std::string::npos) {
            marathon_length = std::stoi(solve_type_tmp.substr(solve_type_tmp.find(' ') + 1));
            solve_type = encode_string("Marathon", "solve_type");
        } else {
            solve_type = encode_string(solve_type_tmp, "solve_type");
        }

        int display_type = encode_string(parts[3], "display_type");
        int average_type = std::stoi(parts[4]);
        std::string control_type_tmp = parts[5];

        if (control_type_tmp == "Keyboard+macros") {
            continue; // Skip if control type is not valid
        }
        int control_type = (control_type_tmp == "Mouse") ? 1 : 0; 

        int pb_type = encode_string(parts[6], "pb_type");
        std::string compressed_data = parts[7];
        std::string decompressed_data = decompress_data(compressed_data);
        
        // Prepare for single solution processing
        std::vector<float> single_times, single_moves, single_tps;
        std::vector<float> one_solve_times, one_solve_moves, one_solve_tps;
        bool one_solve_times_are_none = true;
        std::vector<std::string> single_solutions;
        std::vector<float> bld_memo;
        std::string final_timestamp = "-1";

        // Process decompressed data
        std::stringstream decompressed_ss(decompressed_data);
        std::string data_one_solve;
        bool bad_data = false;
        while (std::getline(decompressed_ss, data_one_solve, ':')) {
            std::vector<std::string> data;
            std::stringstream data_ss(data_one_solve);
            std::string data_part;
            
            while (std::getline(data_ss, data_part, ';')) {
                data.push_back(data_part);
            }
            if (data.size() < 6){
                bad_data = true;
            }
            if (solve_type == encode_string("Standard", "solve_type") ||
                solve_type == encode_string("BLD", "solve_type")) {
                // Handle Standard or BLD
                if (data.size() == 4) {
                    data.pop_back();
                }

                if (solve_type == encode_string("BLD", "solve_type") && (data.size() == 6)) {
                    bld_memo.push_back(std::stoi(data[data.size() - 2]) / 1000.0f);
                } else {
                    bld_memo.clear();
                    bld_memo.push_back(-1);
                }

                // Extract solving times and moves
                int one_solve_final_time = std::stoi(data[0]);
                int one_solve_final_moves = std::stoi(data[1]);
                if (one_solve_final_moves < 0){
                    one_solve_final_moves = -1;
                }
                float one_solve_final_tps;
                bool broken_tps = (one_solve_final_moves == -1 && pb_type == 3);

                if (broken_tps) {
                    final_timestamp = "-1";
                } else {
                    final_timestamp = data[data.size() - 1];
                }

                if (broken_tps) {
                    one_solve_final_tps = static_cast<float>(std::stoi(data[data.size() - 1]) / 1000.0f);
                } else {
                    if (solve_type == encode_string("BLD", "solve_type")) {
                        one_solve_final_tps = (one_solve_final_time < 0.001) ? 9999 : static_cast<float>(one_solve_final_moves) / (static_cast<float>(one_solve_final_time) - std::stof(data[data.size() - 2]));
                    }
                    else{
                        one_solve_final_tps = (one_solve_final_time < 0.001) ? 9999 : static_cast<float>(one_solve_final_moves) / static_cast<float>(one_solve_final_time);
                    }
                }

                if (one_solve_final_tps < 0) {
                    one_solve_final_tps = -0.001;
                }
                if (one_solve_final_tps > 1000) {
                    one_solve_final_tps = 9999;
                }

                single_times.push_back(one_solve_final_time);
                single_moves.push_back(one_solve_final_moves);
                single_tps.push_back(one_solve_final_tps);
                if (data.size() > 3) {
                    single_solutions.push_back(data[3]);
                }

            } else {
                // Handle other types
                if (data.size() == 4) {
                    data.pop_back();
                }
                one_solve_times.clear();
                one_solve_moves.clear();
                one_solve_tps.clear();
                // Split the times and moves based on the '.' delimiter
                std::stringstream time_stream(data[0]);
                std::stringstream move_stream(data[1]);
                std::string time_part, move_part;

                while (std::getline(time_stream, time_part, '.')) {
                    one_solve_times.push_back(std::stof(time_part));
                }

                while (std::getline(move_stream, move_part, '.')) {
                    one_solve_moves.push_back(std::stoi(move_part));
                }
                one_solve_times_are_none = false;
                

                for (size_t i = 0; i < one_solve_times.size(); ++i) {
                    if (one_solve_times[i] != 0) {
                        one_solve_tps.push_back(static_cast<float>(one_solve_moves[i]) /static_cast<float>(one_solve_times[i]));
                    } else {
                        one_solve_tps.push_back(9999);
                    }
                }

                std::vector<std::string> one_solve_solutions;
                if (data.size() > 3) {
                    std::stringstream solution_ss(data[3]);
                    std::string solution_part;
                    while (std::getline(solution_ss, solution_part, '.')) {
                        one_solve_solutions.push_back(solution_part);
                    }
                }

                bool broken_tps = (std::find(one_solve_moves.begin(), one_solve_moves.end(), -1) != one_solve_moves.end()) && pb_type == 3;

                int one_solve_final_time  = std::accumulate(one_solve_times.begin(), one_solve_times.end(), 0);
                int one_solve_final_moves = std::accumulate(one_solve_moves.begin(), one_solve_moves.end(), 0);
                if (one_solve_final_moves < 0){
                    one_solve_final_moves = -1;
                }

                if (broken_tps) {
                    final_timestamp = "-1";
                } else {
                    final_timestamp = data[data.size() - 1];
                }

                float one_solve_final_tps;
                if (broken_tps) {
                    one_solve_final_tps = static_cast<float>(std::stoi(data[data.size() - 1])) / 1000.0f;
                } else {
                    one_solve_final_tps = (std::any_of(one_solve_times.begin(), one_solve_times.end(), [](float t) { return t <0.001; })) 
                                            ? 9999 
                                            : static_cast<float>(one_solve_final_moves) / static_cast<float>(one_solve_final_time);
                }

                if (one_solve_final_tps < 0) {
                    one_solve_final_tps = -0.001f;
                }
                if (one_solve_final_tps > 1000) {
                    one_solve_final_tps = 9999;
                }

                single_times.push_back(one_solve_final_time);
                single_moves.push_back(one_solve_final_moves);
                single_tps.push_back(one_solve_final_tps);
                single_solutions.insert(single_solutions.end(), one_solve_solutions.begin(), one_solve_solutions.end());
            }
        }
        // Average calculations
        float main_time, main_moves, main_tps;

        if (average_type != 1) {
            if (!bad_data){
                auto min_time = *std::min_element(single_times.begin(), single_times.end());
                auto max_time = *std::max_element(single_times.begin(), single_times.end());
                main_time = std::accumulate(single_times.begin(), single_times.end(), 0.0) - min_time - max_time;
                main_time /= (single_times.size() - 2);

                auto min_moves = *std::min_element(single_moves.begin(), single_moves.end());
                auto max_moves = *std::max_element(single_moves.begin(), single_moves.end());
                main_moves = std::accumulate(single_moves.begin(), single_moves.end(), 0) - min_moves - max_moves;
                main_moves /= (single_moves.size() - 2);

                auto min_tps = *std::min_element(single_tps.begin(), single_tps.end());
                auto max_tps = *std::max_element(single_tps.begin(), single_tps.end());
                main_tps = std::accumulate(single_tps.begin(), single_tps.end(), 0.0) - min_tps - max_tps;
                main_tps /= (single_tps.size() - 2);

                if (!(solve_type == encode_string("Standard", "solve_type") ||
                    solve_type == encode_string("BLD", "solve_type"))) {
                    single_solutions.clear(); // If not Standard or BLD, clear solutions
                }
            }
            else{
                main_time = single_times[0];
                main_moves = single_moves[0];
                main_tps = single_tps[0];
            }
        }else {
            if (!single_times.empty()) {
                main_time = std::accumulate(single_times.begin(), single_times.end(), 0) / static_cast<float>(single_times.size());
            }

            if (!single_moves.empty()) {
                main_moves = std::accumulate(single_moves.begin(), single_moves.end(), 0) / static_cast<float>(single_moves.size());
            }

            if (!single_tps.empty()) {
                main_tps = std::accumulate(single_tps.begin(), single_tps.end(), 0.0f) / static_cast<float>(single_tps.size());
            }
            if (!(one_solve_times_are_none)){
                single_times = one_solve_times;
                single_moves = one_solve_moves;
                single_tps = one_solve_tps;
            }
        }

        // Prepare results
        ResultEntry result_entry = {
            size_n, //int 
            size_m, //int 
            solve_type,  //int
            marathon_length, //int 
            display_type, //int 
            average_type, //int 
            control_type, //int 
            pb_type, //int 
            static_cast<int>(main_time), //int 
            static_cast<int>(main_moves), //int 
            static_cast<int>(round(main_tps * 1000)), //int 
            single_solutions, //vectors of strings 
            single_times, //vectors of floats
            single_moves, //vectors of floats 
            single_tps, //vectors of floats 
            final_timestamp, //string 
            bld_memo ////vectors of floats 
        };

        results.push_back(result_entry);
    }

    return {results, new_hashes};
}


std::vector<std::string> load_data_from_pb(const std::string& pb_file) {
    struct stat file_stat;

    // Check if file exists
    if (stat(pb_file.c_str(), &file_stat) != 0) {
        std::cerr << "The file " << pb_file << " does not exist.\nUpdate is impossible.\n"
                  << "Please make sure you have the\nSlidysim PB file next to the program." << std::endl;
        return {};  // Return an empty vector
    }

    // Get file size in KB
    double file_size_kb = file_stat.st_size / 1024.0;

    // Open the file
    std::ifstream file(pb_file);
    if (!file.is_open()) {
        std::cerr << "Failed to open the file " << pb_file << std::endl;
        return {};  // Return an empty vector
    }

    // Read lines from the file
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(file, line)) {
        lines.push_back(line);
    }
    file.close();  // Close the file after reading

    //std::cout << "[LINES IN PB FILE: " << lines.size() - 1 << "]" << std::endl;

    // If there are fewer than 2 lines, the file is considered empty
    if (lines.size() < 2) {
        std::cerr << "PB file is empty. Update is impossible.\n"
                  << "Please make sure you have some records in it." << std::endl;
        return {};  // Return an empty vector
    }

    return lines;  // Return the vector of lines
}

// Function to serialize the data
std::string serialize_data(const std::vector<std::string>& data) {
    std::ostringstream oss;
    for (size_t i = 0; i < data.size(); ++i) {
        std::string clean_data = data[i];
        // Remove line breaks
        clean_data.erase(std::remove_if(clean_data.begin(), clean_data.end(),
                                          [](char c) { return c == '\n' || c == '\r'; }),
                         clean_data.end());
        
        oss << clean_data;
        if (i < data.size() - 1) {
            oss << ";";
        }
    }
    return oss.str();
}

std::string get_non_uploaded_data(const std::string& db_file_path) {
    sqlite3* db;
    sqlite3_stmt* stmt;
    std::vector<std::string> data_to_send;

    // Open the database
    if (sqlite3_open(db_file_path.c_str(), &db) != SQLITE_OK) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return "";
    }

    // Get total rows
    const char* count_query = "SELECT COUNT(*) FROM resultstable;";
    if (sqlite3_prepare_v2(db, count_query, -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int total_rows = sqlite3_column_int(stmt, 0);
            std::cout << "[TOTAL SCORES IN DB: " << total_rows << "] ";
        }
        sqlite3_finalize(stmt);
    }

    // Query for non-uploaded data
    const char* data_query = "SELECT size_n, size_m, solve_type, marathon_length, display_type, "
                            "average_type, mouse_control, pb_type, time, moves, tps, "
                            "solutions_data, timestamp, solve_data_available "
                            "FROM resultstable WHERE uploaded = 0;";

    if (sqlite3_prepare_v2(db, data_query, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::ostringstream entry;
            for (int i = 0; i < 14; ++i) { // We have 14 columns to extract
                entry << sqlite3_column_text(stmt, i);
                if (i < 13) { // Comma after all except the last
                    entry << ",";
                }
            }
            data_to_send.push_back(entry.str());
        }
        sqlite3_finalize(stmt);
    } else {
        std::cerr << "An error occurred while fetching data from DB:\n" << sqlite3_errmsg(db) << std::endl;
    }

    // Output the result
    if (!data_to_send.empty()) {
        std::cout << "[TO UPLOAD: " << data_to_send.size() << "]" << std::endl;
    } else {
        std::cout << "[ALL PBs UPLOADED]" << std::endl;
    }

    // Close the database
    sqlite3_close(db);
    return serialize_data(data_to_send);
}

void display_progress(std::atomic<bool>& is_uploading) {
    auto start = std::chrono::high_resolution_clock::now();

    while (is_uploading) {
        // Calculate the elapsed time in seconds
        auto now = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start).count();

        // Create a string with the elapsed time
        std::ostringstream oss;
        oss << "\r[UPLOADING TO SERVER] Time elapsed: " << elapsed << " seconds";

        // Print the elapsed time with carriage return to overwrite the previous line
        std::cout << oss.str() << std::flush;

        // Sleep for 500 milliseconds before updating again
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    // Clear the progress line after completion
    std::cout << "\r[UPLOADING TO SERVER] Uploading stopped            " << std::endl;
}


bool uploadCycle() {
    std::string pb_file = "pbs.csv";
    if (!hasFileChanged(pb_file)) {
        return false;
    }
    //get metadata of pbs.csv file (last time it was changed)
    //compare to last saved, if last saved is 0 (some default value), then continue, otherwise print "PBs file did not change." and return FALSE

    
    Logger logger;

    // 1. Load data from PB file
    std::vector<std::string> lines = load_data_from_pb(pb_file);
    if (lines.empty()) {
        std::cerr << "No data loaded. Exiting." << std::endl;
        return false;
    }
    std::set<std::string> hashes = readHashesFromDB(db_file_path);

    // 2. Parse data from PB file
   // logger.log("[PARSING PB FILE]");
    std::vector<ResultEntry> results;
    std::vector<std::string> new_hashes;
    auto output = parse_data_from_pb(hashes, lines);
    results = output.first;
    new_hashes = output.second;

    // 3. Add PB file data to SQLite database
    logger.log("[ADDING SCORES TO PB DB]");
    createDatabase(db_file_path, new_hashes);
    insertResults(db_file_path, results);

    // 4. Get non-uploaded data and serialize it
    std::string serialized_data = get_non_uploaded_data(db_file_path);
    if (serialized_data.empty()) {
        std::cout << "[NO NEW DATA TO UPLOAD]" << std::endl;
        return false;
    }

    // Conditional upload (debug mode)
    if (DONT_ACTUALLY_INTERACT_WITH_SERVER) {
        std::cout << "[DEBUG] [NOT UPLOADING]" << std::endl;
        return true;
    }

     // 5. Upload PBs to the server
    logger.log("[UPLOADING TO SERVER]");
    std::atomic<bool> is_uploading(true);
    std::thread upload_thread([&]() {
        // Split serialized_data into parts with up to 500 "ROWS" each.
        std::vector<std::string> parts;
        std::string delimiter = ";";
        size_t start = 0;
        int row_count = 0;
        std::string current_part;

        // Iterate over serialized_data and split it into parts of up to 500 rows.
        while (true) {
            size_t end = serialized_data.find(delimiter, start);
            if (end == std::string::npos) {
                // Add the remaining part.
                current_part += serialized_data.substr(start);
                parts.push_back(current_part);
                break;
            }

            current_part += serialized_data.substr(start, end - start + 1); // Include the delimiter.
            start = end + 1;
            ++row_count;

            // If we reached 200 rows, store the current part and reset.
            if (row_count >= 200) {
                parts.push_back(current_part);
                current_part.clear();
                row_count = 0;
            }
        }

        bool all_uploaded = true;
        int part_number = 1;

        // Upload each part sequentially and save to file.
        for (const auto& part : parts) {
            if (part_number > 1){
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            // Upload the part.
            bool uploaded = upload_pbs_to_server(part);
            if (!uploaded) {
                std::cout << "Failed to upload a part of personal bests." << std::endl;
                all_uploaded = false;
                break;
            }

            ++part_number;
        }

        is_uploading = false; // Set to false when upload is complete

        // Proceed only if all parts were uploaded successfully.
        if (all_uploaded) {
            if (!update_uploaded_status(db_file_path)) {
                std::cerr << "Failed to update the uploaded status." << std::endl;
                return false;
            } else {
                logger.log("[UPLOADED SUCCESSFULLY].");
                return true;
            }
        } else {
            std::cout << "Failed to upload personal bests." << std::endl;
            return false;
        }
    });

    // Start displaying progress in the main thread
    display_progress(is_uploading);

    // Wait for the upload thread to finish
    upload_thread.join();

    return true;
}

bool reupload_scores() {
    // Connect to the SQLite database
    sqlite3* db;
    pbs_meta_data = 0;
    int result = sqlite3_open(db_file_path.c_str(), &db);
    
    if (result != SQLITE_OK) {
        std::cerr << "Failed to open database: " << sqlite3_errmsg(db) << "\n";
        return false;
    }

    // SQL query to set 'uploaded' to '0' for all scores in resultstable
    const char* sql = "UPDATE resultstable SET uploaded = '0';";
    char* errorMessage = nullptr;

    result = sqlite3_exec(db, sql, nullptr, nullptr, &errorMessage);
    if (result != SQLITE_OK) {
        std::cerr << "SQL error: " << errorMessage << "\n";
        sqlite3_free(errorMessage);
        sqlite3_close(db);
        return false;
    }

    // Close the database after the update
    sqlite3_close(db);

    // Run the upload cycle
    if (uploadCycle()) {
        std::cout << "Upload cycle completed successfully.\n";
        return true;
    } else {
        std::cout << "Upload cycle encountered an error.\n";
        return false;
    }
}

void resizeConsole(int width, int height) {
    // Get the console handle
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    // Set the screen buffer size
    COORD bufferSize;
    bufferSize.X = width;
    bufferSize.Y = height;
    SetConsoleScreenBufferSize(hConsole, bufferSize);

    // Define the window size
    SMALL_RECT windowSize;
    windowSize.Left = 0;
    windowSize.Top = 0;
    windowSize.Right = width - 1; // Adjusting to make sure it fits in the width
    windowSize.Bottom = height - 1; // Adjusting to make sure it fits in the height

    // Set the console window size
    SetConsoleWindowInfo(hConsole, TRUE, &windowSize);
}

void displayHeaderOld(){
    setConsoleColor(DARK_GREEN);
    std::cout << "\t\t\t╔═══════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "\t\t\t║                                                                       ║\n";
    std::cout << "\t\t\t║    ███████╗██╗     ██╗██████╗ ██╗   ██╗███████╗██╗███╗   ███╗         ║\n";
    std::cout << "\t\t\t║    ██╔════╝██║     ██║██╔══██╗╚██╗ ██╔╝██╔════╝██║████╗ ████║         ║\n";
    std::cout << "\t\t\t║    ███████╗██║     ██║██║  ██║ ╚████╔╝ ███████╗██║██╔████╔██║         ║\n";
    std::cout << "\t\t\t║    ╚════██║██║     ██║██║  ██║  ╚██╔╝  ╚════██║██║██║╚██╔╝██║         ║\n";
    std::cout << "\t\t\t║    ███████║███████╗██║██████╔╝   ██║   ███████║██║██║ ╚═╝ ██║         ║\n";
    std::cout << "\t\t\t║    ╚══════╝╚══════╝╚═╝╚═════╝    ╚═╝   ╚══════╝╚═╝╚═╝     ╚═╝         ║\n";
    std::cout << "\t\t\t║                                                                       ║\n";
    std::cout << "\t\t\t║    ██████╗ ███████╗ ██████╗ ██████╗ ██████╗ ██████╗ ███████╗          ║\n";
    std::cout << "\t\t\t║    ██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔══██╗██╔════╝          ║\n";
    std::cout << "\t\t\t║    ██████╔╝█████╗  ██║     ██║   ██║██████╔╝██║  ██║███████╗          ║\n";
    std::cout << "\t\t\t║    ██╔══██╗██╔══╝  ██║     ██║   ██║██╔══██╗██║  ██║╚════██║          ║\n";
    std::cout << "\t\t\t║    ██║  ██║███████╗╚██████╗╚██████╔╝██║  ██║██████╔╝███████║          ║\n";
    std::cout << "\t\t\t║    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚══════╝          ║\n";
    std::cout << "\t\t\t║                                                                       ║\n";
    std::cout << "\t\t\t║    ███╗   ███╗ █████╗ ███╗   ██╗ █████╗  ██████╗ ███████╗██████╗      ║\n";
    std::cout << "\t\t\t║    ████╗ ████║██╔══██╗████╗  ██║██╔══██╗██╔════╝ ██╔════╝██╔══██╗     ║\n";
    std::cout << "\t\t\t║    ██╔████╔██║███████║██╔██╗ ██║███████║██║  ███╗█████╗  ██████╔╝     ║\n";
    std::cout << "\t\t\t║    ██║╚██╔╝██║██╔══██║██║╚██╗██║██╔══██║██║   ██║██╔══╝  ██╔══██╗     ║\n";
    std::cout << "\t\t\t║    ██║ ╚═╝ ██║██║  ██║██║ ╚████║██║  ██║╚██████╔╝███████╗██║  ██║     ║\n";
    std::cout << "\t\t\t║    ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝     ║\n";
    std::cout << "\t\t\t║                                                                       ║\n";
    std::cout << "\t\t\t╚═══════════════════════════════════════════════════════════════════════╝\n";
}

void displayHeader() {
    setConsoleColor(DARK_GREEN);
    std::cout << "+==============================================+\n";
    std::cout << "|                                              |\n";
    std::cout << "|   ____  _ _     _       ____  _              |\n";
    std::cout << "|  / ___|| (_) __| |_   _/ ___|(_)_ __ ___     |\n";
    std::cout << "|  \\___ \\| | |/ _` | | | \\___ \\| | '_ ` _ \\    |\n";
    std::cout << "|   ___) | | | (_| | |_| |___) | | | | | | |   |\n";
    std::cout << "|  |____/|_|_|\\__,_|\\__, |____/|_|_| |_| |_|   |\n";
    std::cout << "|  |  _ \\ ___  ___ _|___/ __ __| |___          |\n";
    std::cout << "|  | |_) / _ \\/ __/ _ \\| '__/ _` / __|         |\n";
    std::cout << "|  |  _ <  __/ (_| (_) | | | (_| \\__ \\         |\n";
    std::cout << "|  |_| \\_\\___|\\___\\___/|_|  \\__,_|___/         |\n";
    std::cout << "|  |  \\/  | __ _ _ __   __ _  __ _  ___ _ __   |\n";
    std::cout << "|  | |\\/| |/ _` | '_ \\ / _` |/ _` |/ _ \\ '__|  |\n";
    std::cout << "|  | |  | | (_| | | | | (_| | (_| |  __/ |     |\n";
    std::cout << "|  |_|  |_|\\__,_|_| |_|\\__,_|\\__, |\\___|_|     |\n";
    std::cout << "|                            |___/             |\n";
    std::cout << "|                                              |\n";
    std::cout << "+==============================================+\n";
}


void displayMenu() {
    
    system("cls");
    displayHeader();

    setConsoleColor(LIGHT_MAGENTA);
    std::cout << "\n\tSuccessfully authorized as " + global_username << std::endl << std::endl;
    setConsoleColor(LIGHT_CYAN);
    std::cout << "+==============================================+\n";
    std::cout << "||  1 - Run And Hide (Slidysim AUTO Update!)  ||\n";
    std::cout << "||  2 - Run Upload Cycle Once                 ||\n";
    std::cout << "||  3 - Run Automated cycles every minute     ||\n";
    std::cout << "||  4 - Reupload All scores to server         ||\n";
    std::cout << "||  5 - Logout (delete credentials file)      ||\n";
    std::cout << "||  6 - Delete PB database (only custom one)  ||\n";
    std::cout << "||                                            ||\n";
    std::cout << "||      To exit, please use Ctrl+C or [X]     ||\n";
    std::cout << "+==============================================+\n";
    std::cout << "Enter your choice: ";
    setConsoleColor(DARK_CYAN);
}

std::string getCurrentTimeString() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::ostringstream timeStream;
    timeStream << std::put_time(std::localtime(&now_c), "%Y-%m-%d %H:%M:%S");
    return timeStream.str();
}

void autoUploadCycle(std::atomic<bool>& running) {
    while (running) {
        
        printSeparator(getCurrentTimeString());
        if (uploadCycle()) {
           // std::cout << "Upload cycle completed successfully.\n";
        } else {
          //  std::cout << "Upload cycle encountered an error.\n";
        }
        sqlite3* db;
        if (sqlite3_open(db_file_path.c_str(), &db) == SQLITE_OK) {
            sqlite3_close(db); //closing db if its still opened because of stupid bug
        }
            std::cout << "Press any key to stop. Next cycle starts in:\n"; // Instruction message
            
            int countdown = 60; // Initialize with the first countdown value
    
            auto start_time = std::chrono::steady_clock::now();

            while (countdown > 0 && running) {
                if (slidysim_is_dead){
                    running = false;
                    exit(1); //exiting when slidysim is dead
                    //std::cout << "Slidysim was closed. Auto-update is stopped.\nEnter any key to get back to menu.\n";
                    std::cin.ignore(); // Ignore leftover newline character
                    std::cin.get();    // Wait for a key press
                    break;
                }
                // Check for user input
                if (_kbhit()) {
                    _getch(); // Consume the key press.
                    running = false;
                    break;
                }

                // Sleep for a short time before checking the elapsed time again
                std::this_thread::sleep_for(std::chrono::milliseconds(500));

                // Calculate the elapsed time since the last second update
                auto current_time = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - start_time);

                // Update the countdown if 1000 milliseconds (1 second) have passed
                if (elapsed.count() >= 1000) {
                    // Clear the previous countdown number and print the updated countdown
                    std::cout << "\r            \r"; // Clear the previous countdown line
                    std::cout << countdown << " seconds..."; // Print the current countdown
                    std::cout.flush(); // Ensure the message is printed immediately
                    --countdown; // Decrease countdown

                    // Reset the start time for the next second
                    start_time = current_time;
                }
            }

            std::cout << "\r                        \r"; // Clear the final countdown message
    }
}



void initAutoUpdateCycle(){
    std::atomic<bool> running{false};
    // Scoped block to limit the lifetime of the thread
    std::cout << "\nStarting auto upload. Press any key to stop...\n";
    running = true;
    std::thread autoUploadThread(autoUploadCycle, std::ref(running));
    // Wait for the user to press any key to stop.
    autoUploadThread.join();
}

int main() {
    createIndex();
    disableQuickEditMode();
    SetConsoleTitle("Slidysim Records Manager (1.1.0)");
    SetConsoleOutputCP(CP_UTF8);
    resizeConsole(50, 50);
    system("cls");
    displayHeader();
    if (check_from_file()) {
        //std::cout << "Successfully authorized as " + global_username << std::endl;
    } else {
        if (authorize_user()) {
            //std::cout << "Successfully authorized as " + global_username << std::endl;
        } else {
            std::cout << "Failed to authorize user." << std::endl;
            std::cin.ignore(); // Ignore leftover newline character
            std::cin.get();    // Wait for a key press
            return 0;
        }
    }
    setConsoleColor(LIGHT_MAGENTA);
    std::cout << "\n\tSuccessfully authorized as " + global_username << std::endl << std::endl;
    setConsoleColor(DARK_CYAN);
    runAndHide();
    initAutoUpdateCycle();
    do {
        displayMenu();
        int choice;
        std::cin >> choice;

        switch (choice) {
            case 1:{
                slidysim_is_dead = false;
                runAndHide();
                initAutoUpdateCycle();
                break;
            }
            case 2: {
                std::cout << "Running Upload Cycle...\n";
                if (uploadCycle()) {
                    std::cout << "Upload cycle completed successfully.\n";
                } else {
                    std::cout << "Upload cycle encountered an error.\n";
                }
                sqlite3* db;
                if (sqlite3_open(db_file_path.c_str(), &db) == SQLITE_OK) {
                    sqlite3_close(db); //closing db if its still opened because of stupid bug
                }
                std::cout << "Please press any key to continue.\n";
                std::cin.ignore(); // Ignore leftover newline character
                std::cin.get();    // Wait for a key press
                break;
            }
            case 3: {
                slidysim_is_dead = false;
                initAutoUpdateCycle();
                break;
            }
            case 4: {
                //reupload all scores to server
                if (reupload_scores()) {
                    std::cout << "Operation completed successfully." << std::endl;
                } else {
                    std::cout << "Failed to reupload scores." << std::endl;
                }
                std::cin.ignore(); // Ignore leftover newline character
                std::cin.get();    // Wait for a key press
                break;
            }
            case 5: {
                if (logout()) {
                    std::cout << "Logged out successfully. You will have to re-enter username and password next time." << std::endl;
                    std::cin.ignore(); // Ignore leftover newline character
                    std::cin.get();    // Wait for a key press
                    setConsoleColor(LIGHT_GRAY);
                    return 0;
                } else {
                    std::cout << "Logout failed (Probably could not delete credentials file)." << std::endl;
                }
                std::cin.ignore(); // Ignore leftover newline character
                std::cin.get();    // Wait for a key press
                break;    
            }
            case 6: {
                if (deleteDatabase()) {
                    std::cout << "PB database deleted successfully." << std::endl;
                } else {
                    std::cout << "Failed to delete the database.\nYou might have to restart the CLI." << std::endl;
                }
                std::cin.ignore(); // Ignore leftover newline character
                std::cin.get();    // Wait for a key press
                break;    
            }            
            default: {
                std::cout << "Exiting...\n";
                setConsoleColor(LIGHT_GRAY);
                return 0;
            }
        }
    } while (true);
    setConsoleColor(LIGHT_GRAY);
    return 0;
}