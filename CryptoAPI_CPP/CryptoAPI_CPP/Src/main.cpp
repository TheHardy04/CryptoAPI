#include <iostream>
#include "curl/curl.h"

// Callback function to handle the data received from the HTTP request
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    size_t totalSize = size * nmemb;
    userp->append((char*)contents, totalSize);
    return totalSize;
}

int main() {
    CURL* curl;
    CURLcode res;

    // Initialize libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {
        std::string readBuffer;

        // Set the URL for the HTTP request
        curl_easy_setopt(curl, CURLOPT_URL, "https://jsonplaceholder.typicode.com/todos/1");

        // Set callback function to handle the data
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);

        // Pass the string to the callback function to store the response
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        // Perform the HTTP request
        res = curl_easy_perform(curl);

        // Check if the request was successful
        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        }
        else {
            // Output the response
            std::cout << "Response from server: " << readBuffer << std::endl;
        }

        // Cleanup
        curl_easy_cleanup(curl);
    }

    // Global cleanup of libcurl
    curl_global_cleanup();

    return 0;
}
