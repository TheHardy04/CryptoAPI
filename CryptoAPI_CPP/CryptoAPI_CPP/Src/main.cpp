#include <iostream>
#include <chrono>  
#include <string>
#include <map>
#include <ctime>
#include <curl/curl.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <sstream>
#include <iomanip>
#include <cstdlib>

// URL encode helper function
std::string url_encode(const std::string& value) {
    CURL* curl = curl_easy_init();
    char* output = curl_easy_escape(curl, value.c_str(), static_cast<int>(value.length()));
    std::string result(output);
    curl_free(output);
    curl_easy_cleanup(curl);
    return result;
}

// Base64 encode function
std::string base64_encode(const unsigned char* input, int length) {
    BIO* bmem, * b64;
    BUF_MEM* bptr;
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // No newline
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    std::string output(bptr->data, bptr->length);
    BIO_free_all(b64);
    return output;
}

// HMAC-SHA512 signature generator
std::string get_kraken_signature(const std::string& urlpath, const std::string& postdata, const std::string& secret) {
    unsigned char* decoded_secret = (unsigned char*)malloc(secret.length());
    int len = EVP_DecodeBlock(decoded_secret, (unsigned char*)secret.c_str(), static_cast<int>(secret.length()));

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)postdata.c_str(), postdata.length(), hash);

    unsigned char* result = HMAC(EVP_sha512(), decoded_secret, len, hash, SHA256_DIGEST_LENGTH, NULL, NULL);
    free(decoded_secret);

    return base64_encode(result, SHA512_DIGEST_LENGTH);
}

// CURL response handler
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    size_t totalSize = size * nmemb;
    userp->append((char*)contents, totalSize);
    return totalSize;
}

// Function to make the Kraken API request
std::string make_kraken_request(const std::string& api_key, const std::string& api_secret, const std::string& url_path, const std::map<std::string, std::string>& payload) {
    CURL* curl;
    CURLcode res;
    std::string response;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {
        std::string postfields;
        auto now = std::chrono::system_clock::now();
        auto duration = now.time_since_epoch();
        long long nonce = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();  // Get time in milliseconds
        postfields += "nonce=" + std::to_string(nonce);

        for (const auto& pair : payload) {
            postfields += "&" + pair.first + "=" + url_encode(pair.second);
        }

		std::cout << "Postfields: " << postfields << std::endl;

        std::string signature = get_kraken_signature(url_path, postfields, api_secret);

        struct curl_slist* headers = nullptr;
		headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
		headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, ("API-Key: " + api_key).c_str());
        headers = curl_slist_append(headers, ("API-Sign: " + signature).c_str());

        curl_easy_setopt(curl, CURLOPT_URL, ("https://api.kraken.com" + url_path).c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "CURL error: " << curl_easy_strerror(res) << std::endl;
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
    return response;
}

// Function to check Kraken balance
void check_kraken_balance() {
    char* api_key = nullptr;
    char* api_secret = nullptr;
    size_t len;

    _dupenv_s(&api_key, &len, "KRAKEN_API_KEY");
    _dupenv_s(&api_secret, &len, "KRAKEN_API_SECRET");

    if (!api_key || !api_secret) {
        std::cerr << "API key or secret not found in environment variables." << std::endl;
        if (api_key) free(api_key);
        if (api_secret) free(api_secret);
        return;
    }

    std::map<std::string, std::string> payload;
    std::string response = make_kraken_request(api_key, api_secret, "/0/private/Balance", payload);
    std::cout << "Balance Response: " << response << std::endl;

    free(api_key);
    free(api_secret);
}

// Function to place an order on Kraken
void place_order(const std::string& pair, const std::string& type, const std::string& ordertype, const std::string& volume, const std::string& price = "") {
    char* api_key = nullptr;
    char* api_secret = nullptr;
    size_t len;

	// Get the API key and secret from environment variables
    _dupenv_s(&api_key, &len, "KRAKEN_API_KEY");
    _dupenv_s(&api_secret, &len, "KRAKEN_API_SECRET");

    if (!api_key || !api_secret) {
        std::cerr << "API key or secret not found in environment variables." << std::endl;
        if (api_key) free(api_key);
        if (api_secret) free(api_secret);
        return;
    }

	std::cout << "API Key: " << api_key << std::endl;

    std::map<std::string, std::string> payload = {
        {"pair", pair},
        {"type", type},
        {"ordertype", ordertype},
        {"volume", volume}
    };

    if (ordertype == "limit" && !price.empty()) {
        payload["price"] = price;
    }

    std::string response = make_kraken_request(api_key, api_secret, "/0/private/AddOrder", payload);
    std::cout << "Order Response: " << response << std::endl;

    free(api_key);
    free(api_secret);
}

int main() {
    std::cout << "Checking Kraken balance..." << std::endl;
    check_kraken_balance();

    //std::cout << "Placing an order on Kraken..." << std::endl;
    //place_order("BTCUSD", "sell", "market", "0.01");

    return 0;
}