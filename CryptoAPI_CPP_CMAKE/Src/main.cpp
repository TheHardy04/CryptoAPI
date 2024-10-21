#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <ctime>
#include <curl/curl.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <iomanip>
#include <chrono>

// Function to get the current timestamp in milliseconds
std::string get_current_timestamp() {
    // Get the current time in seconds since the epoch
    auto now = std::chrono::system_clock::now();
    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    // Convert milliseconds to string
    return std::to_string(milliseconds);
}

// URL encode helper function
std::string url_encode(const std::string& value) {
    CURL* curl = curl_easy_init();
    char* output = curl_easy_escape(curl, value.c_str(), static_cast<int>(value.length()));
    std::string result(output);
    curl_free(output);
    curl_easy_cleanup(curl);
    return result;
}
// Function to encode a map into a URL-encoded string
std::string encode_map(const std::map<std::string, std::string>& map) {
	std::ostringstream os;
	for (auto const& pair : map) {
		if (os.tellp() != 0) {
			os << "&";
		}
        os << url_encode(pair.first) << "=" << url_encode(pair.second);
	}
	return os.str();
}

// Base64 encode function done with ChatGPT
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

// Function to Base64-decode a string done with ChatGPT
std::string base64_decode(const std::string& encoded) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new_mem_buf(encoded.data(), static_cast<int>(encoded.size()));
    bio = BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // No newlines in output
    std::vector<char> decoded(encoded.size() * 3 / 4); // Approximate size
    int len = BIO_read(bio, decoded.data(), static_cast<int>(decoded.size()));
    BIO_free_all(bio);
    return std::string(decoded.begin(), decoded.begin() + len);
}

// HMAC-SHA512 signature generator
std::string get_kraken_signature(const std::string& urlpath, std::map<std::string,std::string>& data, const std::string& secret) {
    
	// Encode the data map into a URL-encoded string
	std::string postdata = encode_map(data);

	// Combine the URL path and the POST data
	std::string encoded = url_encode(data["nonce"])+postdata;

	// Generate SHA256 hash and combine it with the URL path
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(encoded.c_str()),encoded.length(),hash);
	size_t combined_size = urlpath.length() + SHA256_DIGEST_LENGTH;
    unsigned char* combined = new unsigned char[combined_size];
	memcpy(combined, urlpath.c_str(), urlpath.length());
	memcpy(combined + urlpath.length(), hash, SHA256_DIGEST_LENGTH);

	// Decode the secret key in base64
	std::string secret_b64 = base64_decode(secret);

	// Generate the HMAC-SHA512 signature
    unsigned char* result;
    unsigned int len = SHA512_DIGEST_LENGTH;
    result = (unsigned char*)malloc(len);
    HMAC(EVP_sha512(), secret_b64.c_str(), secret_b64.length(), combined, combined_size,result, &len);
	std::string signature = base64_encode(result, len);

	// Cleanup
	delete[] combined;
	free(result);

	return signature;
}

// CURL response handler
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    size_t totalSize = size * nmemb;
    userp->append((char*)contents, totalSize);
    return totalSize;
}

// Function to make the Kraken API request
std::string make_kraken_request(const std::string& api_key, const std::string& api_secret, const std::string& url_path, std::map<std::string, std::string>& payload) {
    CURL* curl;
    CURLcode res;
    std::string response;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {

        //// Enable verbose output to see what is being sent
        //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);  // DEBUG

        std::string nonce = get_current_timestamp();
		// std::string nonce = "1234567890";  // TEST
		payload["nonce"] = nonce;

		
        std::string signature = get_kraken_signature(url_path, payload, api_secret);

        std::string encoded_payload = encode_map(payload);

        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, ("API-Key: " + api_key).c_str());
        headers = curl_slist_append(headers, ("API-Sign: " + signature).c_str()); 
        
        curl_easy_setopt(curl, CURLOPT_URL, ("https://api.kraken.com" + url_path).c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, encoded_payload.c_str());
        curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "identity");
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
    size_t len = 0;

#ifdef _WIN32


    _dupenv_s(&api_key, &len, "KRAKEN_API_KEY");
    _dupenv_s(&api_secret, &len, "KRAKEN_API_SECRET");
    //_dupenv_s(&api_secret, &len, "KRAKEN_TEST_KEY");  // TEST

#else
    // Linux-specific code
    api_key = getenv("KRAKEN_API_KEY");
    api_secret = getenv("KRAKEN_API_SECRET");
#endif

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
    size_t len = 0;

	// Get the API key and secret from environment variables
#ifdef _WIN32
// Windows-specific code
    _dupenv_s(&api_key, &len, "KRAKEN_API_KEY");
    _dupenv_s(&api_secret, &len, "KRAKEN_API_SECRET");
    //_dupenv_s(&api_secret, &len, "KRAKEN_TEST_KEY");  // TEST

#else
    // Linux-specific code
    api_key = getenv("KRAKEN_API_KEY");
    api_secret = getenv("KRAKEN_API_SECRET");
#endif

    if (!api_key || !api_secret) {
        std::cerr << "API key or secret not found in environment variables." << std::endl;
        if (api_key) free(api_key);
        if (api_secret) free(api_secret);
        return;
    }

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

    std::cout << "Placing an order on Kraken..." << std::endl;
    place_order("BTCUSD", "sell", "market", "0.01");

    return 0;
}