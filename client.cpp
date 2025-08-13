#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <random>

namespace asio = boost::asio;
using asio::ip::tcp;

// SHA1 helper
std::string sha1_hex(const std::string &data) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);
    std::ostringstream oss;
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return oss.str();
}

// Generate random UTF-8 safe string without [\n\r\t ]
std::string random_string(size_t length = 8) {
    static const std::string chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-={}[]|:;<>?,./";
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, chars.size() - 1);
    std::string s;
    for (size_t i = 0; i < length; i++)
        s += chars[dis(gen)];
    return s;
}

int main() {
    try {
        asio::io_context io_context;
        asio::ssl::context ctx(asio::ssl::context::tls_client);

    std::cout << "[DEBUG] Setting up SSL context..." << std::endl;
    ctx.use_private_key_file("qa-challenge-21-.pem", boost::asio::ssl::context::pem);
    ctx.use_certificate_chain_file("qa-challenge-21-.pem");
    ctx.load_verify_file("qa-challenge-21-.pem");
    ctx.set_verify_mode(boost::asio::ssl::verify_peer);
    std::cout << "[DEBUG] SSL context setup complete." << std::endl;

        std::cout << "[DEBUG] Creating SSL socket and resolver..." << std::endl;
        boost::asio::ssl::stream<tcp::socket> ssl_sock(io_context, ctx);
        tcp::resolver resolver(io_context);
        boost::system::error_code ec;
        std::cout << "[DEBUG] Resolving server address..." << std::endl;
        auto endpoints = resolver.resolve("18.202.148.130","3336",ec);
        if (ec) {
            std::cerr << "[ERROR] Resolve failed: " << ec.message() << "\n";
            return 1;
        }
        std::cout << "[DEBUG] Server address resolved." << std::endl;

        std::cout << "[DEBUG] Connecting to server..." << std::endl;
        asio::connect(ssl_sock.lowest_layer(), endpoints, ec);
        if (ec) {
            std::cerr << "[ERROR] Connect failed: " << ec.message() << "\n";
            return 1;
        }
        std::cout << "[DEBUG] TCP connection established." << std::endl;
        std::cout << "[DEBUG] Performing SSL handshake..." << std::endl;
        ssl_sock.handshake(boost::asio::ssl::stream_base::client);
        std::cout << "[DEBUG] SSL handshake complete. Connected to server.\n";

        std::string authdata;
    std::cout << "[DEBUG] Ready to read/write from server." << std::endl;
    asio::streambuf buf;
    std::istream is(&buf);

        while (true) {
            asio::read_until(ssl_sock, buf, "\n");
            std::cout << "[DEBUG] Received line from server." << std::endl;
            std::string line;
            std::getline(is, line);
            if (line.empty()) continue;

            std::istringstream iss(line);
            std::vector<std::string> args;
            std::string token;
            while (iss >> token) args.push_back(token);

            if (args.empty()) continue;

            if (args[0] == "HELO") {
                std::cout << "[DEBUG] Received HELO, sending TOAKUEI..." << std::endl;
                asio::write(ssl_sock, asio::buffer("TOAKUEI\n"));
            }
            else if (args[0] == "ERROR") {
                std::cerr << "[ERROR] Server error: ";
                for (size_t i = 1; i < args.size(); i++)
                    std::cerr << args[i] << " ";
                std::cerr << "\n";
                break;
            }
            else if (args[0] == "POW") {
                std::cout << "[DEBUG] Received POW challenge. Solving..." << std::endl;
                authdata = args[1];
                int difficulty = std::stoi(args[2]);
                while (true) {
                    std::string suffix = random_string();
                    std::string cksum = sha1_hex(authdata + suffix);
                    if (cksum.rfind(std::string(difficulty, '0'), 0) == 0) {
                        std::cout << "[DEBUG] POW solved. Sending suffix: " << suffix << std::endl;
                        asio::write(ssl_sock, asio::buffer(suffix + "\n"));
                        break;
                    }
                }
            }
            else if (args[0] == "END") {
                std::cout << "[DEBUG] Received END. Sending OK and closing connection..." << std::endl;
                asio::write(ssl_sock, asio::buffer("OK\n"));
                break;
            }
            else if (args[0] == "NAME") {
                asio::write(ssl_sock, asio::buffer(sha1_hex(authdata + args[1]) + " Sheetal Mohanan\n"));
            }
            else if (args[0] == "MAILNUM") {
                asio::write(ssl_sock, asio::buffer(sha1_hex(authdata + args[1]) + " 1\n"));
            }
            else if (args[0] == "MAIL1") {
                asio::write(ssl_sock, asio::buffer(sha1_hex(authdata + args[1]) + " sheetalmohanan@gmail.com\n"));
            }
            else if (args[0] == "SKYPE") {
                asio::write(ssl_sock, asio::buffer(sha1_hex(authdata + args[1]) + " N/A\n"));
            }
            else if (args[0] == "BIRTHDATE") {
                asio::write(ssl_sock, asio::buffer(sha1_hex(authdata + args[1]) + " 25.09.1998\n"));
            }
            else if (args[0] == "COUNTRY") {
                asio::write(ssl_sock, asio::buffer(sha1_hex(authdata + args[1]) + " India\n"));
            }
            else if (args[0] == "ADDRNUM") {
                asio::write(ssl_sock, asio::buffer(sha1_hex(authdata + args[1]) + " 2\n"));
            }
            else if (args[0] == "ADDRLINE1") {
                asio::write(ssl_sock, asio::buffer(sha1_hex(authdata + args[1]) + " 1/11, MIG 2 , TNHB1500 Flats\n"));
            }
            else if (args[0] == "ADDRLINE2") {
                asio::write(ssl_sock, asio::buffer(sha1_hex(authdata + args[1]) + " Shollinganalur, Chennai"));
            }
        }

    std::cout << "[DEBUG] Closing socket." << std::endl;
    ssl_sock.lowest_layer().close();
    }
    catch (std::exception &e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }
}
