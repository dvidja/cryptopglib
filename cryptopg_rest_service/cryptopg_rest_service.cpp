//
// Created by Anton Sarychev on 16.11.23.
//

#include <iostream>

#include <cpprest/http_client.h>


int main() {
    web::http::client::http_client client("http://google.com");
    web::http::http_request req(web::http::methods::GET);

    auto resp = client.request(req).get();
    std::cout << resp.status_code() << " : sync request" << std::endl;
    std::cout << resp.extract_string(true).get() << std::endl;
    std::cout << "Starting service...." << std::endl;
}