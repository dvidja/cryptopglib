//
// Created by Anton Sarychev on 1/3/21.
//
#include "cryptopglib/cryptopg.h"


#include <iostream>
#include <filesystem>
#include <boost/program_options.hpp>

#include "model/pgp_key_info.h"

int main(int ac, char** av)
{
    try {
        boost::program_options::options_description desc("Allowed options");
        desc.add_options()
                ("help", "This help message")
                ("key_info", boost::program_options::value<std::filesystem::path>(), "get pgp key info");

        boost::program_options::variables_map vm;
        boost::program_options::store(boost::program_options::parse_command_line(ac, av, desc), vm);
        boost::program_options::notify(vm);

        if (vm.count("help")) {
            std::cout << desc << "\n";
            return 0;
        }

        if (vm.count("key_info")) {
            auto key_file = vm["key_info"].as<std::filesystem::path>();
            std::cout << "Get information for the pgp key: "
                 << key_file << ".\n";
            PrintKeyInfo(key_file);
        } else {
            std::cout << "Path to the key was not set.\n";
        }
    }
    catch(std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
    catch(...) {
        std::cerr << "Exception of unknown type!\n";
        return 1;
    }
    return 0;
}
