#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace lb {

struct NowPlaying {
    std::string title;
    std::string artist;
    std::string album;
    std::string art_mime;
    std::string art_data;
    std::string status;
    std::string desktop;
    std::string bundle;
    std::string bus;
    int64_t length_us = 0;
    int64_t position_us = 0;
    double rate = 1;
    bool ok = false;
};

NowPlaying load_fixture(const std::string& path);
NowPlaying query_mpris();
std::string bundle_for_player(const std::string& desktop);
std::string media_ndjson(const NowPlaying& now);
int bridge_main();

}  // namespace lb
