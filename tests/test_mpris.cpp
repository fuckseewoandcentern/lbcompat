#include "lb/mpris.hpp"
#include "host.hpp"

#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

int main() {
    const char* path = "/tmp/lb-mpris-fixture.txt";
    {
        std::ofstream out(path);
        out << "title=Night Drive\nartist=Ada\nalbum=City\nstatus=Playing\n"
               "length=180000000\nposition=5000000\nplayer=spotify\nrate=1\n";
    }
    lb::NowPlaying n = lb::load_fixture(path);
    if (!n.ok || n.title != "Night Drive" || n.bundle != "com.spotify.client") {
        std::fprintf(stderr, "fixture mapping failed\n");
        return 1;
    }
    std::string json = lb::media_ndjson(n);
    if (json.find("\"type\":\"ready\"") == std::string::npos || json.find("Night Drive") == std::string::npos ||
        json.find("\"durationMicros\":180000000") == std::string::npos ||
        json.find("\"elapsedMicros\":5000000") == std::string::npos ||
        json.find("com.spotify.client") == std::string::npos) {
        std::fprintf(stderr, "ndjson missing fields\n%s\n", json.c_str());
        return 1;
    }
    std::vector<std::string> args = {"/usr/bin/perl", "mediasession-adapter.pl", "stream_all"};
    auto plan = lb::plan_spawn("/usr/bin/perl", args);
    if (!plan.bridge || plan.argv.empty()) {
        std::fprintf(stderr, "perl stream_all was not rewritten\n");
        return 1;
    }
    std::printf("mpris bridge checks passed\n");
    return 0;
}
