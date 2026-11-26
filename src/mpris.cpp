#include "lb/mpris.hpp"

#include <dbus/dbus.h>

#include <sys/time.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace lb {
namespace {

std::string lower_copy(std::string s) {
    for (char& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}

std::string json_escape(const std::string& s) {
    std::string o;
    o.reserve(s.size());
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') {
            o.push_back('\\');
            o.push_back(static_cast<char>(c));
        } else if (c == '\n') {
            o += "\\n";
        } else if (c >= 32) {
            o.push_back(static_cast<char>(c));
        }
    }
    return o;
}

int64_t now_us() {
    timeval tv {};
    gettimeofday(&tv, nullptr);
    return static_cast<int64_t>(tv.tv_sec) * 1000000ll + tv.tv_usec;
}

std::string b64(const std::string& in) {
    static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string o;
    unsigned val = 0;
    int valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            o.push_back(t[(val >> valb) & 0x3f]);
            valb -= 6;
        }
    }
    if (valb > -6) o.push_back(t[((val << 8) >> (valb + 8)) & 0x3f]);
    while (o.size() % 4) o.push_back('=');
    return o;
}

std::string update_line(const NowPlaying& n) {
    bool playing = n.status == "Playing";
    int state = playing ? 1 : (n.status == "Paused" ? 2 : 0);
    (void)state;
    double rate = n.rate == 0 ? 1 : n.rate;
    std::ostringstream o;
    o << "{\"type\":\"update\",\"bundle\":\"" << json_escape(n.bundle) << "\",\"title\":\"" << json_escape(n.title)
      << "\",\"artist\":\"" << json_escape(n.artist) << "\",\"album\":\"" << json_escape(n.album)
      << "\",\"playing\":" << (playing ? "true" : "false") << ",\"rate\":" << rate
      << ",\"durationMicros\":" << n.length_us << ",\"elapsedMicros\":" << n.position_us
      << ",\"timestampEpochMicros\":" << now_us() << ",\"music\":" << (n.bundle.empty() ? "false" : "true")
      << ",\"artworkMime\":\"" << json_escape(n.art_mime) << "\",\"artworkData\":\"" << json_escape(n.art_data)
      << "\"}\n";
    return o.str();
}

struct Field {
    std::string s;
    int64_t i = 0;
    double d = 0;
    std::vector<std::string> strs;
    std::map<std::string, Field> dict;
};

void read_dbus(DBusMessageIter* it, Field& out) {
    int t = dbus_message_iter_get_arg_type(it);
    if (t == DBUS_TYPE_STRING || t == DBUS_TYPE_OBJECT_PATH) {
        const char* s = nullptr;
        dbus_message_iter_get_basic(it, &s);
        out.s = s ? s : "";
    } else if (t == DBUS_TYPE_INT64) {
        int64_t v = 0;
        dbus_message_iter_get_basic(it, &v);
        out.i = v;
    } else if (t == DBUS_TYPE_UINT64) {
        uint64_t v = 0;
        dbus_message_iter_get_basic(it, &v);
        out.i = static_cast<int64_t>(v);
    } else if (t == DBUS_TYPE_INT32) {
        int32_t v = 0;
        dbus_message_iter_get_basic(it, &v);
        out.i = v;
    } else if (t == DBUS_TYPE_UINT32) {
        uint32_t v = 0;
        dbus_message_iter_get_basic(it, &v);
        out.i = v;
    } else if (t == DBUS_TYPE_DOUBLE) {
        double v = 0;
        dbus_message_iter_get_basic(it, &v);
        out.d = v;
    } else if (t == DBUS_TYPE_BOOLEAN) {
        dbus_bool_t v = 0;
        dbus_message_iter_get_basic(it, &v);
        out.i = v ? 1 : 0;
    } else if (t == DBUS_TYPE_VARIANT) {
        DBusMessageIter sub;
        dbus_message_iter_recurse(it, &sub);
        read_dbus(&sub, out);
    } else if (t == DBUS_TYPE_ARRAY) {
        DBusMessageIter sub;
        dbus_message_iter_recurse(it, &sub);
        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
            int st = dbus_message_iter_get_arg_type(&sub);
            if (st == DBUS_TYPE_DICT_ENTRY) {
                DBusMessageIter ent;
                dbus_message_iter_recurse(&sub, &ent);
                Field key, val;
                read_dbus(&ent, key);
                dbus_message_iter_next(&ent);
                read_dbus(&ent, val);
                out.dict[key.s] = val;
            } else {
                Field val;
                read_dbus(&sub, val);
                if (!val.s.empty()) out.strs.push_back(val.s);
            }
            dbus_message_iter_next(&sub);
        }
    }
}

Field get_prop(DBusConnection* bus, const std::string& name, const char* iface, const char* prop) {
    Field out;
    DBusMessage* msg = dbus_message_new_method_call(name.c_str(), "/org/mpris/MediaPlayer2", "org.freedesktop.DBus.Properties", "Get");
    if (!msg) return out;
    dbus_message_append_args(msg, DBUS_TYPE_STRING, &iface, DBUS_TYPE_STRING, &prop, DBUS_TYPE_INVALID);
    DBusError err;
    dbus_error_init(&err);
    DBusMessage* reply = dbus_connection_send_with_reply_and_block(bus, msg, 400, &err);
    dbus_message_unref(msg);
    if (!reply) {
        dbus_error_free(&err);
        return out;
    }
    DBusMessageIter it;
    if (dbus_message_iter_init(reply, &it)) read_dbus(&it, out);
    dbus_message_unref(reply);
    return out;
}

void fill_art(NowPlaying& n, const std::string& url) {
    if (url.rfind("file://", 0) != 0) return;
    std::string path = url.substr(7);
    std::ifstream in(path, std::ios::binary);
    if (!in) return;
    std::string bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (bytes.empty() || bytes.size() > 200000) return;
    n.art_data = b64(bytes);
    if (path.size() >= 4 && path.substr(path.size() - 4) == ".png") n.art_mime = "image/png";
    else n.art_mime = "image/jpeg";
}

}  // namespace

std::string bundle_for_player(const std::string& desktop) {
    std::string d = lower_copy(desktop);
    if (d.find("spotify") != std::string::npos) return "com.spotify.client";
    if (d.find("netease") != std::string::npos || d.find("cloudmusic") != std::string::npos || d.find("orpheus") != std::string::npos)
        return "com.netease.163music";
    if (d.find("qqmusic") != std::string::npos || d == "qq") return "com.tencent.QQMusicMac";
    if (d.find("itunes") != std::string::npos || d == "music") return "com.apple.Music";
    if (desktop.empty()) return "";
    return "mpris:" + desktop;
}

NowPlaying load_fixture(const std::string& path) {
    NowPlaying n;
    std::ifstream in(path);
    if (!in) return n;
    std::string line;
    while (std::getline(in, line)) {
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = line.substr(0, eq);
        std::string v = line.substr(eq + 1);
        if (!v.empty() && v.back() == '\r') v.pop_back();
        if (k == "title") n.title = v;
        else if (k == "artist") n.artist = v;
        else if (k == "album") n.album = v;
        else if (k == "status") n.status = v;
        else if (k == "length") n.length_us = std::strtoll(v.c_str(), nullptr, 10);
        else if (k == "position") n.position_us = std::strtoll(v.c_str(), nullptr, 10);
        else if (k == "player" || k == "desktop") n.desktop = v;
        else if (k == "bundle") n.bundle = v;
        else if (k == "rate") n.rate = std::strtod(v.c_str(), nullptr);
        else if (k == "art") fill_art(n, v.rfind("file://", 0) == 0 ? v : "file://" + v);
    }
    if (n.bundle.empty()) n.bundle = bundle_for_player(n.desktop.empty() ? "player" : n.desktop);
    if (n.status.empty()) n.status = "Playing";
    if (n.rate == 0) n.rate = 1;
    n.ok = true;
    return n;
}

NowPlaying query_mpris() {
    NowPlaying n;
    DBusError err;
    dbus_error_init(&err);
    DBusConnection* bus = dbus_bus_get(DBUS_BUS_SESSION, &err);
    if (!bus) {
        dbus_error_free(&err);
        return n;
    }
    DBusMessage* msg = dbus_message_new_method_call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "ListNames");
    DBusMessage* reply = dbus_connection_send_with_reply_and_block(bus, msg, 400, &err);
    dbus_message_unref(msg);
    if (!reply) {
        dbus_error_free(&err);
        return n;
    }
    Field names;
    DBusMessageIter it;
    if (dbus_message_iter_init(reply, &it)) read_dbus(&it, names);
    dbus_message_unref(reply);
    for (const std::string& name : names.strs) {
        if (name.rfind("org.mpris.MediaPlayer2.", 0) != 0) continue;
        Field status = get_prop(bus, name, "org.mpris.MediaPlayer2.Player", "PlaybackStatus");
        Field meta = get_prop(bus, name, "org.mpris.MediaPlayer2.Player", "Metadata");
        Field pos = get_prop(bus, name, "org.mpris.MediaPlayer2.Player", "Position");
        Field rate = get_prop(bus, name, "org.mpris.MediaPlayer2.Player", "Rate");
        Field desk = get_prop(bus, name, "org.mpris.MediaPlayer2", "DesktopEntry");
        Field ident = get_prop(bus, name, "org.mpris.MediaPlayer2", "Identity");
        n.bus = name;
        n.status = status.s.empty() ? "Stopped" : status.s;
        n.title = meta.dict["xesam:title"].s;
        if (!meta.dict["xesam:artist"].strs.empty()) n.artist = meta.dict["xesam:artist"].strs[0];
        n.album = meta.dict["xesam:album"].s;
        n.length_us = meta.dict["mpris:length"].i;
        n.position_us = pos.i;
        n.rate = rate.d == 0 ? 1 : rate.d;
        n.desktop = !desk.s.empty() ? desk.s : (!ident.s.empty() ? ident.s : name);
        n.bundle = bundle_for_player(n.desktop);
        fill_art(n, meta.dict["mpris:artUrl"].s);
        n.ok = true;
        if (n.status == "Playing") break;
    }
    return n;
}

std::string media_ndjson(const NowPlaying& n) {
    bool playing = n.status == "Playing";
    int state = playing ? 1 : (n.status == "Paused" ? 2 : 0);
    std::string name = n.desktop.empty() ? "Player" : n.desktop;
    std::ostringstream o;
    o << "{\"type\":\"ready\"}\n";
    o << "{\"type\":\"sessions\",\"sessions\":[";
    if (!n.bundle.empty()) {
        o << "{\"bundle\":\"" << json_escape(n.bundle) << "\",\"name\":\"" << json_escape(name)
          << "\",\"pid\":0,\"playing\":" << (playing ? "true" : "false") << ",\"state\":" << state << "}";
    }
    o << "]}\n";
    o << update_line(n);
    return o.str();
}

int bridge_main() {
    NowPlaying n;
    if (const char* f = std::getenv("LB_MPRIS_FIXTURE")) n = load_fixture(f);
    else n = query_mpris();
    std::cout << media_ndjson(n) << std::flush;
    if (std::getenv("LB_BRIDGE_ONCE")) return 0;
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.rfind("REFRESH", 0) == 0 || line.rfind("TARGET", 0) == 0) {
            if (!std::getenv("LB_MPRIS_FIXTURE")) {
                NowPlaying fresh = query_mpris();
                if (fresh.ok) n = fresh;
            }
            std::cout << update_line(n) << std::flush;
        } else if (line.rfind("SEEK", 0) == 0) {
            double sec = 0;
            auto sp = line.rfind(' ');
            if (sp != std::string::npos) sec = std::strtod(line.c_str() + sp + 1, nullptr);
            n.position_us = static_cast<int64_t>(sec * 1000000.0);
            std::cout << update_line(n) << std::flush;
        } else if (line.rfind("SEND", 0) == 0) {
            if (line.find("PlayPause") != std::string::npos) n.status = n.status == "Playing" ? "Paused" : "Playing";
            else if (line.find("Pause") != std::string::npos) n.status = "Paused";
            else if (line.find("Play") != std::string::npos) n.status = "Playing";
            std::cout << update_line(n) << std::flush;
        } else {
            std::fprintf(stderr, "bridge command %s\n", line.c_str());
        }
    }
    return 0;
}

}  // namespace lb
