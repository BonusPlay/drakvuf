/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2024 Tamas K Lengyel.                                  *
 * Tamas K Lengyel is hereinafter referred to as the author.               *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed DRAKVUF technology into proprietary   *
 * software, alternative licenses can be acquired from the author.         *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files.                             *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * DRAKVUF with other software in compressed or archival form does not     *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * DRAKVUF or grant special permissions to use it in other open source     *
 * software.  Please contact tamas.k.lengyel@gmail.com with any such       *
 * requests.  Similarly, we don't incorporate incompatible open source     *
 * software into Covered Software without special permission from the      *
 * copyright holders.                                                      *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * DRAKVUF in other works, are happy to help.  As mentioned above,         *
 * alternative license can be requested from the author to integrate       *
 * DRAKVUF into proprietary applications and appliances.  Please email     *
 * tamas.k.lengyel@gmail.com for further information.                      *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port DRAKVUF to new platforms, fix bugs, *
 * and add new features.  You are highly encouraged to submit your changes *
 * on https://github.com/tklengyel/drakvuf, or by other methods.           *
 * By sending these changes, it is understood (unless you specify          *
 * otherwise) that you are offering unlimited, non-exclusive right to      *
 * reuse, modify, and relicense the code.  DRAKVUF will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).                                        *
 * To specify special license conditions of your contributions, just say   *
 * so when you send them.                                                  *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the DRAKVUF   *
 * license file for more details (it's in a COPYING file included with     *
 * DRAKVUF, and also available from                                        *
 * https://github.com/tklengyel/drakvuf/COPYING)                           *
 *                                                                         *
 ***************************************************************************/
#include "slog.hpp"

#include <json-c/json.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <iomanip>
#include <locale>
#include <memory>
#include <mutex>
#include <sstream>

namespace
{

std::mutex output_mutex;

std::string byte_escape(const uint8_t* data, size_t size)
{
    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(size);

    for (size_t i = 0; i < size; ++i)
    {
        const uint8_t c = data[i];
        switch (c)
        {
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            case '\\': result += "\\\\"; break;
            case '"': result += "\\\""; break;
            default:
                if (c >= 0x20 && c <= 0x7e)
                {
                    result.push_back(static_cast<char>(c));
                }
                else
                {
                    result += "\\x";
                    result.push_back(hex[c >> 4]);
                    result.push_back(hex[c & 0x0f]);
                }
        }
    }
    return result;
}

std::string byte_escape(const std::string& data)
{
    return byte_escape(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

std::string checked_text(const std::string& data)
{
    if (g_utf8_validate(data.data(), static_cast<gssize>(data.size()), nullptr))
        return data;
    return byte_escape(data);
}

std::string checked_key(const std::string& data)
{
    std::string result = checked_text(data);
    size_t nul = result.find('\0');
    while (nul != std::string::npos)
    {
        result.replace(nul, 1, "\\x00");
        nul = result.find('\0', nul + 4);
    }
    return result;
}

std::string nonfinite_double(double data)
{
    if (std::isnan(data))
        return "nan";
    return std::signbit(data) ? "-inf" : "inf";
}

std::string text_escape(const std::string& data)
{
    if (!g_utf8_validate(data.data(), static_cast<gssize>(data.size()), nullptr))
        return byte_escape(data);

    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(data.size());
    for (const unsigned char c : data)
    {
        switch (c)
        {
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            case '\\': result += "\\\\"; break;
            case '"': result += "\\\""; break;
            default:
                if (c < 0x20 || c == 0x7f)
                {
                    result += "\\x";
                    result.push_back(hex[c >> 4]);
                    result.push_back(hex[c & 0x0f]);
                }
                else
                {
                    result.push_back(static_cast<char>(c));
                }
        }
    }
    return result;
}

std::string timestamp(gint64 value)
{
    std::ostringstream out;
    out.imbue(std::locale::classic());
    out << value / G_USEC_PER_SEC << '.' << std::setfill('0') << std::setw(6)
        << value % G_USEC_PER_SEC;
    return out.str();
}

std::string hex_string(const slog::hex_value& value)
{
    std::ostringstream out;
    out.imbue(std::locale::classic());
    out << "0x" << std::hex << std::nouppercase << value.data;
    return out.str();
}

json_object* to_json(const slog::value& input);
std::optional<std::string> decode_unicode(const unicode_string_t* data);

slog::value unicode_field(const unicode_string_t* data)
{
    if (auto decoded = decode_unicode(data))
        return slog::text(std::move(*decoded));
    if (data && data->contents)
        return slog::bytes(data->contents, data->length);
    return slog::null;
}

json_object* to_json(const slog::keyval_array& group)
{
    json_object* result = json_object_new_object();
    for (const auto& item : group)
    {
        const auto key = checked_key(item.key);
        json_object_object_add(result, key.c_str(), to_json(item.data));
    }
    return result;
}

json_object* to_json(const slog::value& input)
{
    return std::visit([](const auto& data) -> json_object*
    {
        using type = std::decay_t<decltype(data)>;
        if constexpr (std::is_same_v<type, std::monostate>)
        {
            return nullptr;
        }
        else if constexpr (std::is_same_v<type, bool>)
        {
            return json_object_new_boolean(data);
        }
        else if constexpr (std::is_same_v<type, int64_t>)
        {
            return json_object_new_int64(data);
        }
        else if constexpr (std::is_same_v<type, uint64_t>)
        {
            return json_object_new_uint64(data);
        }
        else if constexpr (std::is_same_v<type, double>)
        {
            if (!std::isfinite(data))
            {
                const auto value = nonfinite_double(data);
                return json_object_new_string_len(value.data(), static_cast<int>(value.size()));
            }
            return json_object_new_double(data);
        }
        else if constexpr (std::is_same_v<type, std::string>)
        {
            const auto value = checked_text(data);
            return json_object_new_string_len(value.data(), static_cast<int>(value.size()));
        }
        else if constexpr (std::is_same_v<type, std::vector<uint8_t>>)
        {
            const auto value = byte_escape(data.data(), data.size());
            return json_object_new_string_len(value.data(), static_cast<int>(value.size()));
        }
        else if constexpr (std::is_same_v<type, slog::hex_value>)
        {
            const auto value = hex_string(data);
            return json_object_new_string_len(value.data(), static_cast<int>(value.size()));
        }
        else if constexpr (std::is_same_v<type, std::vector<slog::value>>)
        {
            json_object* result = json_object_new_array_ext(static_cast<int>(data.size()));
            for (const auto& item : data)
                json_object_array_add(result, to_json(item));
            return result;
        }
        else
        {
            return to_json(data);
        }
    }, input.data);
}

std::string kv_quote(const std::string& input, bool is_text)
{
    return '"' + (is_text ? text_escape(input) : byte_escape(input)) + '"';
}

std::string kv_value(const slog::value& input);

std::string kv_key(const std::string& input)
{
    if (!input.empty())
    {
        const bool safe = std::all_of(input.begin(), input.end(), [](unsigned char c)
        {
            return g_ascii_isalnum(c) || c == '_' || c == '-' || c == '.';
        });
        if (safe)
            return input;
    }
    return kv_quote(input, true);
}

std::string kv_group(const slog::keyval_array& group)
{
    std::string result{"{"};
    bool first = true;
    for (const auto& item : group)
    {
        if (!first)
            result.push_back(',');
        first = false;
        result += kv_quote(item.key, true);
        result.push_back(':');
        result += kv_value(item.data);
    }
    result.push_back('}');
    return result;
}

std::string kv_value(const slog::value& input)
{
    return std::visit([](const auto& data) -> std::string
    {
        using type = std::decay_t<decltype(data)>;
        if constexpr (std::is_same_v<type, std::monostate>)
            return "null";
        else if constexpr (std::is_same_v<type, bool>)
            return data ? "true" : "false";
        else if constexpr (std::is_same_v<type, int64_t> || std::is_same_v<type, uint64_t>)
            return std::to_string(data);
        else if constexpr (std::is_same_v<type, double>)
        {
            if (!std::isfinite(data))
                return kv_quote(nonfinite_double(data), true);
            std::ostringstream out;
            out.imbue(std::locale::classic());
            out << data;
            return out.str();
        }
        else if constexpr (std::is_same_v<type, std::string>)
            return kv_quote(data, g_utf8_validate(data.data(), static_cast<gssize>(data.size()), nullptr));
        else if constexpr (std::is_same_v<type, std::vector<uint8_t>>)
            return '"' + byte_escape(data.data(), data.size()) + '"';
        else if constexpr (std::is_same_v<type, slog::hex_value>)
            return hex_string(data);
        else if constexpr (std::is_same_v<type, std::vector<slog::value>>)
        {
            std::string result{"["};
            for (size_t i = 0; i < data.size(); ++i)
            {
                if (i)
                    result.push_back(',');
                result += kv_value(data[i]);
            }
            result.push_back(']');
            return result;
        }
        else
            return kv_group(data);
    }, input.data);
}

void append_kv_keyval(std::string& output, const std::string& prefix, const slog::keyval& item, bool& first)
{
    if (const auto* group = std::get_if<slog::keyval_array>(&item.data.data))
    {
        const std::string child_prefix = prefix + item.key + '.';
        for (const auto& child : *group)
            append_kv_keyval(output, child_prefix, child, first);
        return;
    }

    if (!first)
        output.push_back(' ');
    first = false;
    output += kv_key(prefix + item.key);
    output.push_back('=');
    output += kv_value(item.data);
}

std::string render_json(const slog::keyval_array& data)
{
    json_object* root = to_json(data);
    const char* serialized = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    std::string result = serialized ? serialized : "{}";
    json_object_put(root);
    return result;
}

std::string render_kv(const slog::keyval_array& data)
{
    std::string result;
    bool first = true;
    for (const auto& item : data)
        append_kv_keyval(result, {}, item, first);
    return result;
}

using renderer = std::string (*)(const slog::keyval_array&);
std::atomic<renderer> default_renderer{render_kv};

std::string render_line(const slog::keyval_array& data)
{
    std::string line = default_renderer.load(std::memory_order_relaxed)(data);
    line.push_back('\n');
    return line;
}

slog::keyval_array base_record(const char* plugin, gint64 time)
{
    slog::keyval_array result;
    result.push_back(slog::attr("Plugin", slog::text(plugin)));
    result.push_back(slog::attr("TimeStamp", slog::time(time)));
    return result;
}

void append_record(slog::keyval_array& target, slog::keyval_array source)
{
    target.insert(target.end(), std::make_move_iterator(source.begin()), std::make_move_iterator(source.end()));
}

std::optional<std::string> decode_unicode(const unicode_string_t* data)
{
    if (!data)
        return {};

    if (!data->length)
        return std::string();

    if (!data->contents || !data->encoding)
        return {};

    const auto copy_contents = [](const unicode_string_t& input)
    {
        return std::string(input.contents, input.contents + input.length);
    };

    if (data->encoding
        && (!g_ascii_strcasecmp(data->encoding, "UTF-8") || !g_ascii_strcasecmp(data->encoding, "UTF8")))
    {
        auto result = copy_contents(*data);
        if (g_utf8_validate(result.data(), static_cast<gssize>(result.size()), nullptr))
            return result;
        return {};
    }

    unicode_string_t converted{};
    if (VMI_SUCCESS == vmi_convert_str_encoding(data, &converted, "UTF-8"))
    {
        std::optional<std::string> result;
        if (converted.contents)
        {
            auto decoded = copy_contents(converted);
            if (g_utf8_validate(decoded.data(), static_cast<gssize>(decoded.size()), nullptr))
                result = std::move(decoded);
        }
        else if (!converted.length)
            result = std::string();
        std::free(converted.contents);
        return result;
    }

    std::free(converted.contents);
    return {};
}

} // namespace

namespace slog
{

value text(const char* data)
{
    return value(data);
}

value text(std::nullptr_t)
{
    return null;
}

value text(std::string data)
{
    return value(std::move(data));
}

value text(std::string_view data)
{
    return value(data);
}

value bytes(const void* data, size_t size)
{
    std::vector<uint8_t> result;
    if (data && size)
    {
        const auto* begin = static_cast<const uint8_t*>(data);
        result.assign(begin, begin + size);
    }
    return result;
}

value bytes(std::string_view data)
{
    return bytes(data.data(), data.size());
}

value flags(uint64_t value, const flags_map& names)
{
    std::vector<slog::value> set;
    for (const auto& [bit, name] : names)
        if ((bit & value) == bit)
            set.emplace_back(name);

    return keyval_array
    {
        attr("Value", hex(value)),
        attr("Names", std::move(set))
    };
}

value::value(const unicode_string_t* input) : value(unicode_field(input)) {}

std::string escaped_text(const unicode_string_t* data)
{
    if (auto decoded = decode_unicode(data))
        return std::move(*decoded);
    if (data && data->contents)
        return byte_escape(data->contents, data->length);
    return {};
}

value time(gint64 data)
{
    return timestamp(data);
}

void set_default_json() noexcept
{
    default_renderer.store(render_json, std::memory_order_relaxed);
}

void set_default_kv() noexcept
{
    default_renderer.store(render_kv, std::memory_order_relaxed);
}

void emit_record(const keyval_array& data) noexcept
{
    const std::string line = render_line(data);

    std::lock_guard<std::mutex> lock(output_mutex);
    fwrite(line.data(), 1, line.size(), stdout);
    fflush(stdout);
}

bool write_record(const std::filesystem::path& path, const keyval_array& data) noexcept
{
    // 0644 regardless of the process umask: these files are read by tooling that
    // runs as a different user, and must not be group- or world-writable.
    const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return false;

    if (fchmod(fd, 0644))
    {
        close(fd);
        return false;
    }

    const std::string line = render_line(data);
    bool done = true;
    for (size_t written = 0; written < line.size(); )
    {
        const ssize_t count = write(fd, line.data() + written, line.size() - written);
        if (count <= 0)
        {
            if (count < 0 && errno == EINTR)
                continue;
            done = false;
            break;
        }
        written += static_cast<size_t>(count);
    }

    return close(fd) == 0 && done;
}

void emit_trap_record(const char* plugin, drakvuf_t drakvuf, const drakvuf_trap_info_t* info, keyval_array data) noexcept
{
    keyval_array result = base_record(plugin, info ? info->timestamp : g_get_real_time());
    if (info)
    {
        result.push_back(attr("VCPU", info->vcpu));
        if (info->regs)
            result.push_back(attr("CR3", hex(info->regs->cr3)));

        const proc_data_t* process = drakvuf_get_os_type(drakvuf) == VMI_OS_WINDOWS
            ? &info->attached_proc_data
            : &info->proc_data;
        result.push_back(attr("UserId", process->userid));
        result.push_back(attr("PID", process->pid));
        result.push_back(attr("PPID", process->ppid));
        result.push_back(attr("TID", process->tid));
        result.push_back(attr("ProcessName", text(process->name)));
        if (info->trap && info->trap->name)
            result.push_back(attr("Method", text(info->trap->name)));
        result.push_back(attr("EventUID", hex(info->event_uid)));
    }
    append_record(result, std::move(data));
    emit_record(result);
}

void emit_process_record(const char* plugin, gint64 time, const proc_data_t& process, keyval_array data) noexcept
{
    keyval_array result = base_record(plugin, time);
    result.push_back(attr("UserId", process.userid));
    result.push_back(attr("PID", process.pid));
    result.push_back(attr("PPID", process.ppid));
    result.push_back(attr("TID", process.tid));
    result.push_back(attr("ProcessName", text(process.name)));
    append_record(result, std::move(data));
    emit_record(result);
}

void emit_running_process(const char* plugin, gint64 time, const proc_data_t& process) noexcept
{
    keyval_array data;
    data.push_back(attr("RunningProcess", text(process.name)));
    data.push_back(attr("Bitness", number(static_cast<int>(process.bitness))));
    emit_process_record(plugin, time, process, std::move(data));
}

} // namespace slog
