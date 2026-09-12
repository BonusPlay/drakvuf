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
#pragma once
#include <libdrakvuf/libdrakvuf.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iterator>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace slog
{

inline constexpr std::monostate null{};

// Tags an integer for hex rendering; without it a hex field is indistinguishable
// from a plain number.
struct hex_value { uint64_t data; };

struct keyval;
using keyval_array = std::vector<keyval>;

struct value
{
    using storage = std::variant<
        std::monostate, bool, int64_t, uint64_t, double,
        std::string, std::vector<uint8_t>, hex_value,
        std::vector<value>, keyval_array>;

    storage data;

    value() = default;
    value(std::monostate) {}
    value(std::nullptr_t) {}

    template<typename T,
        std::enable_if_t<std::is_arithmetic_v<T> || std::is_enum_v<T>, int> = 0>
    value(T input);

    value(const char* input) : data{input ? storage{std::string(input)} : storage{}} {}
    value(std::string input) : data{std::move(input)} {}
    value(std::string_view input) : data{std::string(input)} {}
    value(std::vector<uint8_t> input) : data{std::move(input)} {}
    value(hex_value input) : data{input} {}
    value(const unicode_string_t* input);
    value(std::vector<value> input) : data{std::move(input)} {}
    value(keyval_array input) : data{std::move(input)} {}

    template<typename T>
    value(const std::optional<T>& input);

    // Strings are scalar text; any other range becomes a group when its elements
    // look like key/value pairs, an array otherwise.
    template<typename Range,
        typename = std::enable_if_t<!std::is_convertible_v<const Range&, std::string_view>>,
        typename = decltype(std::begin(std::declval<const Range&>()),
            std::end(std::declval<const Range&>()))>
    value(const Range& items);
};

struct keyval
{
    std::string key;
    value data;

    keyval(std::string name, value input)
        : key(std::move(name)), data(std::move(input))
    {}

    // allows std::map<std::string, T> convert
    template<typename K, typename V>
    keyval(const std::pair<K, V>& input)
        : keyval(std::string(input.first), value(input.second))
    {}
};

template<typename T,
    std::enable_if_t<std::is_arithmetic_v<T> || std::is_enum_v<T>, int>>
inline value::value(T input)
{
    if constexpr (std::is_enum_v<T>)
        data = value(static_cast<std::underlying_type_t<T>>(input)).data;
    else if constexpr (std::is_same_v<T, bool>)
        data = input;
    else if constexpr (std::is_floating_point_v<T>)
        data = static_cast<double>(input);
    else if constexpr (std::is_signed_v<T>)
        data = static_cast<int64_t>(input);
    else
        data = static_cast<uint64_t>(input);
}

template<typename T>
inline value::value(const std::optional<T>& input) : value(input ? value(*input) : value()) {}

template<typename Range, typename, typename>
value::value(const Range& items)
{
    if constexpr (std::is_constructible_v<keyval, decltype(*std::begin(items))>)
    {
        keyval_array result;
        for (const auto& item : items)
            result.push_back(keyval(item));
        data = std::move(result);
    }
    else
    {
        std::vector<value> result;
        for (const auto& item : items)
            result.emplace_back(item);
        data = std::move(result);
    }
}

value text(const char* data);
value text(std::nullptr_t);
value text(std::string data);
value text(std::string_view data);

template<typename T>
value text(const std::optional<T>& data)
{
    return data ? text(*data) : value{};
}

value bytes(const void* data, size_t size);
value bytes(std::string_view data);

using flags_map = std::map<uint64_t, std::string>;

// {"Value":"0x40042","Names":["FO_SYNCHRONOUS_IO",...]}
value flags(uint64_t value, const flags_map& names);

// Decoded UTF-8; bytes that will not decode are escaped. Never invalid UTF-8.
std::string escaped_text(const unicode_string_t* data);

value time(gint64 data);

template<typename T>
value number(T data)
{
    return value(data);
}

template<typename T>
value hex(T data)
{
    static_assert((std::is_integral_v<T> && !std::is_same_v<T, bool>) || std::is_enum_v<T>,
        "slog::hex requires an integral or enum value");
    if constexpr (std::is_enum_v<T>)
        return hex(static_cast<std::underlying_type_t<T>>(data));
    else
        return hex_value{static_cast<uint64_t>(static_cast<std::make_unsigned_t<T>>(data))};
}

template<typename T>
value hex(const std::optional<T>& data)
{
    return data ? hex(*data) : value{};
}

template<typename T>
keyval attr(std::string_view key, T&& data)
{
    return keyval{std::string(key), std::forward<T>(data)};
}

inline void append(keyval_array& target, keyval data)
{
    target.push_back(std::move(data));
}

inline void append(keyval_array& target, keyval_array data)
{
    target.insert(target.end(), std::make_move_iterator(data.begin()),
        std::make_move_iterator(data.end()));
}

// setup only; log callers do not select or pass a format.
void set_default_json() noexcept;
void set_default_kv() noexcept;

void emit_record(const keyval_array& data) noexcept;
void emit_trap_record(const char* plugin, drakvuf_t drakvuf, const drakvuf_trap_info_t* info, keyval_array data) noexcept;
void emit_process_record(const char* plugin, gint64 timestamp, const proc_data_t& process, keyval_array data) noexcept;

// write record to a file
bool write_record(const std::filesystem::path& path, const keyval_array& data) noexcept;

template<typename... Args>
void emit(const char* plugin, drakvuf_t drakvuf, const drakvuf_trap_info_t* info, Args&&... args) noexcept
{
    keyval_array data;
    (append(data, std::forward<Args>(args)), ...);
    emit_trap_record(plugin, drakvuf, info, std::move(data));
}

template<typename... Args>
void emit_proc_data(const char* plugin, const proc_data_t& process, Args&&... args) noexcept
{
    keyval_array data;
    (append(data, std::forward<Args>(args)), ...);
    emit_process_record(plugin, g_get_real_time(), process, std::move(data));
}

void emit_running_process(const char* plugin, gint64 timestamp, const proc_data_t& process) noexcept;

} // namespace slog
