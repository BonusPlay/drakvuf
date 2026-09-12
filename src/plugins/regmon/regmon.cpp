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

#include <inttypes.h>
#include <assert.h>
#include <vector>
#include <string>
#include <optional>

#include "plugins/plugins.h"
#include "slog/slog.hpp"
#include "plugins/plugin_utils.h"

#include "regmon.h"

enum RegistryValueTypes
{
    REG_NONE = 0,
    REG_SZ,
    REG_EXPAND_SZ,
    REG_BINARY,
    REG_DWORD,
    REG_DWORD_LITTLE_ENDIAN = REG_DWORD,
    REG_DWORD_BIG_ENDIAN,
    REG_LINK,
    REG_MULTI_SZ,
    REG_RESOURCE_LIST,
    REG_FULL_RESOURCE_DESCRIPTOR,
    REG_RESOURCE_REQUIREMENTS_LIST,
    REG_QWORD,
    REG_QWORD_LITTLE_ENDIAN = REG_QWORD
};

enum
{
    //REG_OPTION_NON_VOLATILE = 0x00000000,
    REG_OPTION_VOLATILE = 0x00000001,
    REG_OPTION_CREATE_LINK = 0x00000002,
    REG_OPTION_BACKUP_RESTORE = 0x00000004,
    REG_OPTION_OPEN_LINK = 0x00000008,
    REG_OPTION_DONT_VIRTUALIZE = 0x00000010,
};

static const flags_str_t reg_options =
{
    //REGISTER_FLAG(REG_OPTION_NON_VOLATILE),
    REGISTER_FLAG(REG_OPTION_VOLATILE),
    REGISTER_FLAG(REG_OPTION_CREATE_LINK),
    REGISTER_FLAG(REG_OPTION_BACKUP_RESTORE),
    REGISTER_FLAG(REG_OPTION_OPEN_LINK),
    REGISTER_FLAG(REG_OPTION_DONT_VIRTUALIZE)
};

void regmon::print_registry_call_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    const slog::value& key_name, const std::optional<slog::value>& value_name,
    const std::optional<slog::value>& value, uint32_t reg_opts)
{

    slog::emit("regmon", drakvuf, info,
        slog::attr("Key", key_name),
        slog::attr("ValueName", value_name),
        slog::attr("Value", value),
        slog::attr("RegOptions", slog::flags(reg_opts, reg_options))
    );
}

event_response_t regmon::log_reg_impl( drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    uint64_t key_handle,
    const std::optional<slog::value>& value_name,
    const std::optional<slog::value>& data )
{
    if (!key_handle) return 0;

    gchar* key_path = drakvuf_reg_keyhandle_path( drakvuf, info, key_handle );

    if ( key_path )
        print_registry_call_info(drakvuf, info, key_path, value_name, data, 0);

    g_free( key_path );

    return 0;
}

event_response_t regmon::log_reg_impl( drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    uint64_t key_handle,
    addr_t value_name_addr, bool with_value_name,
    const std::optional<slog::value>& data )
{
    std::optional<slog::value> value_name;
    if (with_value_name)
        value_name = slog::value(unicode_string(drakvuf, info, value_name_addr));

    return log_reg_impl(drakvuf, info, key_handle, value_name, data);
}

event_response_t regmon::log_reg_key( drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    uint64_t key_handle)
{
    return log_reg_impl(drakvuf, info, key_handle, 0L, false, {});
}

event_response_t regmon::log_reg_key_value( drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    uint64_t key_handle, addr_t value_name_addr )
{
    return log_reg_impl(drakvuf, info, key_handle, value_name_addr, true, {});
}

char* regmon::get_key_path_from_attr(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t attr)
{
    if (!attr) return nullptr;

    auto vmi = vmi_lock_guard(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    addr_t key_handle;
    ctx.addr = attr + this->objattr_root;
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &key_handle) )
        return nullptr;

    addr_t key_name_addr;
    ctx.addr = attr + this->objattr_name;
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &key_name_addr) )
        return nullptr;

    gchar* key_root_p = drakvuf_reg_keyhandle_path( drakvuf, info, key_handle );
    unicode_string_t* us = drakvuf_read_unicode( drakvuf, info, key_name_addr );
    if ( !us )
    {
        g_free(key_root_p);
        return nullptr;
    }

    char* key_path = g_strdup_printf("%s%s%s",
            key_root_p ?: "",
            key_root_p ? "\\" : "",
            (const char*)us->contents ?: "");
    g_free(key_root_p);
    vmi_free_unicode_str(us);

    return key_path;
}

event_response_t regmon::log_reg_objattr(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t attr, uint32_t reg_opts)
{
    char* key_path = get_key_path_from_attr(drakvuf, info, attr);

    if (key_path)
        print_registry_call_info(drakvuf, info, key_path, {}, {}, reg_opts);

    g_free(key_path);

    return 0;
}

// Borrowed view over the guest bytes. slog decodes eagerly, so this need not
// outlive the call.
static slog::value utf16_value(uint8_t* data, size_t size)
{
    unicode_string_t view{size, data, "UTF-16LE"};
    return slog::value(&view);
}

static size_t without_trailing_nuls(const uint8_t* data, size_t size)
{
    while (size >= sizeof(uint16_t) && !data[size - 1] && !data[size - 2])
        size -= sizeof(uint16_t);
    return size;
}

static slog::value parse_registry_data(uint32_t type, std::vector<uint8_t>& data)
{
    if (type == REG_SZ || type == REG_LINK || type == REG_EXPAND_SZ)
    {
        size_t size = data.size();
        if (size % sizeof(uint16_t) == 0)
            size = without_trailing_nuls(data.data(), size);
        return utf16_value(data.data(), size);
    }

    if (type == REG_MULTI_SZ)
    {
        if (data.size() % sizeof(uint16_t))
            return slog::value(std::vector<slog::value>{utf16_value(data.data(), data.size())});

        // The array ends in an empty string; drop that terminator (and any NUL
        // padding after it) so it does not come out as a trailing "".
        const size_t end = without_trailing_nuls(data.data(), data.size());

        std::vector<slog::value> strings;
        size_t begin = 0;
        for (size_t offset = 0; offset < end; offset += sizeof(uint16_t))
        {
            uint16_t code_unit = 0;
            memcpy(&code_unit, data.data() + offset, sizeof(code_unit));
            if (!code_unit)
            {
                strings.push_back(utf16_value(data.data() + begin, offset - begin));
                begin = offset + sizeof(uint16_t);
            }
        }
        if (begin < end)
            strings.push_back(utf16_value(data.data() + begin, end - begin));
        return slog::value(std::move(strings));
    }

    if ((type == REG_DWORD || type == REG_DWORD_BIG_ENDIAN) && data.size() == sizeof(uint32_t))
    {
        uint32_t value = 0;
        memcpy(&value, data.data(), sizeof(value));
        value = type == REG_DWORD_BIG_ENDIAN ? GUINT32_FROM_BE(value) : GUINT32_FROM_LE(value);
        return slog::number(value);
    }

    if (type == REG_QWORD && data.size() == sizeof(uint64_t))
    {
        uint64_t value = 0;
        memcpy(&value, data.data(), sizeof(value));
        return slog::number(GUINT64_FROM_LE(value));
    }

    return slog::bytes(data.data(), data.size());
}

event_response_t regmon::log_reg_key_value_data( drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    uint64_t key_handle, addr_t value_name_addr,
    uint32_t type, addr_t data_addr, size_t data_size )
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = data_addr
    );

    std::vector<uint8_t> data(data_size);
    size_t bytes_read = 0;
    {
        auto vmi = vmi_lock_guard(drakvuf);
        if (!data.empty()
            && (VMI_FAILURE == vmi_read(vmi, &ctx, data.size(), data.data(), &bytes_read)
                || bytes_read != data.size()))
        {
            PRINT_DEBUG("[REGMON] Error reading data, expected %zu bytes, but actually read %zu\n",
                data.size(), bytes_read);
            return 0;
        }
    }

    std::optional<slog::value> value = parse_registry_data(type, data);
    return log_reg_impl(drakvuf, info, key_handle, value_name_addr, true, value);
}

event_response_t regmon::log_reg_key_value_entries( drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    uint64_t key_handle, addr_t value_entries_addr, size_t value_entries_count )
{
    /*
    typedef struct _KEY_VALUE_ENTRY {
      PUNICODE_STRING ValueName;
      ULONG           DataLength;
      ULONG           DataOffset;
      ULONG           Type;
    } KEY_VALUE_ENTRY, *PKEY_VALUE_ENTRY;
    */

    bool is32bit = (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E);
    size_t KEY_VALUE_ENTRY_sizeof = drakvuf_get_address_width(drakvuf) + 3 * sizeof(uint32_t) + (is32bit ? 0 : 4 /*padding*/);

    std::vector<slog::value> value_names;
    for (size_t i = 0; i < value_entries_count; ++i)
    {
        auto vmi = vmi_lock_guard(drakvuf);

        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = value_entries_addr + i * KEY_VALUE_ENTRY_sizeof
        );

        addr_t value_name_addr;
        if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &value_name_addr) )
            continue;

        value_names.push_back(unicode_string(drakvuf, info, value_name_addr));
    }

    std::optional<slog::value> names = slog::value(std::move(value_names));
    return log_reg_impl(drakvuf, info, key_handle, names, {});
}

event_response_t regmon::delete_key_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    NTSYSAPI NTSTATUS ZwDeleteKey(
      HANDLE KeyHandle
    );
    */
    uint64_t key_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    return log_reg_key( drakvuf, info, key_handle );
}

event_response_t regmon::set_value_key_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    NTSYSAPI NTSTATUS ZwSetValueKey(
      HANDLE          KeyHandle,
      PUNICODE_STRING ValueName,
      ULONG           TitleIndex,
      ULONG           Type,
      PVOID           Data,
      ULONG           DataSize
    );
    */
    uint64_t key_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t value_name_addr = drakvuf_get_function_argument(drakvuf, info, 2);
    uint32_t type = drakvuf_get_function_argument(drakvuf, info, 4);
    addr_t data_addr = drakvuf_get_function_argument(drakvuf, info, 5);
    uint32_t data_size = drakvuf_get_function_argument(drakvuf, info, 6);
    return log_reg_key_value_data( drakvuf, info, key_handle, value_name_addr, type, data_addr, data_size );
}

event_response_t regmon::delete_value_key_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    NTSYSAPI NTSTATUS ZwDeleteValueKey(
      HANDLE          KeyHandle,
      PUNICODE_STRING ValueName
    );
    */
    uint64_t key_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t value_name_addr = drakvuf_get_function_argument(drakvuf, info, 2);
    return log_reg_key_value( drakvuf, info, key_handle, value_name_addr );
}

event_response_t regmon::create_key_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    NTSYSAPI NTSTATUS ZwCreateKey(
      PHANDLE            KeyHandle,
      ACCESS_MASK        DesiredAccess,
      POBJECT_ATTRIBUTES ObjectAttributes,
      ULONG              TitleIndex,
      PUNICODE_STRING    Class,
      ULONG              CreateOptions,
      PULONG             Disposition
    );
    */
    addr_t objattr_addr = drakvuf_get_function_argument(drakvuf, info, 3);
    uint32_t create_options = drakvuf_get_function_argument(drakvuf, info, 6);
    return log_reg_objattr( drakvuf, info, objattr_addr, create_options );
}

event_response_t regmon::create_key_transacted_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    NTSYSAPI NTSTATUS ZwCreateKeyTransacted(
      PHANDLE            KeyHandle,
      ACCESS_MASK        DesiredAccess,
      POBJECT_ATTRIBUTES ObjectAttributes,
      ULONG              TitleIndex,
      PUNICODE_STRING    Class,
      ULONG              CreateOptions,
      HANDLE             TransactionHandle,
      PULONG             Disposition
    );
    */
    addr_t objattr_addr = drakvuf_get_function_argument(drakvuf, info, 3);
    uint32_t create_options = drakvuf_get_function_argument(drakvuf, info, 6);
    return log_reg_objattr( drakvuf, info, objattr_addr, create_options );
}

event_response_t regmon::enumerate_key_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    NTSYSAPI NTSTATUS ZwEnumerateKey(
      HANDLE                KeyHandle,
      ULONG                 Index,
      KEY_INFORMATION_CLASS KeyInformationClass,
      PVOID                 KeyInformation,
      ULONG                 Length,
      PULONG                ResultLength
    );
    */
    uint64_t key_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    return log_reg_key( drakvuf, info, key_handle );
}

event_response_t regmon::enumerate_value_key_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    NTSYSAPI NTSTATUS ZwEnumerateValueKey(
      HANDLE                      KeyHandle,
      ULONG                       Index,
      KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
      PVOID                       KeyValueInformation,
      ULONG                       Length,
      PULONG                      ResultLength
    );
    */
    uint64_t key_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    return log_reg_key( drakvuf, info, key_handle );
}

event_response_t regmon::open_key_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    NTSYSAPI NTSTATUS ZwOpenKey(
      PHANDLE            KeyHandle,
      ACCESS_MASK        DesiredAccess,
      POBJECT_ATTRIBUTES ObjectAttributes
    );
    */
    addr_t objattr_addr = drakvuf_get_function_argument(drakvuf, info, 3);
    return log_reg_objattr( drakvuf, info, objattr_addr, 0 );
}

event_response_t regmon::open_key_ex_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    NTSYSAPI NTSTATUS ZwOpenKeyEx(
      PHANDLE            KeyHandle,
      ACCESS_MASK        DesiredAccess,
      POBJECT_ATTRIBUTES ObjectAttributes,
      ULONG              OpenOptions
    );
    */
    addr_t objattr_addr = drakvuf_get_function_argument(drakvuf, info, 3);
    uint32_t open_options = drakvuf_get_function_argument(drakvuf, info, 4);
    return log_reg_objattr( drakvuf, info, objattr_addr, open_options );
}

event_response_t regmon::open_key_transacted_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    NTSYSAPI NTSTATUS ZwOpenKeyTransacted(
      PHANDLE            KeyHandle,
      ACCESS_MASK        DesiredAccess,
      POBJECT_ATTRIBUTES ObjectAttributes,
      HANDLE             TransactionHandle
    );
    */
    addr_t objattr_addr = drakvuf_get_function_argument(drakvuf, info, 3);
    return log_reg_objattr( drakvuf, info, objattr_addr, 0 );
}

event_response_t regmon::open_key_transacted_ex_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    NTSYSAPI NTSTATUS ZwOpenKeyTransactedEx(
      PHANDLE            KeyHandle,
      ACCESS_MASK        DesiredAccess,
      POBJECT_ATTRIBUTES ObjectAttributes,
      ULONG              OpenOptions,
      HANDLE             TransactionHandle
    );
    */
    addr_t objattr_addr = drakvuf_get_function_argument(drakvuf, info, 3);
    uint32_t open_options = drakvuf_get_function_argument(drakvuf, info, 4);
    return log_reg_objattr( drakvuf, info, objattr_addr, open_options );
}

event_response_t regmon::query_key_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    NTSYSAPI NTSTATUS ZwQueryKey(
      HANDLE                KeyHandle,
      KEY_INFORMATION_CLASS KeyInformationClass,
      PVOID                 KeyInformation,
      ULONG                 Length,
      PULONG                ResultLength
    );
    */
    uint64_t key_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    return log_reg_key( drakvuf, info, key_handle );
}

event_response_t regmon::query_multiple_value_key_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    __kernel_entry NTSTATUS NtQueryMultipleValueKey(
      HANDLE           KeyHandle,
      PKEY_VALUE_ENTRY ValueEntries,
      ULONG            EntryCount,
      PVOID            ValueBuffer,
      PULONG           BufferLength,
      PULONG           RequiredBufferLength
    );
    */
    uint64_t key_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t value_entries_addr = drakvuf_get_function_argument(drakvuf, info, 2);
    size_t value_entries_count = drakvuf_get_function_argument(drakvuf, info, 3);
    return log_reg_key_value_entries( drakvuf, info, key_handle, value_entries_addr, value_entries_count );
}

event_response_t regmon::query_value_key_cb( drakvuf_t drakvuf, drakvuf_trap_info_t* info )
{
    /*
    NTSYSAPI NTSTATUS ZwQueryValueKey(
      HANDLE                      KeyHandle,
      PUNICODE_STRING             ValueName,
      KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
      PVOID                       KeyValueInformation,
      ULONG                       Length,
      PULONG                      ResultLength
    );
    */
    uint64_t key_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t value_name_addr = drakvuf_get_function_argument(drakvuf, info, 2);
    return log_reg_key_value( drakvuf, info, key_handle, value_name_addr );
}

regmon::regmon(drakvuf_t drakvuf)
    : pluginex(drakvuf)
{
    if ( !drakvuf_get_kernel_struct_member_rva(drakvuf, "_OBJECT_ATTRIBUTES", "ObjectName", &this->objattr_name) )
        throw -1;
    if ( !drakvuf_get_kernel_struct_member_rva(drakvuf, "_OBJECT_ATTRIBUTES", "RootDirectory", &this->objattr_root) )
        throw -1;

    delete_key_hook = createSyscallHook("NtDeleteKey", &regmon::delete_key_cb);
    set_value_key_hook = createSyscallHook("NtSetValueKey", &regmon::set_value_key_cb);
    delete_value_key_hook = createSyscallHook("NtDeleteValueKey", &regmon::delete_value_key_cb);
    create_key_hook = createSyscallHook("NtCreateKey", &regmon::create_key_cb);
    create_key_transacted_hook = createSyscallHook("NtCreateKeyTransacted", &regmon::create_key_transacted_cb);
    enumerate_key_hook = createSyscallHook("NtEnumerateKey", &regmon::enumerate_key_cb);
    enumerate_value_key_hook = createSyscallHook("NtEnumerateValueKey", &regmon::enumerate_value_key_cb);
    open_key_hook = createSyscallHook("NtOpenKey", &regmon::open_key_cb);
    open_key_ex_hook = createSyscallHook("NtOpenKeyEx", &regmon::open_key_ex_cb);
    open_key_transacted_hook = createSyscallHook("NtOpenKeyTransacted", &regmon::open_key_transacted_cb);
    open_key_transacted_ex_hook = createSyscallHook("NtOpenKeyTransactedEx", &regmon::open_key_transacted_ex_cb);
    query_key_hook = createSyscallHook("NtQueryKey", &regmon::query_key_cb);
    query_multiple_value_key_hook = createSyscallHook("NtQueryMultipleValueKey", &regmon::query_multiple_value_key_cb);
    query_value_key_hook = createSyscallHook("NtQueryValueKey", &regmon::query_value_key_cb);
}
