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

#include "arguments.hpp"

#include <array>
#include <cstdio>
#include <cstring>
#include <utility>
#include <vector>
#include <plugins/helpers/unicode_string.h>
#include <plugins/helpers/vmi_lock_guard.h>

namespace
{

slog::value numeric_value(uint64_t raw, const argument_options& options)
{
    return options.format == argument_options::number_format::hex
        ? slog::hex(raw) : slog::number(raw);
}

slog::value address_value(uint64_t address, slog::value data, bool omit_address)
{
    if (omit_address)
        return data;

    slog::keyval_array result;
    result.push_back(slog::attr("Address", slog::hex(address)));
    result.push_back(slog::attr("Value", std::move(data)));
    return result;
}

} // namespace

slog::value decode_argument(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    uint64_t raw, const argument_spec& spec)
{
    if (spec.kind == argument_kind::number)
        return numeric_value(raw, spec.options);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = raw
    );

    switch (spec.kind)
    {
        case argument_kind::c_string:
        {
            auto vmi = vmi_lock_guard(drakvuf);
            char* buffer = vmi_read_str(vmi, &ctx);
            auto data = slog::text(buffer ? buffer : "");
            g_free(buffer);
            return address_value(raw, std::move(data), spec.options.omit_address);
        }
        case argument_kind::wide_string:
        {
            unicode_string buffer(drakvuf_read_wchar_string(drakvuf, &ctx));
            return address_value(raw, buffer, spec.options.omit_address);
        }
        case argument_kind::unicode_string:
        {
            const bool is32bit = drakvuf_process_is32bit(drakvuf, info);
            unicode_string buffer(is32bit ? drakvuf_read_unicode32(drakvuf, info, raw)
                : drakvuf_read_unicode(drakvuf, info, raw));
            return address_value(raw, buffer, spec.options.omit_address);
        }
        case argument_kind::bytes16:
        {
            auto vmi = vmi_lock_guard(drakvuf);
            std::array<uint8_t, 16> buffer{};
            const size_t size = VMI_SUCCESS == vmi_read(
                vmi, &ctx, buffer.size(), buffer.data(), nullptr) ? buffer.size() : 0;
            return address_value(raw, slog::bytes(buffer.data(), size), spec.options.omit_address);
        }
        case argument_kind::uint32_pointer:
        {
            auto vmi = vmi_lock_guard(drakvuf);
            uint32_t data = 0;
            if (vmi_read_32(vmi, &ctx, &data) != VMI_SUCCESS)
                data = 0;
            return numeric_value(data, spec.options);
        }
        case argument_kind::uint64_pointer:
        {
            auto vmi = vmi_lock_guard(drakvuf);
            uint64_t data = 0;
            if (vmi_read_64(vmi, &ctx, &data) != VMI_SUCCESS)
                data = 0;
            return numeric_value(data, spec.options);
        }
        case argument_kind::pointer_pointer:
        {
            addr_t data = 0;
            if (drakvuf_read_addr(drakvuf, info, &ctx, &data) != VMI_SUCCESS)
                data = 0;
            return numeric_value(data, spec.options);
        }
        case argument_kind::guid:
        {
            struct
            {
                uint32_t Data1;
                uint16_t Data2;
                uint16_t Data3;
                uint8_t Data4[8];
            } __attribute__((packed, aligned(4))) guid{};

            auto vmi = vmi_lock_guard(drakvuf);
            if (vmi_read(vmi, &ctx, sizeof(guid), &guid, nullptr) != VMI_SUCCESS)
                memset(&guid, 0, sizeof(guid));

            char text[64]{};
            snprintf(text, sizeof(text),
                "%08X-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX",
                guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1],
                guid.Data4[2], guid.Data4[3], guid.Data4[4],
                guid.Data4[5], guid.Data4[6], guid.Data4[7]);
            return slog::text(text);
        }
        case argument_kind::number:
            break; // Handled above without reading guest memory.
    }
    return slog::null;
}
