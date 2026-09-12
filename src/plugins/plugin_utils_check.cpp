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

#include <check.h>

#include <string>
#include <variant>
#include <vector>

#include "plugin_utils.h"
#include "slog/slog.hpp"

enum
{
    ATTRIBUTE_1 = 0x00000001,
    ATTRIBUTE_2 = 0x00000002,
    ATTRIBUTE_3 = 0x00000004,
};

static const flags_str_t flags_and_attrs =
{
    REGISTER_FLAG(ATTRIBUTE_1),
    REGISTER_FLAG(ATTRIBUTE_2),
    REGISTER_FLAG(ATTRIBUTE_3),
};

static uint64_t flags_value(const slog::value& field)
{
    const auto& group = std::get<slog::keyval_array>(field.data);
    ck_assert(group.size() == 2);
    ck_assert(group[0].key == std::string("Value"));
    return std::get<slog::hex_value>(group[0].data.data).data;
}

static std::vector<std::string> flags_names(const slog::value& field)
{
    const auto& group = std::get<slog::keyval_array>(field.data);
    ck_assert(group.size() == 2);
    ck_assert(group[1].key == std::string("Names"));

    std::vector<std::string> names;
    for (const auto& name : std::get<std::vector<slog::value>>(group[1].data.data))
        names.push_back(std::get<std::string>(name.data));
    return names;
}

START_TEST(test_flags_one)
{
    auto field = slog::flags(ATTRIBUTE_1, flags_and_attrs);
    ck_assert(flags_value(field) == ATTRIBUTE_1);
    ck_assert(flags_names(field) == (std::vector<std::string>{"ATTRIBUTE_1"}));
}
END_TEST

START_TEST(test_flags_two)
{
    auto field = slog::flags(ATTRIBUTE_1 | ATTRIBUTE_2, flags_and_attrs);
    ck_assert(flags_value(field) == (ATTRIBUTE_1 | ATTRIBUTE_2));
    ck_assert(flags_names(field) == (std::vector<std::string>{"ATTRIBUTE_1", "ATTRIBUTE_2"}));
}
END_TEST

START_TEST(test_flags_three)
{
    auto field = slog::flags(ATTRIBUTE_1 | ATTRIBUTE_2 | ATTRIBUTE_3, flags_and_attrs);
    ck_assert(flags_value(field) == (ATTRIBUTE_1 | ATTRIBUTE_2 | ATTRIBUTE_3));
    ck_assert(flags_names(field)
        == (std::vector<std::string>{"ATTRIBUTE_1", "ATTRIBUTE_2", "ATTRIBUTE_3"}));
}
END_TEST

START_TEST(test_flags_64bit)
{
    // The unmapped high bits have no name but must survive in Value.
    uint64_t flags = 0xffffffff00000000 | ATTRIBUTE_1 | ATTRIBUTE_2 | ATTRIBUTE_3;
    auto field = slog::flags(flags, flags_and_attrs);
    ck_assert(flags_value(field) == flags);
    ck_assert(flags_names(field)
        == (std::vector<std::string>{"ATTRIBUTE_1", "ATTRIBUTE_2", "ATTRIBUTE_3"}));
}
END_TEST

START_TEST(test_flags_none_known)
{
    auto unknown = slog::flags(0x8000000000000000, flags_and_attrs);
    ck_assert(flags_value(unknown) == 0x8000000000000000);
    ck_assert(flags_names(unknown).empty());

    auto none = slog::flags(0, flags_and_attrs);
    ck_assert(flags_value(none) == 0);
    ck_assert(flags_names(none).empty());
}
END_TEST


START_TEST(test_parse_known_enum_value)
{
    uint64_t value = ATTRIBUTE_1;
    ck_assert(parse_enum(value, flags_and_attrs) == std::string("ATTRIBUTE_1"));
}
END_TEST

START_TEST(test_parse_unknown_enum_value)
{
    uint64_t value = ATTRIBUTE_1 | ATTRIBUTE_2;
    ck_assert(parse_enum(value, flags_and_attrs) == std::to_string(value));
}
END_TEST

static Suite* flags_suite(void)
{
    Suite* s;
    TCase* tc_core;

    s = suite_create("Bit flags as a log field");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_flags_one);
    tcase_add_test(tc_core, test_flags_two);
    tcase_add_test(tc_core, test_flags_three);
    tcase_add_test(tc_core, test_flags_64bit);
    tcase_add_test(tc_core, test_flags_none_known);
    suite_add_tcase(s, tc_core);

    return s;
}

static Suite* parse_enum_suite(void)
{
    Suite* s;
    TCase* tc_core;

    s = suite_create("Stringify enum values");

    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_parse_known_enum_value);
    tcase_add_test(tc_core, test_parse_unknown_enum_value);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite* s;
    SRunner* sr;

    s = flags_suite();
    sr = srunner_create(s);
    srunner_add_suite(sr, parse_enum_suite());

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
