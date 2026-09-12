libusermode_h = include_directories(
    '..', '../..'
)
libusermode = static_library('usermode',
    'userhook.cpp',
    'userhook_pf.cpp',
    'userhook_inject.cpp',
    'running.cpp',
    'utils.cpp',
    'arguments.cpp',

    dependencies : deps,
    include_directories : libusermode_h,
    link_with : libdrakvuf
)

if check.found()
    userhook_check = executable('userhook_check',
        sources : 'check.cpp',
        include_directories : libusermode_h,
        dependencies : [deps, check],
        link_with : [libdrakvuf, libusermode, libslog],
        install : false
    )
    test('userhook_check', userhook_check)

endif
