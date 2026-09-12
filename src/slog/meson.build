slog_incdir = include_directories('..', '../..')
slog_threads = dependency('threads')

libslog = static_library('slog',
    'slog.cpp',
    dependencies : [deps, slog_threads],
    include_directories : slog_incdir,
    link_with : libdrakvuf,
)
