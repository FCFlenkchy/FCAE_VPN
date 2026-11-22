"""Generate the shared DLL loader without modifying the pinned submodule."""
import pathlib
import sys
source = pathlib.Path(sys.argv[1]).read_text()
original = 'kernel32.LoadLibraryExW(library_name, null, win.LOAD_LIBRARY_SEARCH_APPLICATION_DIR | win.LOAD_LIBRARY_SEARCH_SYSTEM32)'
if source.count(original) != 1:
    raise SystemExit('Pinned Zeptun loader changed; review the integration')
source = source.replace(original, 'fcae_wintun_load_library()')
source = source.replace('pub const supported =', 'extern "c" fn fcae_wintun_load_library() callconv(.winapi) ?win.HMODULE;\n\npub const supported =', 1)
pathlib.Path(sys.argv[2]).write_text(source)
