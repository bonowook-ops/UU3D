#pragma once

// Stupid Never Dies diag1 (logging only). In Flat3D the scene fills only the
// left half of each eye. These helpers gate the diagnostic logging to this
// one title (StupidNeverDies.exe on DX12) so nothing changes for other games.

#include <windows.h>

#include <iterator>
#include <string_view>

#include "../StupidNeverDiesUI.hpp"

namespace vrmod::flat3d::snd_diag {
inline bool enabled() {
    static const bool title = [] {
        wchar_t buffer[MAX_PATH * 2]{};
        const auto length = GetModuleFileNameW(nullptr, buffer, (DWORD)std::size(buffer));
        if (length == 0 || length >= std::size(buffer)) {
            return false;
        }
        return uevr::stupid_never_dies_ui::target(std::wstring_view{buffer, length}, true);
    }();
    return title;
}
} // namespace vrmod::flat3d::snd_diag
