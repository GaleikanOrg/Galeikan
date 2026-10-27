#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <wchar.h>
#include <wctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Keep PATH management outside NSIS strings, which are limited to 1024 chars. */
#define OWNER_KEY L"Software\\Galeikan\\Installer"

static int read_string(HKEY key, const wchar_t *name, wchar_t **out, DWORD *kind) {
    DWORD bytes = 0;
    DWORD type = REG_EXPAND_SZ;
    LONG status = RegQueryValueExW(key, name, NULL, &type, NULL, &bytes);
    if (status == ERROR_FILE_NOT_FOUND) {
        *out = (wchar_t *)calloc(1, sizeof(wchar_t));
        *kind = REG_EXPAND_SZ;
        return *out != NULL;
    }
    if (status != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) ||
        bytes > 1024 * 1024 || bytes % sizeof(wchar_t) != 0) return 0;
    wchar_t *value = (wchar_t *)calloc((size_t)bytes / sizeof(wchar_t) + 2, sizeof(wchar_t));
    if (!value) return 0;
    status = RegQueryValueExW(key, name, NULL, &type, (BYTE *)value, &bytes);
    if (status != ERROR_SUCCESS) {
        free(value);
        return 0;
    }
    value[bytes / sizeof(wchar_t)] = L'\0';
    *out = value;
    *kind = type;
    return 1;
}

static int same_token(const wchar_t *start, size_t length, const wchar_t *directory) {
    while (length && iswspace(*start)) { ++start; --length; }
    while (length && iswspace(start[length - 1])) --length;
    if (length >= 2 && start[0] == L'"' && start[length - 1] == L'"') {
        ++start;
        length -= 2;
    }
    while (length > 3 && start[length - 1] == L'\\') --length;
    size_t wanted = wcslen(directory);
    while (wanted > 3 && directory[wanted - 1] == L'\\') --wanted;
    return length == wanted &&
        CompareStringOrdinal(start, (int)length, directory, (int)wanted, TRUE) == CSTR_EQUAL;
}

static int find_token(const wchar_t *path, const wchar_t *directory,
                      size_t *begin, size_t *end) {
    size_t start = 0;
    size_t length = wcslen(path);
    while (start < length) {
        size_t finish = start;
        while (finish < length && path[finish] != L';') ++finish;
        if (same_token(path + start, finish - start, directory)) {
            *begin = start;
            *end = finish;
            return 1;
        }
        start = finish + 1;
    }
    return 0;
}

static int write_path(HKEY environment, const wchar_t *path, DWORD kind) {
    size_t length = wcslen(path);
    if (length > (SIZE_MAX / sizeof(wchar_t)) - 1 ||
        length > (size_t)UINT32_MAX / sizeof(wchar_t) - 1) return 0;
    return RegSetValueExW(environment, L"Path", 0, kind, (const BYTE *)path,
                          (DWORD)((length + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
}

static void notify_shell(void) {
    DWORD_PTR ignored = 0;
    SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
                        (LPARAM)L"Environment", SMTO_ABORTIFHUNG, 5000, &ignored);
}

static int add_path(HKEY environment, HKEY owner, const wchar_t *directory) {
    wchar_t *path = NULL;
    wchar_t *owned = NULL;
    DWORD kind = REG_EXPAND_SZ, owned_kind = REG_SZ;
    int okay = 0;
    if (!read_string(environment, L"Path", &path, &kind) ||
        !read_string(owner, L"PathEntry", &owned, &owned_kind)) goto done;

    size_t begin = 0, end = 0;
    if (find_token(path, directory, &begin, &end)) {
        /* An existing entry is user-owned unless this installer recorded it. */
        okay = 1;
        goto done;
    }

    size_t old_length = wcslen(path), dir_length = wcslen(directory);
    int separator = old_length && path[old_length - 1] != L';';
    if (old_length > (SIZE_MAX / sizeof(wchar_t)) - dir_length - 2) goto done;
    wchar_t *updated = (wchar_t *)calloc(old_length + dir_length + separator + 1, sizeof(wchar_t));
    if (!updated) goto done;
    wcscpy(updated, path);
    if (separator) wcscat(updated, L";");
    wcscat(updated, directory);

    /* Record ownership first so uninstall can recover even after interruption. */
    if (RegSetValueExW(owner, L"PathEntry", 0, REG_SZ, (const BYTE *)directory,
                       (DWORD)((dir_length + 1) * sizeof(wchar_t))) == ERROR_SUCCESS) {
        if (write_path(environment, updated, kind)) {
            notify_shell();
            okay = 1;
        } else {
            RegDeleteValueW(owner, L"PathEntry");
        }
    }
    free(updated);
done:
    free(path);
    free(owned);
    return okay;
}

static int remove_path(HKEY environment, HKEY owner, const wchar_t *directory) {
    wchar_t *path = NULL;
    wchar_t *owned = NULL;
    DWORD kind = REG_EXPAND_SZ, owned_kind = REG_SZ;
    int okay = 0;
    if (!read_string(environment, L"Path", &path, &kind) ||
        !read_string(owner, L"PathEntry", &owned, &owned_kind)) goto done;
    if (!*owned || !same_token(owned, wcslen(owned), directory)) {
        okay = 1;
        goto done;
    }

    size_t begin = 0, end = 0;
    if (find_token(path, directory, &begin, &end)) {
        size_t length = wcslen(path);
        if (end < length && path[end] == L';') ++end;
        else if (begin > 0 && path[begin - 1] == L';') --begin;
        memmove(path + begin, path + end, (length - end + 1) * sizeof(wchar_t));
        if (!write_path(environment, path, kind)) goto done;
        notify_shell();
    }
    okay = RegDeleteValueW(owner, L"PathEntry") == ERROR_SUCCESS;
done:
    free(path);
    free(owned);
    return okay;
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, PWSTR command_line, int show) {
    (void)instance; (void)previous; (void)command_line; (void)show;
    int argc = 0;
    wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv || argc != 3 || !*argv[2] || wcschr(argv[2], L';')) {
        if (argv) LocalFree(argv);
        return 2;
    }
    HKEY environment = NULL, owner = NULL;
    int result = 3;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Environment", 0, NULL, 0,
                        KEY_QUERY_VALUE | KEY_SET_VALUE, NULL, &environment, NULL) != ERROR_SUCCESS) goto done;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, OWNER_KEY, 0, NULL, 0,
                        KEY_QUERY_VALUE | KEY_SET_VALUE, NULL, &owner, NULL) != ERROR_SUCCESS) goto done;
    if (wcscmp(argv[1], L"add") == 0) {
        wchar_t *prior = NULL;
        DWORD prior_kind = REG_SZ;
        if (!read_string(owner, L"PathEntry", &prior, &prior_kind)) {
            result = 4;
        } else {
            int ready = !*prior || same_token(prior, wcslen(prior), argv[2]) ||
                        remove_path(environment, owner, prior);
            result = ready && add_path(environment, owner, argv[2]) ? 0 : 4;
            free(prior);
        }
    } else if (wcscmp(argv[1], L"remove") == 0) {
        result = remove_path(environment, owner, argv[2]) ? 0 : 5;
    }
    else result = 2;
done:
    if (owner) RegCloseKey(owner);
    if (environment) RegCloseKey(environment);
    LocalFree(argv);
    return result;
}
