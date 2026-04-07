/* VULN: Path traversal via file-read functions with unsanitized user input.
 * Should trigger detection for c.fileread.* sinks with tainted input.
 */

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ftw.h>
#include <glob.h>

void list_directory(const char *user_path) {
    /* Vulnerable: user controls the directory path */
    DIR *d = opendir(user_path);
    if (d) {
        struct dirent *entry;
        while ((entry = readdir(d)) != NULL) {
            printf("%s\n", entry->d_name);
        }
        closedir(d);
    }
}

void scan_directory(const char *user_path) {
    struct dirent **namelist;
    int n = scandir(user_path, &namelist, NULL, alphasort);
    if (n > 0) {
        while (n--) {
            printf("%s\n", namelist[n]->d_name);
            free(namelist[n]);
        }
        free(namelist);
    }
}

void resolve_link(const char *user_path) {
    char buf[4096];
    ssize_t len = readlink(user_path, buf, sizeof(buf) - 1);
    if (len != -1) {
        buf[len] = '\0';
        printf("link target: %s\n", buf);
    }
}

void canonicalize_path(const char *user_path) {
    char *resolved = realpath(user_path, NULL);
    if (resolved) {
        printf("real path: %s\n", resolved);
        free(resolved);
    }
}

void check_symlink(const char *user_path) {
    struct stat st;
    if (lstat(user_path, &st) == 0) {
        printf("mode: %o\n", st.st_mode);
    }
}

void reopen_file(const char *user_path) {
    FILE *fp = freopen(user_path, "r", stdin);
    if (fp) {
        char buf[256];
        fgets(buf, sizeof(buf), fp);
        printf("%s", buf);
    }
}

static int walk_cb(const char *fpath, const struct stat *sb, int typeflag) {
    printf("%s\n", fpath);
    return 0;
}

void walk_tree(const char *user_path) {
    ftw(user_path, walk_cb, 16);
}

void glob_files(const char *user_pattern) {
    glob_t results;
    if (glob(user_pattern, 0, NULL, &results) == 0) {
        for (size_t i = 0; i < results.gl_pathc; i++) {
            printf("%s\n", results.gl_pathv[i]);
        }
        globfree(&results);
    }
}

void change_dir(const char *user_path) {
    chdir(user_path);
}

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;
    list_directory(argv[1]);
    scan_directory(argv[1]);
    resolve_link(argv[1]);
    canonicalize_path(argv[1]);
    check_symlink(argv[1]);
    reopen_file(argv[1]);
    walk_tree(argv[1]);
    glob_files(argv[1]);
    change_dir(argv[1]);
    return 0;
}
