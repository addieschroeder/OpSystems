#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>

// Function to read and display process information
void display_process_info(const char* pid) {
    char path[256], line[256];
    FILE *fp;
    struct passwd *pw;
    uid_t uid;

    // Construct the path to the status file for the process
    snprintf(path, sizeof(path), "/proc/%s/status", pid);
    fp = fopen(path, "r");
    if (!fp) return; // Skip if the file can't be opened (process may have ended)

    // Read the UID and context switches from the status file
    uid_t process_uid = 0;
    char *voluntary_ctxt_switches = NULL, *nonvoluntary_ctxt_switches = NULL;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "Uid:", 4) == 0) {
            sscanf(line, "Uid:\t%u", &process_uid);
        } else if (strncmp(line, "voluntary_ctxt_switches:", 24) == 0) {
            voluntary_ctxt_switches = strdup(line + 24);
        } else if (strncmp(line, "nonvoluntary_ctxt_switches:", 27) == 0) {
            nonvoluntary_ctxt_switches = strdup(line + 27);
        }
    }
    fclose(fp);

    // Check if the process belongs to the current user
    uid = getuid();
    pw = getpwuid(uid);
    if (process_uid != uid) {
        free(voluntary_ctxt_switches);
        free(nonvoluntary_ctxt_switches);
        return; // Skip if the process does not belong to the current user
    }

    // Display process information
    printf("PID: %s\n", pid);
    printf("Voluntary Context Switches: %s", voluntary_ctxt_switches); // Includes newline from file
    printf("Nonvoluntary Context Switches: %s", nonvoluntary_ctxt_switches); // Includes newline from file

    // Construct the path to the cmdline file for the executable path
    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid);
    fp = fopen(path, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            printf("Executable Path: %s\n", line);
        }
        fclose(fp);
    }

    // Cleanup
    free(voluntary_ctxt_switches);
    free(nonvoluntary_ctxt_switches);
    printf("\n");
}

int main() {
    DIR *dir;
    struct dirent *ent;

    // Open the /proc directory
    dir = opendir("/proc");
    if (!dir) {
        perror("Failed to open /proc");
        return EXIT_FAILURE;
    }

    // Iterate over all entries in /proc
    while ((ent = readdir(dir)) != NULL) {
        // Check if the entry is a PID directory (all numeric)
        if (ent->d_type == DT_DIR && strspn(ent->d_name, "0123456789") == strlen(ent->d_name)) {
            display_process_info(ent->d_name);
        }
    }

    closedir(dir);
    return EXIT_SUCCESS;
}
