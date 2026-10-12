#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/prctl.h>

#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#define STACK_SIZE (1024 * 1024)
#define CPU_PERIOD_US 100000ULL

#if defined(__x86_64__)
#define BOXFORGE_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define BOXFORGE_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "BoxForge seccomp architecture is not configured for this platform"
#endif

#define DENY_SYSCALL(nr) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, \
             SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))

struct container_config {
    char *rootfs;
    char **command;

    uint64_t memory_bytes;
    double cpu_percent;
    long pids_limit;

    int has_memory;
    int has_cpu;
    int has_pids;

    int gate_read;
    int gate_write;
};

/* ---------------------------------------------------------
 * General helpers
 * --------------------------------------------------------- */

static void usage(FILE *out)
{
    fprintf(out,
        "Usage:\n"
        "  boxforge help\n"
        "  boxforge run [--memory SIZE] [--cpu PERCENT%%] "
        "[--pids COUNT] <rootfs> <command> [args...]\n\n"
        "Examples:\n"
        "  boxforge run \"$HOME/BoxForge/rootfs\" /bin/sh\n"
        "  boxforge run --memory 128M --cpu 50%% --pids 64 "
        "\"$HOME/BoxForge/rootfs\" /bin/sh\n\n"
        "Memory units: K, M, G (base 1024).\n"
        "CPU: 50%% = half of one CPU; 200%% = two CPUs.\n"
        "PIDs: maximum number of processes and threads in the cgroup.\n");
}

static int write_text_file(const char *path, const char *value)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);

    if (fd < 0)
        return -1;

    size_t len = strlen(value);
    size_t done = 0;

    while (done < len) {
        ssize_t n = write(fd, value + done, len - done);

        if (n < 0) {
            if (errno == EINTR)
                continue;

            int saved = errno;
            close(fd);
            errno = saved;
            return -1;
        }

        if (n == 0) {
            close(fd);
            errno = EIO;
            return -1;
        }

        done += (size_t)n;
    }

    if (close(fd) < 0)
        return -1;

    return 0;
}

/* ---------------------------------------------------------
 * Argument parsing
 * --------------------------------------------------------- */

static int parse_memory(const char *s, uint64_t *out)
{
    if (!s || !*s || !isdigit((unsigned char)s[0]))
        return -1;

    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(s, &end, 10);

    if (errno || end == s || value == 0)
        return -1;

    uint64_t multiplier = 1;

    if (*end) {
        char suffix = (char)toupper((unsigned char)*end++);

        if (suffix == 'K')
            multiplier = 1024ULL;
        else if (suffix == 'M')
            multiplier = 1024ULL * 1024ULL;
        else if (suffix == 'G')
            multiplier = 1024ULL * 1024ULL * 1024ULL;
        else
            return -1;

        if (*end == 'i' || *end == 'I')
            end++;

        if (*end == 'b' || *end == 'B')
            end++;

        if (*end != '\0')
            return -1;
    }

    if (value > UINT64_MAX / multiplier)
        return -1;

    *out = (uint64_t)value * multiplier;
    return 0;
}

static int parse_cpu(const char *s, double *out)
{
    if (!s || !*s)
        return -1;

    errno = 0;
    char *end = NULL;
    double value = strtod(s, &end);

    if (errno || end == s || !isfinite(value) ||
        value <= 0.0 || value > 10000.0)
        return -1;

    if (*end == '%')
        end++;

    if (*end != '\0')
        return -1;

    *out = value;
    return 0;
}

static int parse_args(
    int argc,
    char **argv,
    struct container_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));

    if (argc < 2)
        return -1;

    if (strcmp(argv[1], "help") == 0 ||
        strcmp(argv[1], "--help") == 0 ||
        strcmp(argv[1], "-h") == 0) {
        usage(stdout);
        exit(EXIT_SUCCESS);
    }

    if (strcmp(argv[1], "run") != 0)
        return -1;

    int i = 2;

    while (i < argc) {
        if (strcmp(argv[i], "--memory") == 0) {
            if (i + 1 >= argc ||
                parse_memory(argv[i + 1],
                             &cfg->memory_bytes) < 0) {
                fprintf(stderr,
                        "BoxForge: invalid --memory value; "
                        "example: 128M\n");
                return -1;
            }

            cfg->has_memory = 1;
            i += 2;
        } else if (strcmp(argv[i], "--cpu") == 0) {
            if (i + 1 >= argc ||
                parse_cpu(argv[i + 1],
                          &cfg->cpu_percent) < 0) {
                fprintf(stderr,
                        "BoxForge: invalid --cpu value; "
                        "example: 50%%\n");
                return -1;
            }

            cfg->has_cpu = 1;
            i += 2;
        } else if (strcmp(argv[i], "--pids") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr,
                        "BoxForge: --pids requires a positive integer\n");
                return -1;
            }

            errno = 0;
            char *end = NULL;
            long value = strtol(argv[i + 1], &end, 10);

            if (errno || end == argv[i + 1] ||
                *end != '\0' || value < 1 ||
                value > INT_MAX) {
                fprintf(stderr,
                        "BoxForge: invalid --pids value; "
                        "example: 64\n");
                return -1;
            }

            cfg->has_pids = 1;
            cfg->pids_limit = value;
            i += 2;
        } else if (strncmp(argv[i], "--", 2) == 0) {
            fprintf(stderr,
                    "BoxForge: unknown option: %s\n",
                    argv[i]);
            return -1;
        } else {
            break;
        }
    }

    if (i + 1 >= argc)
        return -1;

    cfg->rootfs = realpath(argv[i], NULL);

    if (!cfg->rootfs) {
        perror("BoxForge: resolve rootfs");
        return -2;
    }

    struct stat st;

    if (stat(cfg->rootfs, &st) < 0 ||
        !S_ISDIR(st.st_mode)) {
        fprintf(stderr,
                "BoxForge: rootfs must be an existing directory\n");
        free(cfg->rootfs);
        cfg->rootfs = NULL;
        return -1;
    }

    cfg->command = &argv[i + 1];
    return 0;
}

/* ---------------------------------------------------------
 * Cgroup v2 resource controls
 * --------------------------------------------------------- */

static int get_cgroup_parent(char *out, size_t out_size)
{
    char candidate[PATH_MAX];

    int n = snprintf(
        candidate,
        sizeof(candidate),
        "/sys/fs/cgroup/user.slice/user-%u.slice/"
        "user@%u.service/app.slice",
        (unsigned)getuid(),
        (unsigned)getuid());

    if (n < 0 || (size_t)n >= sizeof(candidate)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    struct stat st;

    if (stat(candidate, &st) < 0 ||
        !S_ISDIR(st.st_mode) ||
        access(candidate, W_OK | X_OK) < 0) {
        errno = EACCES;
        return -1;
    }

    if ((size_t)n + 1 > out_size) {
        errno = ENAMETOOLONG;
        return -1;
    }

    strcpy(out, candidate);
    return 0;
}

static int make_cgroup(
    const struct container_config *cfg,
    char *path,
    size_t path_size)
{
    if (!cfg->has_memory &&
        !cfg->has_cpu &&
        !cfg->has_pids)
        return 0;

    char parent[PATH_MAX];

    if (get_cgroup_parent(parent, sizeof(parent)) < 0) {
        fprintf(stderr,
                "BoxForge: no writable cgroup parent: %s\n",
                strerror(errno));
        return -1;
    }

    int n = snprintf(path, path_size,
                     "%s/boxforge-%ld",
                     parent, (long)getpid());

    if (n < 0 || (size_t)n >= path_size) {
        errno = ENAMETOOLONG;
        return -1;
    }

    if (mkdir(path, 0755) < 0) {
        fprintf(stderr,
                "BoxForge: create cgroup: %s\n",
                strerror(errno));
        return -1;
    }

    char file[PATH_MAX];
    char value[128];

    if (cfg->has_memory) {
        n = snprintf(file, sizeof(file),
                     "%s/memory.max", path);

        if (n < 0 || (size_t)n >= sizeof(file))
            goto path_error;

        snprintf(value, sizeof(value), "%llu\n",
                 (unsigned long long)cfg->memory_bytes);

        if (write_text_file(file, value) < 0) {
            fprintf(stderr,
                    "BoxForge: set memory limit: %s\n",
                    strerror(errno));
            goto fail;
        }
    }

    if (cfg->has_cpu) {
        n = snprintf(file, sizeof(file),
                     "%s/cpu.max", path);

        if (n < 0 || (size_t)n >= sizeof(file))
            goto path_error;

        double quota_d =
            (cfg->cpu_percent / 100.0) *
            (double)CPU_PERIOD_US;

        unsigned long long quota =
            (unsigned long long)(quota_d + 0.5);

        if (quota < 1000ULL)
            quota = 1000ULL;

        snprintf(value, sizeof(value),
                 "%llu %llu\n",
                 quota, CPU_PERIOD_US);

        if (write_text_file(file, value) < 0) {
            fprintf(stderr,
                    "BoxForge: set CPU limit: %s\n",
                    strerror(errno));
            goto fail;
        }
    }

    if (cfg->has_pids) {
        n = snprintf(file, sizeof(file),
                     "%s/pids.max", path);

        if (n < 0 || (size_t)n >= sizeof(file))
            goto path_error;

        snprintf(value, sizeof(value),
                 "%ld\n", cfg->pids_limit);

        if (write_text_file(file, value) < 0) {
            fprintf(stderr,
                    "BoxForge: set PID limit: %s\n",
                    strerror(errno));
            goto fail;
        }
    }

    return 1;

path_error:
    fprintf(stderr, "BoxForge: cgroup path too long\n");

fail:
    rmdir(path);
    path[0] = '\0';
    return -1;
}

static int add_pid_to_cgroup(const char *path, pid_t pid)
{
    if (!path || !*path)
        return 0;

    char file[PATH_MAX];
    char value[64];

    int n = snprintf(file, sizeof(file),
                     "%s/cgroup.procs", path);

    if (n < 0 || (size_t)n >= sizeof(file)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    snprintf(value, sizeof(value), "%ld\n", (long)pid);
    return write_text_file(file, value);
}

/* ---------------------------------------------------------
 * User namespace mappings
 * --------------------------------------------------------- */

static int write_proc_map(
    pid_t pid,
    const char *name,
    const char *value,
    int optional)
{
    char path[128];

    snprintf(path, sizeof(path),
             "/proc/%ld/%s", (long)pid, name);

    if (write_text_file(path, value) == 0)
        return 0;

    if (optional && errno == ENOENT)
        return 0;

    fprintf(stderr,
            "BoxForge: write %s: %s\n",
            name, strerror(errno));
    return -1;
}

static int setup_user_mapping(pid_t pid)
{
    char map[128];

    if (write_proc_map(pid, "setgroups", "deny\n", 1) < 0)
        return -1;

    snprintf(map, sizeof(map), "0 %u 1\n",
             (unsigned)getuid());

    if (write_proc_map(pid, "uid_map", map, 0) < 0)
        return -1;

    snprintf(map, sizeof(map), "0 %u 1\n",
             (unsigned)getgid());

    if (write_proc_map(pid, "gid_map", map, 0) < 0)
        return -1;

    return 0;
}

static int wait_for_parent_release(int fd)
{
    char byte;

    for (;;) {
        ssize_t n = read(fd, &byte, 1);

        if (n == 1)
            return 0;

        if (n < 0 && errno == EINTR)
            continue;

        return -1;
    }
}

/* ---------------------------------------------------------
 * Capability dropping
 * --------------------------------------------------------- */

static int drop_container_capabilities(void)
{
    for (int cap = 0; cap <= CAP_LAST_CAP; cap++) {
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) < 0) {
            if (errno == EINVAL)
                continue;

            perror("BoxForge: drop capability");
            return -1;
        }
    }

    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0
    };

    struct __user_cap_data_struct data[2] = {{0}};

    if (syscall(SYS_capset, &header, data) < 0) {
        perror("BoxForge: clear capabilities");
        return -1;
    }

    return 0;
}

/* ---------------------------------------------------------
 * Seccomp filtering
 * --------------------------------------------------------- */

static int install_container_seccomp(void)
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, arch)),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                 BOXFORGE_AUDIT_ARCH, 1, 0),

        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),

        DENY_SYSCALL(__NR_mount),
        DENY_SYSCALL(__NR_umount2),
        DENY_SYSCALL(__NR_pivot_root),
        DENY_SYSCALL(__NR_setns),
        DENY_SYSCALL(__NR_unshare),
        DENY_SYSCALL(__NR_ptrace),
        DENY_SYSCALL(__NR_bpf),
        DENY_SYSCALL(__NR_reboot),
        DENY_SYSCALL(__NR_kexec_load),
        DENY_SYSCALL(__NR_init_module),
        DENY_SYSCALL(__NR_finit_module),
        DENY_SYSCALL(__NR_delete_module),
        DENY_SYSCALL(__NR_open_by_handle_at),
        DENY_SYSCALL(__NR_keyctl),
        DENY_SYSCALL(__NR_add_key),
        DENY_SYSCALL(__NR_request_key),

        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };

    struct sock_fprog program = {
        .len = (unsigned short)
            (sizeof(filter) / sizeof(filter[0])),
        .filter = filter
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("BoxForge: set no_new_privs");
        return -1;
    }

    if (prctl(PR_SET_SECCOMP,
              SECCOMP_MODE_FILTER, &program) < 0) {
        perror("BoxForge: install seccomp");
        return -1;
    }

    return 0;
}

/* ---------------------------------------------------------
 * PID 1 supervisor
 * --------------------------------------------------------- */

static volatile sig_atomic_t pending_init_signal = 0;

static void init_signal_handler(int signo)
{
    pending_init_signal = signo;
}

static int supervise_command(char **command)
{
    const int signals[] = {
        SIGTERM, SIGINT, SIGHUP, SIGQUIT
    };

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));

    sa.sa_handler = init_signal_handler;
    sigemptyset(&sa.sa_mask);

    for (size_t i = 0;
         i < sizeof(signals) / sizeof(signals[0]); i++) {
        if (sigaction(signals[i], &sa, NULL) < 0) {
            perror("BoxForge: install signal handler");
            return 125;
        }
    }

    pid_t workload = fork();

    if (workload < 0) {
        perror("BoxForge: fork workload");
        return 125;
    }

    if (workload == 0) {
        struct sigaction def;
        memset(&def, 0, sizeof(def));

        def.sa_handler = SIG_DFL;
        sigemptyset(&def.sa_mask);

        for (size_t i = 0;
             i < sizeof(signals) / sizeof(signals[0]); i++)
            (void)sigaction(signals[i], &def, NULL);

        if (setpgid(0, 0) < 0) {
            perror("BoxForge: setpgid");
            _exit(125);
        }

        execvp(command[0], command);

        perror("BoxForge: exec command");
        _exit(errno == ENOENT ? 127 : 126);
    }

    if (setpgid(workload, workload) < 0 &&
        errno != EACCES && errno != ESRCH)
        perror("BoxForge: setpgid workload");

    fprintf(stderr, "BoxForge: workload PID = %ld\n",
            (long)workload);

    int main_status = 0;
    int main_finished = 0;

    for (;;) {
        if (pending_init_signal) {
            int signo = pending_init_signal;
            pending_init_signal = 0;

            if (kill(-workload, signo) < 0)
                (void)kill(workload, signo);
        }

        int status = 0;
        pid_t reaped = waitpid(-1, &status, 0);

        if (reaped > 0) {
            if (reaped == workload) {
                main_status = status;
                main_finished = 1;

                /*
                 * Terminate other processes in this PID
                 * namespace when the main workload exits.
                 */
                if (kill(-1, SIGKILL) < 0 && errno != ESRCH)
                    perror("BoxForge: stop remaining processes");
            }

            continue;
        }

        if (reaped < 0 && errno == EINTR)
            continue;

        if (reaped < 0 && errno == ECHILD)
            break;

        if (reaped < 0) {
            perror("BoxForge: waitpid");
            return 125;
        }
    }

    if (!main_finished)
        return 125;

    if (WIFEXITED(main_status))
        return WEXITSTATUS(main_status);

    if (WIFSIGNALED(main_status))
        return 128 + WTERMSIG(main_status);

    return 125;
}

/* ---------------------------------------------------------
 * Container process
 * --------------------------------------------------------- */

static int child_main(void *opaque)
{
    struct container_config *cfg = opaque;

    close(cfg->gate_write);

    /*
     * Wait for the parent to set UID/GID mappings and
     * move this process into the resource cgroup.
     */
    if (wait_for_parent_release(cfg->gate_read) < 0) {
        fprintf(stderr, "BoxForge: startup synchronization failed\n");
        _exit(125);
    }

    close(cfg->gate_read);

    if (sethostname("boxforge", strlen("boxforge")) < 0) {
        perror("BoxForge: sethostname");
        _exit(125);
    }

    if (mount(NULL, "/", NULL,
              MS_REC | MS_PRIVATE, NULL) < 0) {
        perror("BoxForge: make mounts private");
        _exit(125);
    }

    if (chdir(cfg->rootfs) < 0) {
        perror("BoxForge: chdir rootfs");
        _exit(125);
    }

    if (mount(cfg->rootfs, cfg->rootfs,
              NULL, MS_BIND | MS_REC, NULL) < 0) {
        perror("BoxForge: bind mount rootfs");
        _exit(125);
    }

    if (chdir(cfg->rootfs) < 0) {
        perror("BoxForge: chdir rootfs after bind mount");
        _exit(125);
    }

    char oldroot[] = ".boxforge-oldroot-XXXXXX";

    if (!mkdtemp(oldroot)) {
        perror("BoxForge: create old root directory");
        _exit(125);
    }

    char put_old[96];
    snprintf(put_old, sizeof(put_old), "./%s", oldroot);

    if (syscall(SYS_pivot_root, ".", put_old) < 0) {
        perror("BoxForge: pivot_root");
        _exit(125);
    }

    if (chdir("/") < 0) {
        perror("BoxForge: chdir /");
        _exit(125);
    }

    char oldroot_path[96];
    snprintf(oldroot_path, sizeof(oldroot_path),
             "/%s", oldroot);

    if (umount2(oldroot_path, MNT_DETACH) < 0) {
        perror("BoxForge: detach old root");
        _exit(125);
    }

    if (rmdir(oldroot_path) < 0) {
        perror("BoxForge: remove old root directory");
        _exit(125);
    }

    if (mount("proc", "/proc", "proc",
              MS_NOSUID | MS_NOEXEC | MS_NODEV,
              NULL) < 0) {
        perror("BoxForge: mount /proc");
        _exit(125);
    }

    if (drop_container_capabilities() < 0)
        _exit(125);

    if (install_container_seccomp() < 0)
        _exit(125);

    fprintf(stderr, "BoxForge: capabilities dropped\n");
    fprintf(stderr, "BoxForge: seccomp filter installed\n");
    fprintf(stderr, "BoxForge: container initialized\n");
    fprintf(stderr, "BoxForge: hostname = boxforge\n");
    fprintf(stderr, "BoxForge: container PID = %ld\n",
            (long)getpid());
    fprintf(stderr, "BoxForge: root filesystem = /\n");

    _exit(supervise_command(cfg->command));
}

/* ---------------------------------------------------------
 * Main launcher
 * --------------------------------------------------------- */

int main(int argc, char **argv)
{
    struct container_config cfg;

    int parsed = parse_args(argc, argv, &cfg);

    if (parsed == -2)
        return 1;

    if (parsed < 0) {
        usage(stderr);
        return 2;
    }

    char cgroup_path[PATH_MAX] = "";

    int cgroup_created =
        make_cgroup(&cfg, cgroup_path, sizeof(cgroup_path));

    if (cgroup_created < 0) {
        free(cfg.rootfs);
        return 1;
    }

    int gate[2];

    if (pipe2(gate, O_CLOEXEC) < 0) {
        perror("BoxForge: pipe");

        if (cgroup_created > 0)
            rmdir(cgroup_path);

        free(cfg.rootfs);
        return 1;
    }

    cfg.gate_read = gate[0];
    cfg.gate_write = gate[1];

    void *stack = malloc(STACK_SIZE);

    if (!stack) {
        perror("BoxForge: allocate child stack");

        close(gate[0]);
        close(gate[1]);

        if (cgroup_created > 0)
            rmdir(cgroup_path);

        free(cfg.rootfs);
        return 1;
    }

    int flags =
        CLONE_NEWUSER |
        CLONE_NEWUTS |
        CLONE_NEWPID |
        CLONE_NEWNS |
        CLONE_NEWNET |
        SIGCHLD;

    pid_t child = clone(
        child_main,
        (char *)stack + STACK_SIZE,
        flags,
        &cfg);

    if (child < 0) {
        perror("BoxForge: clone");

        free(stack);
        close(gate[0]);
        close(gate[1]);

        if (cgroup_created > 0)
            rmdir(cgroup_path);

        free(cfg.rootfs);
        return 1;
    }

    close(gate[0]);

    int setup_ok = 1;

    if (setup_user_mapping(child) < 0)
        setup_ok = 0;

    /*
     * The child is blocked on the pipe until this step
     * succeeds, so the workload cannot run beforehand.
     */
    if (setup_ok && cgroup_created > 0 &&
        add_pid_to_cgroup(cgroup_path, child) < 0) {
        fprintf(stderr,
                "BoxForge: attach container to cgroup: %s\n",
                strerror(errno));
        setup_ok = 0;
    }

    if (!setup_ok) {
        kill(child, SIGKILL);
        close(gate[1]);
        (void)waitpid(child, NULL, 0);

        if (cgroup_created > 0)
            rmdir(cgroup_path);

        free(stack);
        free(cfg.rootfs);
        return 1;
    }

    if (write(gate[1], "1", 1) != 1) {
        perror("BoxForge: release child");

        kill(child, SIGKILL);
        close(gate[1]);
        (void)waitpid(child, NULL, 0);

        if (cgroup_created > 0)
            rmdir(cgroup_path);

        free(stack);
        free(cfg.rootfs);
        return 1;
    }

    close(gate[1]);

    if (cgroup_created > 0) {
        fprintf(stderr,
                "BoxForge: resource cgroup = %s\n",
                cgroup_path);

        if (cfg.has_memory) {
            fprintf(stderr,
                    "BoxForge: memory limit = %llu bytes\n",
                    (unsigned long long)cfg.memory_bytes);
        }

        if (cfg.has_cpu) {
            fprintf(stderr,
                    "BoxForge: CPU limit = %.2f%%\n",
                    cfg.cpu_percent);
        }

        if (cfg.has_pids) {
            fprintf(stderr,
                    "BoxForge: PID limit = %ld\n",
                    cfg.pids_limit);
        }
    }

    int status = 0;

    while (waitpid(child, &status, 0) < 0) {
        if (errno == EINTR)
            continue;

        perror("BoxForge: waitpid");
        status = 1 << 8;
        break;
    }

    if (cgroup_created > 0) {
        if (rmdir(cgroup_path) < 0 && errno != ENOENT) {
            fprintf(stderr,
                    "BoxForge: warning: could not remove cgroup: %s\n",
                    strerror(errno));
        }
    }

    free(stack);
    free(cfg.rootfs);

    if (WIFEXITED(status))
        return WEXITSTATUS(status);

    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);

    return 1;
}
