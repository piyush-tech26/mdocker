#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <linux/limits.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ftw.h>

#define STACK_SIZE (1024 * 1024)
#define VETH_HOST "veth0_host"
#define VETH_CONTAINER "veth0"
#define CONTAINER_IP "10.200.1.2"
#define HOST_IP "10.200.1.1"
#define NETMASK "255.255.255.0"

extern char **environ;
static pid_t child_pid = 0;

typedef struct {
    char **argv;
    int argc;
    long memory_limit;
    int cpu_percent;
    int pids_limit;
    int sync_pipe_read;
    pid_t container_pid;
} container_config;
//for container making and working
int parent_main(int argc, char **argv);
int child_main(int argc, char **argv);
int clone_callback(void *arg);
// for pivot root
static int pivot_root(const char *new_root, const char *put_old);
int write_file(const char *path, const char *value);
//for cgroups
int setup_cgroups(const char *cgroup_path, pid_t pid, long memory_limit, int cpu_percent, int pids_limit);
void cleanup_cgroup(const char *cgroup_path);

void forward_signal(int sig);
void setup_signal_forwarding();
//for overlayfs
int remove_callback(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf);
int remove_directory_recursive(const char *path);
int setup_overlayfs(pid_t container_pid,char *merged_path, size_t merged_sixe);
void cleanup_overlayfs(pid_t container_pid);
//for network
int setup_network_host_side(pid_t container_pid);
int setup_network_container_side();
void cleanup_network(pid_t container_pid);
int run_command(const char *cmd);

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s run <command> [args...]\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "child") == 0) {
        printf("[CHILD MODE] Starting...\n");
        return child_main(argc, argv);
    } else if (strcmp(argv[1], "run") == 0) {
        printf("[PARENT MODE] Starting...\n");
        return parent_main(argc, argv);
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        return 1;
    }
}

static int pivot_root(const char *new_root, const char *put_old) {
    return syscall(SYS_pivot_root, new_root, put_old);
}

int write_file(const char *path, const char *value) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd == -1) {
        perror(path);
        return -1;
    }

    size_t len = strlen(value);
    ssize_t written = write(fd, value, len);
    close(fd);

    if (written != (ssize_t)len) {
        perror("write");
        return -1;
    }

    return 0;
}

int run_command(const char *cmd) {
    int ret = system(cmd);
    if (ret == -1) {
        perror("system");
        return -1;
    }
    if (WIFEXITED(ret) && WEXITSTATUS(ret) != 0) {
        fprintf(stderr, "Command failed: %s (exit %d)\n", cmd, WEXITSTATUS(ret));
        return -1;
    }
    return 0;
}

int setup_network_host_side(pid_t container_pid) {
    char cmd[512];
    char veth_host[64];
    
    snprintf(veth_host, sizeof(veth_host), "veth%d", container_pid);
    
    printf("\n=== Setting up network (host side) ===\n");
    printf("Container PID: %d\n", container_pid);
    printf("veth pair: %s <-> %s\n", veth_host, VETH_CONTAINER);
    
    // Create veth pair
    snprintf(cmd, sizeof(cmd), "ip link add %s type veth peer name %s", veth_host, VETH_CONTAINER);
    printf("Creating veth pair...\n");
    if (run_command(cmd) == -1) {
        fprintf(stderr, "Failed to create veth pair\n");
        return -1;
    }
    
    // Move container end to container's network namespace
    snprintf(cmd, sizeof(cmd), "ip link set %s netns %d", VETH_CONTAINER, container_pid);
    printf("Moving %s to container namespace...\n", VETH_CONTAINER);
    if (run_command(cmd) == -1) {
        fprintf(stderr, "Failed to move veth to container\n");
        return -1;
    }
    
    // Configure host end
    snprintf(cmd, sizeof(cmd), "ip addr add %s/24 dev %s", HOST_IP, veth_host);
    printf("Configuring host IP: %s\n", HOST_IP);
    if (run_command(cmd) == -1) {
        fprintf(stderr, "Failed to set host IP\n");
        return -1;
    }
    
    // Bring up host end
    snprintf(cmd, sizeof(cmd), "ip link set %s up", veth_host);
    printf("Bringing up %s...\n", veth_host);
    if (run_command(cmd) == -1) {
        fprintf(stderr, "Failed to bring up host veth\n");
        return -1;
    }
    
    // Enable IP forwarding
    printf("Enabling IP forwarding...\n");
    if (run_command("echo 1 > /proc/sys/net/ipv4/ip_forward") == -1) {
        fprintf(stderr, "Failed to enable IP forwarding\n");
    }
    
    // Setup NAT for internet access
    printf("Setting up NAT (iptables)...\n");
    snprintf(cmd, sizeof(cmd), "iptables -t nat -A POSTROUTING -s 10.200.1.0/24 -j MASQUERADE 2>/dev/null || true");
    run_command(cmd);
    
    snprintf(cmd, sizeof(cmd), "iptables -A FORWARD -i %s -j ACCEPT 2>/dev/null || true", veth_host);
    run_command(cmd);
    
    snprintf(cmd, sizeof(cmd), "iptables -A FORWARD -o %s -j ACCEPT 2>/dev/null || true", veth_host);
    run_command(cmd);
    
    printf("Host network setup complete!\n\n");
    return 0;
}

int setup_network_container_side() {
    char cmd[512];
    
    printf("\n=== Setting up network (container side) ===\n");
    
    // Bring up loopback
    printf("Bringing up loopback...\n");
    if (run_command("ip link set lo up") == -1) {
        fprintf(stderr, "Failed to bring up loopback\n");
        return -1;
    }
    
    // Configure container end of veth
    snprintf(cmd, sizeof(cmd), "ip addr add %s/24 dev %s", CONTAINER_IP, VETH_CONTAINER);
    printf("Configuring container IP: %s\n", CONTAINER_IP);
    if (run_command(cmd) == -1) {
        fprintf(stderr, "Failed to set container IP\n");
        return -1;
    }
    
    // Bring up container veth
    snprintf(cmd, sizeof(cmd), "ip link set %s up", VETH_CONTAINER);
    printf("Bringing up %s...\n", VETH_CONTAINER);
    if (run_command(cmd) == -1) {
        fprintf(stderr, "Failed to bring up container veth\n");
        return -1;
    }
    
    // Set default route
    snprintf(cmd, sizeof(cmd), "ip route add default via %s", HOST_IP);
    printf("Setting default gateway: %s\n", HOST_IP);
    if (run_command(cmd) == -1) {
        fprintf(stderr, "Failed to set default route\n");
        return -1;
    }
    
    // Setup DNS
    printf("Setting up DNS...\n");
    FILE *f = fopen("/etc/resolv.conf", "w");
    if (f) {
        fprintf(f, "nameserver 8.8.8.8\n");
        fprintf(f, "nameserver 8.8.4.4\n");
        fclose(f);
    }
    
    printf("Container network setup complete!\n");
    printf("Container IP: %s\n", CONTAINER_IP);
    printf("Gateway: %s\n\n", HOST_IP);
    
    return 0;
}

void cleanup_network(pid_t container_pid) {
    char cmd[256];
    char veth_host[64];
    
    snprintf(veth_host, sizeof(veth_host), "veth%d", container_pid);
    
    printf("Cleaning up network: %s\n", veth_host);
    
    // Delete veth (this also removes the peer)
    snprintf(cmd, sizeof(cmd), "ip link delete %s 2>/dev/null || true", veth_host);
    run_command(cmd);
}

int setup_cgroups(const char *cgroup_path, pid_t pid, long memory_limit,int cpu_percent, int pids_limit) {
    char pid_str[32];
    char value_str[64];

    printf("Setting up cgroups: %s\n", cgroup_path);

    char procs_path[300];
    snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", cgroup_path);
    snprintf(pid_str, sizeof(pid_str), "%d", pid);

    if (write_file(procs_path, pid_str) == -1) {
        perror("Failed to add process to cgroup");
        return -1;
    }
    printf("Process %d added to cgroup\n", pid);

    char limit_path[300];

    // Set memory limit
    snprintf(limit_path, sizeof(limit_path), "%s/memory.max", cgroup_path);
    snprintf(value_str, sizeof(value_str), "%ld", memory_limit);
    if (write_file(limit_path, value_str) == -1) {
        printf("Warning: Could not set memory limit\n");
    } else {
        printf("Memory limit set: %.1f MB\n", memory_limit / 1024.0 / 1024.0);
    }

    // Set CPU limit
    snprintf(limit_path, sizeof(limit_path), "%s/cpu.max", cgroup_path);
    snprintf(value_str, sizeof(value_str), "%d 100000", (cpu_percent * 100000) / 100);
    if (write_file(limit_path, value_str) == -1) {
        printf("Warning: Could not set CPU limit\n");
    } else {
        printf("CPU limit set: %d%%\n", cpu_percent);
    }

    // Set PID limit
    snprintf(limit_path, sizeof(limit_path), "%s/pids.max", cgroup_path);
    snprintf(value_str, sizeof(value_str), "%d", pids_limit);
    if (write_file(limit_path, value_str) == -1) {
        printf("Warning: Could not set PID limit\n");
    } else {
        printf("PID limit set: %d\n", pids_limit);
    }

    return 0;
}

void cleanup_cgroup(const char *cgroup_path) {
    printf("Cleaning up cgroup: %s\n", cgroup_path);
    if (rmdir(cgroup_path) == -1) {
        perror("rmdir cgroup");
    }
}

int remove_callback(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    int rv = remove(fpath);
    if (rv) perror(fpath);
    return rv;
}

int remove_directory_recursive(const char *path) {
    return nftw(path, remove_callback, 64, FTW_DEPTH | FTW_PHYS);
}

int setup_overlayfs(pid_t container_pid, char *merged_path, size_t merged_size) {
    char overlay_base[PATH_MAX];
    char upper_dir[PATH_MAX];
    char work_dir[PATH_MAX];
    char mount_opts[PATH_MAX * 4];
    
    snprintf(overlay_base, sizeof(overlay_base), "./ov");
    mkdir(overlay_base, 0755);
    
    int n=snprintf(upper_dir, sizeof(upper_dir), "%s/upper_%d", overlay_base, container_pid);
    if (n < 0 || (size_t)n >= sizeof(upper_dir)) {
        fprintf(stderr, "upper_dir truncated\n");
    }
    n=snprintf(work_dir, sizeof(work_dir), "%s/work_%d", overlay_base, container_pid);
    if (n < 0 || (size_t)n >= sizeof(work_dir)) {
        fprintf(stderr, "work_dir truncated\n");
    }
    n=snprintf(merged_path, merged_size, "%s/merged_%d", overlay_base, container_pid);
    if (n < 0 || (size_t)n >= merged_size) {
        fprintf(stderr, "merged_path truncated\n");
    }

    printf("Setting up OverlayFS:\n");
    printf("  Upper dir: %s\n", upper_dir);
    printf("  Work dir:  %s\n", work_dir);
    printf("  Merged:    %s\n", merged_path);
    
    if (mkdir(upper_dir, 0755) == -1 && errno != EEXIST) {
        perror("mkdir upper");
        return -1;
    }
    
    if (mkdir(work_dir, 0755) == -1 && errno != EEXIST) {
        perror("mkdir work");
        return -1;
    }
    
    if (mkdir(merged_path, 0755) == -1 && errno != EEXIST) {
        perror("mkdir merged");
        return -1;
    }
    
    snprintf(mount_opts, sizeof(mount_opts),
             "lowerdir=./rootfs,upperdir=%s,workdir=%s",
             upper_dir, work_dir);
    
    printf("  Mount options: %s\n", mount_opts);
    
    if (mount("overlay", merged_path, "overlay", 0, mount_opts) == -1) {
        perror("mount overlay");
        fprintf(stderr, "  Error: Failed to mount OverlayFS\n");
        return -1;
    }
    
    printf("  OverlayFS mounted successfully!\n");
    return 0;
}

void cleanup_overlayfs(pid_t container_pid) {
    char upper_dir[PATH_MAX];
    char work_dir[PATH_MAX];
    char merged_path[PATH_MAX];
    
    snprintf(upper_dir, sizeof(upper_dir), "./ov/upper_%d", container_pid);
    snprintf(work_dir, sizeof(work_dir), "./ov/work_%d", container_pid);
    snprintf(merged_path, sizeof(merged_path), "./ov/merged_%d", container_pid);
    
    printf("Cleaning up OverlayFS:\n");
    
    if (umount2(merged_path, MNT_DETACH) == -1) {
        // Ignore error
    }
    
    printf("  Removing upper dir...\n");
    remove_directory_recursive(upper_dir);

    printf("  Removing work dir...\n");
    remove_directory_recursive(work_dir);
    
    printf("  Removing merged dir...\n");
    remove_directory_recursive(merged_path);
    
    rmdir("./ov");
    printf("  OverlayFS cleanup complete\n");
}

void forward_signal(int sig) {
    if (child_pid > 0) {
        kill(child_pid, sig);
    }
}

void setup_signal_forwarding() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = forward_signal;
    sigemptyset(&sa.sa_mask);

    int signals[] = { SIGINT, SIGTERM, SIGQUIT, SIGHUP };
    for (int i = 0; i < 4; i++) {
        sigaction(signals[i], &sa, NULL);
    }
}

int parent_main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s run <command>\n", argv[0]);
        return 1;
    }

    printf("Parent PID: %d\n", getpid());

    if (geteuid() != 0) {
        fprintf(stderr, "Error: mdocker must be run as root (use sudo)\n");
        return 1;
    }

    char *stack = malloc(STACK_SIZE);
    if (!stack) {
        perror("malloc");
        return 1;
    }
    char *stack_top = stack + STACK_SIZE;

    char merged_path[PATH_MAX];
    pid_t my_pid = getpid();
    
    if(setup_overlayfs(my_pid, merged_path, sizeof(merged_path))==-1) {
        fprintf(stderr, "Failed to setup OverlayFS, exiting\n");
        free(stack);
        return 1;
    }

    int sync_pipe[2];
    if (pipe(sync_pipe) == -1) {
        perror("pipe");
        free(stack);
        return 1;
    }

    container_config config = {
        .argv = &argv[2],
        .argc = argc - 2,
        .memory_limit = 100 * 1024 * 1024,
        .cpu_percent = 50,
        .pids_limit = 128,
        .sync_pipe_read = sync_pipe[0],
        .container_pid = 0  // Will be set after clone
    };

    setenv("MDOCKER_MERGED_PATH", merged_path, 1);

    char cgroup_path[256];
    snprintf(cgroup_path, sizeof(cgroup_path),"/sys/fs/cgroup/mdocker_%d", my_pid);

    printf("Creating cgroup: %s\n", cgroup_path);

    if (mkdir(cgroup_path, 0755) == -1) {
        perror("mkdir cgroup");
        close(sync_pipe[0]);
        close(sync_pipe[1]);
        free(stack);
        return 1;
    }

    int flags = CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | CLONE_NEWNET | SIGCHLD;

    printf("Creating container with network namespace...\n");
    pid_t pid = clone(clone_callback, stack_top, flags, &config);
    if (pid == -1) {
        perror("clone");
        close(sync_pipe[0]);
        close(sync_pipe[1]);
        cleanup_cgroup(cgroup_path);
        free(stack);
        return 1;
    }

    close(sync_pipe[0]);

    printf("Container PID: %d\n", pid);

    // Setup cgroups
    if (setup_cgroups(cgroup_path, pid, config.memory_limit, config.cpu_percent, config.pids_limit) == -1) {
        fprintf(stderr, "Error: cgroup setup failed\n");
        close(sync_pipe[1]);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        cleanup_cgroup(cgroup_path);
        free(stack);
        return 1;
    }

    // Setup network (host side)
    if (setup_network_host_side(pid) == -1) {
        fprintf(stderr, "Error: network setup failed\n");
        close(sync_pipe[1]);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        cleanup_cgroup(cgroup_path);
        cleanup_network(pid);
        free(stack);
        return 1;
    }

    // Release child to proceed
    printf("Releasing child to continue...\n");
    if (write(sync_pipe[1], "x", 1) != 1) {
        perror("sync write");
        close(sync_pipe[1]);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        cleanup_cgroup(cgroup_path);
        cleanup_network(pid);
        free(stack);
        return 1;
    }
    close(sync_pipe[1]);

    // Wait for container
    int status;
    if (waitpid(pid, &status, 0) == -1) {
        perror("waitpid");
        cleanup_cgroup(cgroup_path);
        cleanup_network(pid);
        cleanup_overlayfs(my_pid);
        free(stack);
        return 1;
    }

    if (WIFSIGNALED(status)) {
        printf("Container killed by signal: %d\n", WTERMSIG(status));
    } else {
        printf("Container exited with status: %d\n", WEXITSTATUS(status));
    }

    cleanup_cgroup(cgroup_path);
    cleanup_network(pid);
    cleanup_overlayfs(my_pid);
    free(stack);
    return WEXITSTATUS(status);
}

int clone_callback(void *arg) {
    container_config *config = (container_config *)arg;
    
    printf("  [Namespace] PID: %d\n", getpid());
    printf("  [Waiting for parent to setup cgroups and network...]\n");
    
    char buf;
    if (read(config->sync_pipe_read, &buf, 1) != 1) {
        perror("sync read");
        exit(1);
    }
    close(config->sync_pipe_read);
    
    printf("  [Cgroups and network ready, proceeding...]\n");

    char **new_argv = malloc(sizeof(char*) * (config->argc + 3));
    new_argv[0] = "/proc/self/exe";
    new_argv[1] = "child";
    for (int i = 0; i < config->argc; i++) {
        new_argv[i + 2] = config->argv[i];
    }
    new_argv[config->argc + 2] = NULL;

    printf("  [Re-exec] to child mode...\n");
    setenv("internal_call", "1", 1);
    execve("/proc/self/exe", new_argv, environ);
    perror("execve");
    free(new_argv);
    return 1;
}

int child_main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Child: need command\n");
        return 1;
    }

    char *internal = getenv("internal_call");
    if (!internal || strcmp(internal, "1") != 0) {
        fprintf(stderr, "Error: child mode should be called internally only\n");
        return 1;
    }

    printf("  [CHILD] PID inside namespace: %d\n", getpid());

    // Make mounts private
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        perror("mount MS_PRIVATE");
        return 1;
    }

    char *merged_path = getenv("MDOCKER_MERGED_PATH");
    if (!merged_path) {
        fprintf(stderr, "Error: MDOCKER_MERGED_PATH not set\n");
        return 1;
    }
    
    char mount_target[PATH_MAX];
    snprintf(mount_target, sizeof(mount_target), "%s", merged_path);

    if (mount(mount_target, mount_target, NULL, MS_BIND | MS_REC, NULL)==-1) {
        perror("bind mount merged");
        return 1;
    }

    char old_root[PATH_MAX];
    int n=snprintf(old_root, sizeof(old_root), "%s/old_root", mount_target);
    if (n < 0 || (size_t)n >= sizeof(old_root)) {
        fprintf(stderr, "old_root truncated\n");
    }

    if (mkdir(old_root, 0755) == -1 && errno != EEXIST) {
        perror("mkdir old_root");
        return 1;
    }

    if (pivot_root(mount_target, old_root) == -1) {
        perror("pivot_root");
        return 1;
    }
    printf("  [CHILD] pivot_root successful!\n");

    if (chdir("/") == -1) {
        perror("chdir /");
        return 1;
    }

    if (umount2("/old_root", MNT_DETACH) == -1) {
        perror("umount old_root");
    }
    rmdir("/old_root");

    if (sethostname("mdocker", 7) == -1) {
        perror("sethostname");
        return 1;
    }

    // Setup /dev
    if (mkdir("/dev", 0755) == -1 && errno != EEXIST) {
        perror("mkdir /dev");
    }

    if (mount("tmpfs", "/dev", "tmpfs", MS_NOSUID | MS_STRICTATIME, "mode=0755") == -1) {
        perror("mount /dev");
    }

    if (mkdir("/dev/shm", 01777) == -1 && errno != EEXIST) {
        perror("mkdir /dev/shm");
    }

    if (mount("tmpfs", "/dev/shm", "tmpfs", 0, "") == -1) {
        perror("mount /dev/shm");
    }

    // Create device nodes
    if (mknod("/dev/null", S_IFCHR | 0666, makedev(1, 3)) == -1 && 
        errno != EEXIST) {
        perror("mknod /dev/null");
    }
    if (mknod("/dev/zero", S_IFCHR | 0666, makedev(1, 5)) == -1 && 
        errno != EEXIST) {
        perror("mknod /dev/zero");
    }
    if (mknod("/dev/urandom", S_IFCHR | 0666, makedev(1, 9)) == -1 && 
        errno != EEXIST) {
        perror("mknod /dev/urandom");
    }
    if (mknod("/dev/tty", S_IFCHR | 0666, makedev(5, 0)) == -1 && 
        errno != EEXIST) {
        perror("mknod /dev/tty");
    }

    // Mount /proc
    if (mkdir("/proc", 0555) == -1 && errno != EEXIST) {
        perror("mkdir /proc");
    }
    if (mount("proc", "/proc", "proc", 0, NULL) == -1) {
        perror("mount /proc");
    }

    // Mount /sys
    if (mkdir("/sys", 0555) == -1 && errno != EEXIST) {
        perror("mkdir /sys");
    }
    if (mount("sysfs", "/sys", "sysfs", 0, NULL) == -1) {
        perror("mount /sys");
    }

    // Setup /etc for resolv.conf
    if (mkdir("/etc", 0755) == -1 && errno != EEXIST) {
        perror("mkdir /etc");
    }

    // Setup network (container side)
    if (setup_network_container_side() == -1) {
        fprintf(stderr, "Warning: network setup failed in container\n");
    }

    printf("  [CHILD] Container setup complete!\n");

    setup_signal_forwarding();
    printf("  [CHILD] Executing: %s\n", argv[2]);

    setenv("HOME", "/", 1);
    setenv("PATH", "/bin:/sbin:/usr/bin:/usr/sbin", 1);
    setenv("TERM", "xterm", 1);

    char **cmd_argv = &argv[2];
    child_pid = fork();
    if (child_pid == -1) {
        perror("fork");
        return 1;
    }
    if (child_pid == 0) {
        execvp(cmd_argv[0], cmd_argv);
        perror("execvp");
        exit(1);
    }
    
    int status;
    pid_t wpid;
    while ((wpid = wait(&status)) > 0) {
        if (wpid == child_pid) {
            exit(WEXITSTATUS(status));
        }
    }
    return 0;
}
