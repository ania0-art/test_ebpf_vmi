#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>

typedef struct {
    const char *name;
    const char *binary;
    const char *description;
} TestCase;

TestCase tests[] = {
    {
        .name = "Test 1",
        .binary = "./test_cgroup_attach",
        .description = "Cgroup ATTACH/DETACH Basic Flow"
    },
    {
        .name = "Test 2",
        .binary = "./test_cross_process",
        .description = "Cross-Process DETACH Detection"
    },
    {
        .name = "Test 3",
        .binary = "./test_sockmap_attach",
        .description = "Sockmap ATTACH Resolution"
    },
    {
        .name = "Test 4",
        .binary = "./test_resolution_failure",
        .description = "Resolution Failure & Tier-3 Fallback (manual)"
    }
};

#define NUM_TESTS (sizeof(tests) / sizeof(tests[0]))

void print_separator() {
    printf("\n");
    printf("================================================================================\n");
}

int run_test(const TestCase *test) {
    printf("\n");
    print_separator();
    printf("Running %s: %s\n", test->name, test->description);
    print_separator();

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "fork() failed\n");
        return 1;
    }

    if (pid == 0) {
        // 子进程：执行测试程序
        execl(test->binary, test->binary, NULL);
        // 如果 execl 返回，说明执行失败
        fprintf(stderr, "Failed to execute %s: ", test->binary);
        perror("");
        exit(1);
    } else {
        // 父进程：等待子进程完成
        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            if (exit_code == 0) {
                printf("\n[RESULT] %s: PASSED ✓\n", test->name);
                return 0;
            } else {
                printf("\n[RESULT] %s: FAILED ✗ (exit code: %d)\n", test->name, exit_code);
                return 1;
            }
        } else {
            printf("\n[RESULT] %s: FAILED ✗ (abnormal termination)\n", test->name);
            return 1;
        }
    }
}

int main() {
    printf("================================================================================\n");
    printf("BPF ATTACH/DETACH Target Resolution Test Suite\n");
    printf("================================================================================\n");
    printf("Total tests: %lu\n", NUM_TESTS);
    printf("HVMI must be running to observe logs!\n");
    print_separator();

    int passed = 0;
    int failed = 0;

    for (size_t i = 0; i < NUM_TESTS; i++) {
        int result = run_test(&tests[i]);
        if (result == 0) {
            passed++;
        } else {
            failed++;
        }

        // 测试间隔 2 秒
        if (i < NUM_TESTS - 1) {
            printf("\nWaiting 2 seconds before next test...\n");
            sleep(2);
        }
    }

    // 最终统计
    print_separator();
    printf("Test Suite Summary\n");
    print_separator();
    printf("Total:  %lu tests\n", NUM_TESTS);
    printf("Passed: %d tests ✓\n", passed);
    printf("Failed: %d tests ✗\n", failed);
    print_separator();

    printf("\nVerification Checklist:\n");
    printf("[ ] Check HVMI logs for all ATTACH/DETACH events\n");
    printf("[ ] Verify Target Type values (1=Cgroup, 2=Sockmap)\n");
    printf("[ ] Verify Target GVA non-zero for successful resolutions\n");
    printf("[ ] Verify Tier-1/Tier-2/Tier-3 matching messages\n");
    printf("[ ] Verify Cross-Process warnings in Test 2\n");
    printf("[ ] Test 4 requires manual code modification\n");
    print_separator();

    return (failed == 0) ? 0 : 1;
}
