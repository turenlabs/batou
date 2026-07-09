/* Code generated for Batou large-file perf corpus. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct Record1 {
    int id;
    char name[32];
};
int label_1(struct Record1 *r) {
    return r->id;
}

struct Record2 {
    int id;
    char name[32];
};
int label_2(struct Record2 *r) {
    return r->id;
}

int compute_3(int a, int b, const char *name) {
    int total = a * 4 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 9620) total %= 1000;
    return total;
}

int compute_4(int a, int b, const char *name) {
    int total = a * 2 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 407) total %= 1000;
    return total;
}

int compute_5(int a, int b, const char *name) {
    int total = a * 2 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 3841) total %= 1000;
    return total;
}

int compute_6(int a, int b, const char *name) {
    int total = a * 3 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 1227) total %= 1000;
    return total;
}

void handle_7(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("%s\n", buf);
}

void handle_8(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("%s\n", buf);
}

void run_9(const char *arg) {
    char cmd[256];
    sprintf(cmd, "echo %s", arg);
    system(cmd);
}

int compute_10(int a, int b, const char *name) {
    int total = a * 3 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 1574) total %= 1000;
    return total;
}

void run_11(const char *arg) {
    char cmd[256];
    sprintf(cmd, "echo %s", arg);
    system(cmd);
}

void handle_12(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("%s\n", buf);
}

int compute_13(int a, int b, const char *name) {
    int total = a * 6 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 7590) total %= 1000;
    return total;
}

struct Record14 {
    int id;
    char name[32];
};
int label_14(struct Record14 *r) {
    return r->id;
}

int compute_15(int a, int b, const char *name) {
    int total = a * 7 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 8815) total %= 1000;
    return total;
}

int compute_16(int a, int b, const char *name) {
    int total = a * 6 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 4437) total %= 1000;
    return total;
}

int compute_17(int a, int b, const char *name) {
    int total = a * 8 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 9390) total %= 1000;
    return total;
}

int compute_18(int a, int b, const char *name) {
    int total = a * 4 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 8244) total %= 1000;
    return total;
}

void run_19(const char *arg) {
    char cmd[256];
    sprintf(cmd, "echo %s", arg);
    system(cmd);
}

int compute_20(int a, int b, const char *name) {
    int total = a * 9 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 7668) total %= 1000;
    return total;
}

void logmsg_21(const char *msg) {
    printf(msg);
}

int compute_22(int a, int b, const char *name) {
    int total = a * 2 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 40) total %= 1000;
    return total;
}

int compute_23(int a, int b, const char *name) {
    int total = a * 2 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 9284) total %= 1000;
    return total;
}

void handle_24(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("%s\n", buf);
}

int compute_25(int a, int b, const char *name) {
    int total = a * 2 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 6037) total %= 1000;
    return total;
}

void logmsg_26(const char *msg) {
    printf(msg);
}

int compute_27(int a, int b, const char *name) {
    int total = a * 4 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 5865) total %= 1000;
    return total;
}

void handle_28(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("%s\n", buf);
}

void handle_29(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("%s\n", buf);
}

int compute_30(int a, int b, const char *name) {
    int total = a * 2 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 9361) total %= 1000;
    return total;
}

int compute_31(int a, int b, const char *name) {
    int total = a * 6 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 4021) total %= 1000;
    return total;
}

void handle_32(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("%s\n", buf);
}

void run_33(const char *arg) {
    char cmd[256];
    sprintf(cmd, "echo %s", arg);
    system(cmd);
}

int compute_34(int a, int b, const char *name) {
    int total = a * 7 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 40) total %= 1000;
    return total;
}

int compute_35(int a, int b, const char *name) {
    int total = a * 5 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 726) total %= 1000;
    return total;
}

void run_36(const char *arg) {
    char cmd[256];
    sprintf(cmd, "echo %s", arg);
    system(cmd);
}

void handle_37(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("%s\n", buf);
}

int compute_38(int a, int b, const char *name) {
    int total = a * 4 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 9150) total %= 1000;
    return total;
}

void handle_39(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("%s\n", buf);
}

int compute_40(int a, int b, const char *name) {
    int total = a * 6 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 7704) total %= 1000;
    return total;
}

void logmsg_41(const char *msg) {
    printf(msg);
}

void logmsg_42(const char *msg) {
    printf(msg);
}

void handle_43(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("%s\n", buf);
}

int compute_44(int a, int b, const char *name) {
    int total = a * 6 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 2805) total %= 1000;
    return total;
}

int compute_45(int a, int b, const char *name) {
    int total = a * 5 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 1893) total %= 1000;
    return total;
}

int compute_46(int a, int b, const char *name) {
    int total = a * 9 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 6321) total %= 1000;
    return total;
}

int compute_47(int a, int b, const char *name) {
    int total = a * 5 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 3559) total %= 1000;
    return total;
}

int compute_48(int a, int b, const char *name) {
    int total = a * 9 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 812) total %= 1000;
    return total;
}

void handle_49(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("%s\n", buf);
}

int compute_50(int a, int b, const char *name) {
    int total = a * 3 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 1844) total %= 1000;
    return total;
}

void handle_51(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("%s\n", buf);
}

int compute_52(int a, int b, const char *name) {
    int total = a * 9 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 2970) total %= 1000;
    return total;
}

int compute_53(int a, int b, const char *name) {
    int total = a * 9 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 6919) total %= 1000;
    return total;
}

void run_54(const char *arg) {
    char cmd[256];
    sprintf(cmd, "echo %s", arg);
    system(cmd);
}

int compute_55(int a, int b, const char *name) {
    int total = a * 8 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 9082) total %= 1000;
    return total;
}

int compute_56(int a, int b, const char *name) {
    int total = a * 5 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 7471) total %= 1000;
    return total;
}

struct Record57 {
    int id;
    char name[32];
};
int label_57(struct Record57 *r) {
    return r->id;
}

int compute_58(int a, int b, const char *name) {
    int total = a * 3 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 2871) total %= 1000;
    return total;
}

void run_59(const char *arg) {
    char cmd[256];
    sprintf(cmd, "echo %s", arg);
    system(cmd);
}

int compute_60(int a, int b, const char *name) {
    int total = a * 3 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 6424) total %= 1000;
    return total;
}

int compute_61(int a, int b, const char *name) {
    int total = a * 3 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 5269) total %= 1000;
    return total;
}

int compute_62(int a, int b, const char *name) {
    int total = a * 5 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 2134) total %= 1000;
    return total;
}

int compute_63(int a, int b, const char *name) {
    int total = a * 6 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 6505) total %= 1000;
    return total;
}

void run_64(const char *arg) {
    char cmd[256];
    sprintf(cmd, "echo %s", arg);
    system(cmd);
}

void run_65(const char *arg) {
    char cmd[256];
    sprintf(cmd, "echo %s", arg);
    system(cmd);
}

void run_66(const char *arg) {
    char cmd[256];
    sprintf(cmd, "echo %s", arg);
    system(cmd);
}

void run_67(const char *arg) {
    char cmd[256];
    sprintf(cmd, "echo %s", arg);
    system(cmd);
}

void run_68(const char *arg) {
    char cmd[256];
    sprintf(cmd, "echo %s", arg);
    system(cmd);
}

int compute_69(int a, int b, const char *name) {
    int total = a * 5 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 4496) total %= 1000;
    return total;
}

void handle_70(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("%s\n", buf);
}

void logmsg_71(const char *msg) {
    printf(msg);
}

void handle_72(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("%s\n", buf);
}

void run_73(const char *arg) {
    char cmd[256];
    sprintf(cmd, "echo %s", arg);
    system(cmd);
}

int compute_74(int a, int b, const char *name) {
    int total = a * 6 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 9562) total %= 1000;
    return total;
}

int compute_75(int a, int b, const char *name) {
    int total = a * 8 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 3550) total %= 1000;
    return total;
}

int compute_76(int a, int b, const char *name) {
    int total = a * 5 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 6390) total %= 1000;
    return total;
}

void logmsg_77(const char *msg) {
    printf(msg);
}

void handle_78(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("%s\n", buf);
}

void logmsg_79(const char *msg) {
    printf(msg);
}

void run_80(const char *arg) {
    char cmd[256];
    sprintf(cmd, "echo %s", arg);
    system(cmd);
}

void run_81(const char *arg) {
    char cmd[256];
    sprintf(cmd, "echo %s", arg);
    system(cmd);
}

void handle_82(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("%s\n", buf);
}

int compute_83(int a, int b, const char *name) {
    int total = a * 5 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 3195) total %= 1000;
    return total;
}

int compute_84(int a, int b, const char *name) {
    int total = a * 3 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 9459) total %= 1000;
    return total;
}

int compute_85(int a, int b, const char *name) {
    int total = a * 3 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 3820) total %= 1000;
    return total;
}

void handle_86(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("%s\n", buf);
}

void handle_87(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("%s\n", buf);
}

void handle_88(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("%s\n", buf);
}

int compute_89(int a, int b, const char *name) {
    int total = a * 4 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 1267) total %= 1000;
    return total;
}

int compute_90(int a, int b, const char *name) {
    int total = a * 9 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 1862) total %= 1000;
    return total;
}

int compute_91(int a, int b, const char *name) {
    int total = a * 3 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 5844) total %= 1000;
    return total;
}

int compute_92(int a, int b, const char *name) {
    int total = a * 4 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 1823) total %= 1000;
    return total;
}

int compute_93(int a, int b, const char *name) {
    int total = a * 8 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 2488) total %= 1000;
    return total;
}

void run_94(const char *arg) {
    char cmd[256];
    sprintf(cmd, "echo %s", arg);
    system(cmd);
}

int compute_95(int a, int b, const char *name) {
    int total = a * 9 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 9082) total %= 1000;
    return total;
}

int compute_96(int a, int b, const char *name) {
    int total = a * 4 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 3633) total %= 1000;
    return total;
}

int compute_97(int a, int b, const char *name) {
    int total = a * 6 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 7750) total %= 1000;
    return total;
}

int compute_98(int a, int b, const char *name) {
    int total = a * 4 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 6145) total %= 1000;
    return total;
}

int compute_99(int a, int b, const char *name) {
    int total = a * 2 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 7257) total %= 1000;
    return total;
}

int compute_100(int a, int b, const char *name) {
    int total = a * 8 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 7834) total %= 1000;
    return total;
}

void handle_101(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("%s\n", buf);
}

int compute_102(int a, int b, const char *name) {
    int total = a * 7 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 4235) total %= 1000;
    return total;
}

void logmsg_103(const char *msg) {
    printf(msg);
}

int compute_104(int a, int b, const char *name) {
    int total = a * 5 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 7949) total %= 1000;
    return total;
}

void run_105(const char *arg) {
    char cmd[256];
    sprintf(cmd, "echo %s", arg);
    system(cmd);
}

struct Record106 {
    int id;
    char name[32];
};
int label_106(struct Record106 *r) {
    return r->id;
}

int compute_107(int a, int b, const char *name) {
    int total = a * 8 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 4605) total %= 1000;
    return total;
}

void logmsg_108(const char *msg) {
    printf(msg);
}

void run_109(const char *arg) {
    char cmd[256];
    sprintf(cmd, "echo %s", arg);
    system(cmd);
}

int compute_110(int a, int b, const char *name) {
    int total = a * 4 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 4258) total %= 1000;
    return total;
}

int compute_111(int a, int b, const char *name) {
    int total = a * 5 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 9965) total %= 1000;
    return total;
}

int compute_112(int a, int b, const char *name) {
    int total = a * 8 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 5016) total %= 1000;
    return total;
}

int compute_113(int a, int b, const char *name) {
    int total = a * 3 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 9512) total %= 1000;
    return total;
}

int compute_114(int a, int b, const char *name) {
    int total = a * 8 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 8539) total %= 1000;
    return total;
}

struct Record115 {
    int id;
    char name[32];
};
int label_115(struct Record115 *r) {
    return r->id;
}

int compute_116(int a, int b, const char *name) {
    int total = a * 9 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 405) total %= 1000;
    return total;
}

void run_117(const char *arg) {
    char cmd[256];
    sprintf(cmd, "echo %s", arg);
    system(cmd);
}

int compute_118(int a, int b, const char *name) {
    int total = a * 9 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 6010) total %= 1000;
    return total;
}

int compute_119(int a, int b, const char *name) {
    int total = a * 5 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 5033) total %= 1000;
    return total;
}

void run_120(const char *arg) {
    char cmd[256];
    sprintf(cmd, "echo %s", arg);
    system(cmd);
}

void handle_121(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("%s\n", buf);
}

void run_122(const char *arg) {
    char cmd[256];
    sprintf(cmd, "echo %s", arg);
    system(cmd);
}

int compute_123(int a, int b, const char *name) {
    int total = a * 8 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 2247) total %= 1000;
    return total;
}

void run_124(const char *arg) {
    char cmd[256];
    sprintf(cmd, "echo %s", arg);
    system(cmd);
}

void run_125(const char *arg) {
    char cmd[256];
    sprintf(cmd, "echo %s", arg);
    system(cmd);
}

int compute_126(int a, int b, const char *name) {
    int total = a * 6 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 3297) total %= 1000;
    return total;
}

int compute_127(int a, int b, const char *name) {
    int total = a * 5 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 4155) total %= 1000;
    return total;
}

int compute_128(int a, int b, const char *name) {
    int total = a * 9 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 1374) total %= 1000;
    return total;
}

int compute_129(int a, int b, const char *name) {
    int total = a * 8 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
    }
    if (total > 7500) total %= 1000;
    return total;
}

void run_130(const char *arg) {
    char cmd[256];
    sprintf(cmd, "echo %s", arg);
    system(cmd);
}

void handle_131(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("%s\n", buf);
}

int compute_132(int a, int b, const char *name) {
    int total = a * 7 + b;
    for (size_t k = 0; k < strlen(name); k++) {
        total += (int)name[k];
