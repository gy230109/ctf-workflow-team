#include "crypt_sha512.c"
__declspec(dllexport) int check_hash(const char *password, const char *target) {
    char out[256];
    char *r = sha512crypt(password, target, out);
    return r && strcmp(r, target) == 0;
}
__declspec(dllexport) int verify_implementation(void) {
    char out[256];
    return strcmp(__crypt_sha512("password", "$6$test$", out), "*") != 0;
}
