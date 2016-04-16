#ifndef HOOK_H

#define HOOK_H

#define HOOK(__function) \
    __attribute__((section(__function##_section)))

#endif /* end of include guard: HOOK_H */
