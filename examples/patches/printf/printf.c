char my_str[] = "hello hello\n";

int __attribute__((section("hook_printf"))) main(int argc, const char *argv[])
{
    puts(my_str);
    return 0;
}
