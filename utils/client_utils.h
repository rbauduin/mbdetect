
extern FILE *log_file;
const char * get_test_id(config_setting_t *test);
void setup_logging(config_setting_t *output_dir);
void close_logging();
#define client_log(...) do {  printf(__VA_ARGS__) ; fprintf(log_file, __VA_ARGS__); } while (0)
