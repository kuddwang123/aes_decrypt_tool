#ifndef HJ_INTERFACE_INCLUDE_LOG_H
#define HJ_INTERFACE_INCLUDE_LOG_H

#define LOG_USE 1
#define LOG_NOUSE 2
#define CONFIG_ENABLE_LOG LOG_NOUSE
#ifndef CONFIG_ENABLE_LOG
#define CONFIG_ENABLE_LOG LOG_USE
#endif
#if CONFIG_ENABLE_LOG == LOG_USE
#define LOG(...) printf(__VA_ARGS__)
#endif
#if CONFIG_ENABLE_LOG == LOG_NOUSE
#define LOG(...) 
#endif

#endif
