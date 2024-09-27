#ifndef _DEFINES_H_
#define _DEFINES_H_

#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) > (y) ? (x) : (y))

#define LOG(...) printf(__VA_ARGS__)
#define TIMER_START(name)   struct timespec name##_start, name##_end; \
                            double name##_accum; \
                            LOG(#name " TIMER START\n"); \
                            if( clock_gettime( CLOCK_REALTIME, &name##_start) == -1 ) { \
                                LOG( #name "_start: Cannot get current time" ); \
                            }                    
#define TIMER_END(name)     if( clock_gettime( CLOCK_REALTIME, &name##_end) == -1 ) { \
                                LOG( #name "_end: Cannot get current time" ); \
                            } \
                            name##_accum = ( name##_end.tv_sec - name##_start.tv_sec ) \
                                + (double)( name##_end.tv_nsec - name##_start.tv_nsec ) \
                                / (double)1000000000L; \
                            LOG(#name " TIMER END: %.6lf\n", name##_accum);

#endif /* _DEFINES_H_ */