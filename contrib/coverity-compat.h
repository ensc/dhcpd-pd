#define _Float32	float
#define _Float32x	double
#define _Float64	double
#define _Float64x	long double
#define _Float128	long double

#if defined(__SIZEOF_LONG_DOUBLE__) && __SIZEOF_LONG_DOUBLE__ != 16
#  warning unsupported size of 'double'
#endif

#if defined(__SIZEOF_DOUBLE__) && __SIZEOF_DOUBLE__ != 8
#  warning unsupported size of 'double'
#endif

#if defined(__SIZEOF_FLOAT__) && __SIZEOF_FLOAT__ != 4
#  warning unsupported size of 'float'
#endif
