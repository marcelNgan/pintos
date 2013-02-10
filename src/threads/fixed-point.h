#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#define P 17
#define Q 14
#define F 1 << (Q)  // for fractions

#define CONVERT_TO_FP(n) (n) * (F)
#define FLOOR(x) (x) / (F)
#define ROUND(x) ((x) >= 0 ? ((x) + (F) / 2) / (F)\
                                  : ((x)-(F)/2) / (F))
#define ADD(x , y) (x) + (y)
#define SUB(x , y) (x) - (y)
#define ADD_INT(x , n) (x) + (n) * (F)
#define SUB_INT(x , n) (x) - (n) * (F)

#define MULT(x , y) ((int64_t)(x)) * (y) / (F)
#define MULT_INT(x , n) (x) * (n)
#define DIV(x , y) ((int64_t) (x)) * (F) / (y)
#define DIV_INT(x , n) (x) / (n)

#endif
