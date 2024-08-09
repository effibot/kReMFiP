//
// Created by effi on 08/08/24.
//

#ifndef TEST_H
#define TEST_H

typedef struct _struct_B {
    int b;
} B;

typedef struct _struct_A {
    unsigned int a;
    int b;
    char *c;
    B bb;
} struct_A;


void* init(void);

#endif //TEST_H
