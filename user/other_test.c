//
// Created by effi on 08/08/24.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include "test.h"
#include <time.h>


#define container_of(ptr, type, member) ({ \
const typeof( ((type *)0)->member ) *__mptr = (ptr); \
                (type *)( (char *)__mptr - offsetof(type,member) );})



int use_b(B *obj) {
    struct_A *A = container_of(obj, struct_A, bb);
    printf("A->a = %d\n", A->a);
    return obj->b;
}

void use_b2(B *obj) {
    struct_A *A = container_of(obj, struct_A, bb);
    A->c = "new hello";
}

void* init(void){
    struct_A *x = malloc(sizeof(struct_A*));
    //x = malloc(sizeof(x));
    if (x == NULL){
        return NULL;
    }
    unsigned int random_ticket;
    srand(time(NULL));
    random_ticket = (unsigned int) rand();
    x->a = 1u + (random_ticket % 32u);
    x->b = 2;
    x->c = "hello";
    x->bb.b = 3;
    int test = use_b(&x->bb);
    printf("test = %d\n", test);
    printf("generated random %d\n",x->a);
    printf("say hi: %s\n", x->c);
    use_b2(&x->bb);
    return (void*)x;
}