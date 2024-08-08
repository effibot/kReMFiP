//
// Created by effi on 08/08/24.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include "test.h"
#include <time.h>

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
    printf("generated random %d\n",x->a);
    return (void*)x;
}