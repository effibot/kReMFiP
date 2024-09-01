//
// Created by effi on 08/08/24.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdint.h>

#include "test.h"

struct_A x, *x_ptr;


int main(int argc, char **argv){

    //x = *x_ptr;
    x_ptr = (struct_A*)init();
    x = *x_ptr;
    printf("x.a = %d; x_ptr->a = %d\n", (&x)->a, x_ptr->a);
    printf("again: %s", x.c);
    return 0;
}

