//
// Created by effi on 16/09/24.
//

#ifndef SCTH_LIB_H
#define SCTH_LIB_H

// Library functions prototypes.
void **scth_finder(void);
void scth_cleanup(void);
int scth_hack(void *new_call_addr);
void scth_unhack(int to_restore);
int* scth_get_sysnis(void);

#endif //SCTH_LIB_H
