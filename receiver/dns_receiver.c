//
// Created by Zdeněk Lapeš on 13/10/22.
// Copyright 2022 <Zdenek Lapes>
//

/******************************************************************************/
/**                              TODO                                        **/
/******************************************************************************/
// TODO: dir ../../create PARENT_DIR
// TODO: dir_path zanoreni

/******************************************************************************/
/**                             INCLUDES                                     **/
/******************************************************************************/
#include "receiver_implementation.h"

int main(int argc, char *argv[]) {
    //
    program_t *program = malloc(sizeof(program_t));
    if (program == NULL) {
        ERROR_EXIT("Failed to allocate memory for program", EXIT_FAILURE);
    }
    program->argc = argc;
    program->argv = argv;
    set_args_receiver(program);        // Validate and parse args, if failed exit
    set_dns_datagram(program, false);  // Validate and init dns_datagram_t, if failed exit

    //
    receive_packets(program);

    //
    dealocate_all_exit(program, EXIT_SUCCESS, NULL);
}
