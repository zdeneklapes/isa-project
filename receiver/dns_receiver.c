//
// Created by Zdeněk Lapeš on 13/10/22.
// Copyright 2022 <Zdenek Lapes>
//

/******************************************************************************/
/**                              TODO                                        **/
/******************************************************************************/
// TODO: Check if file exists
// TODO: Allocate args_t on heap
// TODO: receiver check path of filepath and create it
// TODO: Allocate args_t on heap
// TODO: dir ../../create
// TODO: dir_path zanoreni
// TODO: recursive dir creation

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
