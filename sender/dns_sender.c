//
// Created by Zdeněk Lapeš on 13/10/22.
// Copyright 2022 <Zdenek Lapes>
//
// Inspiration: https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168

/******************************************************************************/
/**                                 TODO                                     **/
/******************************************************************************/

/******************************************************************************/
/**                                INCLUDES                                  **/
/******************************************************************************/
// #include "sender_implementation.h"
#include "../common/argument_parser.h"

int main(int argc, char *argv[]) {
    // Init
    program_t *program = malloc(sizeof(program_t));
    if (program == NULL) {
        ERROR_EXIT("Failed to allocate memory for program", EXIT_FAILURE);
    }
    program->argc = argc;
    program->argv = argv;
    set_args_sender(program);                           // Validate and parse args, if failed exit
    program->dgram = init_dns_datagram(true, program);  // Validate and init dns_datagram_t, if failed exit

    // TODO: start_sending(program);

    dealocate_all_exit(program, EXIT_SUCCESS, NULL);
}
