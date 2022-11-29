/**
 * Project: ISA - DNS Tunneling
 *
 * @file dns_receiver.c
 *
 * @brief Implementation of ISA project
 *
 * @author Zdenek Lapes (xlapes02)
 */

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
