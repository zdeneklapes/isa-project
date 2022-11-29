/**
 * Project: ISA - DNS Tunneling
 *
 * @file dns_sender.c
 *
 * @brief Implementation of ISA project
 *
 * @author Zdenek Lapes (xlapes02)
 */

/******************************************************************************/
/**                                INCLUDES                                  **/
/******************************************************************************/
#include <stdlib.h>
#include <time.h>

#include "../common/argument_parser.h"
#include "../common/initializations.h"
#include "sender_implementation.h"

int main(int argc, char *argv[]) {
    srand(time(NULL));

    program_t *program = malloc(sizeof(program_t));
    if (program == NULL) {
        ERROR_EXIT("Failed to allocate memory for program", EXIT_FAILURE);
    }
    program->argc = argc;
    program->argv = argv;
    set_args_sender(program);         // Validate and parse args, if failed exit
    set_dns_datagram(program, true);  // Validate and init dns_datagram_t, if failed exit

    // Send
    start_sending(program);

    //
    dealocate_all_exit(program, EXIT_SUCCESS, NULL);
}
