/* ------------------------------------------------------------------
 * SBox - Program Startup
 * ------------------------------------------------------------------ */

#include "xcbackup.h"

/**
 * Show program usage message
 */
static void show_usage ( void )
{
    fprintf ( stderr,
        "usage: xcbackup -cxlts stdin|password [-o random|offset] archive path [paths...]\n" "\n"
        "version: " XCBACKUP_VERSION "\n" "\n" "options:\n" "  -c    create new archive\n"
        "  -x    extract archive\n" "  -l    list files in archive\n"
        "  -t    test archive checksums\n" "  -s    do not print progress\n"
        "  -o    output file offset\n" "\n" );
}

/**
 * Check password strength
 */
static int check_password ( const char *password )
{
    char c;
    int has_upper_case = 0;
    int has_lower_case = 0;
    int has_digit = 0;
    int has_special = 0;
    size_t i;
    size_t len;

    len = strlen ( password );

    if ( len < 10 )
    {
        fprintf ( stderr, "Error: Password is too short.\n" );
        return 0;
    }

    for ( i = 0; i < len; i++ )
    {
        c = password[i];

        if ( isupper ( c ) )
        {
            has_upper_case = 1;

        } else if ( islower ( c ) )
        {
            has_lower_case = 1;

        } else if ( isdigit ( c ) )
        {
            has_digit = 1;

        } else
        {
            has_special = 1;
        }
    }

    if ( !has_upper_case )
    {
        fprintf ( stderr, "Warning: At least one upper case letter required.\n" );

    }

    if ( !has_lower_case )
    {
        fprintf ( stderr, "Warning: At least one lower case letter required.\n" );

    }

    if ( !has_digit )
    {
        fprintf ( stderr, "Warning: At least one digit required.\n" );

    }

    if ( !has_special )
    {
        fprintf ( stderr, "Warning: At least one special character required.\n" );
    }

    if ( !has_upper_case || !has_lower_case || !has_digit || !has_special )
    {
        return 0;
    }

    return 1;
}

/** 
 * Check if flag is set in the options string
 */
static int check_flag ( const char *options, char flag )
{
    return !!strchr ( options, flag );
}

/**
 * Read password from stdin
 */
#ifdef ENABLE_STDIN_PASSWORD
#include <termios.h>
static int read_stdin_password ( char *password, size_t size )
{
    int c;
    size_t i;
    struct termios termios_backup;
    struct termios termios_current;

    if ( tcgetattr ( STDIN_FILENO, &termios_backup ) < 0 )
    {
        return -1;
    }

    termios_current = termios_backup;

    termios_current.c_lflag &= ~( ECHO );

    if ( tcsetattr ( STDIN_FILENO, TCSANOW, &termios_current ) < 0 )
    {
        return -1;
    }

    for ( i = 0; i + 1 < size; i++ )
    {
        c = getchar (  );

        if ( c == '\n' || c == EOF )
        {
            break;
        }

        password[i] = c;
    }

    password[i] = '\0';

    if ( tcsetattr ( STDIN_FILENO, TCSANOW, &termios_backup ) < 0 )
    {
        return -1;
    }

    return 0;
}
#endif

/**
 * Program entry point
 */
int main ( int argc, char *argv[] )
{
    int status = 0;
    uint32_t options = OPTION_VERBOSE;
    int arg_off = 1;
    int flag_c;
    int flag_x;
    int flag_l;
    int flag_t;
    int flag_s;
    unsigned long offset;
    const char *password = NULL;
#ifdef ENABLE_STDIN_PASSWORD
    char password_buf[256];
#endif

    /* Validate arguments count */
    if ( argc < arg_off + 1 )
    {
        show_usage (  );
        return 1;
    }

    /* Do not buffer outputs */
    setbuf ( stdout, NULL );
    setbuf ( stderr, NULL );

    /* Parse flags from arguments */
    flag_c = check_flag ( argv[arg_off], 'c' );
    flag_x = check_flag ( argv[arg_off], 'x' );
    flag_l = check_flag ( argv[arg_off], 'l' );
    flag_t = check_flag ( argv[arg_off], 't' );
    flag_s = check_flag ( argv[arg_off], 's' );

    /* Shift arguments array */
    arg_off++;

    /* Tasks are exclusive */
    if ( flag_c + flag_x + flag_l + flag_t != 1 )
    {
        show_usage (  );
        return 1;
    }

    /* Unset verbose if silent mode flag set */
    if ( flag_s )
    {
        options &= ~OPTION_VERBOSE;
    }

    /* Set list only option if needed */
    if ( flag_l )
    {
        options |= OPTION_LISTONLY;
    }

    /* Set test only option if needed */
    if ( flag_t )
    {
        options |= OPTION_TESTONLY;
    }

    /* Validate arguments count */
    if ( argc < arg_off + 1 )
    {
        show_usage (  );
        return 1;
    }

    /* Get password from command line */
    password = argv[arg_off];

    /* Shift arguments array */
    arg_off++;

    if ( !strcmp ( password, "stdin" ) )
    {
#ifdef ENABLE_STDIN_PASSWORD
        printf ( "Please enter password: " );

        if ( read_stdin_password ( password_buf, sizeof ( password_buf ) ) < 0 )
        {
            fprintf ( stderr, "Error: Failed to read stdin password.\n" );
            return 1;
        }

        putchar ( '\n' );

        password = password_buf;
#else
        fprintf ( stderr, "Error: Reading password from stdin not enabled.\n" );
#endif
    }

    /* Check password strength */
    if ( !check_password ( password ) )
    {
        fprintf ( stderr, "Error: Password is too weak.\n" );
        return 1;
    }

    /* Validate arguments count */
    if ( argc < arg_off + 1 )
    {
        show_usage (  );
        return 1;
    }

    /* Parse output file offset if needed */
    if ( !strcmp ( argv[arg_off], "-o" ) )
    {
        arg_off++;

        if ( argc < arg_off + 1 )
        {
            show_usage (  );
            return 1;
        }

        if ( !strcmp ( argv[arg_off], "random" ) )
        {
            offset = RANDOM_OFFSET;

        } else
        {
            if ( sscanf ( argv[arg_off], "%lu", &offset ) <= 0 )
            {
                show_usage (  );
                return 1;
            }
        }

        options |= OPTION_OFFSET;

        arg_off++;
    }

    /* Perform the task */
    if ( flag_c )
    {
        if ( argc < arg_off + 2 )
        {
            show_usage (  );
            return 1;
        }
#ifdef EXTRACT_ONLY
        fprintf ( stderr, "Error: Archive creation not enabled.\n" );
        status = -1;
#else
        status =
            xcbackup_pack_archive ( argv[arg_off], options, password, offset,
            ( const char ** ) ( argv + arg_off + 1 ) );

#endif
    } else if ( flag_x || flag_l || flag_t )
    {
        if ( argc != arg_off + 1 )
        {
            show_usage (  );
            return 1;
        }
        status = xcbackup_unpack_archive ( argv[arg_off], options, password );
    }

    /* Finally print error code and quit if found */
    if ( status < 0 )
    {
        fprintf ( stderr, "failure: %i\n", errno ? errno : -1 );
        return 1;
    }

    return 0;
}
