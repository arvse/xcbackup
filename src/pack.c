/* ------------------------------------------------------------------
 * SBox - Archive Pack Task
 * ------------------------------------------------------------------ */

#include "xcbackup.h"

#ifndef EXTRACT_ONLY

/**
 * SBox archive pack callback
 */
int xcbackup_pack_callback ( void *context, struct xcbackup_node_t *node, const char *path )
{
    int fd;
    int isdir;
    char slash = '/';
    char zero = '\0';
    char *ptr;
    char *wpath;
    uint32_t net_size;
    uint32_t net_modified;
    size_t len;
    size_t sum = 0;
    struct io_stream_t *io;
    struct iter_context_t *iter_context;
    struct stat statbuf;

    iter_context = ( struct iter_context_t * ) context;

    isdir = node->mode & S_IFDIR;

    if ( isdir && node->head )
    {
        return 0;
    }

    if ( iter_context->io->flush ( iter_context->io ) < 0 )
    {
        return -1;
    }

    if ( iter_context->file->write_complete ( iter_context->file, xcbackup_archive_postfix,
            sizeof ( xcbackup_archive_postfix ) ) < 0 )
    {
        return -1;
    }

    if ( iter_context->file->write_complete ( iter_context->file, xcbackup_archive_prefix,
            sizeof ( xcbackup_archive_prefix ) ) < 0 )
    {
        return -1;
    }

    if ( output_aes_stream_split ( iter_context->io ) < 0 )
    {
        return -1;
    }

    len = strlen ( path );

    if ( !( wpath = ( char * ) malloc ( len + 1 ) ) )
    {
        return -1;
    }

    memcpy ( wpath, path, len + 1 );

    ptr = wpath;

    while ( *ptr )
    {
        if ( *ptr == '.' && ptr[1] == '.' )
        {
            *ptr = '_';
            ptr[1] = '_';
        }
        ptr++;
    }

    ptr = wpath;

    while ( *ptr == '/' )
    {
        ptr++;
    }

    if ( iter_context->io->write_complete ( iter_context->io, ptr, strlen ( ptr ) ) < 0 )
    {
        free ( wpath );
        return -1;
    }

    free ( wpath );

    if ( isdir )
    {
        if ( stat ( path, &statbuf ) < 0 )
        {
            perror ( path );
            return -1;
        }

        if ( statbuf.st_mtime != node->mtime )
        {
            fprintf ( stderr, "Error: Directory '%s' has changed.\n", path );
            return -1;
        }

        if ( iter_context->io->write_complete ( iter_context->io, &slash, sizeof ( slash ) ) < 0 )
        {
            return -1;
        }
    }

    if ( iter_context->io->write_complete ( iter_context->io, &zero, sizeof ( zero ) ) < 0 )
    {
        return -1;
    }

    if ( isdir )
    {
        return 0;
    }

    if ( ( fd = open ( path, O_RDONLY | O_BINARY ) ) < 0 )
    {
        perror ( path );
        return -1;
    }

    if ( fstat ( fd, &statbuf ) < 0 )
    {
        perror ( path );
        close ( fd );
        return -1;
    }

    if ( statbuf.st_mtime != node->mtime )
    {
        fprintf ( stderr, "Error: File '%s' has changed.\n", path );
        close ( fd );
        return -1;
    }

    net_size = htonl ( node->size );
    net_modified = time ( NULL );

    if ( iter_context->io->write_complete ( iter_context->io, &net_size, sizeof ( net_size ) ) < 0 )
    {
        close ( fd );
        return -1;
    }

    if ( iter_context->io->write_complete ( iter_context->io, &net_modified,
            sizeof ( net_modified ) ) < 0 )
    {
        close ( fd );
        return -1;
    }

    if ( !( io = file_stream_new ( fd ) ) )
    {
        close ( fd );
        return -1;
    }

    while ( ( ssize_t ) ( len =
            io->read_max ( io, iter_context->buffer, sizeof ( iter_context->buffer ) ) ) > 0 )
    {
        if ( iter_context->io->write_complete ( iter_context->io, iter_context->buffer, len ) < 0 )
        {
            perror ( path );
            io->close ( io );
            return -1;
        }

        sum += len;
    }

    io->close ( io );

    if ( sum != node->size )
    {
        fprintf ( stderr, "Error: File '%s' has changed.\n", path );
        return -1;
    }

    if ( iter_context->options & OPTION_VERBOSE )
    {
        show_progress ( 'a', path );
    }

    return 0;
}

/**
 * SBox archive measure callback
 */
int xcbackup_measure_callback ( void *context, struct xcbackup_node_t *node, const char *path )
{
    int isdir;
    struct iter_context_t *iter_context;
    struct stat statbuf;

    iter_context = ( struct iter_context_t * ) context;

    isdir = node->mode & S_IFDIR;

    if ( isdir && node->head )
    {
        return 0;
    }

    if ( isdir )
    {
        if ( stat ( path, &statbuf ) < 0 )
        {
            perror ( path );
            return -1;
        }

        iter_context->size += 512 + strlen ( path );
    }

    if ( isdir )
    {
        return 0;
    }

    iter_context->size += 512 + strlen ( path ) + node->size;

    return 0;
}

/** 
 * Pack files to an archive
 */
int xcbackup_pack_archive ( const char *archive, uint32_t options, const char *password,
    unsigned long offset, const char *files[] )
{
    int fd;
    int mode;
    unsigned long size;
    struct io_stream_t *raw;
    struct io_stream_t *file;
    struct io_stream_t *io;
    struct xcbackup_node_t *root;
    struct iter_context_t *iter_context;

    mode = O_CREAT | O_WRONLY | O_BINARY;

    if ( !( options & OPTION_OFFSET ) )
    {
        mode |= O_TRUNC;
    }

    if ( ( fd = open ( archive, mode, 0644 ) ) < 0 )
    {
        perror ( archive );
        return -1;
    }

    if ( !( iter_context =
            ( struct iter_context_t * ) malloc ( sizeof ( struct iter_context_t ) ) ) )
    {
        close ( fd );
        return -1;
    }

    iter_context->options = options;

    if ( !( root = build_file_net ( files ) ) )
    {
        free ( iter_context );
        close ( fd );
        return -1;
    }

    if ( ( options & OPTION_OFFSET ) && offset == RANDOM_OFFSET )
    {
        if ( ( off_t ) ( size = lseek ( fd, 0, SEEK_END ) ) < 0 )
        {
            perror ( "lseek" );
            free_file_net ( root );
            free ( iter_context );
            close ( fd );
            return -1;
        }

        printf ( "estimated container size: %lu bytes\n", size );

        iter_context->size = 512;

        if ( file_net_iter ( root, iter_context, xcbackup_measure_callback ) < 0 )
        {
            free_file_net ( root );
            free ( iter_context );
            return -1;
        }

        printf ( "estimated archive size: %lu bytes\n", iter_context->size );

        if ( size <= iter_context->size )
        {
            offset = 0;

        } else
        {
            srand ( time ( NULL ) );
            offset = rand (  ) * ( size - iter_context->size ) / RAND_MAX;
        }
    }

    if ( options & OPTION_OFFSET )
    {
        printf ( "output file offset: %lu bytes\n", offset );

        if ( lseek ( fd, offset, SEEK_SET ) < 0 )
        {
            perror ( "lseek" );
            free_file_net ( root );
            free ( iter_context );
            close ( fd );
            return -1;
        }
    }

    if ( !( raw = file_stream_new ( fd ) ) )
    {
        free_file_net ( root );
        free ( iter_context );
        close ( fd );
        return -1;
    }

    if ( !( file = buffer_stream_new ( raw ) ) )
    {
        free_file_net ( root );
        raw->close ( raw );
        free ( iter_context );
        return -1;
    }

    if ( !( io = output_aes_stream_new ( file, password ) ) )
    {
        free_file_net ( root );
        free ( iter_context );
        file->close ( file );
        return -1;
    }

    iter_context->io = io;
    iter_context->file = file;

    if ( file_net_iter ( root, iter_context, xcbackup_pack_callback ) < 0 )
    {
        free_file_net ( root );
        free ( iter_context );
        io->close ( io );
        return -1;
    }

    free_file_net ( root );
    free ( iter_context );

    if ( io->flush ( io ) < 0 )
    {
        io->close ( io );
        return -1;
    }

    if ( file->write_complete ( file, xcbackup_archive_postfix,
            sizeof ( xcbackup_archive_postfix ) ) < 0 )
    {
        close ( fd );
        return -1;
    }

    if ( file->flush ( file ) < 0 )
    {
        io->close ( io );
        return -1;
    }

    io->close ( io );

    return 0;
}

#endif
