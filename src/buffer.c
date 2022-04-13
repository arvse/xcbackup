/* ------------------------------------------------------------------
 * SBox - Buffer Stream Impl.
 * ------------------------------------------------------------------ */

#include "xcbackup.h"

/**
 * Buffer stream context
 */
struct buffer_stream_context_t
{
    struct io_stream_t *internal;
    size_t offset;
    size_t length;
    char buffer[CHUNK_SIZE];
};

/**
 * Dequeue data from cache buffer
 */
static size_t dequeue_buffer ( struct buffer_stream_context_t *context, void *data, size_t len )
{
    size_t dequeue_len;

    dequeue_len = MIN ( len, context->length - context->offset );
    memcpy ( data, context->buffer + context->offset, dequeue_len );
    context->offset += dequeue_len;

    return dequeue_len;
}

/**
 * Read data from buffer stream
 */
static ssize_t buffer_stream_read ( struct io_stream_t *io, void *data, size_t len )
{
    size_t length;
    struct buffer_stream_context_t *context;

    context = ( struct buffer_stream_context_t * ) io->context;

    if ( context->offset < context->length )
    {
        return dequeue_buffer ( context, data, len );
    }

    if ( ( ssize_t ) ( length =
            context->internal->read ( context->internal, context->buffer,
                sizeof ( context->buffer ) ) ) < 0 )
    {
        return -1;
    }

    context->offset = 0;
    context->length = length;

    return dequeue_buffer ( context, data, len );
}

/**
 * Write data to buffer stream
 */
static ssize_t buffer_stream_write ( struct io_stream_t *io, const void *data, size_t len )
{
    size_t cache_len;
    struct buffer_stream_context_t *context;

    context = ( struct buffer_stream_context_t * ) io->context;

    if ( context->length == sizeof ( context->buffer ) )
    {
        if ( context->internal->write_complete ( context->internal, context->buffer,
                context->length ) < 0 )
        {
            return -1;
        }

        context->length = 0;
    }

    cache_len = MIN ( len, sizeof ( context->buffer ) - context->length );
    memcpy ( context->buffer + context->length, data, cache_len );
    context->length += cache_len;

    return cache_len;
}

/**
 * Verify buffer stream integrity
 */
static int buffer_stream_verify ( struct io_stream_t *io )
{
    struct buffer_stream_context_t *context;

    context = ( struct buffer_stream_context_t * ) io->context;

    return context->internal->verify ( context->internal );
}

/**
 * Flush buffer stream output
 */
static int buffer_stream_flush ( struct io_stream_t *io )
{
    struct buffer_stream_context_t *context;

    context = ( struct buffer_stream_context_t * ) io->context;

    if ( context->length )
    {
        if ( context->internal->write_complete ( context->internal, context->buffer,
                context->length ) < 0 )
        {
            return -1;
        }

        context->length = 0;
    }

    return context->internal->flush ( context->internal );
}

/**
 * Close IO stream
 */
static void buffer_stream_close ( struct io_stream_t *io )
{
    struct buffer_stream_context_t *context;

    context = ( struct buffer_stream_context_t * ) io->context;

    context->internal->close ( context->internal );

    free ( io );
}

/**
 * Create new buffer stream
 */
struct io_stream_t *buffer_stream_new ( struct io_stream_t *internal )
{
    struct io_stream_t *io;
    struct buffer_stream_context_t *context;

    if ( !( io = io_stream_new (  ) ) )
    {
        return NULL;
    }

    if ( !( context =
            ( struct buffer_stream_context_t * ) malloc ( sizeof ( struct
                    buffer_stream_context_t ) ) ) )
    {
        free ( io );
        return NULL;
    }

    context->length = 0;
    context->offset = 0;
    context->internal = internal;

    io->context = context;
    io->read = buffer_stream_read;
    io->write = buffer_stream_write;
    io->verify = buffer_stream_verify;
    io->flush = buffer_stream_flush;
    io->close = buffer_stream_close;

    return io;
}
